"""BrowseWorker — Phase 1 浏览器操作子 Agent。

★ 本模块由原 core/browse_worker.py 拆分而来，所有公开/私有名保持兼容。
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator, TYPE_CHECKING

from core.llm import LLMClient, Message, parse_tool_call_arguments
from core.context import ContextManager
from core.tools import build_browse_worker_tools
from core.tool_executor import ToolExecutor
from core.config import MAX_TOOL_RESULT, REPEAT_TOOL_THRESHOLD
from core.log import get_logger
from core.prompts import load_prompt
from core.realtime_protocols import classify_realtime_flow, dedupe_realtime_channels

from ._ledger import BrowseTaskLedger
from ._menu_grouper import build_group_checklist

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = get_logger("browse_worker")


# ---- 子 Agent 执行 ----

BROWSE_WORKER_MAX_ROUNDS = 200  # 每个子 Agent 最大轮次（最大组 29 Tab × 6-7 轮 = 200 左右）


class BrowseWorker:
    """Phase 1 浏览器操作子 Agent。

    负责一组菜单页面的深度操作和流量抓取。
    共享主 Agent 的浏览器实例（串行执行，不并发）。
    """

    def __init__(
        self,
        worker_id: str,
        llm: LLMClient,
        sitemap: "Sitemap",
        group: dict,
        target_info: str,
        has_credentials: bool,
        extra_scope: list | None = None,
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.sitemap = sitemap
        self.group = group  # {"name", "menus", "tab_count", "page_count"}
        self.target_info = target_info
        self.has_credentials = has_credentials
        self.extra_scope = extra_scope or []  # 关联域名白名单
        self.ledger = BrowseTaskLedger(self.group.get("menus") or [])

        self.context = ContextManager(llm=self.llm, compress_mode="browse")
        self.tool_executor = ToolExecutor(
            sitemap=sitemap,
            has_credentials=has_credentials,
            task_id=sitemap.task_id,
        )

        self._init_context()

    def _init_context(self):
        """构建子 Agent 的独立上下文。"""
        # 基础 prompt
        prompts_dir = Path(__file__).parent / "prompts"
        if (prompts_dir / "solver.md").exists():
            self.context.add_system(
                (prompts_dir / "solver.md").read_text(encoding="utf-8")
            )

        # Phase 1 角色定义
        scope_hint = ""
        if self.extra_scope:
            scope_hint = (
                f"\n\n## 关联域名（可以访问）\n\n"
                f"以下域名是目标产品的关联域，在操作中遇到指向这些域的链接/跳转时，"
                f"**可以跟进访问**，不要跳过：\n"
                + "\n".join(f"- `{d}`" for d in self.extra_scope)
            )
        self.context.add_system(
            load_prompt("browse_worker_group")
            + f"{self.sitemap.to_summary()}"
            + f"{scope_hint}"
        )

        # 生成本组 checklist
        checklist = build_group_checklist(self.group["menus"])
        ledger_plan = self.ledger.render_plan()

        # ★ 2026-05-26：操作 SOP 外移到 core/prompts/browse_sop.md，路径 A/B 共用
        # 同一份操作规约 + 表单填值规范 + 防死循环策略，避免散落不同文件难维护
        try:
            sop_text = (prompts_dir / "browse_sop.md").read_text(encoding="utf-8")
        except Exception as _e:
            log.warning("加载 browse_sop.md 失败（不影响主流程）: %s", _e)
            sop_text = ""

        # ★ 2026-05-25：checklist + 工具说明 + 操作规约 全部放进 system message
        # 原因：ContextManager.compress() 只压缩 history（user/assistant/tool），不动 system_messages。
        # 老版放在 user message 里，第 10 轮触发压缩后 LLM 就看不到 checklist 了，
        # 后面的几十轮失去剧本就会瞎点 → 漏抓 API。
        # 现在放 system，LLM 在 200 轮内永远能看到完整 selector 和字段表。
        self.context.add_system(
            f"## 本次任务：操作「{self.group['name']}」模块\n\n"
            f"以下是菜单树分析初步识别的 **{self.group['page_count']} 个页面**、"
            f"**{self.group['tab_count']} 个 Tab**，作为你探索的起步入口。\n\n"
            "## 你能用的工具（仅这些，没有别的）\n"
            "- `browser_goto(url)` —— 进入页面（**优先用 page_url 直接 goto**，比点菜单稳）\n"
            "- `browser_get_content()` —— 摸清当前页面有哪些可点元素（返回 forms/buttons/links 含真实 selector）\n"
            "- `browser_get_accessibility_tree()` —— 当 get_content 返回按钮很少时用，从无障碍树发现隐藏的交互元素\n"
            "- `browser_click(selector)` —— 点击。**selector 优先抄下面 checklist 上给的**\n"
            "- `browser_hover(selector)` —— 悬停到元素上，触发 hover 才出现的操作按钮/子菜单（如表格行的编辑按钮）\n"
            "- `browser_fill(selector, value)` —— 填表。邮箱/手机号/日期都要按合法格式填\n"
            "- `browser_screenshot(name)` —— 截图（也可以当『等页面渲染完』用）\n"
            "- `proxy_get_traffic()` —— 抓最近的 HTTP 流量。**这是你的最终目的，每次操作后必调**\n"
            "- `note_add(type, content)` —— 偶尔记录关键发现（如：某页面发现了未在 checklist 中的接口）\n"
            "- `phase_complete(summary)` —— 本组操作完成\n\n"
            f"{sop_text}\n\n"
            "## 结构化页面账本（机器会按真实工具调用统计页面 + 按钮/Tab/表单覆盖率）\n\n"
            f"{ledger_plan}\n\n"
            "## 核心目标：最大化 API 发现\n\n"
            "checklist 只是起步的已知页面入口。每次进入新页面后，你都必须"
            "通过 browser_get_content 或 browser_get_accessibility_tree 扫描页面上"
            "的侧边栏或导航栏链接，把发现的任何未访问页面入口追加到你的操作列表。\n\n"
            "## 完成条件（全部满足才能调 phase_complete）\n\n"
            "1. 所有已发现的页面入口都已经访问过\n"
            "2. 每个页面上的可交互元素（按钮/Tab/表单/筛选/排序/分页）都尝试过\n"
            "3. 连续操作多个页面都没有产生新的业务 API\n\n"
            "禁止因某个页面按钮难点击就推断所有页面都如此，每个页面独立判断。\n\n"
            "## 操作 Checklist（起步入口，selector 已标出。操作过程中自行扩展）\n\n"
            f"{checklist}"
        )

        # user message 只留"开工"指令，简短 → 即使被压缩也无所谓
        self.context.add_user(
            f"开始操作「{self.group['name']}」模块。"
            f"从 Checklist 给出的已知入口起步，每进入一个页面就扫描导航栏/侧边栏，"
            f"把发现的任何新页面入口都加入操作列表。"
            f"所有可见页面和交互元素都操作完毕、无新 API 产生后，调用 phase_complete。"
        )

    async def run(self) -> AsyncGenerator[dict, None]:
        """运行子 Agent 直到完成或超时。"""
        round_num = 0
        _last_tool_sig = ""
        _repeat_count = 0
        completed = False
        # ★ 2026-05-28：STALE 判断升级为"双维度"（API 增量 + checklist 进度）
        # 只有同时满足"无新 API"且"无 checklist 进展"才判定为 STALE。
        # 纯展示页（无 API 但 LLM 在推进 checklist）不再被误杀。
        STALE_ROUNDS_LIMIT = 15
        STALE_NUDGE_AT = 10
        STALE_FINAL_CHANCE = 5  # STALE 退出前给的额外轮次（从10降至5）
        PROGRESS_CHECK_INTERVAL = 30  # 每 N 轮注入一次进度检查点
        last_api_count = len(self.sitemap.apis) if self.sitemap else 0
        rounds_since_new_api = 0
        _nudged = False
        _final_chance_given = False  # 是否已给过"最后机会"
        _progress_reset_count = 0  # has_recent_progress 重置计数（防止无限续命）
        _MAX_PROGRESS_RESETS = 2  # 最多允许 2 次"有进度"续命，之后强制退出
        # ★ checklist 进度追踪：通过检测 LLM 回复中的 ✅ 标记来判断是否在推进
        _last_checklist_progress_round = 0  # 上次检测到 ✅ 进展的轮次
        _checklist_done_count = 0  # 累计检测到的 ✅ 数量
        # ★ 工具白名单：BrowseWorker 专用，砍掉 evaluate / js_* / sitemap_* / proxy_send 等
        worker_tools = build_browse_worker_tools()

        while round_num < BROWSE_WORKER_MAX_ROUNDS and not completed:
            round_num += 1

            # ---- 双维度 STALE 检测 ----
            if self.sitemap:
                cur = len(self.sitemap.apis)
                if cur > last_api_count:
                    last_api_count = cur
                    rounds_since_new_api = 0
                    _nudged = False
                    _final_chance_given = False
                else:
                    rounds_since_new_api += 1

                # ★ 中途轻推：连续 N/2 轮无新 API 时，注入一条推进提示
                if rounds_since_new_api == STALE_NUDGE_AT and not _nudged:
                    _nudged = True
                    self.context.add_user(
                        f"⚠️ 已连续 {STALE_NUDGE_AT} 轮没有新 API 进来。"
                        "你现在卡在哪一个 ⬜ 上？\n"
                        "如果同一个 selector 失败超过 2 次：**立刻打 ✅ 跳过**，去做下一个未完成的 ⬜。\n"
                        "如果你已经完成了大部分页面：调 `phase_complete(summary)` 结束本组。\n"
                        "不要再尝试同一个失败的操作。"
                    )

                if rounds_since_new_api >= STALE_ROUNDS_LIMIT:
                    # ★ 双维度判断：如果 LLM 最近 10 轮内有 checklist 进展，不退出
                    has_recent_progress = (round_num - _last_checklist_progress_round) <= 10
                    # ★ 2026-08-05：限制"有进度"续命次数，防止 LLM 反复输出 ✅ 但无实际 API 进展导致无限循环
                    if has_recent_progress and _progress_reset_count < _MAX_PROGRESS_RESETS:
                        _progress_reset_count += 1
                        log.warning("[%s] STALE 但有 checklist 进度，第 %d 次续命（上限 %d）",
                                    self.worker_id, _progress_reset_count, _MAX_PROGRESS_RESETS)
                        rounds_since_new_api = STALE_NUDGE_AT  # 重置到 nudge 之后，避免立即再触发
                        _nudged = True
                    elif not _final_chance_given:
                        # ★ 退出前"最后机会"：扫描未完成项，注入强制推进指令
                        _final_chance_given = True
                        # 从 system messages 中提取未完成的 ⬜ 数量（粗略估计）
                        unchecked_hint = ""
                        for sm in self.context.system_messages:
                            if "Checklist" in sm.content:
                                unchecked_count = sm.content.count("⬜")
                                if unchecked_count > 0:
                                    unchecked_hint = f"你还有约 {unchecked_count} 个 ⬜ 未完成。"
                                break
                        self.context.add_user(
                            f"🚨 即将因无进展退出（已连续 {STALE_ROUNDS_LIMIT} 轮无新 API 且无 checklist 进展）。\n"
                            f"{unchecked_hint}\n"
                            f"你还有 {STALE_FINAL_CHANCE} 轮机会：\n"
                            f"1. 立即用 `browser_goto` 进入下一个未完成的 ⬜ 页面\n"
                            f"2. 或者调用 `phase_complete(summary)` 结束本组\n"
                            f"不要再重试已失败的操作！"
                        )
                        # 给额外轮次
                        rounds_since_new_api = STALE_ROUNDS_LIMIT - STALE_FINAL_CHANCE
                    else:
                        # 最后机会也用完了，真的退出
                        yield {
                            "type": "browse_worker_done",
                            "worker": self.worker_id,
                            "group": self.group["name"],
                            "rounds": round_num,
                            "reason": f"已连续无进展（API+checklist 双维度），提前结束（共 {round_num} 轮）",
                            "ledger": self.ledger.stats(),
                        }
                        return

            # ---- 周期性进度注入（防止 LLM 遵循度衰减） ----
            if round_num > 1 and round_num % PROGRESS_CHECK_INTERVAL == 0:
                api_count = len(self.sitemap.apis) if self.sitemap else 0
                self.context.add_user(
                    f"📊 进度检查点（第 {round_num}/{BROWSE_WORKER_MAX_ROUNDS} 轮）：\n"
                    f"- 已抓 API：{api_count} 个\n"
                    f"- 已完成 ✅：约 {_checklist_done_count} 项\n"
                    f"- 机器账本：{self.ledger.progress_summary()}\n\n"
                    f"请继续按 system 中的 Checklist 执行下一个 ⬜，优先处理机器账本里的待访问页面和待交互按钮/Tab/表单。\n"
                    f"提醒：进入页面 selector 点不到就立刻用备用 route/page_url 直达；每个页面必须深入操作，交互后要抓流量，不要只浏览不操作。"
                )

            yield {
                "type": "browse_worker_thinking",
                "worker": self.worker_id,
                "group": self.group["name"],
                "round": round_num,
            }

            try:
                messages = self.context.get_messages()
                # ★ 2026-08-05：补 caller 埋点，此前 77% 的 LLM 调用 caller 为空无法追踪
                response = await asyncio.to_thread(
                    self.llm.chat, messages, worker_tools,
                    caller=f"browse:{self.worker_id}"
                )
            except Exception as e:
                yield {
                    "type": "browse_worker_error",
                    "worker": self.worker_id,
                    "error": str(e),
                }
                break

            self.context.add_assistant(response)

            # ★ checklist 进度检测：如果 LLM 回复中包含 ✅，说明在推进任务
            if response.content and "✅" in response.content:
                new_done = response.content.count("✅")
                if new_done > 0:
                    _checklist_done_count += new_done
                    _last_checklist_progress_round = round_num

            if response.reasoning_content:
                yield {
                    "type": "browse_worker_reasoning",
                    "worker": self.worker_id,
                    "content": response.reasoning_content[:200],
                }

            if response.content:
                yield {
                    "type": "browse_worker_message",
                    "worker": self.worker_id,
                    "content": response.content[:300],
                }

            if response.tool_calls:
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, _args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller="browse_worker")

                    # 重复检测
                    tool_sig = f"{func_name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
                    if tool_sig == _last_tool_sig:
                        _repeat_count += 1
                    else:
                        _last_tool_sig = tool_sig
                        _repeat_count = 1

                    if _repeat_count >= REPEAT_TOOL_THRESHOLD:
                        self.context.add_tool_result(tc["id"],
                            f"⚠️ 连续 {_repeat_count} 次相同操作，已中断。换一种方式或跳到下一个。")
                        _repeat_count = 0
                        _last_tool_sig = ""
                        continue

                    # phase_complete = 本组完成
                    if func_name == "phase_complete":
                        self.ledger.mark_phase_complete()
                        self.context.add_tool_result(
                            tc["id"],
                            f"✅ 本组操作完成\n机器账本：{self.ledger.progress_summary()}"
                        )
                        completed = True
                        break

                    # 不允许 done（只有主 Agent 能调）
                    if func_name == "done":
                        self.context.add_tool_result(tc["id"],
                            load_prompt("browse_worker_phase_end"))
                        continue

                    # 不允许 sitemap_add_feature（由主 Agent 统一处理）
                    if func_name == "sitemap_add_feature":
                        self.context.add_tool_result(tc["id"],
                            "功能点由主 Agent 统一添加，你只需操作页面抓流量。继续下一个操作。")
                        continue

                    # 执行工具
                    args_brief = json.dumps(args, ensure_ascii=False)[:150]

                    # ★ 为关键操作生成友好的日志摘要
                    friendly_desc = f"{func_name}({args_brief})"
                    if func_name == "browser_click":
                        selector = args.get("selector", args.get("text", ""))
                        friendly_desc = f"点击: {selector[:60]}"
                    elif func_name == "browser_fill":
                        selector = args.get("selector", "")
                        value = args.get("value", "")[:20]
                        friendly_desc = f"填写: {selector[:40]} = '{value}'"
                    elif func_name == "browser_goto":
                        url = args.get("url", "")
                        friendly_desc = f"访问: {url[:80]}"
                    elif func_name == "proxy_get_traffic":
                        friendly_desc = "抓取流量"
                    elif func_name == "browser_get_content":
                        friendly_desc = "获取页面内容"
                    elif func_name == "browser_screenshot":
                        friendly_desc = f"截图: {args.get('name', '')}"
                    elif func_name == "browser_evaluate":
                        js = args.get("js_code", "")[:40]
                        friendly_desc = f"执行JS: {js}..."
                    elif func_name == "sitemap_add_feature":
                        friendly_desc = f"添加功能点: {args.get('name', '')}"

                    yield {
                        "type": "browse_worker_tool",
                        "worker": self.worker_id,
                        "tool": friendly_desc,
                    }

                    self.ledger.mark_tool(func_name, args)

                    try:
                        result = await self.tool_executor.execute(func_name, args)
                    except Exception as e:
                        result = f"工具执行出错: {e}"

                    # ★ 自动从流量中提取 API（复用 session.py 的逻辑）
                    if func_name == "proxy_get_traffic" and self.sitemap:
                        self._extract_api_samples(result)

                    # ★ 关键工具结果推送到前端（让用户看到抓到了什么）
                    if func_name == "proxy_get_traffic":
                        if result and "暂无流量" in result:
                            yield {
                                "type": "browse_worker_tool_result",
                                "worker": self.worker_id,
                                "content": "⚠️ 抓取流量为空！浏览器可能未走代理，请检查 mitmproxy 是否正常运行。",
                            }
                        elif result:
                            # 从结果中提取 API URL 列表摘要
                            traffic_lines = result.strip().split("\n")
                            api_urls = []
                            for tl in traffic_lines:
                                tl = tl.strip()
                                # 匹配 [flow_xxx] METHOD URL → STATUS 格式
                                if tl.startswith("[flow_"):
                                    parts = tl.split("]", 1)
                                    if len(parts) > 1:
                                        api_urls.append(parts[1].strip()[:80])
                                # 也匹配纯 METHOD URL 格式
                                elif any(tl.startswith(m + " ") for m in
                                         ("GET", "POST", "PUT", "DELETE", "PATCH")):
                                    api_urls.append(tl[:80])
                            if api_urls:
                                summary = f"📡 抓到 {len(api_urls)} 条流量:\n" + "\n".join(
                                    f"  {u}" for u in api_urls[:8])
                                if len(api_urls) > 8:
                                    summary += f"\n  ... +{len(api_urls) - 8} 条"
                                yield {
                                    "type": "browse_worker_tool_result",
                                    "worker": self.worker_id,
                                    "content": summary,
                                }

                    # ★ 截图完成后推送图片路径给前端
                    if func_name == "browser_screenshot" and result:
                        screenshot_name = args.get("name", "screenshot")
                        yield {
                            "type": "browse_worker_screenshot",
                            "worker": self.worker_id,
                            "name": screenshot_name,
                        }

                    if len(result) > MAX_TOOL_RESULT:
                        result = result[:MAX_TOOL_RESULT] + "\n... (截断)"

                    self.context.add_tool_result(tc["id"], result)
            else:
                # 无工具调用 = LLM 输出纯文本（可能是总结），继续等
                if not response.content:
                    break

            # 上下文压缩
            # ★ 2026-08-05：browse_worker 用更激进的压缩阈值（15轮 vs 默认30轮）
            # 此前 browse_worker 上下文膨胀到 124K（45次100K+调用），严重浪费 input tokens
            if self.context.turn_count >= 15 or self.context.should_compress():
                self.context.compress()

        # 保存 sitemap
        self.sitemap.save()

        yield {
            "type": "browse_worker_done",
            "worker": self.worker_id,
            "group": self.group["name"],
            "rounds": round_num,
            "completed": completed,
            "ledger": self.ledger.stats(),
        }

    def _extract_api_samples(self, traffic_text: str):
        """从 proxy_get_traffic 结果中提取 API 样本（复用 session.py 逻辑）。"""
        import re
        flow_ids = re.findall(r'\[(flow_[a-f0-9]+)\]', traffic_text)
        if not flow_ids:
            return
        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()
            for fid in flow_ids:
                flow = _store.get(fid)
                if not flow:
                    continue
                if flow.method.upper() == "CONNECT":
                    continue
                url = flow.url
                static_exts = ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf', '.map', '.gif')
                if any(url.split('?')[0].lower().endswith(ext) for ext in static_exts):
                    continue
                self.sitemap.add_api(flow.method, url.split("?")[0],
                                     discovered_by="browse_worker")
                self.sitemap.add_api_sample(
                    method=flow.method,
                    url=url,
                    headers=flow.request_headers,
                    body=flow.request_body,
                    status_code=flow.status_code,
                    discovered_by="browse_worker",
                    response_body=flow.response_body,
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    content_type=getattr(flow, 'content_type', '') or '',
                    flow_id=fid,
                    trigger_context={
                        "worker": self.worker_id,
                        "module": self.group.get("name", "") if isinstance(self.group, dict) else "",
                        "tool": "proxy_get_traffic",
                    },
                )
                channels = classify_realtime_flow(
                    method=flow.method,
                    url=url,
                    request_headers=flow.request_headers,
                    request_body=flow.request_body or "",
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    response_body=flow.response_body or "",
                    status_code=flow.status_code,
                    discovered_by="browse_worker",
                )
                if channels:
                    self.sitemap.realtime_channels = dedupe_realtime_channels(
                        getattr(self.sitemap, "realtime_channels", []) + channels
                    )
        except Exception as e:
            log.warning("[%s] 提取 API 样本失败: %s", self.worker_id, e)
