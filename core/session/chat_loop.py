"""
ChatLoopMixin — chat() 主循环入口。

chat() 是整个系统的核心调度入口，跨 Phase 运行，
因此保留为完整方法（不再拆更细）。
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import AsyncGenerator

from core.sitemap import Sitemap, Priority, CheckResult
from core.config import MAX_TOOL_RESULT, CONTEXT_BATCH_SIZE, MAIN_MAX_ROUNDS, REPEAT_TOOL_THRESHOLD
from core.tools import ALL_MAIN_TOOLS
from core.intent import parse_user_intent
from core.log import get_logger, metrics
# ★ 统一的工具调用 arguments 解析（避免 JSON 解析失败被静默吞掉）
from core.llm import parse_tool_call_arguments, Message
from core.scan_store import upsert_scan, finish_scan as _finish_scan
from core.harm_validation import exploit_single_target
from core.realtime_protocols import classify_realtime_flow, dedupe_realtime_channels
from core.prompts.phases import (
    PHASE_EXPLORE_PROMPT, PHASE_ANALYZE_PROMPT,
    PHASE_TEST_PROMPT, PHASE_REPORT_PROMPT,
)
from core.prompts.phase1_user import (
    build_path_a_login_msg,
    build_path_a_post_browse_msg,
    build_path_b_user_msg,
    build_path_c_user_msg,
)

log = get_logger("session.chat_loop")


class ChatLoopMixin:
    """chat() 主循环入口。"""

    async def _run_crawler_with_timeout(
        self,
        crawler,
        progress_queue: "asyncio.Queue[str]",
        result_holder: dict,
        *,
        hard_timeout: int,
        silent_timeout: int,
        grace_after_stop: int,
        silent_min_elapsed: int = 0,
        periodic_save: bool = False,
        save_interval: int = 30,
        label: str = "",
    ):
        """通用爬虫监控循环（HARD/SILENT/GRACE 三阶段超时 + 进度队列消费）。

        统一处理主爬取（Step 1 匿名）和 Step 2 补偿（登录补充）两条路径，
        消除 80 行重复监控代码。

        Args:
            crawler: AutoCrawler 实例（必须有 request_stop / progress_tick / get_partial_result）
            progress_queue: 进度回调写入的队列（最大 1000）
            result_holder: 调用方传入的 dict，函数会写入 {"crawl_result": ..., "stop_reason": ...}
                （Generator 无法返回值，用此引用回传结果）
            hard_timeout: 硬超时（秒），超过强制停止
            silent_timeout: 静默超时（秒），N 秒无新点击则判定爬完
            grace_after_stop: 请求停止后等多少秒兜底 cancel
            silent_min_elapsed: silent_timeout 触发前必须先跑过的秒数（避免启动期误判）
            periodic_save: 是否周期保存 sitemap（仅主轮需要）
            save_interval: sitemap 保存间隔（秒）
            label: 日志/事件前缀（如 "登录爬取" 用于 Step 2）

        Yields:
            转发给上层的 SSE 事件（progress / 超时通知 等）
        """
        prefix = f"{label} " if label else ""
        crawl_task = asyncio.create_task(crawler.crawl())
        # ★ 2026-05-29: 将 crawler 和 crawl_task 暴露到 session 实例上，
        #   供 /api/stop 在用户手动停止时直接通知爬虫退出（修复：stop 只 cancel producer 但爬虫继续跑的 bug）
        self._active_crawler = crawler
        self._active_crawl_task = crawl_task
        stop_reason = None
        stop_requested_at = None
        crawl_result = None

        try:
            start_time = asyncio.get_event_loop().time()
            last_progress_tick = -1
            last_save_time = start_time
            last_progress_time = start_time

            while not crawl_task.done():
                now = asyncio.get_event_loop().time()
                elapsed = now - start_time

                # 硬超时
                if elapsed >= hard_timeout:
                    if stop_requested_at is None:
                        stop_reason = "hard_timeout"
                        crawler.request_stop(user_aborted=True)
                        stop_requested_at = now
                        yield self._event("system",
                            f"⏰ {prefix}已达硬上限 {hard_timeout}s，请求爬虫优雅退出（最多再等 {grace_after_stop}s）")
                    elif now - stop_requested_at >= grace_after_stop:
                        crawl_task.cancel()
                        yield self._event("system", f"⚠️ {prefix}优雅退出超时，强制 cancel")
                        raise asyncio.TimeoutError()

                # 静默超时检测（仅在还未请求停止时）
                if stop_requested_at is None:
                    cur_tick = getattr(crawler, "progress_tick", 0)
                    if cur_tick != last_progress_tick:
                        last_progress_tick = cur_tick
                        last_progress_time = now
                    else:
                        silent = now - last_progress_time
                        if silent >= silent_timeout and elapsed >= silent_min_elapsed:
                            stop_reason = "silent_timeout"
                            crawler.request_stop(user_aborted=False)
                            stop_requested_at = now
                            yield self._event("system",
                                f"✅ {prefix}爬虫已 {silent_timeout}s 无新进展（共点击 {cur_tick} 次），"
                                f"判定为已爬完，请求优雅退出")
                else:
                    # 已请求停止：检测是否被爬虫自己取消请求（self healing）
                    if not getattr(crawler, "_stop_requested", True):
                        stop_requested_at = None
                        stop_reason = None
                        last_progress_tick = getattr(crawler, "progress_tick", 0)
                        last_progress_time = now
                        continue
                    if now - stop_requested_at >= grace_after_stop:
                        crawl_task.cancel()
                        yield self._event("system",
                            f"⚠️ {prefix}优雅退出 {grace_after_stop}s 超时，强制 cancel")
                        raise asyncio.TimeoutError()

                # 消费进度队列（带 2s 超时让循环不会饿死）
                try:
                    msg = await asyncio.wait_for(progress_queue.get(), timeout=2.0)
                    if not msg.strip():
                        continue
                    # ★ 修复：不再无条件重置 last_progress_time
                    # 原逻辑：收到任何 _report（含每 30s 一次的心跳 💓）都重置静默计时器，
                    #   导致 silent_timeout 永不触发，爬虫在菜单/选择器循环中空转无法被杀。
                    # 现逻辑：静默超时完全依赖循环开头的 progress_tick 检测（line 113-116），
                    #   progress_tick 只在真实进度（新页面/新 API/点击成功）时递增，
                    #   心跳不算进度，不重置 → 无真实进展时 silent_timeout 正常触发。
                    if msg.startswith("__EVENT__:"):
                        try:
                            payload = json.loads(msg[len("__EVENT__:"):])
                            evt_type = payload.pop("type", "system")
                            yield self._event(evt_type, payload)
                        except Exception:
                            yield self._event("system", f"🕷️ {msg}")
                    else:
                        yield self._event("system", f"🕷️ {msg}")
                except asyncio.TimeoutError:
                    pass

                # 周期保存 sitemap（仅主轮启用，避免重复 IO）
                if periodic_save and self.sitemap and now - last_save_time >= save_interval:
                    try:
                        self.sitemap.save()
                        last_save_time = now
                    except Exception:
                        pass

            crawl_result = crawl_task.result()
            if stop_reason == "silent_timeout":
                yield self._event("system",
                    f"✅ {prefix}爬虫优雅退出完成，所有已抓数据保留，进入后续阶段")
        except (asyncio.TimeoutError, asyncio.CancelledError):
            try:
                crawl_result = crawler.get_partial_result()
                # 区分用户手动停止和超时退出
                user_aborted = getattr(crawler, "_user_aborted", False)
                if user_aborted:
                    yield self._event("system",
                        f"✅ {prefix}爬虫已被用户手动停止，"
                        f"已抓 {crawl_result.get('apis_total', 0)} API / "
                        f"{crawl_result.get('menu_clicked', 0)} 次点击，数据已保留，继续后续阶段")
                else:
                    yield self._event("system",
                        f"⚠️ {prefix}爬虫超时退出（{stop_reason or 'cancelled'}），"
                        f"已抓 {crawl_result.get('apis_total', 0)} API / "
                        f"{crawl_result.get('menu_clicked', 0)} 次点击，数据已保留进入下一阶段")
            except Exception as _e:
                yield self._event("system", f"⚠️ {prefix}爬虫超时且 partial result 失败: {_e}")
                crawl_result = None

        # 写回结果（Generator 没有 return value，用 dict 引用回传）
        result_holder["crawl_result"] = crawl_result
        result_holder["stop_reason"] = stop_reason
        # ★ 清理 session 上的爬虫引用（爬虫已结束，避免 /api/stop 误操作已完成的 task）
        self._active_crawler = None
        self._active_crawl_task = None

    async def chat(self, user_message: str) -> AsyncGenerator[str, None]:
        # ★ 把当前 task_id 注入 LLM 监控上下文，所有后续 LLM 调用都自动归属此会话
        from core.llm import set_current_task
        set_current_task(self.task_id)

        # 记录用户消息到对话历史
        self._event("user", user_message)  # 只记录，不 yield

        if not self.started:
            # ★ 首次启动：先输出"恢复上次会话"提示（如果有），再输出"Agent 已启动"
            # _try_recover 在 __init__ 已装载 sitemap，此时 self.sitemap 不空即恢复场景
            if self.phase == "idle" and self.sitemap:
                yield self._event(
                    "system",
                    f"恢复上次会话: 目标 {self.sitemap.target}, "
                    f"功能点 {len(self.sitemap.features)} 个"
                )
            self.started = True
            _model_name = self.llm.config.model if self.llm else "未配置（fast/无 LLM 模式）"
            yield self._event("system", f"Agent 已启动 (模型: {_model_name})")

        # ---- Hermes 风格反馈学习：识别用户纠正 + 沉淀经验 ----
        try:
            if self.started and self.current_context.history:
                from core.lesson_extractor import looks_like_correction, maybe_extract_lesson
                from core import memory

                # 快速过滤：没有纠正口吻就跳过 LLM 调用
                if looks_like_correction(user_message):
                    # 取最近一条 assistant 输出作为上下文
                    last_text = ""
                    for m in reversed(self.current_context.history):
                        if m.role == "assistant" and m.content:
                            last_text = m.content
                            break
                    target = getattr(self, "target_url", "") or ""
                    extracted = await maybe_extract_lesson(
                        self.llm, user_message, last_text, target
                    )
                    if extracted and extracted.get("is_correction"):
                        # 自动填充 host scope_value（如果用户没明指）
                        scope = extracted.get("scope", "global")
                        sv = extracted.get("scope_value", "")
                        if scope == "host" and not sv and target:
                            from urllib.parse import urlparse as _up
                            sv = (_up(target).hostname or "").lower()
                        item = memory.record(
                            scope=scope,
                            scope_value=sv,
                            trigger=extracted.get("trigger", ""),
                            lesson=extracted.get("lesson", ""),
                            evidence=user_message[:500],
                            source="user_correction",
                        )
                        yield self._event(
                            "system",
                            f"📚 已记入长期记忆 — [{scope}{('=' + sv) if sv else ''}] "
                            f"{item.get('lesson', '')}（id={item.get('id')}）"
                            f"\n💡 下次同类场景将自动召回此经验。"
                        )
        except Exception as _ex:
            log.warning("lesson capture 失败（不影响主流程）: %s", _ex)

        # 非 idle 阶段如果在用户消息里检测到新 URL，目前不做任何处理（保留 hook 点）。
        # 历史代码曾有 url_match 死赋值，已清理 — 切换目标的逻辑由 idle 分支统一处理。

        # 如果已有 sitemap 且在 idle 阶段 → 恢复
        # ---- Phase 报告阶段 ----
        if self.phase == "report":
            # ★ FAST 模式或未配置 LLM：报告阶段追问用本地规则回复
            _user_mode = getattr(self, "user_scan_mode", "smart")
            if self.llm is None or _user_mode == "fast":
                yield self._event("system",
                    "ℹ️ FAST 模式/未配置 LLM，报告阶段不支持智能追问。"
                    "扫描结果已生成，如需深度分析请切换到标准/深度模式重新扫描。")
                yield self._event("done", "FAST 模式扫描完成")
                return
            yield self._event("thinking", "报告阶段 — 处理追问")
            self.current_context.add_user(user_message)
            messages = self.current_context.get_messages()
            try:
                response = await asyncio.to_thread(self.llm.chat, messages, ALL_MAIN_TOOLS, caller="main:explore")
            except Exception as e:
                yield self._event("system", f"LLM 调用出错: {e}")
                return
            self.current_context.add_assistant(response)
            if response.reasoning_content:
                yield self._event("reasoning", response.reasoning_content)
            if response.content:
                yield self._event("message", response.content)
            # 报告阶段追问后如果有工具调用（如重新生成报告）
            if response.tool_calls:
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, _args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller="chat_loop")
                    if func_name == "done":
                        yield self._event("done", args.get("summary", "任务完成"))
                        return
                    if func_name == "phase_complete":
                        continue
                    try:
                        result = await self.tool_executor.execute(func_name, args)
                    except Exception as e:
                        result = f"工具执行出错: {e}"
                    if len(result) > MAX_TOOL_RESULT:
                        result = result[:MAX_TOOL_RESULT] + "\n... (截断)"
                    self.current_context.add_tool_result(tc["id"], result)
                    yield self._event("tool_result", result[:500])
            # ★ report 阶段追问回复完成 — 不触发 server 兜底 done
            # 如果 LLM 调了 done 工具，上面已经 return 了
            # 如果没调 done，说明追问已回复完毕，应继续停留在 report 阶段等待下次追问
            yield self._event("report_reply_done", "追问回复完成")
            return

        # ---- idle 阶段：LLM 意图识别 ----
        if self.phase == "idle":
            # ★ "继续"指令检测：如果用户发"继续"/"resume"且有之前的扫描目标，恢复扫描
            _resume_keywords = ("继续", "resume", "继续扫描", "继续测试", "恢复扫描", "恢复测试", "go on", "continue")
            _trimmed_lower = user_message.strip().lower()
            _is_resume_cmd = any(_trimmed_lower == kw or _trimmed_lower == kw.lower() for kw in _resume_keywords)
            _prev_target = getattr(self, "target_url", "") or (self.sitemap.target if self.sitemap else "")

            if _is_resume_cmd and _prev_target:
                log.info("检测到\"继续\"指令，恢复对 %s 的扫描", _prev_target)
                yield self._event("system", f"恢复扫描: {_prev_target}")
                # 复用已有 sitemap（保留已抓数据），不重置
                if self.sitemap and self.sitemap.target == _prev_target:
                    log.info("复用已有 sitemap: target=%s, 功能点 %d 个", _prev_target, len(self.sitemap.features))
                # 设置好状态，直接跳到 Phase 0 扫描入口（跳过 intent 解析和凭证注入）
                url = _prev_target
                self.target_url = url
                self.target_info = url
                self._sync_tool_executor()
                # ★ 恢复凭证：从实例字段（_try_recover 已恢复）或 sitemap 持久化字段中读取
                _saved_cookies = getattr(self, "_inject_cookies", "") or (getattr(self.sitemap, "_inject_cookies", "") if self.sitemap else "")
                _saved_auth = getattr(self, "_inject_auth", "") or (getattr(self.sitemap, "_inject_auth", "") if self.sitemap else "")
                _saved_headers = getattr(self, "_inject_headers", {}) or (getattr(self.sitemap, "_inject_headers", {}) if self.sitemap else {})
                _had_creds = getattr(self, "has_credentials", False) or (getattr(self.sitemap, "_has_credentials", False) if self.sitemap else False)
                if _had_creds or _saved_cookies or _saved_auth:
                    # 恢复环境变量（让爬虫能复用登录凭证）
                    if _saved_cookies:
                        os.environ["PENTEST_INJECT_COOKIES"] = _saved_cookies
                    if _saved_auth:
                        os.environ["PENTEST_INJECT_AUTH"] = _saved_auth
                    if _saved_headers:
                        os.environ["PENTEST_INJECT_HEADERS"] = json.dumps(_saved_headers, ensure_ascii=False)
                    os.environ["PENTEST_TARGET_URL"] = url
                    self.has_credentials = True
                    log.info("恢复凭证: cookies=%s, auth=%s, has_credentials=True",
                             bool(_saved_cookies), bool(_saved_auth))
                    yield self._event("system", "✅ 已恢复登录凭证（Cookie/Auth），将使用已登录状态继续扫描")
                # 直接进入 Phase 0（下方代码会执行 self.phase = "explore"）
                _skip_intent = True
            else:
                _skip_intent = False

            if not _skip_intent:
                yield self._event("thinking", "正在理解您的需求...")
                intent = await parse_user_intent(self.llm, user_message)
                log.info("intent 解析结果: intent_kind=%s, has_target=%s, target_url=%s, has_packet=%s",
                         intent.get("intent_kind"), intent.get("has_target"),
                         intent.get("target_url", "")[:80], bool(intent.get("packet")))
            else:
                # "继续"指令：构造一个 site 意图直接走扫描流程
                # ★ 从恢复的凭证中填充 session_cookies/auth_header，让凭证注入块能正常工作
                _resume_cookies = getattr(self, "_inject_cookies", "") or ""
                _resume_auth = getattr(self, "_inject_auth", "") or ""
                _resume_headers = getattr(self, "_inject_headers", {}) or {}
                _resume_creds = []
                if _resume_cookies or _resume_auth:
                    _resume_creds = [{
                        "role": "user",
                        "session_cookies": _resume_cookies,
                        "auth_header": _resume_auth,
                        "extra_headers": dict(_resume_headers),
                    }]
                intent = {
                    "intent_kind": "site",
                    "has_target": True,
                    "target_url": url,
                    "credentials": _resume_creds,
                    "session_cookies": _resume_cookies,
                    "auth_header": _resume_auth,
                    "extra_headers": dict(_resume_headers),
                    "test_mode": "",
                    "special_notes": "恢复上次扫描",
                }

            if not intent.get("has_target") or not intent.get("target_url"):
                self.current_context.add_system(
                    "你是游刃AISec自动化渗透智能体。用户还没有给你明确的目标。\n"
                    "请根据用户的输入自然回复，引导用户提供：\n"
                    "1. 目标 URL（必须）\n2. 测试账号密码（如果有）\n3. 特别关注的功能或已知信息（可选）\n\n"
                    "不要编造目标，不要开始测试。"
                )
                self.current_context.add_user(user_message)
                messages = self.current_context.get_messages()
                # ★ 与 report 分支风格统一：LLM 闲聊回复也加异常兜底
                try:
                    response = await asyncio.to_thread(self.llm.chat, messages, caller="main:chat")
                except Exception as e:
                    yield self._event("system", f"LLM 调用出错: {e}")
                    return
                self.current_context.add_assistant(response)
                if response.reasoning_content:
                    yield self._event("reasoning", response.reasoning_content)
                if response.content:
                    yield self._event("message", response.content)
                return

            # ============================================================
            # ★ 包测模式（packet_test）— 2026-05-20 新增能力
            # ============================================================
            _packet_mode_enabled = os.environ.get("PENTEST_PACKET_MODE", "enabled").lower() != "disabled"
            _kind = (intent.get("intent_kind") or "site").lower()

            # ============================================================
            # ★ 方案3：自动切换 — 当用户选了 batch/realtime 但意图不是全链路扫描时
            #   自动切换到智能模式执行，并给前端一个轻提示
            # ============================================================
            _user_mode = getattr(self, "user_scan_mode", "smart")
            if _user_mode in ("batch", "realtime") and _kind != "site" and _kind != "ambiguous":
                _mode_label = "批量模式" if _user_mode == "batch" else "实时模式"
                # 发送 mode_switch 事件，让前端选择器同步切换并显示模式介绍
                yield self._event("mode_switch", {"mode": "smart", "from": _user_mode})
                log.info("自动切换: 用户选择 %s，但 intent_kind=%s，自动走智能模式", _user_mode, _kind)

            if _packet_mode_enabled and _kind == "ambiguous":
                yield self._event(
                    "message",
                    "🤔 我不太确定你想做什么，请明确一下：\n\n"
                    "**A. 只测这一个接口**：跳过爬虫，直接对你给的数据包跑漏洞检测（IDOR/SQL/XSS 等），几分钟出结果。\n"
                    "**B. 测整个网站**：把这个数据包当作登录凭证，对整站做完整渗透（爬取→功能点分析→并行测试），半小时左右。\n\n"
                    "请回复 **A** 或 **B**（或直接说『测这个接口』 / 『测整站』），我再继续。"
                )
                return

            # ============================================================
            # ★ 漏洞利用/危害证明模式（exploit）— 智能 Agent 对话链路
            #   用户已知漏洞存在，要求利用/证明危害/构造payload等
            #   走带工具调用能力的 Agent 循环，而非固定 checklist
            #   支持两种输入：1) 完整 HTTP 数据包  2) 只有 URL + 漏洞描述
            # ============================================================
            if _kind == "exploit" and (intent.get("packet") or intent.get("target_url")):
                packet = intent.get("packet")
                target_url = intent.get("target_url", "")
                special_notes = intent.get("special_notes", "")

                # ★ 从用户消息中提取漏洞类型关键词
                _vuln_keywords = {
                    "SQL注入": ["sql注入", "sql injection", "sqli", "注入漏洞", "sql 注入"],
                    "XSS": ["xss", "跨站脚本", "cross-site scripting", "弹窗"],
                    "命令注入": ["命令注入", "command injection", "cmdi", "rce", "命令执行"],
                    "SSRF": ["ssrf", "服务端请求伪造"],
                    "IDOR越权": ["idor", "越权", "水平越权", "垂直越权", "未授权访问"],
                    "文件上传": ["文件上传", "upload", "webshell"],
                    "文件包含": ["文件包含", "lfi", "rfi", "local file inclusion"],
                    "SSTI": ["ssti", "模板注入", "template injection"],
                    "XXE": ["xxe", "xml外部实体", "xml注入"],
                    "反序列化": ["反序列化", "deserialization", "unserialize"],
                    "CORS配置": ["cors", "跨域"],
                    "CSRF": ["csrf", "跨站请求伪造"],
                    "JWT": ["jwt", "json web token"],
                    "竞态条件": ["竞态", "race condition", "并发"],
                }
                _search_text = (user_message + " " + special_notes).lower()
                _matched_vuln_type = ""
                for vt, keywords in _vuln_keywords.items():
                    if any(kw in _search_text for kw in keywords):
                        _matched_vuln_type = vt
                        break

                yield self._event("phase", {"id": "exploit", "title": "🔓 漏洞利用/危害证明模式"})
                _skill_hint = f"（已加载 {_matched_vuln_type} 利用方法论）" if _matched_vuln_type else ""
                yield self._event("system",
                    f"已识别为漏洞利用模式 — 将针对用户指定的漏洞进行深入利用和危害证明。{_skill_hint}")
                log.info("exploit 模式: target=%s, has_packet=%s, vuln_type=%s, user_message=%s",
                         target_url or (packet.get("url", "") if packet else ""), bool(packet),
                         _matched_vuln_type or "none", user_message[:100])

                # ★ 调用 harm_validation 中的 exploit_single_target（复用完整的危害证明程序）
                async for evt in exploit_single_target(
                    llm=self.llm,
                    tool_executor=self.tool_executor,
                    target_url=target_url,
                    packet=packet,
                    vuln_type=_matched_vuln_type,
                    user_message=user_message,
                    special_notes=special_notes,
                    max_rounds=25,
                    timeout=600.0,
                ):
                    evt_type = evt.get("type", "")
                    evt_data = evt.get("data", "")
                    if evt_type == "reasoning":
                        yield self._event("reasoning", evt_data)
                    elif evt_type == "message":
                        yield self._event("message", evt_data)
                    elif evt_type == "tool_call":
                        yield self._event("system",
                            f"🔧 调用工具: {evt_data.get('name', '')}({json.dumps(evt_data.get('args', {}), ensure_ascii=False)[:200]})")
                    elif evt_type == "tool_result":
                        yield self._event("tool_result", evt_data[:500])
                    elif evt_type == "done":
                        yield self._event("done", evt_data)
                return

            if _packet_mode_enabled and _kind == "packet" and intent.get("packet"):
                packet = intent["packet"]
                async for evt in self._run_packet_test_mode(intent, packet, user_message):
                    yield evt
                return

            # ============================================================
            # ★ 指定功能测试模式（focused_test）— 2026-05-28 新增能力
            # ============================================================
            if _kind == "focused" and intent.get("target_features"):
                async for evt in self._run_focused_test_mode(intent, user_message):
                    yield evt
                return

            # 有目标 URL（site 模式 — 现有全流程，不变）
            url = intent["target_url"]
            credentials = intent.get("credentials", [])
            test_mode = intent.get("test_mode", "")
            special_notes = intent.get("special_notes", "")
            # ★ 凭证注入（绕过验证码 / 自定义签名场景）
            session_cookies = intent.get("session_cookies", "")
            auth_header = intent.get("auth_header", "")
            extra_headers = intent.get("extra_headers", {}) or {}
            dynamic_signing_fields = intent.get("dynamic_signing_fields", []) or []
            dynamic_signing_warning = intent.get("dynamic_signing_warning", "")

            self.target_url = url
            self.target_info = user_message

            # 如果已恢复了同目标的 sitemap，继续使用（避免覆盖已有测试结果）
            if self.sitemap and self.sitemap.target == url:
                if _skip_intent:
                    # "继续"指令：保留已有 sitemap 数据，不重置
                    log.info("复用已有 sitemap（继续指令）: target=%s, 功能点 %d 个",
                             url, len(self.sitemap.features))
                else:
                    # 用户明确重新输入了目标：清理旧的功能点，重新开始
                    log.info("复用已恢复的 sitemap: target=%s, 已有 %d 个功能点",
                             url, len(self.sitemap.features))
                    self._reset_for_new_task()
                    self.target_url = url
                    self.target_info = user_message
                    self.sitemap = Sitemap(target=url, task_id=self.task_id)
            else:
                self.sitemap = Sitemap(target=url, task_id=self.task_id)
            log.info("新任务启动: target=%s, task_id=%s", url, self.task_id)

            yield self._event("system", f"目标确认: {url}")

            # ★ 凭证注入
            # 修复：之前用 if credentials 做守卫，导致只给 cookie/数据包（无用户名密码）时
            # 整个注入块被跳过。改为检查"有没有任何形式的凭证"。
            has_any_auth = bool(credentials or session_cookies or auth_header or extra_headers)
            if has_any_auth:
                self.has_credentials = True
                for _k in ("PENTEST_INJECT_COOKIES", "PENTEST_INJECT_AUTH",
                           "PENTEST_INJECT_HEADERS", "PENTEST_INJECT_LOCAL_STORAGE", "PENTEST_TARGET_URL"):
                    os.environ.pop(_k, None)
                if session_cookies:
                    os.environ["PENTEST_INJECT_COOKIES"] = session_cookies
                if auth_header:
                    os.environ["PENTEST_INJECT_AUTH"] = auth_header
                if extra_headers:
                    os.environ["PENTEST_INJECT_HEADERS"] = json.dumps(extra_headers, ensure_ascii=False)
                    # ★ JWT token 自动注入 localStorage（SPA 前端路由守卫需要）
                    from core.intent import jwt_headers_to_local_storage
                    ls_items = jwt_headers_to_local_storage(extra_headers)
                    if ls_items:
                        existing_ls = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
                        if existing_ls:
                            try:
                                merged = {**json.loads(existing_ls), **ls_items}
                            except Exception:
                                merged = ls_items
                        else:
                            merged = ls_items
                        os.environ["PENTEST_INJECT_LOCAL_STORAGE"] = json.dumps(merged, ensure_ascii=False)
                os.environ["PENTEST_TARGET_URL"] = url
                self._inject_cookies = session_cookies
                self._inject_auth = auth_header
                self._inject_headers = dict(extra_headers)
                self._inject_target_url = url
                # ★ 同步凭证到 sitemap（持久化，供"继续"恢复）
                if self.sitemap:
                    self.sitemap._inject_cookies = session_cookies
                    self.sitemap._inject_auth = auth_header
                    self.sitemap._inject_headers = dict(extra_headers)
                    self.sitemap._has_credentials = True

            # ★ 当只有 cookie/auth/数据包但没有用户名密码时，合成一个 credential
            # 让 AutoCrawler 有登录轮次可跑（否则 credentials=[] → 无登录爬取）
            if not credentials and (session_cookies or auth_header or extra_headers):
                credentials = [{
                    "role": "user",
                    "session_cookies": session_cookies,
                    "auth_header": auth_header,
                    "extra_headers": dict(extra_headers),
                }]
                self.has_credentials = True
            elif credentials and (session_cookies or auth_header or extra_headers):
                # ★ 2026-05-28 修复：LLM 可能误从 Cookie 中提取了 username（无 password），
                # 导致 credentials 非空但里面没有 session_cookies。
                # 把数据包中的 Cookie/Auth/Headers 合并到每个 credential 中，
                # 确保 AutoCrawler 的 _crawl_round 能走 Cookie 注入路径。
                for cred in credentials:
                    if session_cookies and not cred.get("session_cookies"):
                        cred["session_cookies"] = session_cookies
                    if auth_header and not cred.get("auth_header"):
                        cred["auth_header"] = auth_header
                    if extra_headers and not cred.get("extra_headers"):
                        cred["extra_headers"] = dict(extra_headers)

            # ★ 自动添加登录功能点（仅当有真正的用户名/密码凭证时）
            _has_form_credentials = any(
                c.get("username") or c.get("password") for c in credentials
            ) if credentials else False
            if _has_form_credentials:
                login_url = url
                for cred in credentials:
                    if cred.get("login_url"):
                        login_url = cred["login_url"]
                        break
                login_fp = self.sitemap.add_feature(
                    name="登录功能",
                    description="登录页面安全测试：SQL注入、用户枚举、验证码绕过、弱密码、JWT安全",
                    page_url=url,
                    priority=Priority.CRITICAL,
                    requires_auth=False,
                    deferred=False,
                )
                if login_fp:
                    self.sitemap.save()
                    yield self._event("system", f"已自动添加功能点: 登录功能 ({len(login_fp.checklist)} 项 checklist)")

            if test_mode:
                mode_labels = {"src": "SRC漏洞挖掘", "pre_launch": "上线前渗透", "post_launch": "上线后渗透"}
                yield self._event("system", f"测试模式: {mode_labels.get(test_mode, test_mode)}")
            if special_notes:
                yield self._event("system", f"特殊备注: {special_notes}")
                self.current_context.add_system(f"## 用户特殊要求\n\n{special_notes}")

            self._sync_tool_executor()

            # Phase 0: 站点探索
            self.phase = "explore"
            metrics.reset()
            metrics.mark_start()
            metrics.inc("features_total", len(self.sitemap.features) if self.sitemap else 0)
            upsert_scan(self.task_id, target=self.sitemap.target if self.sitemap else "",
                        status="running", scan_mode=self.scan_mode,
                        model=self.llm.config.model if self.llm else "未配置")
            log.info("Phase 0 开始: 站点探索, metrics=%s", metrics.snapshot())

            # ★ 目标可达性预检：重试 3 次，失败后切换被动侦察模式
            target_reachable = await self._probe_target_reachable(url)
            if not target_reachable:
                yield self._event("system",
                    "⚠️ 目标不可达（重试 3 次均失败），切换到被动侦察模式")
                # 被动侦察：仅做信息收集，不启动浏览器爬虫
                passive_findings = await self._passive_recon(url)
                if passive_findings:
                    yield self._event("system",
                        f"📡 被动侦察完成: 发现 {len(passive_findings)} 条信息")
                # 跳过爬虫阶段，直接进入 Phase 1
                crawl_result = None
                # 标记跳过原因
                if self.sitemap:
                    self.sitemap.termination_reason = "目标不可达，跳过浏览器爬取，仅做被动侦察"
                    self.sitemap.save()
                # 跳到 Phase 1
                async for evt in self._advance_phase():
                    yield evt
                return
            # ★ Hermes 风格：注入与目标相关的历史经验
            n_inj = self._inject_memories(self.current_context)
            if n_inj > 0:
                yield self._event("system", f"📚 已注入 {n_inj} 条历史经验到上下文")
            crawl_result = None

            if credentials:
                rounds_desc = f"{len(credentials)} 个角色登录爬取（跳过匿名）"
                yield self._event("phase", f"Phase 0: 站点自动探索 — 直接登录爬取 ({rounds_desc})")
            else:
                yield self._event("phase",
                    "Phase 0: 站点匿名探索 — 仅 Step 1 匿名爬取（无账号，跳过登录爬取）")

            # 进度回调：爬虫内部的日志实时推送到前端
            # ★ maxsize=1000 防御：消费慢/挂起时不会无界增长，超出直接丢弃旧消息（被 except 吞）
            progress_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)

            def on_crawler_progress(msg: str):
                # ★ 爬虫进度同时写日志文件：原逻辑只走 SSE 事件流，
                #   日志文件在爬虫运行期间零输出，用户误以为卡死
                try:
                    log.info("[CRAWL] %s", msg)
                    progress_queue.put_nowait(msg)
                except Exception:
                    pass

            from core.auto_crawler import AutoCrawler
            _intent_extra_scope = intent.get("extra_scope") or []
            if _intent_extra_scope:
                yield self._event("system",
                    f"🔗 关联域名（来自数据包 Host）: {', '.join(_intent_extra_scope)}")

            # ★ LLM 回调：供 AutoCrawler → analyze_page_js → llm_analyze_key_js 使用
            # llm 未配置或 FAST 模式时返回空 Message，让爬虫的 JS 分析降级跳过
            async def _llm_chat_fn(messages, caller="js_llm_analyze"):
                _fast_mode = getattr(self, "user_scan_mode", "smart") == "fast"
                if self.llm is None or _fast_mode:
                    return Message(role="assistant", content="")
                return await asyncio.to_thread(self.llm.chat, messages, caller=caller)

            # ★ 有凭证时跳过匿名爬取，直接登录爬取（匿名爬取对后台系统价值极低，
            #   且容易耗尽超时配额导致登录爬取被跳过）
            _skip_anon = bool(credentials)
            # ★ 根据 scan_mode 读取 ScanConfig 的爬虫配置（fast 模式用短超时/少页面）
            from core.scan_strategies import get_scan_strategy
            _crawl_cfg = get_scan_strategy(getattr(self, "user_scan_mode", "batch"))
            _crawl_max_pages = _crawl_cfg.crawl_max_pages
            _crawl_hard_timeout = _crawl_cfg.total_timeout
            # fast 模式大幅缩短爬虫超时（crawl_timeout 是给纯爬虫的，total_timeout 是整轮）
            if _crawl_cfg.mode.value == "fast":
                _crawl_hard_timeout = min(_crawl_cfg.crawl_timeout, 120)
                _crawl_silent = 60
            else:
                _crawl_silent = 180
            crawler = AutoCrawler(
                target=url, credentials=credentials,
                max_pages_per_round=_crawl_max_pages, on_progress=on_crawler_progress,
                extra_scope=_intent_extra_scope,
                skip_anonymous_round=_skip_anon,
                llm_chat_fn=_llm_chat_fn,
            )
            yield self._event("system",
                "正在登录爬取站点（跳过匿名，直接使用凭证）..." if credentials
                else "正在匿名爬取站点（进度实时更新）...")

            # ★ 2026-05-26：监控循环抽到 _run_crawler_with_timeout，消除与第二轮重复的 80 行
            # 主轮特性：周期保存 sitemap（30s）、silent_timeout 需 elapsed >= 60 才生效
            HARD_TIMEOUT = _crawl_hard_timeout
            SILENT_TIMEOUT = _crawl_silent
            GRACE_AFTER_STOP = 30

            _crawl_holder: dict = {}
            async for evt in self._run_crawler_with_timeout(
                crawler, progress_queue, _crawl_holder,
                hard_timeout=HARD_TIMEOUT,
                silent_timeout=SILENT_TIMEOUT,
                grace_after_stop=GRACE_AFTER_STOP,
                silent_min_elapsed=60,
                periodic_save=True,
                save_interval=30,
                label="",
            ):
                yield evt
            crawl_result = _crawl_holder.get("crawl_result")
            stop_reason = _crawl_holder.get("stop_reason")

            try:
                if stop_reason in ("silent_timeout", "hard_timeout") and credentials and crawl_result:
                    roles_done = crawl_result.get("roles_crawled", [])
                    has_login_round = any(r != "anonymous" for r in roles_done)
                    if not has_login_round:
                        yield self._event("system",
                            f"🔄 Step 1（匿名爬取）已完成但登录爬取未执行，"
                            f"启动第二轮爬取（{len(credentials)} 个角色）...")
                        try:
                            # ★ 为第二轮爬取创建独立的 progress_queue，避免消费第一轮残留消息
                            # maxsize 防御 + try/except 同步主轮做法
                            login_progress_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
                            def _on_login_crawler_progress(msg: str):
                                try:
                                    login_progress_queue.put_nowait(msg)
                                except Exception:
                                    pass

                            login_crawler = AutoCrawler(
                                target=url, credentials=credentials,
                                max_pages_per_round=_crawl_max_pages, on_progress=_on_login_crawler_progress,
                                extra_scope=_intent_extra_scope,
                                skip_anonymous_round=True,
                                llm_chat_fn=_llm_chat_fn,
                            )

                            # ★ 2026-05-26：第二轮监控也走统一 helper，消除原 60 行重复
                            LOGIN_HARD_TIMEOUT = 1800  # 登录爬取硬上限 30 分钟
                            LOGIN_SILENT_TIMEOUT = 300  # 登录爬取静默超时 5 分钟
                            LOGIN_GRACE = 60  # 优雅退出等待 60s

                            _login_holder: dict = {}
                            async for evt in self._run_crawler_with_timeout(
                                login_crawler, login_progress_queue, _login_holder,
                                hard_timeout=LOGIN_HARD_TIMEOUT,
                                silent_timeout=LOGIN_SILENT_TIMEOUT,
                                grace_after_stop=LOGIN_GRACE,
                                silent_min_elapsed=0,  # 第二轮不需要启动期保护
                                periodic_save=False,   # 主轮已有兜底，不重复保存
                                label="登录爬取",
                            ):
                                yield evt
                            login_result = _login_holder.get("crawl_result")

                            if login_result:
                                # ★ 2026-05-26：合并逻辑外移到 core.crawl_merger（120 行 → 1 行）
                                from core.crawl_merger import merge_crawl_results
                                merge_crawl_results(crawl_result, login_result)

                                yield self._event("system",
                                    f"✅ 登录爬取完成！合并后: "
                                    f"{len(crawl_result.get('roles_crawled', []))} 个角色, "
                                    f"{len(crawl_result.get('api_endpoints', []))} API, "
                                    f"{len(crawl_result.get('pages', {}))} 页面")
                        except Exception as login_err:
                            yield self._event("system", f"⚠️ 登录爬取出错（不影响已有数据）: {login_err}")
            except Exception as e:
                yield self._event("system", f"爬取出错: {e}，尝试补救...")
                try:
                    crawl_result = crawler.get_partial_result()
                except Exception:
                    crawl_result = None

            # ★ 超时/出错后补救：从 mitmproxy FlowStore 读取已抓到的流量
            if crawl_result is None:
                yield self._event("system", "正在从 mitmproxy 补救已抓取的流量...")
                try:
                    from mcp_servers.proxy_mcp import _store, _load_new_flows
                    from urllib.parse import urlparse as _urlparse
                    _load_new_flows()
                    target_host = _urlparse(url).netloc
                    rescued_apis = []
                    rescued_realtime_channels = []
                    for flow_id in list(_store._order):
                        flow = _store.get(flow_id)
                        if not flow or target_host not in flow.url:
                            continue
                        url_path = _urlparse(flow.url).path.lower()
                        if any(url_path.endswith(ext) for ext in
                               ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.map')):
                            continue
                        rescued_apis.append({
                            "method": flow.method, "url": flow.url,
                            "post_data": flow.request_body[:2000] if flow.request_body else "",
                            "headers": flow.request_headers,
                            "status_code": flow.status_code,
                            "response_body": flow.response_body or "",
                            "response_headers": getattr(flow, "response_headers", {}) or {},
                            "content_type": getattr(flow, "content_type", "") or "",
                            "flow_id": flow_id,
                            "discovered_by": "mitmproxy_rescue",
                        })
                        rescued_realtime_channels.extend(classify_realtime_flow(
                            method=flow.method,
                            url=flow.url,
                            request_headers=flow.request_headers,
                            request_body=flow.request_body or "",
                            response_headers=getattr(flow, "response_headers", {}) or {},
                            response_body=flow.response_body or "",
                            status_code=flow.status_code,
                            discovered_by="mitmproxy_rescue",
                        ))
                    if rescued_apis:
                        crawl_result = {
                            "target": url,
                            "crawl_rounds": 0,
                            "roles_crawled": [],
                            "login_status": {},
                            "pages_total": 0,
                            "apis_total": len(rescued_apis),
                            "apis_inferred_verified": 0,
                            "forms_total": 0,
                            "forms_submitted": 0,
                            "js_endpoints_found": 0,
                            "total_clickable_elements": 0,
                            "menu_clicked": 0,
                            "menu_with_api": 0,
                            "menu_without_api": 0,
                            "menu_coverage": [],
                            "pages": {},
                            "api_endpoints": rescued_apis,
                            "realtime_channels": dedupe_realtime_channels(rescued_realtime_channels),
                            "realtime_channels_total": len(dedupe_realtime_channels(rescued_realtime_channels)),
                            "forms": [],
                            "js_endpoints": [],
                            "role_comparison": {"compared": False},
                        }
                        yield self._event("system",
                            f"✅ 从 mitmproxy 补救了 {len(rescued_apis)} 个 API（含完整请求头和响应）")
                except Exception as e:
                    yield self._event("system", f"⚠️ 补救失败: {e}")

            if crawl_result:
                for url_key, page_data in crawl_result.get("pages", {}).items():
                    self.sitemap.add_page(url_key, page_data.get("title", ""))
                    self.sitemap.mark_visited(url_key)
                for api in crawl_result.get("api_endpoints", []):
                    self.sitemap.add_api(api["method"], api["url"],
                                         discovered_by=api.get("discovered_by", "crawler"))
                    self.sitemap.add_api_sample(
                        method=api["method"],
                        url=api["url"],
                        headers=api.get("headers", {}),
                        body=api.get("post_data", "") or api.get("body", ""),
                        status_code=api.get("status_code", 0),
                        discovered_by=api.get("discovered_by", "crawler"),
                        response_body=api.get("response_body", ""),
                        response_headers=api.get("response_headers", {}),
                        content_type=api.get("content_type", ""),
                        js_context=api.get("js_context", ""),
                        flow_id=api.get("flow_id", ""),
                        trigger_context=api.get("trigger_context", {}),
                    )

                realtime_channels = dedupe_realtime_channels(
                    getattr(self.sitemap, "realtime_channels", []) + (crawl_result.get("realtime_channels") or [])
                )
                self.sitemap.realtime_channels = realtime_channels

                # ★ 提前计算 rounds_real：爬虫聚合统计可能因超时为 0，
                # 但只要抓到了 API 就说明至少跑了 1 轮
                _apis_for_rounds = max(len(self.sitemap.apis),
                                       int(crawl_result.get('apis_total', 0) or 0))
                rounds_real = int(crawl_result.get('crawl_rounds', 1) or 0)
                if rounds_real == 0 and _apis_for_rounds > 0:
                    rounds_real = 1

                stats = (
                    f"📊 Phase 0 爬取完成:\n"
                    f"  爬取轮数: {rounds_real} (角色: {', '.join(crawl_result.get('roles_crawled', []))})\n"
                )

                # ★ API 文档自动发现
                api_doc_hits = crawl_result.get("api_doc_hits", [])
                if api_doc_hits:
                    try:
                        from core.api_doc_discovery import detect_and_extract
                        import httpx

                        doc_auth = {}
                        try:
                            from mcp_servers.proxy_mcp import _store as _flow_store
                            for fid in list(_flow_store._order):
                                f = _flow_store.get(fid)
                                if f and f.request_headers:
                                    for k in ("cookie", "Cookie", "authorization", "Authorization"):
                                        if k in f.request_headers and f.request_headers[k]:
                                            doc_auth[k] = f.request_headers[k]
                                    if doc_auth:
                                        break
                        except Exception:
                            pass

                        doc_total = 0
                        async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as doc_client:
                            seen_urls = set()
                            for hit in api_doc_hits:
                                hit_url = hit.get("url", "")
                                if hit_url in seen_urls:
                                    continue
                                seen_urls.add(hit_url)
                                try:
                                    from mcp_servers.proxy_mcp import _store as _flow_store2, _load_new_flows
                                    _load_new_flows()
                                    resp_body = ""
                                    for fid in list(_flow_store2._order):
                                        f = _flow_store2.get(fid)
                                        if f and f.url == hit_url and f.response_body:
                                            resp_body = f.response_body[:5000]
                                            break
                                    if not resp_body:
                                        continue
                                except Exception:
                                    continue

                                doc_results = await detect_and_extract(
                                    url=hit_url,
                                    response_body=resp_body,
                                    sitemap=self.sitemap,
                                    http_client=doc_client,
                                    auth_headers=doc_auth,
                                )
                                if doc_results:
                                    doc_total += sum(len(r.get("endpoints", [])) for r in doc_results)

                        if doc_total > 0:
                            stats += f"  🔍 API 文档自动发现: 补充了 {doc_total} 个端点（来源: {', '.join(set(h.get('name','') for h in api_doc_hits))}）\n"
                    except Exception as e:
                        log.debug("API 文档端点提取失败（非致命）: %s", e)

                # 登录状态
                login_status = crawl_result.get("login_status", {})
                if login_status:
                    for role, success in login_status.items():
                        icon = "✅" if success else "❌"
                        stats += f"  {icon} {role} 登录{'成功' if success else '失败'}\n"
                    if any(not s for s in login_status.values()):
                        stats += "  ⚠️ 登录失败的角色：后续爬取可能是未登录态，功能清单不完整\n"

                pages_real = max(len(self.sitemap.pages), int(crawl_result.get('pages_total', 0) or 0))
                apis_real = max(len(self.sitemap.apis), int(crawl_result.get('apis_total', 0) or 0))
                menu_clicked = int(crawl_result.get('menu_clicked', 0) or 0)
                menu_with_api = int(crawl_result.get('menu_with_api', 0) or 0)
                menu_without_api = int(crawl_result.get('menu_without_api', 0) or 0)
                forms_total = int(crawl_result.get('forms_total', 0) or 0)
                forms_submitted = int(crawl_result.get('forms_submitted', 0) or 0)
                apis_inferred = int(crawl_result.get('apis_inferred_verified', 0) or 0)
                js_endpoints_found = int(crawl_result.get('js_endpoints_found', 0) or 0)
                realtime_channels = getattr(self.sitemap, "realtime_channels", []) or []
                realtime_counts = {
                    "graphql": sum(1 for c in realtime_channels if c.get("protocol") == "graphql"),
                    "websocket": sum(1 for c in realtime_channels if c.get("protocol") == "websocket"),
                    "sse": sum(1 for c in realtime_channels if c.get("protocol") == "sse"),
                }

                stats += (
                    f"\n📋 发现统计:\n"
                    f"  页面: {pages_real} 个\n"
                    f"  菜单/按钮点击: {menu_clicked} 个"
                    f"（{menu_with_api} 个触发了 API，{menu_without_api} 个无 API 响应）\n"
                    f"  表单: {forms_total} 个 (已提交 {forms_submitted})\n"
                    f"  API 端点: {apis_real} 个"
                    f"（其中 {apis_inferred} 个由推测+指纹验证发现）\n"
                    f"  JS 中发现的隐藏端点: {js_endpoints_found} 个"
                )
                if any(realtime_counts.values()):
                    stats += (
                        f"\n  实时/非 REST 通道: GraphQL {realtime_counts['graphql']} 个, "
                        f"WebSocket {realtime_counts['websocket']} 个, SSE {realtime_counts['sse']} 个"
                    )
                if crawl_result.get('apis_total', 0) == 0 and apis_real > 0:
                    stats += "\n  ℹ️ 爬虫聚合统计中断（如超时），上述页面/API 数取自 sitemap 实际记录"
                js_stats = crawl_result.get("js_stats", {})
                if js_stats.get("files_analyzed", 0) > 0:
                    stats += (
                        f"\n\n📦 JS 深度分析:\n"
                        f"  分析 JS 文件: {js_stats.get('files_analyzed', 0)} 个 ({js_stats.get('total_size_kb', 0)} KB)\n"
                        f"  JS 中发现 API 调用: {js_stats.get('api_calls', 0)} 个\n"
                        f"  前端路由: {js_stats.get('routes', 0)} 个"
                    )
                    js_auth = crawl_result.get("js_auth_patterns", [])
                    if js_auth:
                        auth_types = set(a.get("type", "") for a in js_auth)
                        stats += f"\n  鉴权模式: {', '.join(auth_types)}"
                    js_sensitive = crawl_result.get("js_sensitive_info", [])
                    if js_sensitive:
                        info_types = set(s.get("type", "") for s in js_sensitive)
                        stats += f"\n  ⚠️ 敏感信息泄露: {len(js_sensitive)} 处 ({', '.join(info_types)})"
                    js_maps = crawl_result.get("js_source_maps", [])
                    if js_maps:
                        stats += f"\n  🗺️ Source Map: 发现 {len(js_maps)} 个（可还原源码）"
                comp = crawl_result.get("role_comparison", {})
                if comp.get("compared") and comp.get("diff"):
                    stats += "\n\n🔄 多角色对比:"
                    for d in comp["diff"]:
                        stats += f"\n- {d['note']}"
                yield self._event("system", stats)

                # 流量抓包健康检查
                try:
                    flow_file = Path("data/pentest_agent_flows.jsonl")
                    if flow_file.exists():
                        flow_count = sum(1 for _ in open(flow_file, encoding="utf-8", errors="replace"))
                        from urllib.parse import urlparse as _up
                        target_host = _up(self.target_url).netloc if self.target_url else ""
                        target_flows = 0
                        if target_host:
                            for line in open(flow_file, encoding="utf-8", errors="replace"):
                                if target_host in line:
                                    target_flows += 1
                        if target_flows > 0:
                            yield self._event("system",
                                f"✅ 流量抓包正常: 共 {flow_count} 条流量，其中目标站点 {target_flows} 条")
                        else:
                            yield self._event("system",
                                f"⚠️ 流量抓包异常: 共 {flow_count} 条流量，但目标站点 0 条！\n"
                                f"可能原因: 浏览器未走 mitmproxy 代理（端口不匹配或代理未启动）\n"
                                f"影响: Phase 1 模拟点击时 proxy_get_traffic 无法抓到 API，功能点将缺少 API 关联")
                    else:
                        yield self._event("system",
                            f"⚠️ 流量文件不存在，mitmproxy 可能未启动。Phase 1 流量抓取将不可用。")
                except Exception:
                    pass

                # LLM 域名清洗
                yield self._event("system", "正在分析爬取到的域名，排除非业务相关的第三方请求...")
                cleaned_count = await self._llm_filter_domains(crawl_result)
                if cleaned_count > 0:
                    yield self._event("system", f"🧹 已清除 {cleaned_count} 个非业务域名的 API（第三方追踪/广告/分析等）")

                # 自动生成原子级功能点
                yield self._event("system", "正在自动生成原子级功能点...")
                atomic_features = self.sitemap.generate_atomic_features(crawl_result)
                total_checks = sum(len(fp.checklist) for fp in atomic_features)

                yield self._event("system",
                    f"✅ 自动生成 {len(atomic_features)} 个原子功能点, "
                    f"共 {total_checks} 项 checklist\n"
                    f"（每个按钮/表单/API = 1 个功能点, checklist 按 HTTP 方法+URL 特征自动推导）")

                self.sitemap.save()

                # ★ 策略回调：Phase 0 爬取完成（实时模式启动 FlowWatcher）
                async for evt in self.strategy.on_crawl_complete(self, crawl_result):
                    yield evt

                # ★ 实时模式：对自动生成的功能点立即触发测试
                if self.scan_mode == "realtime" and atomic_features:
                    yield self._event("system",
                        f"⚡ 实时模式 — 开始即时测试 {len(atomic_features)} 个功能点")
                    for feat in atomic_features:
                        async for evt in self.strategy.on_feature_discovered(self, feat):
                            yield evt

                # XSS 专项扫描
                try:
                    from core.xss import XssScanner
                    auth_headers, cookies = self._extract_auth_for_xss(crawl_result)
                    xss_proxy = os.getenv("BROWSER_PROXY", "http://127.0.0.1:18080")
                    oob_callback = getattr(self, "oob_callback_url", "") or os.getenv("XSS_OOB_URL", "")
                    # ★ FAST 模式：XSS 扫描器不传 LLM，禁用 LLM 判断
                    _fast_mode = getattr(self, "user_scan_mode", "smart") == "fast"
                    xss_scanner = XssScanner(
                        sitemap=self.sitemap,
                        llm=None if _fast_mode else self.llm,
                        proxy=xss_proxy,
                        auth_headers=auth_headers,
                        cookies=cookies,
                        enable_param_mining=True,
                        enable_header_injection=True,
                        enable_browser_verify=True,
                        enable_dom_scan=True,
                        enable_llm_judge=not _fast_mode,
                        enable_waf_bypass=True,
                        enable_stored_xss=True,
                        enable_mutation_xss=True,
                        enable_postmessage=True,
                        enable_upload_xss=True,
                        enable_template_injection=True,
                        enable_blind_xss=bool(oob_callback),
                        oob_callback_url=oob_callback,
                        enable_csp_analysis=True,
                        output_dir=str(Path("data/tasks")),
                        task_id=self.task_id,
                        max_targets=400,
                    )
                    self._xss_scanner = xss_scanner
                    self._xss_events_queue = asyncio.Queue()

                    async def _run_xss_in_background():
                        try:
                            async for evt in xss_scanner.run():
                                await self._xss_events_queue.put(evt)
                            await self._xss_events_queue.put({"type": "_xss_internal_done"})
                        except Exception as e:
                            log.warning("XSS scanner crashed: %s", e)
                            await self._xss_events_queue.put({
                                "type": "_xss_internal_done",
                                "error": str(e),
                            })

                    self._xss_task = asyncio.create_task(_run_xss_in_background())
                    yield self._event("system",
                        f"🛡️ XSS 专项扫描已在后台启动（完整 13-step 流水线）"
                        + (f" 含盲打回调 {oob_callback}" if oob_callback else ""))
                except Exception as e:
                    log.warning("Failed to start XSS scanner: %s", e)
                    yield self._event("system", f"⚠️ XSS 扫描启动失败: {str(e)[:120]}")

                # ★ FAST 模式：跳过 Phase 1 LLM 分析，直接推进到 Phase 2 本地规则引擎测试
                _user_mode = getattr(self, "user_scan_mode", "smart")
                if _user_mode == "fast" or self.llm is None:
                    _skip_reason = "FAST 模式" if _user_mode == "fast" else "LLM 未配置"
                    yield self._event("system",
                        f"ℹ️ {_skip_reason}，跳过 Phase 1 LLM 分析阶段，"
                        f"直接进入 Phase 2 本地规则引擎测试")
                    self.phase = "analyze"
                    async for evt in self._advance_phase(
                        f"{_skip_reason}，跳过分析阶段（fast/无 LLM 模式）"
                    ):
                        yield evt
                    return

                # Phase 1: LLM 补充分析
                self.phase = "analyze"

                from core.browse_worker import parse_menu_tree, group_menus_by_tab_weight
                menu_tree = parse_menu_tree(crawl_result) if crawl_result else None
                menu_groups = group_menus_by_tab_weight(menu_tree, crawl_result) if menu_tree else []

                # ★ 实时模式：BrowseWorker 已在 on_crawl_complete 中完成操作，
                # 有菜单树时跳过路径 A 的登录+BrowseWorker 调度，直接进入 LLM 补充功能点分析
                # 没有菜单树时走路径 B，让主 Agent 自己操作浏览器（FlowWatcher 在后台即时测试）
                if self.scan_mode == "realtime" and menu_groups and len(menu_groups) >= 1:
                    yield self._event("phase",
                        "Phase 1: LLM 补充分析 — 基于实时操作结果补充功能点")
                    self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)
                    api_count = len(self.sitemap.apis) if self.sitemap else 0
                    self.current_context.add_user(
                        build_path_a_post_browse_msg(
                            self.sitemap.to_summary(), api_count
                        )
                    )

                elif menu_groups and len(menu_groups) >= 1:
                    total_pages = sum(g["page_count"] for g in menu_groups)
                    total_tabs = sum(g["tab_count"] for g in menu_groups)
                    yield self._event("phase",
                        f"Phase 1: 分段深度操作 — {len(menu_groups)} 组子 Agent 串行执行"
                        f"（{total_pages} 页面, {total_tabs} Tab）")
                    yield self._event("system",
                        f"📋 菜单树分组方案：\n" +
                        "\n".join(
                            f"  [{i+1}] 「{g['name']}」: {g['page_count']} 页面, {g['tab_count']} Tab"
                            for i, g in enumerate(menu_groups)
                        ))

                    self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)
                    self.current_context.add_user(
                        build_path_a_login_msg(self.target_info, self.sitemap.to_summary())
                    )

                    login_round = 0
                    while login_round < 30:
                        login_round += 1
                        yield self._event("thinking", f"Phase 1 登录准备 — 第 {login_round} 轮")
                        try:
                            messages = self.current_context.get_messages()
                            response = await asyncio.to_thread(self.llm.chat, messages, ALL_MAIN_TOOLS, caller="main:login")
                        except Exception as e:
                            yield self._event("system", f"LLM 调用出错: {e}")
                            break
                        self.current_context.add_assistant(response)
                        if response.reasoning_content:
                            yield self._event("reasoning", response.reasoning_content)
                        if response.content:
                            yield self._event("message", response.content)
                        if response.tool_calls:
                            phase_done = False
                            for tc in response.tool_calls:
                                func_name = tc["function"]["name"]
                                args, _args_failed = parse_tool_call_arguments(
                                    tc["function"]["arguments"], caller="chat_loop")
                                if func_name == "phase_complete":
                                    self.current_context.add_tool_result(tc["id"], "✅ 登录完成，开始子 Agent 调度")
                                    phase_done = True
                                    break
                                if func_name == "done":
                                    self.current_context.add_tool_result(tc["id"], "请先调用 phase_complete")
                                    continue
                                args_str = json.dumps(args, ensure_ascii=False)[:150]
                                yield self._event("tool_call", f"{func_name}({args_str})")
                                try:
                                    result = await self.tool_executor.execute(func_name, args)
                                except Exception as e:
                                    result = f"工具执行出错: {e}"
                                if func_name == "proxy_get_traffic" and self.sitemap:
                                    self._extract_api_samples_from_traffic(result)
                                if func_name == "browser_screenshot" and isinstance(result, str) \
                                        and "截图已保存" in result:
                                    ss_name = args.get("name", "screenshot") if isinstance(args, dict) else "screenshot"
                                    yield self._event("screenshot", f"/api/screenshot/{ss_name}")
                                if len(result) > MAX_TOOL_RESULT:
                                    result = result[:MAX_TOOL_RESULT] + "\n... (截断)"
                                self.current_context.add_tool_result(tc["id"], result)
                                if len(result) > 800:
                                    yield self._event("message", result)
                                else:
                                    yield self._event("tool_result", result[:500])
                            if phase_done:
                                break
                        else:
                            break

                    # 串行执行每组子 Agent
                    from core.browse_worker import BrowseWorker
                    for i, group in enumerate(menu_groups):
                        yield self._event("phase",
                            f"Phase 1a: 子 Agent [{i+1}/{len(menu_groups)}]「{group['name']}」"
                            f"（{group['page_count']} 页面, {group['tab_count']} Tab）")

                        worker = BrowseWorker(
                            worker_id=f"browse_{i+1}",
                            llm=self.llm,
                            sitemap=self.sitemap,
                            group=group,
                            target_info=self.target_info,
                            has_credentials=self.has_credentials,
                            extra_scope=crawl_result.get("extra_scope", []) if crawl_result else [],
                        )

                        async for evt in worker.run():
                            evt_type = evt.get("type", "")
                            if evt_type == "browse_worker_message":
                                yield self._event("message",
                                    f"[{worker.worker_id}] {evt.get('content', '')}")
                            elif evt_type == "browse_worker_tool":
                                tool_str = evt.get('tool', '')
                                yield self._event("tool_call",
                                    f"[{worker.worker_id}] {tool_str}")
                            elif evt_type == "browse_worker_tool_result":
                                content = evt.get('content', '')
                                if content:
                                    yield self._event("system",
                                        f"[{worker.worker_id}] {content}")
                            elif evt_type == "browse_worker_screenshot":
                                ss_name = evt.get('name', 'screenshot')
                                yield self._event("screenshot",
                                    f"/api/screenshot/{ss_name}")
                            elif evt_type == "browse_worker_reasoning":
                                content = evt.get('content', '')
                                if any(kw in content for kw in
                                    ('✅', '❌', '页面', 'Tab', '菜单', '按钮',
                                     'API', 'proxy_get_traffic', '完成', '下一个')):
                                    yield self._event("thinking",
                                        f"[{worker.worker_id}] {content}")
                            elif evt_type == "browse_worker_error":
                                yield self._event("system",
                                    f"⚠️ [{worker.worker_id}] 出错: {evt.get('error', '')}")
                            elif evt_type == "browse_worker_done":
                                rounds = evt.get("rounds", 0)
                                yield self._event("system",
                                    f"✅ [{worker.worker_id}]「{group['name']}」完成"
                                    f"（{rounds} 轮）")

                    yield self._event("system",
                        f"🎯 所有 {len(menu_groups)} 组子 Agent 操作完成，"
                        f"共抓取 {len(self.sitemap.apis)} 个 API。主 Agent 开始补充功能点...")

                    self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)
                    self.current_context.add_user(
                        build_path_a_post_browse_msg(
                            self.sitemap.to_summary(), len(self.sitemap.apis)
                        )
                    )

                else:
                    # ★ 路径 B：没有菜单树 or 菜单太少 → 走原来的主 Agent 单循环
                    yield self._event("phase", "Phase 1: LLM 补充分析 — 识别业务语义 + 发现爬虫遗漏")
                    self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)

                    # ★ 2026-05-26：浏览器操作 SOP 注入到 system（不被 history 压缩影响）
                    # 与 BrowseWorker 共用 core/prompts/browse_sop.md，
                    # 含黄金循环 / 表单填值规范 / 防死循环跳过策略 / 操作铁律
                    try:
                        sop_path = Path(__file__).parent.parent / "prompts" / "browse_sop.md"
                        if sop_path.exists():
                            self.current_context.add_system(sop_path.read_text(encoding="utf-8"))
                    except Exception as _e:
                        log.warning("加载 browse_sop.md 失败（不影响主流程）: %s", _e)

                    auto_summary = self.sitemap.to_summary()

                    # 构建 JS 分析摘要
                    js_context = ""
                    js_auth = crawl_result.get("js_auth_patterns", [])
                    js_sensitive = crawl_result.get("js_sensitive_info", [])
                    js_maps = crawl_result.get("js_source_maps", [])
                    js_routes = crawl_result.get("js_routes", [])
                    if js_auth or js_sensitive or js_maps or js_routes:
                        js_context = "\n\n## JS 深度分析结果\n\n"
                        if js_auth:
                            js_context += "### 鉴权模式\n"
                            for a in js_auth:
                                js_context += f"- **{a.get('type', '')}**: {a.get('description', '')}\n  代码: `{a.get('snippet', '')[:100]}`\n"
                        if js_routes:
                            js_context += f"\n### 前端路由 ({len(js_routes)} 个)\n"
                            for r in js_routes[:20]:
                                comp = f" → {r['component']}" if r.get("component") else ""
                                meta = f" (meta: {r['meta'][:40]})" if r.get("meta") else ""
                                js_context += f"- `{r['path']}`{comp}{meta}\n"
                        if js_sensitive:
                            js_context += f"\n### ⚠️ 敏感信息泄露 ({len(js_sensitive)} 处)\n"
                            for s in js_sensitive:
                                js_context += f"- **{s.get('type', '')}**: `{s.get('value', '')[:40]}`\n"
                        if js_maps:
                            js_context += f"\n### Source Map ({len(js_maps)} 个)\n"
                            for m in js_maps[:5]:
                                js_context += f"- {m}\n"
                            js_context += "💡 Source Map 可还原完整前端源码，是发现隐藏 API 的重要信息源\n"

                    menu_coverage = crawl_result.get("menu_coverage", [])
                    menu_report = ""
                    if menu_coverage:
                        menu_report = "\n\n## 爬虫菜单覆盖清单（逐项核对）\n\n"
                        menu_report += "以下是爬虫自动点击的所有菜单项及其触发的 API 数量：\n\n"
                        for m in menu_coverage:
                            api_tag = f"✅ {m['apis_triggered']} 个API" if m['apis_triggered'] > 0 else "❌ 无API"
                            menu_report += f"- [{api_tag}] **{m['text']}** (页面: {m['page'][:50]})\n"
                        no_api = [m for m in menu_coverage if m['apis_triggered'] == 0]
                        if no_api:
                            menu_report += f"\n⚠️ 以上 {len(no_api)} 个菜单项未触发 API，"
                            menu_report += "可能是爬虫点击失败或需要特定前置操作才能触发。\n"

                    # 菜单树提取
                    menu_tree_hint = ""
                    if crawl_result:
                        menu_contexts = crawl_result.get("menu_contexts", {}) or {}
                        if menu_contexts:
                            lines = [
                                "\n\n## 🔐 多角色菜单上下文\n",
                                "以下菜单树/菜单 API 已绑定角色与账号上下文，后续做越权分析时应优先比较不同角色菜单差异：\n",
                            ]
                            for role, ctx in menu_contexts.items():
                                urls = ctx.get("menu_api_urls", []) or []
                                sources = ctx.get("sources", []) or []
                                login_ok = "✅" if ctx.get("login_success") else "❌"
                                account = ctx.get("account") or "-"
                                lines.append(
                                    f"- **{role}** 登录:{login_ok} 账号:`{account}` "
                                    f"菜单响应:{ctx.get('menu_response_count', 0)} "
                                    f"来源:{', '.join(sources[:3]) or '-'} "
                                    f"API:{', '.join(u[:80] for u in urls[:3]) or '-'}"
                                )
                            menu_report += "\n".join(lines) + "\n"

                        for api in crawl_result.get("api_endpoints", []):
                            api_url = api.get("url", "")
                            resp_body = api.get("response_body", "")
                            if resp_body and any(kw in api_url.lower() for kw in
                                ("menu/tree", "menu/user-menu", "menu/list", "menu/nav",
                                 "permission/menu", "sys/menu", "system/menu")):
                                try:
                                    tree_data = json.loads(resp_body)
                                    tree_str = json.dumps(tree_data, ensure_ascii=False)
                                    if any(k in tree_str for k in ("menuType", "menuName", "children", "tabs")):
                                        if len(tree_str) > 10000:
                                            tree_str = tree_str[:10000] + "\n... (截断)"
                                        menu_tree_hint = (
                                            "\n\n## ⚠️ 完整菜单树（含 Tab 结构，每个 Tab 必须点击）\n\n"
                                            "以下菜单树来自后端 API，其中 `menuType: 'T'` 的节点是 **页面内的 Tab 标签页**。\n"
                                            "**你必须在进入每个菜单页面后，逐个点击该页面下的所有 Tab，每个 Tab 切换后 proxy_get_traffic。**\n"
                                            "**不点 Tab = 遗漏大量 API（如 系统参数/数据字典/日志管理/定时任务 等 Tab 级功能）！**\n\n"
                                            f"```json\n{tree_str}\n```\n"
                                        )
                                        break
                                except Exception:
                                    pass

                    if not menu_tree_hint and crawl_result:
                        try:
                            from core.browse_worker import build_menu_tree_from_crawl
                            fallback_tree = build_menu_tree_from_crawl(crawl_result)
                            if fallback_tree:
                                summary_lines = []
                                extra_scope = crawl_result.get("extra_scope") or []
                                if extra_scope:
                                    summary_lines.append(
                                        "- 🔗 已纳入关联域 extra_scope：" + ", ".join(str(x) for x in extra_scope[:8])
                                    )
                                for mod in fallback_tree[:30]:
                                    mname = mod.get("name", "")
                                    children = mod.get("children", [])
                                    summary_lines.append(f"- 📂 **{mname}** ({len(children)} 个页面)")
                                    for c in children[:8]:
                                        cname = c.get("name", "")
                                        btns = (c.get("meta", {}) or {}).get("tabs", [])
                                        btn_count = sum(len(t.get("buttons", []) or []) for t in btns)
                                        curl = c.get("page_url", "") or c.get("path", "")
                                        summary_lines.append(f"    - {cname} ({btn_count} 个按钮) → {curl[:60]}")
                                    if len(children) > 8:
                                        summary_lines.append(f"    - ... 还有 {len(children) - 8} 个页面")

                                menu_tree_hint = (
                                    "\n\n## 📋 站点菜单树（爬虫自动构造）\n\n"
                                    "目标站点没有暴露菜单 API，以下菜单树是从爬虫抓到的「页面 + 按钮」清单"
                                    "按 URL 路径前缀分组重建的，可作为遍历指引。\n\n"
                                    "**操作要点：对每个页面 → `browser_goto` 进入 → `proxy_get_traffic` 抓加载 API → "
                                    "若有按钮则逐个点击 → 每点一次 `proxy_get_traffic`。**\n\n"
                                    + "\n".join(summary_lines) + "\n"
                                )
                        except Exception as _e:
                            log.warning("构造爬虫菜单树失败: %s", _e)

                    has_cookie_inject = bool(os.getenv("PENTEST_INJECT_COOKIES") or os.getenv("PENTEST_INJECT_AUTH"))

                    traversal_checklist = ""
                    if crawl_result:
                        traversal_checklist = self._build_traversal_checklist(crawl_result)

                    self.current_context.add_user(
                        build_path_b_user_msg(
                            target_info=self.target_info,
                            atomic_features_count=len(atomic_features),
                            auto_summary=auto_summary,
                            js_context=js_context,
                            menu_report=menu_report,
                            menu_tree_hint=menu_tree_hint,
                            traversal_checklist=traversal_checklist,
                            has_cookie_inject=has_cookie_inject,
                        )
                    )
            else:
                # ★ 路径 C：crawl_result is None（爬虫崩 + mitmproxy 兜底也失败的极端情况）
                # 没有 atomic_features / auto_summary / menu_tree_hint / traversal_checklist 数据。
                # 主 Agent 自己从 0 开始：先 JS 反向出 API → 自己点菜单 → 添加功能点。
                # SOP 同样注入，让操作规约一致。
                self.phase = "analyze"
                yield self._event("phase", "Phase 1: 功能分析 — 爬虫数据缺失，主 Agent 自主浏览 + JS 反向")
                self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)

                # ★ 注入浏览器操作 SOP（与 BrowseWorker / 路径 B 共用同一份）
                try:
                    sop_path = Path(__file__).parent.parent / "prompts" / "browse_sop.md"
                    if sop_path.exists():
                        self.current_context.add_system(sop_path.read_text(encoding="utf-8"))
                except Exception as _e:
                    log.warning("加载 browse_sop.md 失败（不影响主流程）: %s", _e)

                has_cookie_inject = bool(os.getenv("PENTEST_INJECT_COOKIES") or os.getenv("PENTEST_INJECT_AUTH"))
                self.current_context.add_user(
                    build_path_c_user_msg(
                        url=url,
                        user_message=user_message,
                        credentials=credentials or [],
                        has_cookie_inject=has_cookie_inject,
                    )
                )

        else:
            self.current_context.add_user(user_message)

        self._sync_tool_executor()

        # ---- 执行循环 ----
        round_num = 0
        _last_tool_sig = ""
        _repeat_count = 0
        _exit_reason = ""

        # ★ fast/无 LLM 模式：llm 未配置或 FAST 模式时跳过 LLM 分析循环，
        # 直接推进到下一阶段（Phase 2 的 FastScanner 纯本地规则，不需要 LLM）
        _user_mode = getattr(self, "user_scan_mode", "smart")
        if self.llm is None or _user_mode == "fast":
            _skip_reason = "FAST 模式" if _user_mode == "fast" else "LLM 未配置"
            yield self._event("system",
                f"ℹ️ {_skip_reason}，跳过 LLM 分析阶段，直接进入本地规则引擎测试")
            async for evt in self._advance_phase(
                f"{_skip_reason}，跳过分析阶段（fast/无 LLM 模式）"
            ):
                yield evt
            return

        while round_num < MAIN_MAX_ROUNDS:
            round_num += 1
            yield self._event("thinking", f"{self._phase_label()} — 第 {round_num} 轮")

            try:
                messages = self.current_context.get_messages()
                response = await asyncio.to_thread(self.llm.chat, messages, ALL_MAIN_TOOLS, caller="main:test")
            except Exception as e:
                err_str = str(e).lower()
                err_type = type(e).__name__.lower()
                # ★ is_network_err 扩展为 is_retryable：包含 429/rate limit/5xx 等可重试错误，
                # 避免限流时 LLMClient.chat() 的 3 次重试耗尽后任务直接 task_failed 终止。
                is_network_err = (
                    "connection error" in err_str or "connecterror" in err_type
                    or "timeout" in err_type or "dns" in err_type
                    or "could not resolve" in err_str or "nodename nor servname" in err_str
                    or "name or service not known" in err_str
                    or "connection refused" in err_str or "connection reset" in err_str
                    or "network is unreachable" in err_str
                    # ★ 限流与服务端临时错误（与 LLMClient._RETRYABLE_ERROR_KEYWORDS 对齐）
                    or "429" in err_str or "rate limit" in err_str or "rate_limit" in err_str
                    or "too many requests" in err_str
                    or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str
                    or "internal server error" in err_str or "bad gateway" in err_str
                    or "service unavailable" in err_str or "gateway timeout" in err_str
                    or "overloaded" in err_str or "server_error" in err_str
                )
                if is_network_err:
                    log.warning("LLM 网络异常（可能需要配代理或检查网络）: %s: %s",
                                type(e).__name__, e)
                else:
                    log.error("LLM 调用出错: %s", e, exc_info=True)

                _LLM_RETRY_MAX = 5
                _llm_retry_count = 0
                _retried_ok = False
                while is_network_err and _llm_retry_count < _LLM_RETRY_MAX:
                    _llm_retry_count += 1
                    _wait_sec = _llm_retry_count * 5
                    log.info("LLM 网络异常自动重试 %d/%d（等待 %ds）: %s",
                             _llm_retry_count, _LLM_RETRY_MAX, _wait_sec, e)
                    yield self._event("system",
                        f"⚠️ LLM API 网络异常，{_wait_sec}s 后自动重试 "
                        f"({_llm_retry_count}/{_LLM_RETRY_MAX})...")
                    await asyncio.sleep(_wait_sec)
                    try:
                        messages = self.current_context.get_messages()
                        response = await asyncio.to_thread(self.llm.chat, messages, ALL_MAIN_TOOLS, caller="main:test")
                        _retried_ok = True
                        yield self._event("system",
                            f"✅ LLM API 重试成功（第 {_llm_retry_count} 次）")
                        break
                    except Exception as e2:
                        err_str2 = str(e2).lower()
                        err_type2 = type(e2).__name__.lower()
                        is_network_err = (
                            "connection error" in err_str2 or "connecterror" in err_type2
                            or "timeout" in err_type2 or "dns" in err_type2
                            or "could not resolve" in err_str2 or "nodename nor servname" in err_str2
                            or "name or service not known" in err_str2
                            or "connection refused" in err_str2 or "connection reset" in err_str2
                            or "network is unreachable" in err_str2
                            # ★ 同步扩展限流与 5xx
                            or "429" in err_str2 or "rate limit" in err_str2 or "rate_limit" in err_str2
                            or "too many requests" in err_str2
                            or "500" in err_str2 or "502" in err_str2 or "503" in err_str2 or "504" in err_str2
                            or "overloaded" in err_str2 or "server_error" in err_str2
                        )
                        if is_network_err:
                            log.warning("LLM 重试 %d 仍失败: %s", _llm_retry_count, e2)
                        else:
                            log.error("LLM 重试 %d 遇非网络错误，停止重试: %s", _llm_retry_count, e2, exc_info=True)
                            break

                if not _retried_ok:
                    yield self._event("system", f"LLM 调用出错: {e}，发送消息可重试")
                    yield self._event("task_failed", json.dumps({
                        "reason": "llm_error",
                        "phase": self.phase,
                        "round": round_num,
                        "error": str(e)[:300],
                        "message": "LLM API 调用失败，发送消息可重试",
                    }, ensure_ascii=False))
                    _exit_reason = "llm_error"
                    break

            self.current_context.add_assistant(response)

            if response.reasoning_content:
                yield self._event("reasoning", response.reasoning_content)
            if response.content:
                yield self._event("message", response.content)

            if response.tool_calls:
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, _args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller="chat_loop")

                    tool_sig = f"{func_name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
                    if tool_sig == _last_tool_sig:
                        _repeat_count += 1
                    else:
                        _last_tool_sig = tool_sig
                        _repeat_count = 1

                    if _repeat_count >= REPEAT_TOOL_THRESHOLD:
                        warning = (
                            f"⚠️ 检测到你连续 {_repeat_count} 次执行相同操作 `{func_name}`，已自动中断。\n"
                            "请不要重复执行同样的操作！换一种方式尝试，或跳过当前步骤继续下一个任务。\n"
                            "如果 browser_evaluate 返回 null，说明操作已执行成功（click/focus 等 DOM 操作无返回值）。"
                        )
                        self.current_context.add_tool_result(tc["id"], warning)
                        yield self._event("system", warning)
                        _repeat_count = 0
                        _last_tool_sig = ""
                        continue

                    if func_name == "phase_complete":
                        async for evt in self._handle_phase_complete(tc, args):
                            yield evt
                        continue

                    if func_name == "done":
                        yield self._event("done", args.get("summary", "任务完成"))
                        return

                    args_full = json.dumps(args, ensure_ascii=False)
                    args_brief = self._make_tool_brief(func_name, args)
                    yield self._event("tool_call", f"{func_name}({args_brief})", full=f"{func_name}({args_full})")

                    try:
                        result = await self.tool_executor.execute(func_name, args)
                    except Exception as e:
                        log.error("工具 %s 执行出错: %s", func_name, e, exc_info=True)
                        result = f"工具执行出错: {e}"

                    if func_name == "proxy_get_traffic" and self.sitemap and self.phase == "analyze":
                        self._extract_api_samples_from_traffic(result)

                    if func_name == "browser_screenshot" and isinstance(result, str) \
                            and "截图已保存" in result:
                        ss_name = args.get("name", "screenshot") if isinstance(args, dict) else "screenshot"
                        yield self._event("screenshot", f"/api/screenshot/{ss_name}")

                    if len(result) > MAX_TOOL_RESULT:
                        truncated = result[:MAX_TOOL_RESULT]
                        result = f"{truncated}\n\n... (输出截断，原始 {len(result)} 字符)"

                    self.current_context.add_tool_result(tc["id"], result)
                    if len(result) > 800:
                        yield self._event("message", result)
                    else:
                        yield self._event("tool_result", result[:500])
            else:
                nudged = await self._maybe_nudge_phase_forward(round_num)
                if nudged:
                    yield self._event("system", nudged)
                    self.current_context.add_user(nudged)
                    continue
                if self.phase == "report":
                    yield self._event("done", "报告阶段结束（未显式调用 done 工具）")
                    _exit_reason = "report_implicit_done"
                else:
                    yield self._event("task_stuck", json.dumps({
                        "reason": "llm_no_tool_call",
                        "phase": self.phase,
                        "round": round_num,
                        "message": (
                            "LLM 输出纯文字但未调用任何工具，且当前阶段已多次推进无效。"
                            "可能原因：LLM 想等用户输入 / 上下文被压缩破坏 / 模型行为异常。"
                            "你可以发送消息让 Agent 继续，或直接点「停止任务」结束。"
                        ),
                    }, ensure_ascii=False))
                    _exit_reason = "llm_no_tool_call"
                break

            if round_num % CONTEXT_BATCH_SIZE == 0:
                if self.sitemap:
                    self.sitemap.save()
                if self.current_context.should_compress():
                    yield self._event("system", "压缩上下文...")
                    self.current_context.compress()

        if round_num >= MAIN_MAX_ROUNDS and not _exit_reason:
            log.warning("主循环达到最大轮次 %d，强制退出", MAIN_MAX_ROUNDS)
            yield self._event("system",
                f"⚠️ 已达到最大执行轮次 ({MAIN_MAX_ROUNDS} 轮)，自动暂停。\n"
                "发送消息可继续未完成的任务。")
            yield self._event("task_failed", json.dumps({
                "reason": "max_rounds_exceeded",
                "phase": self.phase,
                "round": round_num,
                "message": f"已达到最大执行轮次 ({MAIN_MAX_ROUNDS}) 自动暂停，发送消息可继续",
            }, ensure_ascii=False))

        if self.sitemap:
            self.sitemap.save()
