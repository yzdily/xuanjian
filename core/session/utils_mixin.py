"""
UtilsMixin — 通用工具方法。

方法：
- _phase_label: 当前阶段标签
- _make_tool_brief: 生成工具调用精简摘要
- _maybe_nudge_phase_forward: LLM 无工具调用时推进提示
"""

from __future__ import annotations

import json

from core.sitemap import CheckResult
from core.log import get_logger

log = get_logger("session.utils")


class UtilsMixin:
    """通用工具方法。"""

    def _phase_label(self) -> str:
        labels = {
            "idle": "待命",
            "explore": "Phase 0 探索",
            "analyze": "Phase 1 分析",
            "test": "Phase 2 测试",
            "report": "Phase 3 报告",
        }
        return labels.get(self.phase, self.phase)

    @staticmethod
    def _make_tool_brief(func_name: str, args: dict) -> str:
        """生成工具调用的精简摘要 — 只显示关键参数，隐藏冗长的 headers/Cookie。"""
        # 针对常见工具提取关键信息
        if func_name in ("proxy_send_request", "proxy_replay"):
            method = args.get("method", "")
            url = args.get("url", "")
            return f'"method": "{method}", "url": "{url}"'

        if func_name == "checklist_mark":
            fid = args.get("feature_id", "")
            vtype = args.get("vuln_type", "")
            result = args.get("result", "")
            detail = (args.get("detail", "") or "")[:60]
            return f'"feature_id": "{fid}", "vuln_type": "{vtype}", "result": "{result}", "detail": "{detail}"'

        if func_name == "sitemap_add_feature":
            name = args.get("name", "")
            module = args.get("module", "")
            return f'"name": "{name}", "module": "{module}"'

        if func_name in ("browser_goto", "browser_click", "browser_fill"):
            # 取第一个参数（通常是 URL 或选择器）
            first_val = next(iter(args.values()), "") if args else ""
            return f'"{first_val}"'[:100]

        if func_name == "js_analyze_selected":
            urls = args.get("urls", [])
            return f'{len(urls)} 个文件'

        # 通用：去掉 headers/cookie 等长字段
        brief_args = {}
        for k, v in args.items():
            if k.lower() in ("headers", "cookie", "cookies", "auth", "token"):
                brief_args[k] = "{...}"
            elif isinstance(v, str) and len(v) > 80:
                brief_args[k] = v[:80] + "..."
            else:
                brief_args[k] = v
        result = json.dumps(brief_args, ensure_ascii=False)
        if len(result) > 200:
            result = result[:200] + "..."
        return result

    async def _maybe_nudge_phase_forward(self, round_num: int) -> str:
        """LLM 在主循环输出纯文字而不调任何工具时调用。

        判断当前 phase 是否还有"应该被自动推进"的关键动作：
        - Phase 1 (analyze)：有功能点但没调 phase_complete → 提醒立即 phase_complete
        - Phase 1 且 0 功能点 → 提醒先 sitemap_add_feature
        - Phase 2 (test)：未完成的 checklist 还有 → 提醒 checklist_mark / phase_complete
        - 其他：返回空字符串（保持原 break 行为）

        Returns:
            非空字符串 = 注入到 LLM 上下文的提示消息，并继续主循环
            空字符串 = 不干预，允许 break 退出
        """
        # 防止无限循环：同一 phase 最多 nudge 3 次
        attr = "_nudge_count"
        nudge_log = getattr(self, attr, {})
        key = self.phase
        count = nudge_log.get(key, 0)
        if count >= 3:
            return ""  # 已经反复推过，放弃
        nudge_log[key] = count + 1
        setattr(self, attr, nudge_log)

        if self.phase == "analyze":
            if not self.sitemap:
                return ""
            active_features = [f for f in self.sitemap.features.values() if not f.deferred]
            deferred_count = sum(1 for f in self.sitemap.features.values() if f.deferred)
            tip = (
                f"⛔ 你输出了纯文字但没有调用任何工具，任务会卡死！\n\n"
                f"当前是 Phase 1（功能分析），状态：\n"
                f"- 活跃功能点: {len(active_features)} 个\n"
                f"- 延迟功能点（requires_auth=true 等待登录）: {deferred_count} 个\n"
                f"- 已知 API: {len(self.sitemap.apis)} 个\n\n"
            )
            if len(active_features) == 0:
                # 完全没功能点 → 必须先加
                return tip + (
                    "**立即执行**：\n"
                    "1. 用 `sitemap_set_business` 设置业务类型（如果还没设）\n"
                    "2. 用 `sitemap_add_feature` 把已识别的功能点全部添加进来：\n"
                    "   - 后台/需登录功能 → requires_auth=true（会自动 deferred，不影响 Phase 2）\n"
                    "   - 登录页/注册页/公开接口 → requires_auth=false（Phase 2 会测）\n"
                    "3. 添加完后调用 `phase_complete` 进入测试阶段\n\n"
                    "⛔ **禁止做的事**：\n"
                    "- 禁止试图自己登录（不是你的任务）\n"
                    "- 禁止向用户索要凭据（用户已通过初始消息提供了所有信息）\n"
                    "- 禁止输出'我需要您的帮助'之类的总结性文字，那会让任务卡死"
                )
            # 有功能点 → 直接 phase_complete
            return tip + (
                "**立即执行**：调用 `phase_complete` 进入 Phase 2 测试阶段。\n\n"
                "无论是否拿到登录态：\n"
                "- 公开接口（登录/注册/重置密码/CORS/SSRF 等）可以无认证测试\n"
                "- 后台功能点（requires_auth=true）自动 deferred，不影响 Phase 2 启动\n"
                "- 测试中如果突破登录后会自动激活 deferred 功能点\n\n"
                "⛔ **不要再做任何浏览器操作或问用户问题**，立即 `phase_complete`！"
            )

        if self.phase == "test":
            if not self.sitemap:
                return ""
            pending_total = 0
            for fp in self.sitemap.features.values():
                if hasattr(fp, "get_pending_checks"):
                    pending_total += len(fp.get_pending_checks())
            if pending_total > 0:
                return (
                    f"⛔ 你输出了纯文字但没有调用任何工具。\n"
                    f"当前 Phase 2 还有 {pending_total} 项 checklist 待测。\n"
                    f"立即：\n"
                    f"- 对每个 ⬜ 待测项执行测试 → `checklist_mark` 记录结论\n"
                    f"- 全部测完后调用 `phase_complete` 进入报告阶段\n"
                    f"⛔ 禁止只输出总结文字不调工具。"
                )
            # 测试都做完了 → 推进 phase_complete
            return (
                "⛔ 你输出了纯文字但没有调用任何工具。\n"
                "checklist 已全部完成，请立即调用 `phase_complete` 生成报告。"
            )

        if self.phase == "explore":
            return (
                "⛔ 你输出了纯文字但没有调用任何工具。\n"
                "当前是 Phase 0 站点探索阶段，请继续用工具探索，"
                "或调用 `phase_complete` 进入 Phase 1。"
            )

        return ""  # idle / report 保持原 break 行为
