"""
UtilsMixin — 通用工具方法。

方法：
- _phase_label: 当前阶段标签
- _make_tool_brief: 生成工具调用精简摘要
- _maybe_nudge_phase_forward: LLM 无工具调用时推进提示
- _maybe_escalate_mode: 中途模式升降级（P1-A/P1-C）
- _check_post_crawl_escalation: 爬虫完成后评估升级条件（P1-A）
"""

from __future__ import annotations

import json

from core.sitemap import CheckResult
from core.log import get_logger

log = get_logger("session.utils")

# ★ 模式等级（用于升降级比较）
_MODE_RANK = {"fast": 0, "standard": 1, "deep": 2, "smart": 1}


class UtilsMixin:
    """通用工具方法。"""

    # ============================================================
    # 中途模式升降级（P1-A / P1-C / P0-B）
    # ============================================================

    def _maybe_escalate_mode(self, reason: str, direction: str) -> str | None:
        """在扫描过程中动态调整扫描模式。

        统一入口：业务理解失败(P0-B)、爬后升级(P1-A)、卡死降级(P1-C)
        都通过此方法调整 user_scan_mode。

        Args:
            reason: 升降级原因标识
            direction: "upgrade"（升级）或 "downgrade"（降级）

        Returns:
            新模式字符串（如果发生了变更），否则 None
        """
        current = getattr(self, "user_scan_mode", "smart")
        if current == "smart":
            # smart 模式在启动时已被解析为 fast/standard/deep
            # 如果仍是 smart，按 standard 处理
            current = "standard"

        current_rank = _MODE_RANK.get(current, 1)

        if direction == "downgrade":
            # 降级链路：deep → standard → fast
            if current_rank <= 0:
                return None  # 已经是 fast，无法再降
            target = "fast" if current_rank == 1 else "standard"
        elif direction == "upgrade":
            # 升级链路：fast → standard → deep
            if current_rank >= 2:
                return None  # 已经是 deep，无法再升
            target = "deep" if current_rank == 1 else "standard"
        else:
            return None

        # 记录原始模式（仅首次变更时记录）
        if not hasattr(self, "_original_user_scan_mode") or self._original_user_scan_mode is None:
            self._original_user_scan_mode = current
            self._mode_escalated = False

        old_mode = self.user_scan_mode
        self.user_scan_mode = target
        self._mode_escalated = True

        log.warning(
            "[MODE_ESCALATION] %s → %s (reason=%s, direction=%s, original=%s)",
            old_mode, target, reason, direction, self._original_user_scan_mode,
        )
        return target

    def _check_post_crawl_escalation(self) -> str | None:
        """Phase 0 爬虫完成后评估是否需要升级模式（P1-A）。

        多因子评分：
        - 有支付/转账/文件上传关键词 → 强制升级到 deep
        - 有登录入口 + 认证 → 至少 standard
        - SPA + 大量 JS/API → 至少 standard
        - API 数量多但功能点少 → 建议升级（仅日志，不强制）

        Returns:
            新模式字符串（如果升级了），否则 None
        """
        if not self.sitemap:
            return None

        current = getattr(self, "user_scan_mode", "smart")
        if current in ("fast", "smart"):
            # fast 模式下检查是否需要升级
            apis = getattr(self.sitemap, "apis", {}) or {}
            features = getattr(self.sitemap, "features", {}) or {}
            api_count = len(apis)
            feat_count = len([f for f in features.values() if not getattr(f, "deferred", False)])

            # 收集所有功能点名称/模块名用于关键词匹配
            all_names = ""
            for fp in features.values():
                _fp_name = getattr(fp, "name", "") or ""
                _fp_module = getattr(fp, "module", "") or ""
                all_names += f" {_fp_name} {_fp_module}"
            all_names = all_names.lower()

            # 高危业务关键词 → 强制升级到 deep
            high_value_keywords = [
                "支付", "转账", "付款", "payment", "transfer", "pay",
                "上传", "upload", "文件上传", "attachment",
                "提现", "withdraw", "充值", "recharge",
            ]
            has_high_value = any(kw in all_names for kw in high_value_keywords)

            # 认证相关
            has_auth = getattr(self, "has_credentials", False)

            # SPA / 大量 API 判断
            has_many_apis = api_count > 20
            has_spa_signals = api_count > 10 and feat_count < 5

            if has_high_value:
                return self._maybe_escalate_mode("post_crawl_high_value_features", "upgrade")
            elif (has_auth or has_many_apis or has_spa_signals) and current == "fast":
                # fast → standard（有认证或 API 多，需要 LLM 分析）
                return self._maybe_escalate_mode("post_crawl_auth_or_api_complexity", "upgrade")

        return None

    def _phase_label(self) -> str:
        labels = {
            "idle": "待命",
            "explore": "Phase 0 探索",
            "analyze": "Phase 1 分析",
            "test": "Phase 2 测试",
            "report": "Phase 3 报告",
        }
        return labels.get(self.phase, self.phase)

    def reset_nudge_counter(self, phase: str | None = None) -> None:
        """重置当前（或指定）阶段的 nudge 计数器。

        用途：用户在 STUCK 后输入"继续"指令，期望给 LLM 重新一轮 nudge 机会，
        而不是立即因为 _nudge_count >= 3 而返回空串再次 stuck。
        """
        attr = "_nudge_count"
        try:
            current = getattr(self, attr, None)
            if not isinstance(current, dict):
                current = {}
            target = phase or getattr(self, "phase", "")
            if target:
                current[target] = 0
            setattr(self, attr, current)
        except Exception as e:
            log.warning("reset_nudge_counter 失败（不影响主流程）: %s", e)

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

        ★ 自动推进保护：当 nudge 次数用完（≥3）且 analyze 阶段已有充足功能点时，
        不再卡死等用户干预，而是自动 phase_complete 推进到下一阶段。

        Returns:
            非空字符串 = 注入到 LLM 上下文的提示消息，并继续主循环
            空字符串 = 不干预，允许 break 退出
        """
        # 防止无限循环：同一 phase 最多 nudge 3 次
        attr = "_nudge_count"
        nudge_log = getattr(self, attr, {})
        key = self.phase
        count = nudge_log.get(key, 0)

        # ★ 自动推进保护：nudge 用完时的兜底处理
        if count >= 3:
            _user_mode = getattr(self, "user_scan_mode", "smart")
            # ★ FAST 模式：不应该进入 analyze 阶段，直接返回空串让 break 退出
            if _user_mode == "fast":
                return ""
            # analyze 阶段已有功能点 → 自动 phase_complete，不卡死
            if self.phase == "analyze" and self.sitemap:
                active = [f for f in self.sitemap.features.values() if not f.deferred]
                if len(active) > 0:
                    log.warning(
                        "[AUTO-ADVANCE] analyze 阶段 nudge %d 次仍无工具调用，"
                        "已有 %d 个功能点，自动 phase_complete 推进",
                        count, len(active),
                    )
                    # 返回特殊标记，让 chat_loop 调用 _advance_phase
                    return "__AUTO_PHASE_COMPLETE__"

            # ★ P1-C: 统一卡死降级链路 — 任何模式在 analyze/test 阶段连续 nudge 无工具调用，
            # 自动降级到下一个可用模式（deep→standard→fast），而非直接 task_stuck
            if self.phase in ("analyze", "test"):
                new_mode = self._maybe_escalate_mode(
                    f"stuck_in_{self.phase}_nudge_exhausted", "downgrade"
                )
                if new_mode:
                    # 降级成功：重置 nudge 计数，给新模式一轮机会
                    self.reset_nudge_counter(self.phase)
                    _orig = getattr(self, "_original_user_scan_mode", _user_mode)
                    return (
                        f"⚠️ 检测到阶段卡死（连续 {count} 次无工具调用），"
                        f"已自动降级扫描模式：{_orig} → {new_mode}。\n"
                        f"请继续执行当前阶段任务。如果再次卡死将进一步降级。"
                    )

            # 其他阶段保持原行为：返回空串 → break → task_stuck
            return ""

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
