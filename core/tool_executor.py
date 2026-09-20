"""
ToolExecutor — 统一的工具执行路由

替代原 server.py 中的 _execute_tool 和 _verify_vuln，
以及 WorkerAgent 中的 _execute_tool。
"""
# noqa: giant

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

from core.config import BACKEND_KEYWORDS, PUBLIC_KEYWORDS, VULN_SYNONYMS
from core.tools import BROWSER_TOOL_NAMES
from core.log import get_logger

log = get_logger("executor")

if TYPE_CHECKING:
    from core.sitemap import Sitemap, FeaturePoint


class ToolExecutor:
    """执行工具调用，路由到对应的 MCP Server。"""

    def __init__(self, sitemap: "Sitemap | None" = None, has_credentials: bool = False,
                 task_id: str = "default", realtime_mode: bool = False):
        self.sitemap = sitemap
        self.has_credentials = has_credentials
        self.current_feature_id: str | None = None
        self.task_id = task_id
        self.realtime_mode = realtime_mode

    def set_session(self, session) -> None:
        """同步 Session 状态到 ToolExecutor（让 sitemap 工具、task_id 等可用）。"""
        self.sitemap = session.sitemap
        self.has_credentials = session.has_credentials
        self.task_id = session.task_id

    async def execute(self, name: str, args: dict) -> str:
        """主 Agent 工具执行入口。"""
        # 站点地图工具
        if name.startswith("sitemap_"):
            return self._handle_sitemap(name, args)

        # Checklist 工具
        if name in ("checklist_mark", "checklist_view"):
            return self._handle_checklist(name, args)

        # 漏洞验证
        if name == "vuln_verify":
            return await self._verify_vuln(args)

        # 记忆工具（Hermes 风格 — 写入 / 检索 / 删除经验教训）
        if name in ("record_lesson", "recall_lessons", "forget_lesson"):
            return self._handle_memory(name, args)

        # Note/Report 工具自动注入 task_id（让笔记和报告与任务关联）
        if name in ("note_add", "note_read", "note_summary", "report_generate",
                    "report_check_template", "report_format_with_template", "report_save_formatted"):
            args.setdefault("task_id", self.task_id)
            if name == "note_read":
                args.setdefault("type", "all")

        # 浏览器工具：直接 await（Playwright 必须在同一 event loop）
        if name in BROWSER_TOOL_NAMES:
            return await self._exec_browser(name, args)

        # 加密工具
        if name.startswith("crypto_"):
            return await self._handle_crypto(name, args)

        # 其他工具走 ToolRouter（proxy/knowledge/note 等）
        from core.tool_router import ToolRouter
        # ★ 2026-05-29: 设置 task_id 上下文，让 proxy_mcp 持久化流量时能标记归属任务
        from core.mcp_bridge import _current_task_id
        _current_task_id.set(self.task_id)
        router = ToolRouter()
        return await asyncio.to_thread(router.execute, name, args)

    async def execute_for_worker(self, name: str, args: dict,
                                  feature: "FeaturePoint",
                                  done_reject_count: int) -> tuple[str, bool, int]:
        """子 Agent 工具执行入口。返回 (result, is_completed, done_reject_count)。"""
        from core.sitemap import CheckResult

        if name == "checklist_mark":
            result_enum = CheckResult(args.get("result", "not_vuln"))

            # ★ 2026-05-25 改造：result=vulnerable 时强制要求 reproduce_steps + fix_suggestion
            # （与 _handle_checklist 主 Agent 入口逻辑保持一致）
            if result_enum.value == "vulnerable":
                missing = []
                if not (args.get("reproduce_steps") or "").strip():
                    missing.append("reproduce_steps（复现步骤）")
                if not (args.get("fix_suggestion") or "").strip():
                    missing.append("fix_suggestion（修复建议）")
                if missing:
                    reject_msg = (
                        f"⛔ checklist_mark 被拒：标记 vulnerable 时必须提供 {' 和 '.join(missing)}。\n"
                        f"请补充完整后重新调用 checklist_mark，例如：\n"
                        f"  reproduce_steps: '1. 以普通用户登录获取 Token\n"
                        f"2. 发送 GET /api/user/detail?id=7\n"
                        f"3. 修改 id=1 再发一次\n"
                        f"4. 返回管理员完整信息'\n"
                        f"  fix_suggestion: '1. 服务端增加数据归属校验\n"
                        f"2. 使用 UUID 替代自增 ID\n"
                        f"3. 敏感字段脱敏处理'"
                    )
                    return reject_msg, False, done_reject_count

            # ★ 2026-05-19 改造：detail 质量检查（与主 Agent 入口逻辑一致）
            reject = self._check_detail_quality(result_enum, args.get("detail", "") or "")
            if reject:
                return reject, False, done_reject_count

            # ★ 2026-06-01 改造：经验硬闸门——标 vulnerable 落库前，若有强相关历史经验，
            # 且 detail 中尚未给出「已核对/已排除经验」的说明，则拒绝落库，强制先核对。
            # 这是把「靠 LLM 自觉回头改」升级为「确定性卡口」的关键，确保按经验过滤误报。
            if result_enum.value == "vulnerable":
                gate_hints = self._recall_for_vuln(args.get("vuln_type", ""))
                if gate_hints and not self._has_lesson_ack(args.get("detail", "") or ""):
                    return self._build_lesson_gate_msg(args.get("vuln_type", ""), gate_hints), False, done_reject_count

            # ★ 自动从 FlowStore 拉取证据数据包（与主 Agent 逻辑一致）
            evidence_req = ""
            evidence_resp = ""
            flow_id = args.get("evidence_flow_id", "")
            if flow_id and result_enum.value == "vulnerable":
                evidence_req, evidence_resp = self._fetch_evidence_packet(flow_id)

            # ★ 漏洞类型同义词归一化：LLM 常传 BOLA/IDOR/水平越权 等变体，
            #   VULN_SYNONYMS 已定义映射但之前标记时未使用，导致子Agent反复猜名浪费轮次
            raw_vuln_type = args.get("vuln_type", "")
            canonical_vuln_type = VULN_SYNONYMS.get(raw_vuln_type, raw_vuln_type)
            if canonical_vuln_type != raw_vuln_type:
                log.info("漏洞类型归一化: %r → %r", raw_vuln_type, canonical_vuln_type)
            item = feature.mark_check(
                vuln_type=canonical_vuln_type,
                result=result_enum,
                detail=args.get("detail", ""),
                evidence_flow_id=flow_id,
                evidence_request=evidence_req,
                evidence_response=evidence_resp,
                severity=args.get("severity", ""),
                reproduce_steps=args.get("reproduce_steps", ""),
                fix_suggestion=args.get("fix_suggestion", ""),
            )
            # ★ 2026-05-19：tested_hypotheses / broken_promises 字段写入
            if item:
                tested_h = args.get("tested_hypotheses") or []
                broken_p = args.get("broken_promises") or []
                if isinstance(tested_h, list) and tested_h:
                    try:
                        if hasattr(item, "tested_hypotheses"):
                            item.tested_hypotheses = [str(x) for x in tested_h][:10]
                        else:
                            tag = "[已覆盖假设: " + ", ".join(str(x) for x in tested_h[:10]) + "]"
                            if tag not in (item.detail or ""):
                                item.detail = (item.detail or "") + "\n" + tag
                    except Exception:
                        pass
                if isinstance(broken_p, list) and broken_p:
                    try:
                        if hasattr(item, "broken_promises"):
                            item.broken_promises = [str(x) for x in broken_p][:10]
                        else:
                            tag = "[打破承诺: " + ", ".join(str(x) for x in broken_p[:10]) + "]"
                            if tag not in (item.detail or ""):
                                item.detail = (item.detail or "") + "\n" + tag
                    except Exception:
                        pass
            if self.sitemap:
                self.sitemap.save()

            # ★ 决策剧场：checklist_mark 落地后 emit HARM_VALIDATED 帧
            # 这是 LLM 决策链的"结论"环节 — 把判定 + 复现 + 修复都记到剧本里
            if item is not None:
                try:
                    from core.replay import emit_harm as _eh
                    _eh(
                        task_id=getattr(self.sitemap, "task_id", "") or self.task_id or "",
                        feature_id=feature.id,
                        feature_name=feature.name,
                        vuln_type=item.vuln_type,
                        skill_used="checklist_mark",
                        payload=(args.get("reproduce_steps") or "")[:1500],
                        target_url=getattr(self.sitemap, "target", "") or "",
                        conclusion=result_enum.value,
                        severity=(args.get("severity") or "")[:32],
                        llm_summary=(args.get("detail") or "")[:1500],
                        track="llm",
                        fix_suggestion=(args.get("fix_suggestion") or "")[:1500],
                        evidence_flow_id=flow_id or "",
                    )
                except Exception:
                    pass

            if item:
                pending = len(feature.get_pending_checks())
                icon = "🔴" if result_enum.value == "vulnerable" else "✅" if result_enum.value == "not_vuln" else "🟡"
                base_msg = f"{icon} {item.vuln_type}: {item.detail}\n剩余 {pending} 项待测"

                # ★ 漏洞双重验证提示：要求子 Agent 用不同参数再验证一次
                if result_enum.value == "vulnerable":
                    base_msg += (
                        "\n\n⚠️ **漏洞已记录，请立即做二次验证**（防止误报）：\n"
                        "- IDOR/越权类：换一个不同的 ID 值再试一次，确认都能越权\n"
                        "- SQL注入类：换一个不同的 payload（如 `1 AND 1=2`），确认响应有差异\n"
                        "- 信息泄露类：确认泄露的数据确实不属于当前用户\n"
                        "- 未授权访问类：用另一个不同的接口确认也存在同样问题\n"
                        "如果二次验证失败（非稳定漏洞），请重新调用 checklist_mark 将 result 改为 needs_review。\n"
                        "验证通过后，请调用 `note_add(type=\"result\")` 记录完整漏洞报告。"
                    )
                    # ★ 经验校验：子 Agent 标记漏洞时也注入相关历史教训
                    memory_hints = self._recall_for_vuln(item.vuln_type)
                    if memory_hints:
                        base_msg += f"\n\n🧠 **历史经验校验**（此前在同类漏洞上踩过坑，请逐条核对）：\n{memory_hints}"

                return base_msg, False, done_reject_count
            return f"未找到漏洞类型 '{args.get('vuln_type', '')}'", False, done_reject_count

        if name == "checklist_view":
            if self.sitemap:
                return self.sitemap.get_feature_checklist_for_llm(feature.id), False, done_reject_count
            return "无数据", False, done_reject_count

        if name == "worker_done":
            http_pending = feature.get_http_pending()
            if http_pending and done_reject_count < 2:
                done_reject_count += 1
                pending_names = ", ".join(c.vuln_type for c in http_pending[:5])
                return (f"⛔ 还有 {len(http_pending)} 项 HTTP 待测项未完成: {pending_names}\n"
                        f"请继续测试或用 checklist_mark 标记为 skipped。"), False, done_reject_count
            return "功能点测试完成", True, done_reject_count

        if name == "sitemap_report_discovery" and self.sitemap:
            result = self.sitemap.report_discovery(
                api_or_url=args.get("api_or_url", ""),
                description=args.get("description", ""),
                source_feature=feature.id,
            )
            action = result.get("action", "")
            if action == "queued":
                return f"📋 {result['message']}", False, done_reject_count
            elif action == "already_known":
                return f"已知: 已被 [{result['feature']}] 覆盖", False, done_reject_count
            return f"已记录", False, done_reject_count

        # 加密工具（子 Agent 可用 encrypt/decrypt）
        if name.startswith("crypto_"):
            result = await self._handle_crypto(name, args)
            return result, False, done_reject_count

        # Note 工具注入 task_id（确保子 Agent 笔记写到正确的任务文件）
        if name in ("note_add", "note_read", "note_summary"):
            args.setdefault("task_id", self.task_id)
            if name == "note_read":
                args.setdefault("type", "all")

        # HTTP/knowledge/note 工具
        from core.tool_router import ToolRouter
        from core.mcp_bridge import _current_task_id
        _current_task_id.set(self.task_id)
        router = ToolRouter()
        return await asyncio.to_thread(router.execute, name, args), False, done_reject_count

    # ---- 站点地图工具处理 ----

    def _handle_sitemap(self, name: str, args: dict) -> str:
        if not self.sitemap:
            return "站点地图未初始化"

        if name == "sitemap_add_page":
            p = self.sitemap.add_page(args.get("url", ""), args.get("title", ""), args.get("description", ""))
            return f"页面已记录: {p.url} — {p.title}"

        if name == "sitemap_add_feature":
            return self._add_feature(args)

        if name == "sitemap_activate_deferred":
            activated = self.sitemap.activate_deferred()
            if not activated:
                return "没有需要激活的延迟功能点"
            self.has_credentials = True
            self.sitemap.save()
            lines = [f"✅ 已激活 {len(activated)} 个后台功能点："]
            for fp in activated:
                checks = ", ".join(c.vuln_type for c in fp.checklist)
                lines.append(f"- [{fp.priority.value}] {fp.name} → {checks}")
            lines.append("\n这些功能点已加入测试队列，将在后续 Phase 2 中逐个测试。")
            return "\n".join(lines)

        if name == "sitemap_set_business":
            self.sitemap.business_summary = args.get("business_summary", "")
            self.sitemap.tech_stack = args.get("tech_stack", "")
            return f"业务类型: {self.sitemap.business_summary}, 技术栈: {self.sitemap.tech_stack}"

        if name == "sitemap_get_coverage":
            summary = self.sitemap.to_summary()
            matrix = self.sitemap.get_coverage_matrix()
            return f"{summary}\n\n{matrix}"

        if name == "sitemap_report_discovery":
            result = self.sitemap.report_discovery(
                api_or_url=args.get("api_or_url", ""),
                description=args.get("description", ""),
                source_feature=self.current_feature_id or "",
            )
            action = result.get("action", "")
            if action == "queued":
                log.info("动态发现已记录到待合并列表: %s", args.get("api_or_url", ""))
                return f"📋 {result['message']}"
            elif action == "already_known":
                return f"已知: 该 API 已被功能点 [{result['feature']}] 覆盖"
            else:
                return f"已忽略: {result.get('reason', '')}"

        return f"未知站点地图工具: {name}"

    def _add_feature(self, args: dict) -> str:
        from core.sitemap import Priority

        feat_name = args.get("name", "").strip()
        feat_desc = args.get("description", "").strip()
        requires_auth = args.get("requires_auth", False)

        # 自动判断：含后台关键词的功能自动标 requires_auth
        name_lower = f"{feat_name} {feat_desc}".lower()
        if any(kw in name_lower for kw in PUBLIC_KEYWORDS):
            requires_auth = False
        elif any(kw in name_lower for kw in BACKEND_KEYWORDS):
            requires_auth = True

        is_deferred = (not self.has_credentials) and requires_auth

        # LLM 可能把数组参数传成 JSON 字符串，做类型兼容
        related_apis = args.get("related_apis", [])
        if isinstance(related_apis, str):
            try:
                related_apis = json.loads(related_apis)
            except (json.JSONDecodeError, TypeError):
                related_apis = [related_apis] if related_apis.strip() else []

        suggested_tests = args.get("suggested_tests", [])
        if isinstance(suggested_tests, str):
            try:
                suggested_tests = json.loads(suggested_tests)
            except (json.JSONDecodeError, TypeError):
                suggested_tests = [suggested_tests] if suggested_tests.strip() else []

        fp = self.sitemap.add_feature(
            name=feat_name,
            description=feat_desc,
            page_url=args.get("page_url", ""),
            priority=Priority(args.get("priority", "medium")),
            suggested_tests=suggested_tests,
            related_apis=related_apis,
            requires_auth=requires_auth,
            deferred=is_deferred,
            module=args.get("module", ""),
        )
        if fp is None:
            return (f"⛔ 拒绝添加：功能点名称 '{feat_name}' 无效。\n"
                    f"请提供有意义的功能名称（如'用户登录'、'订单查询'）和描述。")
        # ★ 检测是否是合并到已有功能点
        was_merged = getattr(fp, "_was_merged", False)
        if was_merged:
            try:
                delattr(fp, "_was_merged")
            except Exception:
                pass
        self.sitemap.save()
        if is_deferred:
            log.info("功能点记录（延迟）: %s [%s]", fp.name, fp.priority.value)
            return (f"🔒 功能点已记录（延迟）: [{fp.priority.value}] {fp.name}\n"
                    f"该功能需要登录后台才能测试，暂不生成 checklist。\n"
                    f"突破登录后调用 sitemap_activate_deferred 激活。")
        checks = ", ".join(c.vuln_type for c in fp.checklist)
        log.info("功能点添加: %s [%s], %d 项 checklist (merged=%s)",
                 fp.name, fp.priority.value, len(fp.checklist), was_merged)
        if was_merged:
            return (f"♻️ 已合并到已有功能点（避免重复）: [{fp.priority.value}] {fp.name}\n"
                    f"系统已自动补全 related_apis 和 checklist。\n"
                    f"当前 checklist: {checks or '无'}\n"
                    f"⚠️ 之前已有同名/同 URL/同 API 的功能点，无需重复添加。")
        return f"功能点已添加: [{fp.priority.value}] {fp.name}\nChecklist: {checks or '无'}"

    # ---- Checklist 工具处理 ----

    def _handle_checklist(self, name: str, args: dict) -> str:
        if not self.sitemap or not self.current_feature_id:
            return "当前没有正在测试的功能点"

        if name == "checklist_view":
            return self.sitemap.get_feature_checklist_for_llm(self.current_feature_id)

        if name == "checklist_mark":
            from core.sitemap import CheckResult
            fp = self.sitemap.features.get(self.current_feature_id)
            if not fp:
                return "当前没有正在测试的功能点"
            result_enum = CheckResult(args.get("result", "not_vuln"))

            # ★ 2026-05-25 改造：result=vulnerable 时强制要求 reproduce_steps + fix_suggestion
            # ★ 实时模式下降级为软约束（警告但不拒绝），避免浪费有限轮次
            if result_enum.value == "vulnerable":
                missing = []
                if not (args.get("reproduce_steps") or "").strip():
                    missing.append("reproduce_steps（复现步骤）")
                if not (args.get("fix_suggestion") or "").strip():
                    missing.append("fix_suggestion（修复建议）")
                if missing and not self.realtime_mode:
                    return (
                        f"⛔ checklist_mark 被拒：标记 vulnerable 时必须提供 {' 和 '.join(missing)}。\n"
                        f"请补充完整后重新调用 checklist_mark，例如：\n"
                        f"  reproduce_steps: '1. 以普通用户登录获取 Token\\n"
                        f"2. 发送 GET /api/user/detail?id=7\\n"
                        f"3. 修改 id=1 再发一次\\n"
                        f"4. 返回管理员完整信息'\n"
                        f"  fix_suggestion: '1. 服务端增加数据归属校验\\n"
                        f"2. 使用 UUID 替代自增 ID\\n"
                        f"3. 敏感字段脱敏处理'"
                    )

            # ★ 2026-05-19 改造：detail 质量检查（仅对 not_vuln/skipped 做软约束）
            detail_text = args.get("detail", "") or ""
            reject = self._check_detail_quality(result_enum, detail_text)
            if reject:
                return reject

            # ★ 2026-06-01 改造：经验硬闸门——与 worker 入口逻辑一致。
            # 标 vulnerable 落库前，若有强相关历史经验且 detail 未给出核对说明，拒绝落库。
            if result_enum.value == "vulnerable":
                gate_hints = self._recall_for_vuln(args.get("vuln_type", ""))
                if gate_hints and not self._has_lesson_ack(detail_text):
                    return self._build_lesson_gate_msg(args.get("vuln_type", ""), gate_hints)

            # ★ 自动从 FlowStore 拉取证据数据包
            evidence_req = ""
            evidence_resp = ""
            flow_id = args.get("evidence_flow_id", "")
            if flow_id and result_enum.value == "vulnerable":
                evidence_req, evidence_resp = self._fetch_evidence_packet(flow_id)

            # ★ 漏洞类型同义词归一化（与子Agent入口一致）
            raw_vuln_type = args.get("vuln_type", "")
            canonical_vuln_type = VULN_SYNONYMS.get(raw_vuln_type, raw_vuln_type)
            if canonical_vuln_type != raw_vuln_type:
                log.info("漏洞类型归一化: %r → %r", raw_vuln_type, canonical_vuln_type)
            item = fp.mark_check(
                vuln_type=canonical_vuln_type,
                result=result_enum,
                detail=args.get("detail", ""),
                evidence_flow_id=flow_id,
                evidence_request=evidence_req,
                evidence_response=evidence_resp,
                severity=args.get("severity", ""),
                reproduce_steps=args.get("reproduce_steps", ""),
                fix_suggestion=args.get("fix_suggestion", ""),
            )
            # ★ 2026-05-19：把 tested_hypotheses / broken_promises 写到 item 的扩展字段
            if item:
                tested_h = args.get("tested_hypotheses") or []
                broken_p = args.get("broken_promises") or []
                if isinstance(tested_h, list) and tested_h:
                    try:
                        # 优先用对象属性（如有），否则挂到 detail 末尾
                        if hasattr(item, "tested_hypotheses"):
                            item.tested_hypotheses = [str(x) for x in tested_h][:10]
                        else:
                            tag = "[已覆盖假设: " + ", ".join(str(x) for x in tested_h[:10]) + "]"
                            if tag not in (item.detail or ""):
                                item.detail = (item.detail or "") + "\n" + tag
                    except Exception:
                        pass
                if isinstance(broken_p, list) and broken_p:
                    try:
                        if hasattr(item, "broken_promises"):
                            item.broken_promises = [str(x) for x in broken_p][:10]
                        else:
                            tag = "[打破承诺: " + ", ".join(str(x) for x in broken_p[:10]) + "]"
                            if tag not in (item.detail or ""):
                                item.detail = (item.detail or "") + "\n" + tag
                    except Exception:
                        pass
            if item:
                pending = len(fp.get_pending_checks())
                icon = "🔴" if result_enum.value == "vulnerable" else "✅" if result_enum.value == "not_vuln" else "🟡"
                self.sitemap.save()
                report_path = self.sitemap._report_path()
                log.info("checklist_mark: %s → %s (%s)", item.vuln_type, result_enum.value, item.detail[:50])
                base_msg = f"{icon} {item.vuln_type}: {item.detail}\n剩余 {pending} 项待测\n📄 报告已实时更新: {report_path}"
                if result_enum.value == "vulnerable":
                    # ★ 经验校验：标记漏洞时注入相关历史教训，防止重复犯同类误判
                    memory_hints = self._recall_for_vuln(item.vuln_type)
                    base_msg += (
                        "\n\n⚠️ **请做二次验证**（用不同参数再发一次请求确认漏洞稳定可复现），"
                        "验证通过后调用 `note_add(type=\"result\")` 记录。"
                    )
                    if memory_hints:
                        base_msg += f"\n\n🧠 **历史经验校验**（此前在同类漏洞上踩过坑，请逐条核对）：\n{memory_hints}"
                return base_msg
            return f"未找到漏洞类型 '{args.get('vuln_type', '')}' 在当前 checklist 中"

        return f"未知 checklist 工具: {name}"

    @staticmethod
    def _has_lesson_ack(detail_text: str) -> bool:
        """检测 detail 中是否已包含「核对历史经验」的声明，作为经验闸门的放行依据。

        要求同时出现「指向经验/教训」与「已核对/已排除」两类关键词，
        避免 Agent 用一句空话糊弄过闸门。
        """
        if not detail_text:
            return False
        t = detail_text.replace(" ", "").replace("　", "")
        # 兜底：声明过短（如仅「已核对经验」4 字）视为空话，不予放行，
        # 强制 Agent 写出针对每条经验的实质排除理由。
        if len(t) < 30:
            return False
        ref_kw = ["经验", "教训", "历史", "lesson", "踩坑"]
        ack_kw = ["已核对", "已对照", "已比对", "已逐条", "已排除",
                  "已确认不", "不冲突", "不适用", "已规避", "非同类"]
        has_ref = any(k in t for k in ref_kw)
        has_ack = any(k in t for k in ack_kw)
        return has_ref and has_ack

    def _build_lesson_gate_msg(self, vuln_type: str, hints: str) -> str:
        """构造经验闸门拦截提示：要求 Agent 落库前先逐条核对历史经验。"""
        return (
            "⛔ **经验闸门拦截：本次漏洞判断暂未落库（不会进入报告）**\n\n"
            f"系统检测到你在「{vuln_type}」这类漏洞上此前有历史经验/踩坑记录，"
            "为防止重复同类误报，**落库前必须先逐条核对以下经验**：\n\n"
            f"{hints}\n\n"
            "✅ **放行方式**：重新调用 checklist_mark，并在 detail 中针对上面每一条经验"
            "逐一说明「已核对历史经验：该经验指出…，本次已通过…排除/确认不属于该误报」。\n"
            "❌ 若逐条核对后发现本次判断确实可能踩中同类误报，请把 result 改为 needs_review。\n"
            "（注意：只有 detail 里出现明确的「已核对/已排除历史经验」说明，本漏洞才会被允许落库。）"
        )

    def _recall_for_vuln(self, vuln_type: str) -> str:
        """漏洞标记时查记忆库，返回与该漏洞类型相关的历史教训。

        在 checklist_mark 标记 vulnerable 时调用，让 Agent 在写入结论前
        核对历史经验，防止重复犯同类误判。

        与 _inject_memories 不同：这里只召回与漏洞类型直接相关的教训
        （scope=vuln_type 匹配 或 trigger 关键词强命中），不召回所有 global 教训。
        """
        try:
            from core import memory
            target_url = ""
            # 尝试从 sitemap 获取目标 URL
            if self.sitemap and hasattr(self.sitemap, "target_url"):
                target_url = self.sitemap.target_url or ""
            lessons = memory.recall(
                target_url=target_url,
                vuln_type=vuln_type,
                query=vuln_type,
                limit=10,
            )
            if not lessons:
                return ""
            # 过滤：只保留与该漏洞类型直接相关的教训
            # 1. scope=vuln_type 且 scope_value 匹配（得分 >= 4）
            # 2. trigger 关键词与漏洞类型强命中（得分 >= 2）
            # 排除仅靠 scope=global 低分命中的教训
            filtered = []
            for it in lessons:
                scope = it.get("scope", "")
                sv = it.get("scope_value", "")
                # scope=vuln_type 且匹配
                if scope == "vuln_type" and sv and memory._vt_match(sv, vuln_type):
                    filtered.append(it)
                    continue
                # scope=host 且匹配目标
                if scope == "host" and target_url and sv == memory._host_of(target_url):
                    filtered.append(it)
                    continue
                # trigger 关键词与漏洞类型强命中
                trigger_raw = (it.get("trigger") or "").lower()
                trigger_tokens = [t.strip() for t in re.split(r"[\s,，;；]+", trigger_raw) if t.strip()]
                vt_lower = vuln_type.lower()
                for tk in trigger_tokens:
                    if len(tk) >= 2 and (tk in vt_lower or vt_lower in tk):
                        filtered.append(it)
                        break
            if not filtered:
                return ""
            lines = []
            for i, it in enumerate(filtered[:5], 1):
                scope_desc = it.get("scope", "")
                sv = it.get("scope_value", "")
                if sv:
                    scope_desc += f"={sv}"
                lines.append(f"{i}. [{scope_desc}] {it.get('lesson', '')}")
                if it.get("evidence"):
                    lines.append(f"   原始纠正: {it['evidence'][:200]}")
            lines.append("\n⛔ 如果当前判断与上述经验冲突，必须重新验证后再标记。")
            return "\n".join(lines)
        except Exception as e:
            log.warning("漏洞经验校验失败: %s", e)
            return ""

    @staticmethod
    def _check_detail_quality(result_enum, detail_text: str) -> str:
        """检查 checklist_mark 的 detail 质量。

        2026-05-19 改造：标 not_vuln/skipped 时拒绝笼统话术，逼 LLM 按 SKILL 末尾自检清单交账。
        Returns: 如果应被驳回，返回驳回原因（非空字符串）；通过返回空字符串。
        """
        if result_enum.value not in ("not_vuln", "skipped"):
            return ""  # vulnerable / needs_review 不做笼统检查
        if not detail_text:
            detail_text = ""
        # 长度兜底
        if len(detail_text) < 60:
            return (
                f"⛔ checklist_mark 被拒（detail 太短，仅 {len(detail_text)} 字）：\n"
                f"标 {result_enum.value} 时 detail ≥ 60 字，必须按对应 SKILL 末尾的"
                f"「最低必测自检清单」逐条说明你做了什么。\n"
                f"示例：'试了①path ID 替换(返回403)②include 参数(无回显)③batch 接口(无)"
                f"④CSRF 抓 token PUT 试 Mass Assignment(invalid_field)。结论：所有路径已穷尽。'"
            )
        # 笼统话术黑名单
        detail_lower = detail_text.lower()
        vague_keywords = [
            "业务正常", "属于正常业务", "正常业务", "本就能",
            "无入口", "无攻击面", "无可控参数", "不存在该功能",
            "无可注入", "无相关参数", "未发现", "无相关入口",
            "受csrf保护", "受 csrf 保护", "受csrf token保护", "csrf token验证失败",
            "需要jwt", "需要 jwt", "缺少jwt", "缺少 jwt",
            "只有一个账号", "仅一个账号", "无法对比",
            "rest接口默认", "restful接口", "spa正常返回",
        ]
        hits = [kw for kw in vague_keywords if kw in detail_lower]
        # 命中 ≥ 1 个笼统词且 detail < 200 字 → 驳回（要求扩写到 ≥ 200 字详细交账）
        if hits and len(detail_text) < 200:
            return (
                f"⛔ checklist_mark 被拒（笼统话术）：\n"
                f"detail 中出现可疑笼统理由：{', '.join(hits)}。\n"
                f"这些理由经常掩盖「没有换路径继续测」的事实。请按 SKILL 末尾的"
                f"「最低必测自检清单」**逐条交账**：\n"
                f"  - 试了哪几条必测项？\n"
                f"  - 撞墙时（403/CSRF/WAF）试过 SKILL 里的绕过技巧吗？至少 3 种？\n"
                f"  - 你的判定是「真没有 X」还是「我没找到 X」？前者要给穷尽证据，后者要继续找\n"
                f"如果确实已穷尽且笼统理由是结论而非搪塞，请把 detail 写到 ≥ 200 字详细说明。"
            )
        return ""

    def _fetch_evidence_packet(self, flow_id: str) -> tuple[str, str]:
        """从 FlowStore 根据 flow_id 拉取完整请求/响应数据包。

        Returns:
            (evidence_request, evidence_response) 格式化的 HTTP 数据包文本
        """
        try:
            from core.mcp_bridge import _store, _load_new_flows
            _load_new_flows()

            # 支持多个 flow_id（逗号分隔）
            flow_ids = [fid.strip() for fid in flow_id.split(",") if fid.strip()]
            req_parts = []
            resp_parts = []

            for fid in flow_ids[:3]:  # 最多取 3 个
                flow = _store.get(fid)
                if not flow:
                    continue

                # 构造请求数据包
                req_lines = [f"{flow.method} {flow.url} HTTP/1.1"]
                for k, v in flow.request_headers.items():
                    if k.lower() not in ("accept-encoding", "connection"):
                        req_lines.append(f"{k}: {v}")
                if flow.request_body:
                    req_lines.append("")
                    req_lines.append(flow.request_body[:2000])
                req_parts.append("\n".join(req_lines))

                # 构造响应数据包
                resp_lines = [f"HTTP/1.1 {flow.status_code}"]
                for k, v in flow.response_headers.items():
                    if k.lower() not in ("transfer-encoding", "content-encoding"):
                        resp_lines.append(f"{k}: {v}")
                resp_lines.append("")
                body = flow.response_body[:3000] if flow.response_body else ""
                resp_lines.append(body)
                resp_parts.append("\n".join(resp_lines))

            return "\n\n---\n\n".join(req_parts), "\n\n---\n\n".join(resp_parts)
        except Exception as e:
            log.warning("拉取证据数据包失败: %s", e)
            return "", ""

    # ---- 加密工具 ----

    async def _handle_crypto(self, name: str, args: dict) -> str:
        from core.crypto_engine import detect_from_browser, encrypt, decrypt, get_configs
        import json as _json

        if name == "crypto_detect":
            result = await detect_from_browser()
            if result.get("found"):
                # 把加密配置也存入 sitemap（供 flush_samples_to_files 写入）
                if self.sitemap:
                    from dataclasses import asdict
                    self.sitemap.crypto_configs = [asdict(c) for c in get_configs()]
                    self.sitemap.save()
                return (f"✅ CryptoHook 检测成功！\n\n"
                        f"{result.get('summary', '')}\n\n"
                        f"Keys: {result.get('keys_count', 0)}, "
                        f"IVs: {result.get('ivs_count', 0)}, "
                        f"Secrets: {result.get('secrets_count', 0)}, "
                        f"加密记录: {result.get('records_count', 0)}")
            else:
                return f"ℹ️ {result.get('message', '未检测到加密')}"

        elif name == "crypto_encrypt":
            result = encrypt(args.get("plaintext", ""), args.get("config_index", 0))
            if result.get("success"):
                return (f"✅ 加密成功\n"
                        f"密文(base64): {result['ciphertext']}\n"
                        f"密文(hex): {result.get('ciphertext_hex', '')}")
            return f"❌ 加密失败: {result.get('error', '未知错误')}"

        elif name == "crypto_decrypt":
            result = decrypt(args.get("ciphertext", ""), args.get("config_index", 0))
            if result.get("success"):
                return f"✅ 解密成功\n明文: {result['plaintext']}"
            return f"❌ 解密失败: {result.get('error', '未知错误')}"

        return f"未知加密工具: {name}"

    # ---- 浏览器工具 ----

    @staticmethod
    async def _exec_browser(name: str, args: dict) -> str:
        from mcp_servers import browser_mcp
        func = getattr(browser_mcp, name, None)
        if func:
            actual = getattr(func, "fn", func)
            try:
                return str(await actual(**args))
            except Exception as e:
                return f"浏览器工具执行失败: {name} — {e}"
        return f"浏览器工具未找到: {name}"

    # ---- 漏洞验证 ----

    async def _verify_vuln(self, args: dict) -> str:
        vuln_type = args.get("vuln_type", "unknown")
        description = args.get("description", "")
        normal_id = args.get("normal_flow_id", "")
        attack_id = args.get("attack_flow_id", "")
        verify_method = args.get("verify_method", "custom")
        expected = args.get("expected_evidence", "")

        result_lines = [f"## 漏洞验证: {vuln_type}\n", f"描述: {description}\n"]

        from core.tool_router import ToolRouter
        from core.mcp_bridge import _current_task_id
        _current_task_id.set(self.task_id)
        router = ToolRouter()

        if attack_id:
            replay_result = router.execute("proxy_replay", {"flow_id": attack_id})
            result_lines.append(f"### 重放攻击请求\n{replay_result[:1000]}\n")
            if normal_id:
                diff_result = router.execute("proxy_diff_responses", {
                    "flow_id_a": normal_id, "flow_id_b": attack_id,
                })
                result_lines.append(f"### 响应对比\n{diff_result[:1000]}\n")

        full_result = "\n".join(result_lines)

        if verify_method == "response_diff":
            if "响应完全相同" in full_result or "状态码不同" not in full_result:
                verdict = "⚠️ 需人工确认 — 响应相似，可能存在越权但需进一步验证"
            else:
                verdict = "✅ 验证通过 — 不同参数返回了不同数据"
        elif verify_method == "data_leak":
            verdict = f"需确认响应中是否包含: {expected}"
        elif verify_method == "status_code":
            verdict = "检查重放结果中的状态码是否符合预期"
        else:
            verdict = f"自定义验证 — 预期证据: {expected}"

        full_result += f"\n### 验证结论\n{verdict}\n"
        full_result += f"\n预期证据: {expected}"
        full_result += "\n\n如果验证通过，请用 note_add type=result 记录该漏洞。"
        full_result += "\n如果是误报，跳过该漏洞继续测试下一个方向。"

        if self.current_feature_id and self.sitemap:
            fp = self.sitemap.features.get(self.current_feature_id)
            if fp:
                fp.findings.append(f"[{vuln_type}] {description} — {verdict}")

        return full_result

    # ---- 记忆工具（Hermes 风格） ----

    def _handle_memory(self, name: str, args: dict) -> str:
        """处理 record_lesson / recall_lessons / forget_lesson 三个工具。"""
        from core import memory

        if name == "record_lesson":
            scope = (args.get("scope") or "global").strip()
            if scope not in memory.VALID_SCOPES:
                return f"❌ scope 必须是 {memory.VALID_SCOPES} 之一"
            scope_value = (args.get("scope_value") or "").strip()
            lesson = (args.get("lesson") or "").strip()
            if not lesson:
                return "❌ lesson 不能为空"
            trigger = (args.get("trigger") or "").strip()
            evidence = (args.get("evidence") or "").strip()
            try:
                item = memory.record(
                    scope=scope,
                    scope_value=scope_value,
                    trigger=trigger,
                    lesson=lesson,
                    evidence=evidence,
                    source="self_learn",
                )
                return (f"✅ 已记入长期记忆 (id={item['id']})\n"
                        f"作用域: {scope}{('=' + scope_value) if scope_value else ''}\n"
                        f"经验: {lesson}\n"
                        f"💡 下次同类场景会自动注入到上下文。")
            except Exception as e:
                return f"❌ 记录失败: {e}"

        if name == "recall_lessons":
            target_url = (args.get("target_url") or "").strip()
            vuln_type = (args.get("vuln_type") or "").strip()
            query = (args.get("query") or "").strip()
            try:
                hits = memory.recall(target_url=target_url, vuln_type=vuln_type, query=query, limit=10)
            except Exception as e:
                return f"❌ 检索失败: {e}"
            if not hits:
                return "（无匹配的历史经验）"
            lines = [f"召回 {len(hits)} 条经验："]
            for it in hits:
                tag = it.get("scope", "")
                if it.get("scope_value"):
                    tag += f"={it['scope_value']}"
                lines.append(f"- [{tag}] {it.get('lesson', '')} (id={it.get('id')})")
            return "\n".join(lines)

        if name == "forget_lesson":
            lid = (args.get("lesson_id") or "").strip()
            if not lid:
                return "❌ 必须提供 lesson_id"
            try:
                ok = memory.delete(lid)
            except Exception as e:
                return f"❌ 删除失败: {e}"
            return f"✅ 已删除 {lid}" if ok else f"❌ 未找到 {lid}"

        return f"未知记忆工具: {name}"
