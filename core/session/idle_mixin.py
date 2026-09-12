"""
IdlePhaseMixin — idle 阶段逻辑 + 包测模式。

方法：
- _run_packet_test_mode: 单数据包漏洞探测模式
- _extract_auth_for_xss: 从 crawl_result 提取认证信息给 XSS 扫描
- _llm_suggest_packet_tests: LLM 分析数据包生成 suggested_tests

chat() 方法中 idle 阶段的核心逻辑留在 base.py 的 chat() 内，
因为 chat() 是主入口，不宜拆到 Mixin（调用关系太复杂）。
包测模式独立性强，单独抽出。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import AsyncGenerator

from core.sitemap import Sitemap, Priority, CheckItem
from core.log import get_logger
from core.prompts import load_template

log = get_logger("session.idle")


class IdlePhaseMixin:
    """idle 阶段逻辑：包测模式 + XSS 认证提取。"""

    async def _run_packet_test_mode(
        self, intent: dict, packet: dict, user_message: str
    ) -> AsyncGenerator[str, None]:
        """单数据包漏洞探测模式。

        跳过 Phase 0（爬虫）、Phase 1（功能点分析）、Phase 1.5（业务理解），
        直接对用户给的单个 HTTP 数据包构造 1 个 FeaturePoint 并调用 worker_agent
        跑漏洞 checklist。

        - 复用 sitemap.add_feature 自动 checklist 推断逻辑（_auto_suggest_tests）
        - 复用 worker_agent 完整测试流程（含 SKILL 注入、历史经验注入）
        - 凭证（cookie/auth/extra_headers）从 packet 自动注入
        - 测试完成后直接进入 Phase 3 出报告
        """
        method = packet.get("method", "GET")
        full_url = packet.get("url", "")
        path = packet.get("path", "")
        host = packet.get("host", "")
        scheme = packet.get("scheme", "https")
        body = packet.get("body", "") or ""
        cookies = packet.get("cookies", "") or ""
        headers = packet.get("headers", {}) or {}
        auth_header = ""
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header = v
                break
        extra_headers = intent.get("extra_headers", {}) or {}

        target_url = f"{scheme}://{host}" if host and scheme else (full_url or intent.get("target_url", ""))

        yield self._event("phase", "📦 单数据包漏洞探测模式")
        yield self._event("system",
            f"已识别为单包测试模式 — 目标接口: `{method} {full_url or path}`\n"
            f"将跳过爬虫和全站分析，直接对该接口跑漏洞 checklist。"
        )

        # ---- 1) 初始化 sitemap（task_id 复用主 session 的）----
        self.target_url = target_url
        self.target_info = f"单包测试: {method} {full_url or path}"
        self.sitemap = Sitemap(target=target_url, task_id=self.task_id)

        # ---- 2) 凭证注入（与 site 模式一致）----
        # 包里通常带 cookie / auth 头，是用户已经登录的状态，直接当凭证用
        for _k in ("PENTEST_INJECT_COOKIES", "PENTEST_INJECT_AUTH",
                   "PENTEST_INJECT_HEADERS", "PENTEST_INJECT_LOCAL_STORAGE", "PENTEST_TARGET_URL"):
            os.environ.pop(_k, None)
        if cookies:
            os.environ["PENTEST_INJECT_COOKIES"] = cookies
        if auth_header:
            os.environ["PENTEST_INJECT_AUTH"] = auth_header
        if extra_headers:
            os.environ["PENTEST_INJECT_HEADERS"] = json.dumps(extra_headers, ensure_ascii=False)
            # ★ JWT token 自动注入 localStorage（SPA 前端路由守卫需要）
            from core.intent import jwt_headers_to_local_storage
            ls_items = jwt_headers_to_local_storage(extra_headers)
            if ls_items:
                os.environ["PENTEST_INJECT_LOCAL_STORAGE"] = json.dumps(ls_items, ensure_ascii=False)
        os.environ["PENTEST_TARGET_URL"] = target_url

        self._inject_cookies = cookies
        self._inject_auth = auth_header
        self._inject_headers = dict(extra_headers)
        self._inject_target_url = target_url
        self.has_credentials = bool(cookies or auth_header or extra_headers)

        if self.has_credentials:
            cred_summary = []
            if cookies:
                cred_summary.append(f"{cookies.count('=')} 个 Cookie")
            if auth_header:
                cred_summary.append("Authorization 头")
            if extra_headers:
                cred_summary.append(f"{len(extra_headers)} 个自定义 Header")
            yield self._event("system", f"🔑 已从数据包提取凭证: {', '.join(cred_summary)}")

        # ---- 3) LLM 分析数据包 → suggested_tests（主），规则兜底（辅）----
        api_ref = f"{method} {full_url or path}".strip()
        body_preview = body[:300] if body else ""

        # 3a) 构造数据包摘要给 LLM
        packet_summary = f"```\n{method} {full_url or path} HTTP/1.1\nHost: {host}\n"
        content_type = ""
        for k, v in headers.items():
            packet_summary += f"{k}: {v}\n"
            if k.lower() == "content-type":
                content_type = v
        if body_preview:
            packet_summary += f"\n{body_preview}\n"
        packet_summary += "```"

        # 3b) 调 LLM 分析
        suggested_tests = []
        try:
            from core.llm import Message
            llm_messages = [
                Message(role="system", content=load_template("packet_analysis", packet_summary=packet_summary)),
                Message(role="user", content="请分析上述数据包，输出最可能存在的漏洞类型列表。"),
            ]
            response = await asyncio.to_thread(
                self.llm.chat, llm_messages, None, 0.1, 1024, "packet_suggest"
            )
            text = response.content or ""
            # ★ 使用统一的安全 JSON 解析（支持嵌套数组、平衡括号提取），
            # 避免非贪婪正则 r'\[[\s\S]*?\]' 在内嵌 [...] 时截断匹配。
            from core.llm import parse_llm_json
            suggested_tests = parse_llm_json(text, expect=list) or []
            # 过滤非字符串和空值
            suggested_tests = [str(t).strip() for t in suggested_tests if t and isinstance(t, str)]
            log.info("LLM suggested_tests for packet: %s", suggested_tests)
        except Exception as e:
            log.warning("LLM packet analysis failed, using rule-based fallback: %s", e)
            suggested_tests = []

        yield self._event("system",
            f"🧠 LLM 分析完成，建议测试: {', '.join(suggested_tests) or '(无)'}"
        )

        # 3c) 构造 FeaturePoint — LLM suggested_tests 为主，规则兜底
        feature_name = f"导入接口 {method} {path or '/'}"
        if len(feature_name) > 80:
            feature_name = feature_name[:80]

        # description 包含足够特征让规则兜底能触发
        desc_parts = [f"用户导入的单个 HTTP 数据包，方法 {method}，路径 {path}。"]
        if body_preview:
            desc_parts.append(f"请求体片段: {body_preview[:200]}")
        if any(kw in path.lower() for kw in ("upload", "import", "attach", "file")):
            desc_parts.append("涉及文件上传操作。")
        if any(kw in path.lower() for kw in ("export", "download")):
            desc_parts.append("涉及数据导出/下载。")
        if any(kw in path.lower() for kw in ("login", "auth", "token", "session")):
            desc_parts.append("涉及认证/会话管理。")
        if any(kw in path.lower() for kw in ("admin", "manage", "config", "system")):
            desc_parts.append("涉及管理员/系统配置功能。")
        if any(kw in path.lower() for kw in ("user", "account", "profile")):
            desc_parts.append("涉及用户账户操作。")
        if any(kw in path.lower() for kw in ("order", "pay", "balance", "transfer", "wallet")):
            desc_parts.append("涉及支付/账户余额操作。")
        description = " ".join(desc_parts)

        fp = self.sitemap.add_feature(
            name=feature_name,
            description=description,
            page_url=full_url or target_url,
            priority=Priority.HIGH,  # 用户主动指定的接口默认高优先级
            suggested_tests=suggested_tests,  # ★ LLM 分析结果
            related_apis=[api_ref],
            requires_auth=self.has_credentials,
            deferred=False,
        )

        if not fp:
            yield self._event("error",
                "❌ 无法构造功能点（feature_name 过短或被通用名过滤）。请检查 packet 路径是否合法。"
            )
            self.phase = "idle"
            return

        # 3d) 规则兜底补充（只补 LLM 和规则都没覆盖到的基线项）
        from core.config import VULN_SYNONYMS
        existing_vulns = {c.vuln_type for c in fp.checklist}
        # 仅当 LLM 返回空时（LLM 失败），补最基础的几项
        if not suggested_tests:
            _PACKET_FALLBACK_VULNS = ["未授权访问", "信息泄露"]
            for vt in _PACKET_FALLBACK_VULNS:
                if vt not in existing_vulns:
                    fp.checklist.append(CheckItem(vuln_type=vt, needs_browser=False))
                    existing_vulns.add(vt)

        # 如果 body 含 user/id 类字段，强制加 IDOR（LLM 可能漏判）
        if body and any(kw in body.lower() for kw in ('"id"', "user_id", "uid", '"user":')):
            if "IDOR越权" not in existing_vulns:
                fp.checklist.append(CheckItem(vuln_type="IDOR越权", needs_browser=False))

        # 3e) checklist 优先级排序：LLM 建议的排前面，规则兜底排后面
        suggested_set = set(suggested_tests)
        # 去重：把 VULN_SYNONYMS 标准化后的也纳入 suggested_set
        for t in suggested_tests:
            canonical = VULN_SYNONYMS.get(t, t)
            suggested_set.add(canonical)

        fp.checklist.sort(
            key=lambda c: (0 if c.vuln_type in suggested_set else 1)
        )

        self.sitemap.save()
        yield self._event("system",
            f"✅ 功能点已建立: 「{fp.name}」(checklist {len(fp.checklist)} 项)\n"
            f"将测试: {', '.join(c.vuln_type for c in fp.checklist[:8])}"
            + ("..." if len(fp.checklist) > 8 else "")
        )

        # ---- 4) 跳到 test phase，调 run_parallel_test ----
        self.phase = "test"
        self._sync_tool_executor()

        # 历史经验注入（worker 内部还会按 vuln_type 再注一次，这里是 phase 级）
        n_inj = self._inject_memories(self.current_context)
        if n_inj > 0:
            yield self._event("system", f"📚 已注入 {n_inj} 条历史经验到上下文")

        yield self._event("phase", "Phase 2: 包测试执行中...")
        from core.parallel import run_parallel_test
        async for evt in run_parallel_test(self):
            yield evt

        # run_parallel_test 完成后会自动 _enter_report_phase，这里不需要再调

    # ============================================================

    def _extract_auth_for_xss(self, crawl_result: dict | None) -> tuple[dict, dict]:
        """从 crawl_result 中提取认证 headers 和 cookies 用于 XSS 扫描。

        策略：取 admin 角色（如果有）的最后一次成功认证态，否则用任意角色。
        Returns:
        """
        auth_headers: dict = {}
        cookies: dict = {}

        if not crawl_result:
            return auth_headers, cookies

        # 尝试从登录结果中提取
        login_status = crawl_result.get("login_status", {})
        credentials = getattr(self, '_inject_cookies', '') or os.getenv("PENTEST_INJECT_COOKIES", "")

        if credentials:
            # 已有注入的 Cookie
            for pair in credentials.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()

        auth_token = os.getenv("PENTEST_INJECT_AUTH", "")
        if auth_token:
            auth_headers["Authorization"] = auth_token

        return auth_headers, cookies
