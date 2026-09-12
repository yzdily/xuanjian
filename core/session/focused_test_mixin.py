"""
FocusedTestMixin — 指定功能测试模式。

支持两种触发方式：
1. 用户文字指定："只测登录功能的SQL注入" / "帮我测一下支付页面"
2. 用户上传截图 + 指令："只测截图中的这些功能"

核心逻辑：
- 跳过全站爬虫（或只做最小化导航）
- 根据用户指定的功能构造 FeaturePoint
- 直接进入 Phase 2 并行测试

与 idle_mixin.py 的 _run_packet_test_mode 平行，互不干扰。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import AsyncGenerator

from core.sitemap import Sitemap, Priority, CheckItem
from core.log import get_logger
from core.prompts import load_template

log = get_logger("session.focused_test")


class FocusedTestMixin:
    """指定功能测试模式 — 文字指定 + 截图指定。"""

    async def _run_focused_test_mode(
        self, intent: dict, user_message: str
    ) -> AsyncGenerator[str, None]:
        """指定功能测试模式入口。

        用户明确指定了要测试的功能（通过文字描述或截图识别结果），
        跳过全站爬虫，直接构造功能点并进入测试。

        流程：
        1. 解析 target_features（来自 intent 或截图分析）
        2. 初始化 sitemap + 凭证注入
        3. 为每个指定功能构造 FeaturePoint（含 LLM checklist 推断）
        4. 跳到 Phase 2 并行测试
        5. 出报告
        """
        target_url = intent.get("target_url", "")
        target_features = intent.get("target_features", [])
        credentials = intent.get("credentials", [])
        session_cookies = intent.get("session_cookies", "")
        auth_header = intent.get("auth_header", "")
        extra_headers = intent.get("extra_headers", {}) or {}
        screenshot_analysis = intent.get("screenshot_analysis")

        if not target_url:
            yield self._event("error", "❌ 指定功能测试模式需要提供目标 URL")
            return

        if not target_features and not screenshot_analysis:
            yield self._event("error", "❌ 未识别到要测试的功能，请明确指定功能名称")
            return

        yield self._event("phase", "🎯 指定功能测试模式")

        # ---- 1) 初始化 sitemap ----
        self.target_url = target_url
        self.target_info = f"指定功能测试: {', '.join(f.get('name', '未知') for f in target_features[:5] if isinstance(f, dict))}"
        self.sitemap = Sitemap(target=target_url, task_id=self.task_id)

        # ---- 2) 凭证注入（与 site/packet 模式一致）----
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
                os.environ["PENTEST_INJECT_LOCAL_STORAGE"] = json.dumps(ls_items, ensure_ascii=False)
        os.environ["PENTEST_TARGET_URL"] = target_url

        self._inject_cookies = session_cookies
        self._inject_auth = auth_header
        self._inject_headers = dict(extra_headers)
        self._inject_target_url = target_url
        self.has_credentials = bool(session_cookies or auth_header or extra_headers or credentials)

        if self.has_credentials:
            cred_summary = []
            if session_cookies:
                cred_summary.append(f"{session_cookies.count('=')} 个 Cookie")
            if auth_header:
                cred_summary.append("Authorization 头")
            if extra_headers:
                cred_summary.append(f"{len(extra_headers)} 个自定义 Header")
            if credentials:
                cred_summary.append(f"{len(credentials)} 个账号")
            yield self._event("system", f"🔑 已注入凭证: {', '.join(cred_summary)}")

        # ---- 3) 如果有截图分析结果但没有 target_features，从截图中提取 ----
        if not target_features and screenshot_analysis:
            target_features = screenshot_analysis.get("features", [])
            if screenshot_analysis.get("visible_url") and not target_url:
                target_url = screenshot_analysis["visible_url"]
                self.target_url = target_url

        if not target_features:
            yield self._event("error", "❌ 未能从截图/指令中识别出具体功能点")
            return

        yield self._event("system",
            f"📋 已识别 {len(target_features)} 个目标功能:\n"
            + "\n".join(f"  • {f.get('name', '未知')}: {f.get('description', '')[:60]}"
                       for f in target_features[:10])
        )

        # ---- 4) 为每个功能构造 FeaturePoint ----
        from core.config import FEATURE_VULN_MAPPING, VULN_SYNONYMS
        from core.llm import Message

        created_features = []
        for feat in target_features:
            feat_name = feat.get("name", "").strip()
            if not feat_name:
                continue

            description = feat.get("description", feat_name)
            estimated_api = feat.get("estimated_api", "")
            interaction_type = feat.get("interaction_type", "")

            # 用 LLM 分析该功能应该测什么漏洞
            suggested_tests = await self._llm_suggest_focused_tests(
                feat_name, description, estimated_api, interaction_type
            )

            # 构造 related_apis
            related_apis = []
            if estimated_api:
                related_apis.append(estimated_api)

            # 确定页面 URL
            page_url = feat.get("page_url", target_url)

            fp = self.sitemap.add_feature(
                name=feat_name,
                description=description,
                page_url=page_url,
                priority=Priority.HIGH,
                suggested_tests=suggested_tests,
                related_apis=related_apis,
                requires_auth=self.has_credentials,
                deferred=False,
            )

            if fp:
                created_features.append(fp)
                log.info("创建功能点: %s (checklist %d 项)", feat_name, len(fp.checklist))

        if not created_features:
            yield self._event("error", "❌ 无法为指定功能创建测试点，请检查功能描述是否有效")
            return

        self.sitemap.save()
        yield self._event("system",
            f"✅ 已创建 {len(created_features)} 个功能点，"
            f"共 {sum(len(fp.checklist) for fp in created_features)} 项 checklist\n"
            f"将测试: {', '.join(fp.name for fp in created_features[:5])}"
            + ("..." if len(created_features) > 5 else "")
        )

        # ---- 5) 可选：快速导航抓取 API 样本 ----
        # 如果有凭证，尝试快速访问目标页面抓取真实 API（增强测试精度）
        if self.has_credentials and target_url:
            yield self._event("system", "🔍 快速导航目标页面，抓取 API 样本...")
            try:
                await self._quick_navigate_for_apis(target_url, target_features)
                yield self._event("system", "✅ API 样本抓取完成")
            except Exception as e:
                log.warning("快速导航失败（非致命）: %s", e)
                yield self._event("system", f"⚠️ 快速导航失败（不影响测试）: {e}")

        # ---- 6) 进入 Phase 2 并行测试 ----
        self.phase = "test"
        self._sync_tool_executor()

        # 历史经验注入
        n_inj = self._inject_memories(self.current_context)
        if n_inj > 0:
            yield self._event("system", f"📚 已注入 {n_inj} 条历史经验到上下文")

        yield self._event("phase", "Phase 2: 指定功能测试执行中...")
        from core.parallel import run_parallel_test
        async for evt in run_parallel_test(self):
            yield evt

    # ============================================================
    # 辅助方法
    # ============================================================

    async def _llm_suggest_focused_tests(
        self,
        feat_name: str,
        description: str,
        estimated_api: str,
        interaction_type: str,
    ) -> list[str]:
        """用 LLM 分析指定功能应该测试哪些漏洞类型。"""
        from core.llm import Message

        prompt = load_template(
            "focused_test_suggest",
            feat_name=feat_name,
            description=description,
            estimated_api=estimated_api or "未知",
            interaction_type=interaction_type or "未知",
        )

        try:
            messages = [
                Message(role="user", content=prompt),
            ]
            response = await asyncio.to_thread(
                self.llm.chat, messages, None, 0.1, 1024, "focused_suggest"
            )
            text = response.content or ""
            # ★ 使用统一的安全 JSON 解析，避免非贪婪正则在内嵌 [...] 时截断
            from core.llm import parse_llm_json
            result = parse_llm_json(text, expect=list)
            if isinstance(result, list):
                return [str(t).strip() for t in result if t and isinstance(t, str)]
        except Exception as e:
            log.warning("LLM 功能分析失败: %s", e)

        # fallback: 基于功能名关键词推断
        return self._rule_based_suggest(feat_name, description, estimated_api)

    def _rule_based_suggest(
        self, feat_name: str, description: str, estimated_api: str
    ) -> list[str]:
        """基于规则的漏洞类型推断（LLM 失败时的 fallback）。"""
        from core.config import FEATURE_VULN_MAPPING

        combined_text = f"{feat_name} {description} {estimated_api}".lower()
        vulns = set()

        for keywords, vuln_types in FEATURE_VULN_MAPPING:
            for kw in keywords:
                if kw.lower() in combined_text:
                    vulns.update(vuln_types)
                    break

        # 基础保底
        if not vulns:
            vulns = {"未授权访问", "信息泄露"}

        return list(vulns)[:8]

    async def _quick_navigate_for_apis(
        self, target_url: str, features: list[dict]
    ) -> None:
        """快速导航目标页面，通过代理抓取真实 API 样本。

        不做完整爬虫，只是打开页面等待 API 请求被代理捕获。
        超时 15 秒，失败不影响后续测试。
        """
        try:
            from core.mcp_bridge import browser_goto
            await asyncio.wait_for(
                browser_goto(target_url),
                timeout=15.0,
            )
        except (ImportError, asyncio.TimeoutError, Exception) as e:
            log.debug("快速导航跳过: %s", e)

    # ============================================================
    # 截图模式入口
    # ============================================================

    async def _run_screenshot_focused_test(
        self, intent: dict, screenshot_path: str, user_message: str
    ) -> AsyncGenerator[str, None]:
        """截图 + 指令的指定功能测试模式。

        流程：
        1. 用 vision LLM 分析截图
        2. 如果用户有具体指令，筛选功能点
        3. 调用 _run_focused_test_mode 执行测试
        """
        yield self._event("system", "🖼️ 正在分析截图中的功能...")

        try:
            from core.vision import analyze_screenshot, filter_features_by_instruction

            # 1) 分析截图
            analysis = await analyze_screenshot(self.llm, image_path=screenshot_path)

            if not analysis.get("features"):
                yield self._event("error", "❌ 未能从截图中识别出功能点，请确保截图清晰且包含页面交互元素")
                return

            yield self._event("system",
                f"📸 截图分析完成:\n"
                f"  页面类型: {analysis.get('page_type', '未知')}\n"
                f"  识别到 {len(analysis['features'])} 个功能点"
            )

            # 2) 如果用户有具体指令，筛选功能点
            # 从 user_message 中去掉"截图"相关的通用词，提取具体指令
            instruction = _extract_test_instruction(user_message)

            # 只有在有目标 URL 时才进行功能点筛选（否则没有意义）
            if instruction and intent.get("target_url"):
                features = await filter_features_by_instruction(
                    self.llm, analysis, instruction
                )
                # 确保 features 中的元素都是 dict
                features = [f for f in features if isinstance(f, dict)]
                yield self._event("system", f"🎯 根据指令筛选出 {len(features)} 个目标功能")
            else:
                features = [f for f in analysis.get("features", []) if isinstance(f, dict)]

            # 3) 补充 intent 信息
            intent["target_features"] = features
            intent["screenshot_analysis"] = analysis

            # 如果截图中有 URL 且 intent 没有
            if analysis.get("visible_url") and not intent.get("target_url"):
                intent["target_url"] = analysis["visible_url"]
                intent["has_target"] = True

            # 检查是否有目标 URL，没有则提示用户
            if not intent.get("target_url"):
                feature_names = "\n".join(
                    f"  • {f.get('name', '未知')}: {f.get('description', '')[:60]}"
                    for f in features[:10]
                )
                yield self._event("system",
                    f"📋 已识别到以下功能点:\n{feature_names}\n\n"
                    f"⚠️ 但未检测到目标 URL。请在发送截图时同时提供目标网址，例如：\n"
                    f"  「测试 https://example.com 截图中的登录功能」"
                )
                return

            # 4) 调用通用的 focused test 流程
            async for evt in self._run_focused_test_mode(intent, user_message):
                yield evt

        except Exception as e:
            log.error("截图分析失败: %s", e)
            yield self._event("error", f"❌ 截图分析失败: {e}")


# ============================================================
# 辅助函数
# ============================================================

def _extract_test_instruction(user_message: str) -> str:
    """从用户消息中提取测试指令（去掉截图相关的通用词）。

    例如：
    - "只测截图中的登录功能" → "登录功能"
    - "帮我测一下这个页面的支付" → "支付"
    - "测试截图里的所有功能" → ""（空 = 测全部）
    """
    # 去掉通用前缀
    patterns_to_remove = [
        r"只测[试]?截图[中里]?[的]?",
        r"帮我测[试一下]*这[个张]?[页面截图]*[的]?",
        r"测[试]?截图[里中]?[的]?",
        r"测[试]?[一下]*这[个张]?截图[中里]?[的]?",
        r"看[看一下]*这[个张]?截图.*?测[试]?",
        r"截图[中里]?[的]?",
        r"这[个张]?页面[的]?",
    ]

    text = user_message.strip()
    for pat in patterns_to_remove:
        text = re.sub(pat, "", text)

    # 去掉"所有功能"/"全部"等表示测全部的词
    if re.match(r"^(所有|全部|所有功能|全部功能|这些功能|这些)$", text.strip()):
        return ""

    return text.strip()
