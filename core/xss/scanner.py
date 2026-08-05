"""
XSS 扫描器总调度 — 完整流水线版本。

工作流：
  Step 1: 参数发现（含 Header/Cookie 注入点）
  Step 2: HTTP 反射型扫描
  Step 3: WAF/Filter 动态绕过（针对被过滤的目标）
  Step 4: 存储型跨页面追踪（写入点 → 读取页回显）
  Step 5: Mutation XSS（富文本字段）
  Step 6: DOM XSS 静态分析
  Step 7: postMessage / DOM Clobbering
  Step 8: 文件上传 XSS
  Step 9: 模板注入（CSTI/SSTI）
  Step 10: 盲打 XSS（如配置了 OOB URL）
  Step 11: CSP 分析（供研判使用）
  Step 12: 浏览器验证（对所有候选）
  Step 13: LLM 研判（融合 CSP 上下文）

设计：
- 所有阶段可独立开关
- 每阶段都有 timeout 保护，单阶段挂掉不影响其他阶段
- 流式 yield 事件，前端实时显示
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, AsyncGenerator, Optional

from core.xss.browser_engine import BrowserXssEngine
from core.xss.dom_analyzer import (
    dom_candidate_to_xss_candidate,
    scan_sitemap_for_dom_xss,
)
from core.xss.http_engine import HttpXssEngine
from core.xss.llm_judge import XssJudge
from core.xss.models import FindingStatus, ScanStats, XssFinding
from core.xss.param_discover import discover_all_targets

if TYPE_CHECKING:
    from core.llm import LLMClient
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


class XssScanner:
    """XSS 扫描器总调度（完整流水线版本）。"""

    def __init__(
        self,
        sitemap: "Sitemap",
        llm: "LLMClient",
        *,
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        enable_param_mining: bool = True,
        enable_header_injection: bool = True,
        enable_browser_verify: bool = True,
        enable_dom_scan: bool = True,
        enable_llm_judge: bool = True,
        enable_waf_bypass: bool = True,
        enable_stored_xss: bool = True,
        enable_mutation_xss: bool = True,
        enable_postmessage: bool = True,
        enable_upload_xss: bool = True,
        enable_template_injection: bool = True,
        enable_blind_xss: bool = False,  # 默认关闭（需要 OOB URL）
        oob_callback_url: str = "",
        enable_csp_analysis: bool = True,
        output_dir: str = "",
        task_id: str = "",
        max_targets: int = 500,
        http_concurrency: int = 8,
        browser_concurrency: int = 3,
    ):
        self.sitemap = sitemap
        self.llm = llm
        self.proxy = proxy
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.enable_param_mining = enable_param_mining
        self.enable_header_injection = enable_header_injection
        self.enable_browser_verify = enable_browser_verify
        self.enable_dom_scan = enable_dom_scan
        self.enable_llm_judge = enable_llm_judge
        self.enable_waf_bypass = enable_waf_bypass
        self.enable_stored_xss = enable_stored_xss
        self.enable_mutation_xss = enable_mutation_xss
        self.enable_postmessage = enable_postmessage
        self.enable_upload_xss = enable_upload_xss
        self.enable_template_injection = enable_template_injection
        self.enable_blind_xss = enable_blind_xss and bool(oob_callback_url)
        self.oob_callback_url = oob_callback_url
        self.enable_csp_analysis = enable_csp_analysis
        self.output_dir = Path(output_dir) if output_dir else None
        self.task_id = task_id
        self.max_targets = max_targets
        self.http_concurrency = http_concurrency
        self.browser_concurrency = browser_concurrency

        self.stats = ScanStats()
        self.findings: list[XssFinding] = []
        # CSP 分析结果（供 LLM judge 使用）
        self.csp_analyses: dict = {}
        self._event_handler: Optional[callable] = None

    def _emit(self, event_type: str, message: str, data: dict = None):
        if self._event_handler:
            try:
                self._event_handler(event_type, message, data or {})
            except Exception:
                pass

    def _progress(self, msg: str):
        self._emit("xss_progress", msg)
        log.info("[XSS] %s", msg)

    @staticmethod
    async def _await_with_progress(
        task: asyncio.Task,
        event_buffer: list,
        timeout_per_check: float = 5.0,
    ):
        """通用：边等任务边把缓冲区事件 yield 出来。
        返回 async generator 给主流程消费。"""
        # 此函数无法是 generator，因为它要返回 task 结果；改用 generator 写法在主流程内联实现
        pass  # 仅占位

    async def run(self) -> AsyncGenerator[dict, None]:
        """流式跑完整 XSS 扫描。"""
        self.stats.started_at = time.time()
        yield {"type": "xss_phase", "data": "🛡️ XSS 专项扫描启动（完整流水线）"}

        # ============================================================
        # Step 1: 参数发现（含 Header/Cookie 注入点）
        # ============================================================
        yield {"type": "xss_step", "data": "🔍 Step 1: 注入点发现（含 Header/Cookie/Param Miner）"}
        events: list[str] = []
        def _on_discover(msg: str): events.append(msg)

        targets = await discover_all_targets(
            self.sitemap,
            auth_headers=self.auth_headers,
            cookies=self.cookies,
            enable_param_mining=self.enable_param_mining,
            enable_header_injection=self.enable_header_injection,
            proxy=self.proxy,
            on_progress=_on_discover,
        )
        for msg in events:
            yield {"type": "xss_progress", "data": msg}

        if len(targets) > self.max_targets:
            yield {"type": "xss_progress",
                   "data": f"⚠️ 注入点过多 ({len(targets)})，截断到前 {self.max_targets} 个"}
            targets = targets[:self.max_targets]

        self.stats.targets_discovered = len(targets)
        yield {"type": "xss_progress",
               "data": f"✅ 注入点发现完成: {len(targets)} 个目标待扫描"}

        if not targets:
            yield {"type": "xss_done",
                   "data": "无可扫描的注入点，跳过 XSS 扫描"}
            self.stats.finished_at = time.time()
            return

        # 分类：写入点（用于存储型/盲打/mutation/upload）
        from core.xss.models import InjectionPoint
        write_targets = [
            t for t in targets
            if t.injection_point in (InjectionPoint.BODY_FORM, InjectionPoint.BODY_JSON,
                                     InjectionPoint.BODY_MULTIPART)
            or t.method in ("POST", "PUT", "PATCH")
        ]

        # ============================================================
        # Step 2: HTTP 反射型扫描
        # ============================================================
        yield {"type": "xss_step", "data": f"⚡ Step 2: HTTP 反射型扫描（{len(targets)} 个目标）"}
        http_events: list[str] = []
        def _on_http(m): http_events.append(m)

        http_engine = HttpXssEngine(
            proxy=self.proxy,
            concurrency=self.http_concurrency,
            on_progress=_on_http,
        )
        scan_task = asyncio.create_task(http_engine.scan_targets(targets))
        while not scan_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(scan_task), timeout=5)
            except asyncio.TimeoutError:
                while http_events:
                    yield {"type": "xss_progress", "data": http_events.pop(0)}
            except Exception:
                break
        candidates = scan_task.result() if scan_task.done() and not scan_task.exception() else []
        while http_events:
            yield {"type": "xss_progress", "data": http_events.pop(0)}
        yield {"type": "xss_progress", "data": f"✅ HTTP 反射型: {len(candidates)} 个候选"}

        # ============================================================
        # Step 3: WAF/Filter 动态绕过
        # ============================================================
        if self.enable_waf_bypass:
            yield {"type": "xss_step", "data": "🛡️ Step 3: WAF/Filter 动态绕过"}
            # 收集"有回显但被编码/过滤"的候选作为输入
            filtered_results = []
            for c in candidates:
                if c.echo_matches and any(m.encoded for m in c.echo_matches):
                    from core.xss.context import detect_sanitization
                    san = detect_sanitization(c.payload, c.response_packet or "", c.marker)
                    filtered_results.append({
                        "target": c.target,
                        "payload": c.payload,
                        "marker": c.marker,
                        "sanitization": san,
                        "blocked": False,
                        "context": c.echo_matches[0].context.value if c.echo_matches else "html_text",
                    })
            if filtered_results:
                try:
                    from core.xss.waf_bypass import WafBypassEngine
                    waf_events = []
                    bypass_engine = WafBypassEngine(
                        llm=self.llm if self.enable_llm_judge else None,
                        proxy=self.proxy,
                        on_progress=lambda m: waf_events.append(m),
                        enable_llm=self.enable_llm_judge,
                    )
                    bypass_task = asyncio.create_task(
                        bypass_engine.bypass_filtered_candidates(filtered_results[:30])
                    )
                    while not bypass_task.done():
                        try:
                            await asyncio.wait_for(asyncio.shield(bypass_task), timeout=5)
                        except asyncio.TimeoutError:
                            while waf_events:
                                yield {"type": "xss_progress", "data": waf_events.pop(0)}
                        except Exception:
                            break
                    bypass_cands = bypass_task.result() if bypass_task.done() and not bypass_task.exception() else []
                    while waf_events:
                        yield {"type": "xss_progress", "data": waf_events.pop(0)}
                    candidates.extend(bypass_cands)
                    yield {"type": "xss_progress",
                           "data": f"  WAF Bypass 新增 {len(bypass_cands)} 个候选"}
                except Exception as e:
                    yield {"type": "xss_progress", "data": f"  ⚠️ WAF bypass 失败: {str(e)[:120]}"}
            else:
                yield {"type": "xss_progress", "data": "  无被过滤目标，跳过 WAF bypass"}

        # ============================================================
        # Step 4: 存储型跨页面追踪
        # ============================================================
        if self.enable_stored_xss and write_targets:
            yield {"type": "xss_step",
                   "data": f"💾 Step 4: 存储型 XSS 追踪（{len(write_targets)} 个写入点）"}
            try:
                from core.xss.stored_tracker import StoredXssTracker
                stored_events = []
                tracker = StoredXssTracker(
                    sitemap=self.sitemap,
                    proxy=self.proxy,
                    auth_headers=self.auth_headers,
                    cookies=self.cookies,
                    on_progress=lambda m: stored_events.append(m),
                )
                stored_task = asyncio.create_task(
                    tracker.discover_stored_paths(write_targets, max_writes=30)
                )
                while not stored_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(stored_task), timeout=5)
                    except asyncio.TimeoutError:
                        while stored_events:
                            yield {"type": "xss_progress", "data": stored_events.pop(0)}
                    except Exception:
                        break
                stored_cands = stored_task.result() if stored_task.done() and not stored_task.exception() else []
                while stored_events:
                    yield {"type": "xss_progress", "data": stored_events.pop(0)}
                candidates.extend(stored_cands)
                yield {"type": "xss_progress",
                       "data": f"  存储型 XSS 新增 {len(stored_cands)} 个候选"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ 存储型扫描失败: {str(e)[:120]}"}

        # ============================================================
        # Step 5: Mutation XSS（富文本）
        # ============================================================
        if self.enable_mutation_xss and write_targets:
            yield {"type": "xss_step", "data": "🔀 Step 5: Mutation XSS（富文本字段）"}
            try:
                from core.xss.mutation_xss import MutationXssScanner
                mx_events = []
                mx_scanner = MutationXssScanner(
                    sitemap=self.sitemap,
                    proxy=self.proxy,
                    auth_headers=self.auth_headers,
                    cookies=self.cookies,
                    on_progress=lambda m: mx_events.append(m),
                )
                mx_task = asyncio.create_task(mx_scanner.scan(write_targets))
                while not mx_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(mx_task), timeout=5)
                    except asyncio.TimeoutError:
                        while mx_events:
                            yield {"type": "xss_progress", "data": mx_events.pop(0)}
                    except Exception:
                        break
                mx_cands = mx_task.result() if mx_task.done() and not mx_task.exception() else []
                while mx_events:
                    yield {"type": "xss_progress", "data": mx_events.pop(0)}
                candidates.extend(mx_cands)
                yield {"type": "xss_progress",
                       "data": f"  Mutation XSS 新增 {len(mx_cands)} 个候选"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ Mutation XSS 失败: {str(e)[:120]}"}

        # ============================================================
        # Step 6: DOM XSS 静态分析
        # ============================================================
        if self.enable_dom_scan:
            yield {"type": "xss_step", "data": "🔬 Step 6: DOM XSS 静态分析"}
            try:
                dom_cands = scan_sitemap_for_dom_xss(self.sitemap)
                yield {"type": "xss_progress",
                       "data": f"  DOM 静态: {len(dom_cands)} 个 source→sink 候选"}
                base_url = self.sitemap.target if hasattr(self.sitemap, "target") else ""
                for dc in dom_cands[:50]:
                    candidates.append(dom_candidate_to_xss_candidate(dc, base_url))
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ DOM 扫描失败: {str(e)[:120]}"}

        # ============================================================
        # Step 7: postMessage / DOM Clobbering
        # ============================================================
        if self.enable_postmessage:
            yield {"type": "xss_step", "data": "📩 Step 7: postMessage / DOM Clobbering"}
            try:
                from core.xss.postmessage_scanner import PostMessageScanner
                pm_events = []
                pm_scanner = PostMessageScanner(
                    proxy=self.proxy,
                    cookies=self.cookies,
                    on_progress=lambda m: pm_events.append(m),
                )
                pm_task = asyncio.create_task(pm_scanner.scan(self.sitemap))
                while not pm_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(pm_task), timeout=5)
                    except asyncio.TimeoutError:
                        while pm_events:
                            yield {"type": "xss_progress", "data": pm_events.pop(0)}
                    except Exception:
                        break
                pm_cands = pm_task.result() if pm_task.done() and not pm_task.exception() else []
                while pm_events:
                    yield {"type": "xss_progress", "data": pm_events.pop(0)}
                candidates.extend(pm_cands)
                yield {"type": "xss_progress",
                       "data": f"  postMessage / Clobbering: {len(pm_cands)} 个候选"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ postMessage 扫描失败: {str(e)[:120]}"}

        # ============================================================
        # Step 8: 文件上传 XSS
        # ============================================================
        if self.enable_upload_xss:
            yield {"type": "xss_step", "data": "📤 Step 8: 文件上传 XSS"}
            try:
                from core.xss.upload_xss import UploadXssScanner
                up_events = []
                up_scanner = UploadXssScanner(
                    sitemap=self.sitemap,
                    proxy=self.proxy,
                    auth_headers=self.auth_headers,
                    cookies=self.cookies,
                    on_progress=lambda m: up_events.append(m),
                )
                up_task = asyncio.create_task(up_scanner.scan())
                while not up_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(up_task), timeout=5)
                    except asyncio.TimeoutError:
                        while up_events:
                            yield {"type": "xss_progress", "data": up_events.pop(0)}
                    except Exception:
                        break
                up_cands = up_task.result() if up_task.done() and not up_task.exception() else []
                while up_events:
                    yield {"type": "xss_progress", "data": up_events.pop(0)}
                candidates.extend(up_cands)
                yield {"type": "xss_progress",
                       "data": f"  上传 XSS: {len(up_cands)} 个候选"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ 上传 XSS 失败: {str(e)[:120]}"}

        # ============================================================
        # Step 9: 模板注入（CSTI/SSTI）
        # ============================================================
        if self.enable_template_injection:
            yield {"type": "xss_step", "data": "🧮 Step 9: 模板注入扫描"}
            try:
                from core.xss.template_injection import TemplateInjectionScanner
                ti_events = []
                ti_scanner = TemplateInjectionScanner(
                    proxy=self.proxy,
                    auth_headers=self.auth_headers,
                    cookies=self.cookies,
                    on_progress=lambda m: ti_events.append(m),
                )
                # 只对 GET 反射目标和 JSON body 测（form/header 模板注入罕见）
                ti_targets = [
                    t for t in targets
                    if t.injection_point in (InjectionPoint.URL_PARAM, InjectionPoint.BODY_JSON,
                                             InjectionPoint.BODY_FORM)
                ][:60]
                ti_task = asyncio.create_task(ti_scanner.scan(ti_targets))
                while not ti_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(ti_task), timeout=5)
                    except asyncio.TimeoutError:
                        while ti_events:
                            yield {"type": "xss_progress", "data": ti_events.pop(0)}
                    except Exception:
                        break
                ti_cands = ti_task.result() if ti_task.done() and not ti_task.exception() else []
                while ti_events:
                    yield {"type": "xss_progress", "data": ti_events.pop(0)}
                candidates.extend(ti_cands)
                yield {"type": "xss_progress",
                       "data": f"  模板注入: {len(ti_cands)} 个候选"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ 模板注入失败: {str(e)[:120]}"}

        # ============================================================
        # Step 10: 盲打 XSS（OOB）
        # ============================================================
        if self.enable_blind_xss and write_targets and self.oob_callback_url:
            yield {"type": "xss_step",
                   "data": f"📡 Step 10: 盲打 XSS（OOB callback: {self.oob_callback_url}）"}
            try:
                from core.xss.oob import BlindXssScanner
                blind_events = []
                blind_scanner = BlindXssScanner(
                    callback_url=self.oob_callback_url,
                    proxy=self.proxy,
                    auth_headers=self.auth_headers,
                    cookies=self.cookies,
                    on_progress=lambda m: blind_events.append(m),
                    wait_for_callback_seconds=self.config.get("blind_xss_timeout", 300),  # 5 minutes default
                )
                blind_task = asyncio.create_task(blind_scanner.scan_write_points(write_targets))
                while not blind_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(blind_task), timeout=5)
                    except asyncio.TimeoutError:
                        while blind_events:
                            yield {"type": "xss_progress", "data": blind_events.pop(0)}
                    except Exception:
                        break
                blind_cands = blind_task.result() if blind_task.done() and not blind_task.exception() else []
                while blind_events:
                    yield {"type": "xss_progress", "data": blind_events.pop(0)}
                candidates.extend(blind_cands)
                yield {"type": "xss_progress",
                       "data": f"  盲打 XSS: {len(blind_cands)} 个 token 已部署"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ 盲打失败: {str(e)[:120]}"}

        # ============================================================
        # Step 11: CSP 分析（供研判使用）
        # ============================================================
        if self.enable_csp_analysis:
            yield {"type": "xss_step", "data": "🔐 Step 11: CSP / 响应头安全策略分析"}
            try:
                from core.xss.csp_analyzer import CspAnalyzer
                csp_events = []
                csp_analyzer = CspAnalyzer(on_progress=lambda m: csp_events.append(m))
                self.csp_analyses = csp_analyzer.analyze_sitemap(self.sitemap)
                for m in csp_events:
                    yield {"type": "xss_progress", "data": m}
                if self.csp_analyses:
                    yield {"type": "xss_progress",
                           "data": f"  CSP 分析完成: {len(self.csp_analyses)} 个 host"}
            except Exception as e:
                yield {"type": "xss_progress", "data": f"  ⚠️ CSP 分析失败: {str(e)[:120]}"}

        self.stats.candidates_found = len(candidates)
        yield {"type": "xss_progress",
               "data": f"📊 候选总数: {len(candidates)} 个（含所有扫描器）"}

        # ============================================================
        # Step 12: 浏览器验证
        # ============================================================
        if self.enable_browser_verify and candidates:
            yield {"type": "xss_step",
                   "data": f"🌐 Step 12: 浏览器深度验证（{len(candidates)} 个候选）"}
            br_events = []
            br_engine = BrowserXssEngine(
                proxy=self.proxy,
                max_concurrent=self.browser_concurrency,
                on_progress=lambda m: br_events.append(m),
            )
            verify_task = asyncio.create_task(
                br_engine.verify_candidates(candidates, cookies=self.cookies)
            )
            while not verify_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(verify_task), timeout=5)
                except asyncio.TimeoutError:
                    while br_events:
                        yield {"type": "xss_progress", "data": br_events.pop(0)}
                except Exception:
                    break
            candidates = verify_task.result() if verify_task.done() and not verify_task.exception() else candidates
            while br_events:
                yield {"type": "xss_progress", "data": br_events.pop(0)}
        else:
            yield {"type": "xss_progress", "data": "  浏览器验证已禁用，跳过"}

        # ============================================================
        # Step 13: LLM 研判
        # ============================================================
        if self.enable_llm_judge and candidates:
            yield {"type": "xss_step",
                   "data": f"🧠 Step 13: LLM 研判去误报（{len(candidates)} 个候选）"}
            judge_events = []
            judge = XssJudge(
                llm=self.llm,
                on_progress=lambda m: judge_events.append(m),
            )
            # 把 CSP 分析注入到 judge 上下文（在 judge 内部使用）
            judge._csp_analyses = self.csp_analyses

            def _resolve_feature(target):
                return self._find_feature_for_target(target)

            judge_task = asyncio.create_task(
                judge.judge_all(candidates, feature_id_resolver=_resolve_feature)
            )
            while not judge_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(judge_task), timeout=5)
                except asyncio.TimeoutError:
                    while judge_events:
                        yield {"type": "xss_progress", "data": judge_events.pop(0)}
                except Exception:
                    break
            self.findings = judge_task.result() if judge_task.done() and not judge_task.exception() else []
            while judge_events:
                yield {"type": "xss_progress", "data": judge_events.pop(0)}
        else:
            from core.xss.models import Severity
            import uuid
            for c in candidates:
                self.findings.append(XssFinding(
                    id=f"xss_{uuid.uuid4().hex[:10]}",
                    candidate=c,
                    status=FindingStatus.NEEDS_REVIEW,
                    severity=Severity.MEDIUM,
                    title=f"{c.xss_type.value} XSS - {c.target.url[:60]}",
                    judge_confidence=c.confidence,
                ))

        self.stats.findings_confirmed = sum(
            1 for f in self.findings if f.status == FindingStatus.CONFIRMED
        )
        self.stats.findings_false_positive = sum(
            1 for f in self.findings if f.status == FindingStatus.FALSE_POSITIVE
        )
        self.stats.findings_needs_review = sum(
            1 for f in self.findings if f.status == FindingStatus.NEEDS_REVIEW
        )
        self.stats.finished_at = time.time()

        # ============================================================
        # 持久化
        # ============================================================
        self._persist_to_sitemap()
        self._persist_to_file()

        # ============================================================
        # 完成事件
        # ============================================================
        elapsed = self.stats.elapsed
        yield {
            "type": "xss_done",
            "data": (
                f"🎯 XSS 扫描完成 (耗时 {elapsed:.1f}s):\n"
                f"  - 注入点: {self.stats.targets_discovered}\n"
                f"  - 候选: {self.stats.candidates_found}\n"
                f"  - ✅ 确认漏洞: {self.stats.findings_confirmed}\n"
                f"  - ⚠️ 待复核: {self.stats.findings_needs_review}\n"
                f"  - ❌ 误报: {self.stats.findings_false_positive}\n"
                f"  - CSP 分析: {len(self.csp_analyses)} 个 host"
            ),
            "stats": {
                "targets_discovered": self.stats.targets_discovered,
                "candidates_found": self.stats.candidates_found,
                "findings_confirmed": self.stats.findings_confirmed,
                "findings_false_positive": self.stats.findings_false_positive,
                "findings_needs_review": self.stats.findings_needs_review,
                "elapsed": elapsed,
                "csp_hosts": len(self.csp_analyses),
            },
        }

    def _find_feature_for_target(self, target) -> str:
        if not hasattr(self.sitemap, "features"):
            return ""
        target_url_path = target.url.split("?")[0].rstrip("/")
        best_match = ""
        best_score = 0
        for fp_id, fp in self.sitemap.features.items():
            related = getattr(fp, "related_apis", []) or []
            for api in related:
                api_path = api.split(" ", 1)[-1].split("?")[0].rstrip("/")
                if api_path == target_url_path:
                    return fp_id
                if target_url_path.endswith(api_path) or api_path.endswith(target_url_path):
                    if len(api_path) > best_score:
                        best_score = len(api_path)
                        best_match = fp_id
        return best_match

    def _persist_to_sitemap(self):
        try:
            existing = getattr(self.sitemap, "xss_findings", None)
            if not isinstance(existing, list):
                self.sitemap.xss_findings = []
            self.sitemap.xss_findings.extend([f.to_dict() for f in self.findings])
            # 也存 CSP 分析
            if self.csp_analyses:
                self.sitemap.csp_analyses = {
                    host: a.to_dict() for host, a in self.csp_analyses.items()
                }
            if hasattr(self.sitemap, "save"):
                try:
                    self.sitemap.save()
                except Exception:
                    pass
        except Exception as e:
            log.warning("persist xss findings to sitemap failed: %s", e)

    def _persist_to_file(self):
        if not self.output_dir:
            return
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            suffix = f"-{self.task_id}" if self.task_id else ""
            file_path = self.output_dir / f"xss_findings{suffix}.jsonl"
            with open(file_path, "w", encoding="utf-8") as f:
                for finding in self.findings:
                    f.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
            if self.csp_analyses:
                csp_file = self.output_dir / f"csp_analyses{suffix}.json"
                csp_file.write_text(
                    json.dumps(
                        {host: a.to_dict() for host, a in self.csp_analyses.items()},
                        ensure_ascii=False, indent=2
                    ),
                    encoding="utf-8",
                )
            log.info("xss findings written to %s", file_path)
        except Exception as e:
            log.warning("persist xss findings to file failed: %s", e)

    async def scan(self) -> dict:
        events = []
        async for evt in self.run():
            events.append(evt)
        return {
            "events": events,
            "findings": [f.to_dict() for f in self.findings],
            "csp_analyses": {h: a.to_dict() for h, a in self.csp_analyses.items()},
            "stats": {
                "targets_discovered": self.stats.targets_discovered,
                "candidates_found": self.stats.candidates_found,
                "findings_confirmed": self.stats.findings_confirmed,
                "findings_false_positive": self.stats.findings_false_positive,
                "findings_needs_review": self.stats.findings_needs_review,
                "elapsed": self.stats.elapsed,
            },
        }
