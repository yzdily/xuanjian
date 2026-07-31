"""
AutoCrawler — 主类（编排层）。

本文件是爬虫的"调度中枢"，包含：
- AutoCrawler 主类（继承 LoginMixin / ScopeMixin / UrlFilterMixin）
- crawl() 入口 + _crawl_round() 单角色 BFS 编排
- _crawl_page() / _crawl_page_inner() 单页爬取（菜单循环 + 按钮 + 表单）
- _build_final_result() 多角色对比 + 指纹推测验证

下沉到独立模块的能力（不在本文件内）：
- 数据类               → core/crawler/models.py
- 噪音探测 / 自适应超时 → core/crawler/timeouts.py
- 域名作用域判定        → core/crawler/scope_mixin.py
- URL 队列治理          → core/crawler/url_filter_mixin.py
- 登录 / 代理检查        → core/crawler/login_mixin.py
- 菜单优先级排序        → core/crawler/menu_ranker.py
- 表单填写与提交        → core/crawler/form_mixin.py
- 结果构建与对比验证    → core/crawler/result_builder_mixin.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import os
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger("auto_crawler")

# 数据模型
from .models import (
    CrawledElement, CrawledForm, CrawledPage, CrawlRoundResult,
    FORM_FILL_RULES,
)
# 超时与噪音感知
from .timeouts import (
    _NOISE_DETECT_ENABLED, NOISE_WINDOW_S, NOISE_PATH_THRESHOLD,
    NOISE_PAGE_SOFT_TIMEOUT_S, NOISE_PAGE_HARD_TIMEOUT_S, NOISE_MAX_PAGE_DURATION_S,
    PAGE_PROGRESS_SILENCE_S, PAGE_MENU_LOOP_HARD_S,
    _NoiseDetector, _smart_wait_for_idle,
    _run_crawl_page_with_adaptive_timeout,
)
# 菜单优先级排序（A/B 双模式 + 200+ 关键词）
from .menu_ranker import detect_menu_mode, rank_menus, score_menu, get_top_n_summary
# Mixin
from .scope_mixin import ScopeMixin
from .url_filter_mixin import UrlFilterMixin
from .login_mixin import LoginMixin
from .form_mixin import FormMixin
from .result_builder_mixin import ResultBuilderMixin
from core.realtime_protocols import classify_realtime_flow, dedupe_realtime_channels, websocket_event


# 菜单 API 关键词（模块级常量，供 _crawl_round 和 _build_final_result 共用）
# ★ 2026-05-28 扩充：覆盖更多后台系统的菜单 API 路径
MENU_API_KEYWORDS = (
    # 原有
    "menu/tree", "menu/user-menu", "menu/list", "menu/nav",
    "menu/routes", "permission/menu", "sys/menu", "system/menu",
    "user/menu", "/menus", "/menu-tree", "/router",
    # 新增：通用路径
    "/api/routes", "/api/routers", "/getRouters", "/getrouters",
    "/api/nav", "/api/navigation", "/api/sidebar",
    "/v1/menu", "/v2/menu", "/v3/menu",
    "/admin/menu", "/admin/menus",
    "/api/menu", "/api/menus",
    "/user/nav", "/user/routes", "/user/permissions",
    "/api/getUserPermission", "/api/getPermission",
    "/api/getMenuList", "/api/getMenuTree",
    # 新增：前端路由配置
    "/api/frontend/routes", "/api/app/menu",
    "/api/auth/menu", "/api/auth/routes",
    "/api/role/menu", "/api/role/routes",
    # 新增：常见后台框架
    "/antdpro/menu", "/umi/routes",
)


class AutoCrawler(LoginMixin, ScopeMixin, UrlFilterMixin, FormMixin, ResultBuilderMixin):
    """系统性页面爬取器 — 三遍爬取法。"""

    def __init__(
        self,
        target: str,
        credentials: list[dict] | None = None,
        max_pages_per_round: int = 120,
        on_progress: Callable | None = None,
        extra_scope: list[str] | set[str] | None = None,
        skip_anonymous_round: bool = False,
        llm_chat_fn=None,
        fast_mode: bool = False,
        api_only_mode: bool = False,
    ):
        """
        Args:
            target: 目标 URL
            credentials: 账号列表，如 [{"role": "user", "username": "test", "password": "123"}]
            max_pages_per_round: 每轮最多爬取页面数
            on_progress: 进度回调 fn(message: str)
            extra_scope: ★ 预注入的关联域名白名单（来自 intent 解析，如 packet host 与 target host 不同时）
                         登录后 infer_extra_scope() 仍会继续追加新发现的关联域
            llm_chat_fn: ★ 可选的 LLM 回调（async callable），传入后 JS 分析会对关键业务 JS
                         进行 LLM 增强分析，提取正则遗漏的 API 端点
            fast_mode: ★ 快速爬虫模式：减少 max_pages 到 50，不点击所有菜单，优先 sitemap + API
            api_only_mode: ★ API-only 模式：不操作浏览器，直接从 JS/流量中提取 API
        """
        self.target = target
        self.target_domain = urlparse(target).netloc
        self.credentials = credentials or []
        self.fast_mode = fast_mode
        self.api_only_mode = api_only_mode
        # 快速模式强制降低页面上限
        if fast_mode or api_only_mode:
            max_pages_per_round = min(max_pages_per_round, 50)
        self.max_pages = max_pages_per_round
        self.on_progress = on_progress
        self.skip_anonymous_round = skip_anonymous_round
        self._llm_chat_fn = llm_chat_fn

        # ★ SPA 检测：目标 URL 含 # 且 # 后有路径 → 视为 SPA hash 路由
        self._is_spa = "#/" in target or "#!" in target

        self.rounds: list[CrawlRoundResult] = []

        # ★ 2026-05-28: 菜单树 JSON 完整响应缓存（跨轮次累积）
        self._menu_tree_responses: list[dict] = []

        # ★ 2026-05-22 v2: 当前正在爬取页面的噪音探测器引用（供自适应超时使用）
        self._current_page_noise_detector = None

        # ★ 关联域名白名单（双来源：intent 预注入 + 登录后 infer_extra_scope 自动推断）
        # 用 set 自然去重；过滤掉与 target_domain 相同的（避免冗余）
        self.extra_scope: set[str] = {
            d.lower().lstrip(".") for d in (extra_scope or [])
            if d and d.lower().lstrip(".") != self.target_domain.lower()
        }

        # 已知第三方 SDK / 基础设施域黑名单（绝不爬取）
        self._THIRD_PARTY_BLACKLIST = {
            # ================================================================
            # Google 系
            # ================================================================
            "google.com", "googleapis.com", "googletagmanager.com", "google-analytics.com",
            "recaptcha.net", "gstatic.com", "doubleclick.net",
            "android.clients.google.com", "content-autofill.googleapis.com",
            "googleadservices.com", "googlesyndication.com",
            "firebase.google.com", "firebase.io", "firebaseapp.com",
            # ================================================================
            # 社交/登录 CDN
            # ================================================================
            "facebook.com", "fbcdn.net",
            "twitter.com", "twimg.com",                    # Twitter 图片 CDN
            "linkedin.com", "licdn.com",                   # LinkedIn CDN
            "instagram.com",
            # ================================================================
            # 国际分析/埋点/热力图
            # ================================================================
            "mixpanel.com", "amplitude.com",
            "segment.com", "segment.io", "segment.build",
            "heap.io",                                     # Heap 分析
            "pendo.io",                                    # Pendo 产品分析
            "posthog.com",                                 # PostHog 开源分析
            "plausible.io",                                # Plausible 隐私分析
            "matomo.org", "matomo.cloud", "piwik.pro",     # Matomo/Piwik 分析
            "hotjar.com",
            "fullstory.com",
            "clarity.ms",                                  # Microsoft Clarity 热力图
            "inspectlet.com",                              # Inspectlet 会话录制
            "crazyegg.com",                                # Crazy Egg 热力图
            "luckyorange.com",                             # Lucky Orange 热力图
            "mouseflow.com",                               # Mouseflow 会话录制
            "quantummetric.com",                           # Quantum Metric 体验分析
            "contentsquare.com",                           # Contentsquare 体验分析
            "optimizely.com",                              # Optimizely A/B 测试
            "vwo.com",                                     # VWO A/B 测试
            "abtasty.com",                                 # ABTasty A/B 测试
            # ================================================================
            # 国际监控/APM
            # ================================================================
            "sentry.io", "datadoghq.com", "newrelic.com",
            "bugsnag.com", "raygun.io", "logrocket.com",
            "rollbar.com",                                 # Rollbar 错误监控
            "honeybadger.io",                              # Honeybadger 错误监控
            "elastic.co", "elastic.io",                    # Elastic APM
            "grafana.net",                                 # Grafana Cloud
            "vercel-insights.com",                         # Vercel Analytics
            "speedcurve.com",                              # SpeedCurve 性能监控
            "pingdom.net", "pingdom.com",                  # Pingdom 监控
            "uptimerobot.com",                             # UptimeRobot 监控
            "statuspage.io",                               # StatusPage 状态页
            # ================================================================
            # 国际归因/广告/推送
            # ================================================================
            "appsflyer.com",
            "adjust.com",                                  # Adjust 归因
            "branch.io",                                   # Branch 深度链接/归因
            "kochava.com",                                 # Kochava 归因
            "singular.net",                                # Singular 归因
            "tenjin.com",                                  # Tenjin 归因
            "onesignal.com",                               # OneSignal 推送
            "pushwoosh.com",                               # Pushwoosh 推送
            "braze.com", "appboy.com",                     # Braze 推送/营销 (旧名 Appboy)
            "iterable.com",                                # Iterable 推送/营销
            "clevertap.com",                               # CleverTap 推送/分析
            "leanplum.com",                                # Leanplum 推送/营销
            # ================================================================
            # 国际 CDN / 静态资源
            # ================================================================
            "cloudflare.com", "cloudflare-dns.com",
            "fastly.net", "fastlylb.net",
            "akamai.net", "akamaized.net",
            "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
            "jquery.com", "bootstrapcdn.com",
            "amazonaws.com", "azureedge.net", "cloudfront.net",
            "stackpathcdn.com",                            # StackPath CDN
            "edgecastcdn.net",                             # Edgecast CDN (Verizon)
            "bunny.net", "b-cdn.net",                      # Bunny CDN
            "cdn77.org",                                   # CDN77
            "keycdn.com",                                   # KeyCDN
            "sucuri.net",                                   # Sucuri WAF/CDN
            "incapdns.net", "impervadns.net",              # Imperva/Incapsula WAF
            "cdnetworks.com", "cdngc.net",                 # CDNetworks
            # ================================================================
            # 用户引导/帮助/产品引导
            # ================================================================
            "intercom.io", "intercomcdn.com",
            "userpilot.io", "userpilot.com",
            "beamercontent.com", "beamer.io", "getbeamer.com",
            "appcues.com", "appcues.net",
            "pendo.io",                                    # Pendo 引导 (也做分析)
            "walkme.com",                                  # WalkMe 引导
            "whatfix.com",                                 # WhatFix 引导
            # ================================================================
            # 支付
            # ================================================================
            "stripe.com", "paypal.com",
            # ================================================================
            # 监控 (Freshworks 等)
            # ================================================================
            "freshmarketer.com", "freshping.io", "haystack.es",
            # ================================================================
            # 字节跳动系 (纯 SDK/埋点/CDN，非客户业务)
            # ================================================================
            "snssdk.com",          # 抖音 SDK 日志/监控/接口
            "zijieapi.com",        # 字节内部服务网关（广告/AB/SDK/埋点 mcs/mon）
            "pstatp.com",          # 图片/视频 CDN
            "byteimg.com", "ibyteimg.com",  # 图片 CDN
            "bytecdn.cn", "bytefcdn.com", "bytefcdn-oversea.com",  # CDN
            "volceapplog.com",     # 火山引擎埋点上报 (mcs.volceapplog.com)
            "ixiguavideo.com",     # 西瓜视频 CDN
            "amemv.com",           # 抖音旧域名 SDK
            "bytegoofy.com",       # 字节 A/B 测试
            "ibytedtos.com",       # 字节 CDN/分发
            "i18n-pglstatp.com",   # 海外埋点/统计
            # ================================================================
            # 国内分析/埋点/热力图
            # ================================================================
            "growingio.com",       # GrowingIO 埋点 (api.growingio.com / assets.growingio.com)
            "sensorsdata.cn",      # 神策数据 SDK 上报
            "zhugeio.com",         # 诸葛io 埋点
            "talkingdata.com",     # TalkingData 统计
            "umeng.com",           # 友盟统计
            "cnzz.com",            # CNZZ 统计
            "hm.baidu.com",        # 百度统计埋点 JS
            "51.la",               # 51la 统计
            "ptengine.cn", "ptengine.com",  # Ptengine 热力图
            "appadhoc.com",        # AppAdhoc A/B 测试
            # ================================================================
            # 国内推送 SDK
            # ================================================================
            "jpush.cn",            # 极光推送
            "getui.net",           # 个推
            "xg.qq.com",           # 信鸽推送
            # ================================================================
            # 国内 CDN / 静态资源
            # ================================================================
            "gtimg.cn",            # 腾讯图片 CDN
            "idqqimg.com",         # QQ 图片 CDN
            "qpic.cn",             # QQ 图片 CDN
            "tencdns.net",         # 腾讯 DNS
            "dnsv1.com",           # 腾讯 CDN DNS
            "alicdn.com",          # 阿里 CDN
            "alikunlun.com",       # 阿里 CDN (旧)
            "taobaocdn.com",       # 淘宝 CDN (旧)
            "mmcdn.cn",            # 阿里多媒体 CDN
            "bdimg.com",           # 百度图片 CDN
            "bdstatic.com",        # 百度静态资源
            "bcebos.com",          # 百度云 CDN
            "qbox.me", "qiniudn.com", "qiniucdn.com",  # 七牛 CDN
            "aicdn.com", "jiashule.com",  # 又拍云 CDN
            "wscdns.com", "wscngs.com",   # 网宿 CDN
            "lxdns.com",                   # 蓝讯 CDN (旧)
            "chinanetcenter.com",          # 网宿
            "kspkg.com",           # 快手 CDN
            "hdslb.com",           # B站 CDN
            "bilivideo.com",       # B站视频 CDN
            # ================================================================
            # 京东系 (监控 SDK)
            # ================================================================
            "sgm-m.jd.com",
            # ================================================================
            # 其他常见 SDK/监控
            # ================================================================
            "algolia.net", "algolianet.com",  # Algolia 搜索 SDK
            "launchdarkly.com",               # LaunchDarkly Feature Flag
            "io1.app",                        # io.1 分析
            "go-mpulse.net",                  # Akamai mPulse 性能监控
            "rum.haystack.es",                # Haystack RUM
        }

        # ★ 协作式停止 flag
        self._stop_requested: bool = False
        self._user_aborted: bool = False  # 区分"用户主动中止"和"静默超时"
        # 进度计数器（供外部判断"静默期"使用）
        self._progress_tick: int = 0  # 每点完一个菜单 / 抓到一个 API +1
        # ★ ID 子页去重：记录各路径模式的入队次数，防列表详情子页耗光配额
        self._id_page_pattern_count: dict[str, int] = {}

        # ★ 2026-05-22 v3 修复"全站导航菜单循环点击"
        # 任务级菜单点击指纹：同一个菜单项（text + href）在整个任务内只点一次。
        # 注意：作用域=单次 AutoCrawler 实例（即单角色单轮 BFS），不跨任务。
        # 指纹规则：
        #   1. 优先用 (text, href_path) — href 标准化为路径+查询，去掉 host/scheme
        #   2. 无 href（按钮型菜单）：用 (text, page_path) — 保留页面上下文，避免误杀
        # 命中后直接 skip，不计入 clicked_count，避免噪音阈值被假命中拖累
        self._global_clicked_menu_fingerprints: set[tuple[str, str]] = set()
        # 统计：跳过了多少次重复菜单（用于日志/调试）
        self._global_menu_dedup_skipped: int = 0

        # ★ 2026-05-22 v4: 当前正在爬取的角色（由 _crawl_round 设置，供菜单模式判定用）
        self._current_role: str = "anonymous"
        self._current_account: str = ""
        self._current_credential_id: str = ""

    # ---- 外部协作接口 ----

    def request_stop(self, user_aborted: bool = False) -> None:
        """协作式请求停止。爬虫会在下一个安全点退出，已抓数据不丢。
        
        Args:
            user_aborted: True 表示用户主动中止（不可恢复），False 表示静默超时
                         （可恢复，Step 2 会重置停止信号继续爬取）
        """
        self._stop_requested = True
        if user_aborted:
            self._user_aborted = True

    @property
    def stop_requested(self) -> bool:
        return self._stop_requested

    @property
    def progress_tick(self) -> int:
        """单调递增的进度计数。外部用它判断'是否还在产新东西'。"""
        return self._progress_tick

    def get_partial_result(self) -> dict[str, Any]:
        """随时获取当前已抓的快照（不等爬虫跑完）。

        与 _build_final_result 不同的是：
        - 不做角色对比（如果还没跑到 Step 3）
        - 不做指纹推测验证（耗时，跳过）
        - 不做 JS 深度分析合并（如果跑了的话会包含，没跑就为空）
        - 但所有已抓的 API/页面/按钮/表单/CrawledElement 全部包含

        被取消/超时/用户中断时，session.py 用这个代替原来的 None。
        """
        all_apis: dict = {}
        all_pages: dict = {}
        all_forms: list = []
        all_js_endpoints: set = set()
        all_realtime_channels: list[dict] = []

        for r in self.rounds:
            for key, api in r.api_endpoints.items():
                if key not in all_apis:
                    api_item = {**api, "discovered_by": r.role}
                    trigger_ctx = dict(api_item.get("trigger_context", {}) or {})
                    trigger_ctx.setdefault("role", r.role)
                    api_item["trigger_context"] = trigger_ctx
                    all_apis[key] = api_item
            for url, page in r.pages.items():
                if url not in all_pages:
                    all_pages[url] = {
                        "title": page.title,
                        "forms_count": len(page.forms),
                        "clickable_elements": len(page.elements),
                        "links_count": len(page.links),
                        "discovered_by": r.role,
                    }
                for f in page.forms:
                    all_forms.append({
                        "page": url, "action": f.action, "method": f.method,
                        "fields": [i.get("name") for i in f.inputs if i.get("name")],
                        "submitted": f.submitted,
                        "requests_triggered": len(f.submit_requests),
                    })
            for channel in r.realtime_channels:
                if isinstance(channel, dict):
                    item = dict(channel)
                    item.setdefault("role", r.role)
                    all_realtime_channels.append(item)
            all_js_endpoints.update(r.js_endpoints)

        # menu_coverage 简化版（只统计点过的）
        menu_coverage = []
        for r in self.rounds:
            for page_url, page in r.pages.items():
                for elem in page.elements:
                    triggered_api_count = len([
                        req for req in elem.triggered_requests
                        if req.get("resource_type") in ("xhr", "fetch")
                        or "/api/" in req.get("url", "")
                    ])
                    menu_coverage.append({
                        "page": page_url[:80],
                        "text": elem.text[:30],
                        "apis_triggered": triggered_api_count,
                        "total_requests": len(elem.triggered_requests),
                    })
        with_api = sum(1 for m in menu_coverage if m["apis_triggered"] > 0)
        without_api = sum(1 for m in menu_coverage if m["apis_triggered"] == 0)

        return {
            "target": self.target,
            "crawl_rounds": len(self.rounds),
            "roles_crawled": [r.role for r in self.rounds],
            "login_status": {r.role: r.login_success for r in self.rounds if r.role != "anonymous"},
            "pages_total": len(all_pages),
            "apis_total": len(all_apis),
            "apis_inferred_verified": 0,
            "forms_total": len(all_forms),
            "forms_submitted": sum(1 for f in all_forms if f["submitted"]),
            "js_endpoints_found": len(all_js_endpoints),
            "total_clickable_elements": sum(len(p.elements) for r in self.rounds for p in r.pages.values()),
            "menu_clicked": len(menu_coverage),
            "menu_with_api": with_api,
            "menu_without_api": without_api,
            "menu_coverage": menu_coverage,
            "pages": all_pages,
            "api_endpoints": [
                {"method": a["method"], "url": a["url"], "has_body": bool(a.get("post_data")),
                 "post_data": a.get("post_data", ""),
                 "headers": a.get("headers", {}),
                 "discovered_by": a.get("discovered_by", ""),
                 "status_code": a.get("status_code", 0) or a.get("verify_status", 0),
                 "response_body": a.get("response_body", ""),
                 "response_headers": a.get("response_headers", {}),
                 "content_type": a.get("content_type", ""),
                 "flow_id": a.get("flow_id", ""),
                 "trigger_context": a.get("trigger_context", {}),
                 "js_context": a.get("js_context", "")}
                for a in all_apis.values()
            ],
            "realtime_channels": dedupe_realtime_channels(all_realtime_channels),
            "realtime_channels_total": len(dedupe_realtime_channels(all_realtime_channels)),
            "forms": all_forms,
            "js_endpoints": list(all_js_endpoints),
            "role_comparison": {"compared": False, "reason": "partial result"},
            "extra_scope": list(self.extra_scope),  # ★ 补全 partial result，供 fallback 菜单树纳入关联域
            "api_doc_hits": getattr(self, "_api_doc_hits", []),  # ★ 补全 partial result
            "menu_tree_responses": self._menu_tree_responses,  # ★ 补全 partial result
            "menu_contexts": self._build_menu_contexts_for_result(
                self._menu_tree_responses,
                {r.role: r.login_success for r in self.rounds if r.role != "anonymous"},
            ),
            # 复用 _build_final_result 的 crawled_elements 同样字段
            "crawled_elements": [
                {
                    "page_url": el.page_url,
                    "tag": el.tag,
                    "text": el.text,
                    "selector": el.selector,
                    "is_menu": ("data-menu-idx" in (el.selector or "")),
                    "triggered_apis": len([
                        req for req in (el.triggered_requests or [])
                        if req.get("resource_type") in ("xhr", "fetch")
                        or "/api/" in req.get("url", "")
                    ]),
                }
                for r in self.rounds
                for page in r.pages.values()
                for el in page.elements
                if el.text and el.text.strip()
            ],
            "_partial": True,  # 标记，方便下游识别
        }

    def _normalize_url(self, url: str) -> str:
        """URL 去重归一化：SPA 保留 hash 路径，非 SPA 截掉 hash。"""
        url_no_query = url.split("?")[0]
        if self._is_spa:
            # SPA: 保留 hash 路径，但去掉 hash 中的查询参数
            # http://x.com/#/admin/user?page=1 → http://x.com/#/admin/user
            if "#" in url_no_query:
                base, fragment = url_no_query.split("#", 1)
                fragment_path = fragment.split("?")[0]
                return f"{base}#{fragment_path}"
            return url_no_query
        else:
            return url_no_query.split("#")[0]

    def _report(self, msg: str):
        if self.on_progress:
            self.on_progress(msg)

    def _get_clickable_sels(self) -> str:
        """返回全量可点击元素的 CSS 选择器字符串（供重新标记 DOM 使用）。"""
        return (
            'button, input[type=submit], input[type=button], [role=button], [onclick], '
            '[role=tab], .nav-link, .menu-item, [data-toggle], [aria-haspopup], '
            '[role=menuitem], .el-menu-item, .ant-menu-item, .sidebar-item, '
            '.nav-item a, .el-submenu__title, .ant-menu-submenu-title, '
            '.MuiListItem-root, .MuiMenuItem-root, .MuiButton-root, '
            '.v-list-item, .v-btn, .n-menu-item, .arco-menu-item, '
            '.t-menu__item, .ivu-menu-item, '
            '[class*="menu-item"], [class*="nav-item"], [data-menu-item]'
        )

    def _get_nav_ctx(self) -> str:
        """返回导航菜单容器的 CSS 选择器字符串（供重新标记 DOM 使用）。"""
        return (
            'nav, [role=navigation], .sidebar, .el-menu, .ant-menu, .nav-menu, '
            '.ant-layout-sider, .el-aside, '
            '[class*="sidebar"], [class*="nav-"], [class*="-nav"], [id*="sidebar"], [id*="nav-menu"], '
            '[class*="NavigationMenu"], [class*="SideNav"], [class*="AppNav"], '
            '.MuiDrawer-root, .MuiList-root, [class*="MuiNav"], [class*="MuiDrawer"], '
            '.v-navigation-drawer, .v-list, .n-menu, .n-layout-sider, .arco-menu, .arco-layout-sider, '
            '.t-menu, .t-aside, .ivu-menu, .ivu-layout-sider, .navbar-nav, .nav-sidebar, '
            '[class*="Sidebar"], [class*="sidebar-nav"], [class*="side-nav"], '
            '[data-sidebar], [data-nav], [aria-label*="navigation" i], [aria-label*="sidebar" i], '
            '[aria-label*="menu" i], [data-testid*="nav" i], [data-testid*="sidebar" i], [data-testid*="menu" i]'
        )

    def _emit_event(self, event_type: str, payload: dict):
        """向上层推送结构化事件（如人工介入请求）。

        通过特殊前缀 ``__EVENT__:`` 复用现有字符串 progress 通道，
        Session 层会识别并转换为对应 SSE 事件。
        """
        if not self.on_progress:
            return
        try:
            import json as _json
            envelope = {"type": event_type, **payload}
            self.on_progress(f"__EVENT__:{_json.dumps(envelope, ensure_ascii=False)}")
        except Exception as _e:
            log.debug("emit_event 推送事件失败: %s", _e)

    async def crawl(self) -> dict[str, Any]:
        """执行完整的三遍爬取。"""
        self._api_doc_hits = []  # ★ 重置，避免跨任务串扰
        try:
            # ★ API-only 模式：不操作浏览器，直接提取 JS API 和静态资源
            if self.api_only_mode:
                self._report("API-only 模式: 直接从 JS/静态资源提取 API，不操作浏览器")
                return await self._api_only_extract()

            # Round 1: 未登录爬取（skip_anonymous_round=True 时跳过，直接进登录爬取）
            # 快速模式且有凭证时，跳过匿名轮以节省时间
            if not self.skip_anonymous_round and not (self.fast_mode and self.credentials):
                self._report("Step 1/3: 未登录爬取")
                anon_result = await self._crawl_round(role="anonymous", login_info=None)
                # ★ v4.1: _crawl_round 内部已经把 result 加进 self.rounds 了（防止中途丢数据）
                # 这里只在还没加过时补一次（兼容旧路径 / 极端边界）
                if not any(id(r) == id(anon_result) for r in self.rounds):
                    self.rounds.append(anon_result)

                # ★ 每轮结束检查停止信号：
                # - 用户主动中止（_user_aborted）→ 立即退出，不跑 Step 2
                # - 静默超时（silent_timeout）→ 如果还有登录凭证要跑，重置 stop 标志，
                #   给 Step 2 一个机会（匿名访问没东西 ≠ 登录后也没东西）
                if self._stop_requested and not self._user_aborted and self.credentials:
                    self._report("⏸ Step 1 静默超时，但有登录凭证待爬取 — 重置停止信号，继续 Step 2")
                    self._stop_requested = False
                    self._progress_tick += 1  # 重置外部静默计时器
                elif self._stop_requested:
                    self._report("⏸ 收到停止信号，跳过后续登录爬取")
                    return await self._build_final_result({"compared": False, "reason": "stopped"})
            else:
                self._report("⏩ 跳过 Step 1（匿名爬取已有数据），直接开始登录爬取")
                self._stop_requested = False  # 确保停止信号重置

            # Round 2+: 每个账号登录后爬取
            for i, cred in enumerate(self.credentials):
                if self._stop_requested:
                    # 同样：静默超时不跳过后续角色，只有用户主动中止才跳过
                    if not self._user_aborted and i + 1 < len(self.credentials):
                        self._report(f"⏸ 角色 {cred.get('role', f'user_{i+1}')} 静默超时 — 重置停止信号，继续下一个角色")
                        self._stop_requested = False
                        self._progress_tick += 1
                    else:
                        self._report(f"⏸ 收到停止信号，跳过剩余 {len(self.credentials) - i} 个角色爬取")
                        break
                role = cred.get("role", f"user_{i+1}")
                self._report(f"Step 2/3: 登录爬取 (角色: {role})")
                result = await self._crawl_round(role=role, login_info=cred)
                if not any(id(r) == id(result) for r in self.rounds):
                    self.rounds.append(result)

            # 多角色对比
            self._report("Step 3/3: 多角色对比 + 推测验证 + 结果汇总")
            comparison = self._compare_rounds()

            return await self._build_final_result(comparison)
        finally:
            # ★ 任务结束清理 JS 缓存，避免模块级 dict 累积导致 CPU 飙满 / 跨任务串扰
            try:
                from core.js_analyzer import clear_js_cache
                clear_js_cache(self.target)
            except Exception as _e:
                log.debug("清理 JS 缓存失败: %s", _e)

    async def _crawl_round(self, role: str, login_info: dict | None) -> CrawlRoundResult:
        """执行一轮爬取。"""
        from playwright.async_api import async_playwright

        # ★ 新一轮开始 → tick+1，重置外部静默计时器，避免 Step1 结束后的空窗期
        # 被误判为"90s 无新进展"而提前 request_stop()
        self._progress_tick += 1

        # ★ 2026-05-22 v4: 暴露当前角色给 _crawl_page_inner 用于菜单模式判定
        # （不改 _crawl_page 函数签名，避免触动 _run_crawl_page_with_adaptive_timeout
        # 的协程工厂闭包；用实例属性是最小侵入做法）
        self._current_role = role
        self._current_account = str((login_info or {}).get("username") or "")
        self._current_credential_id = str(
            (login_info or {}).get("credential_id")
            or (login_info or {}).get("id")
            or role
        )

        result = CrawlRoundResult(role=role)
        # ★ v4.1: 立刻把 result 引用挂进 self.rounds，让 get_partial_result()
        # 在中途被 cancel/超时时也能拿到当前正在累积的数据（result 是引用，会跟着填充）
        # 注意避免重复 append（外层 crawl() 仍会再 append 同一个对象 → 用 id 去重）
        if not any(id(r) == id(result) for r in self.rounds):
            self.rounds.append(result)
        pw = await async_playwright().start()

        proxy_url = os.getenv("BROWSER_PROXY", "http://127.0.0.1:18080")
        use_proxy = await self._check_proxy(proxy_url, self.target)

        # 是否需要"有头模式 + 手动介入"：仅当 Step 2 真正要做表单登录、
        # 且没有现成 Cookie/请求包注入、且未强制 headless 时启用。
        # 这样既能让用户手动过验证码，又不会打扰无登录场景（Step 1 匿名爬取永远 headless）。
        _headless_env = os.getenv("BROWSER_HEADLESS", "auto").lower()
        needs_form_login = (
            login_info is not None
            and not (login_info.get("session_cookies") or login_info.get("extra_headers") or login_info.get("auth_header"))
            and bool(login_info.get("username") or login_info.get("password"))
        )
        if _headless_env == "true":
            headless = True
        elif _headless_env == "false":
            headless = False
        else:  # auto
            headless = not needs_form_login

        launch_opts: dict[str, Any] = {"headless": headless, "args": ["--ignore-certificate-errors"]}

        # 如果 Playwright 自带的 Chromium 不存在，自动检测系统浏览器
        if not launch_opts.get("executable_path"):
            from core.browser_resolver import get_launch_executable_path
            _exe = get_launch_executable_path()
            if _exe:
                launch_opts["executable_path"] = _exe
        if use_proxy:
            launch_opts["proxy"] = {"server": proxy_url}

        if not headless:
            self._report(f"  🪟 启用有头浏览器（角色: {role}）— 遇到验证码可手动操作")

        # ★ 反检测：使用真实 UA，隐藏 Headless/Playwright 指纹
        _REAL_UA = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        launch_opts["args"].extend([
            f"--user-agent={_REAL_UA}",
            "--disable-blink-features=AutomationControlled",
            "--disable-web-security",  # 禁用同源策略，解决 CDN 跨域资源 403/CORS 问题
            "--disable-features=IsolateOrigins,site-per-process",  # 配合 disable-web-security
        ])

        browser = await pw.chromium.launch(**launch_opts)
        ctx = await browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent=_REAL_UA,
        )

        # 注入 stealth 脚本
        await ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
            window.chrome = {runtime: {}};
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({state: Notification.permission})
                    : originalQuery(parameters);
        """)

        # ★ Cookie 注入：如果用户提供了 session_cookies，直接注入到 context（跳过表单登录）
        cookies_injected = False
        if login_info and login_info.get("session_cookies"):
            from core.intent import parse_cookie_string
            ck_list = parse_cookie_string(login_info["session_cookies"], self.target)
            if ck_list:
                try:
                    await ctx.add_cookies(ck_list)
                    cookies_injected = True
                    self._report(f"  🍪 已注入 {len(ck_list)} 个 Cookie (跳过表单登录)")
                except Exception as e:
                    self._report(f"  ⚠️ Cookie 注入失败: {e}，将尝试表单登录")

        # ★ 完整 Header 注入：如果用户提供了请求包，把所有自定义 header 注入到 context
        # extra_headers 是 dict（来自 intent.extra_headers），覆盖 sign/key/timestamp 等所有字段
        extra_headers = login_info.get("extra_headers", {}) if login_info else {}
        headers_to_inject: dict[str, Any] = {}
        auth_header_value = ""
        if login_info and login_info.get("auth_header"):
            auth_header_value = login_info["auth_header"]
            extra_headers = dict(extra_headers)  # 复制
            extra_headers.setdefault("Authorization", auth_header_value)

        if extra_headers:
            try:
                # 移除一些不应注入到所有请求的 header（这些只在第一个抓包里有意义）
                headers_to_inject = {
                    k: v for k, v in extra_headers.items()
                    if k.lower() not in {"content-type", "content-length", "accept", "referer", "origin"}
                }
                if headers_to_inject:
                    await ctx.set_extra_http_headers(headers_to_inject)
                    self._report(f"  📦 已注入 {len(headers_to_inject)} 个自定义 Header: {', '.join(list(headers_to_inject.keys())[:5])}{'...' if len(headers_to_inject) > 5 else ''}")
                    cookies_injected = True  # 视同已认证

                    # ★ JWT token 自动注入 localStorage + Vuex Store（SPA 前端路由守卫需要）
                    # 仅 set_extra_http_headers 不够——前端 Vue 路由守卫从 Vuex store 读取 token，
                    # 不从 HTTP 请求头读取。没走登录流程时 Vuex store 里没 token → 跳 error 页。
                    from core.intent import jwt_headers_to_local_storage
                    ls_items = jwt_headers_to_local_storage(headers_to_inject)
                    if ls_items:
                        import json as _json
                        ls_json = _json.dumps(ls_items, ensure_ascii=False)
                        # 注入 localStorage
                        await ctx.add_init_script(f"""
                            (() => {{
                                try {{
                                    const items = JSON.parse({ls_json!r});
                                    for (const [k, v] of Object.entries(items)) {{
                                        localStorage.setItem(k, v);
                                    }}
                                }} catch(e) {{}}
                            }})();
                        """)
                        self._report(f"  🔑 已注入 {len(ls_items)} 个 localStorage 项: {', '.join(list(ls_items.keys())[:5])}")

                    # ★ ★ Vuex Store 拦截注入（让前端路由守卫认为已登录）
                    # 不拦截 XHR/fetch——避免 CORS 预检失败、反爬检测、请求重复注入
                    jwt_token = ""
                    for _hk, _hv in headers_to_inject.items():
                        if isinstance(_hv, str) and _hv.startswith("eyJ") and len(_hv) > 20:
                            jwt_token = _hv
                            break
                    if jwt_token:
                        await ctx.add_init_script(f"""
                            (() => {{
                                const TOKEN = {jwt_token!r};

                                function _tryInjectStore(vm) {{
                                    if (!vm || !vm.$store) return;
                                    const state = vm.$store.state;
                                    const targets = [state.user, state.auth, state.login, state.account];
                                    for (const mod of targets) {{
                                        if (mod && typeof mod === 'object') {{
                                            try {{ vm.$store.commit('SET_TOKEN', TOKEN); }} catch(e) {{}}
                                            try {{ mod.token = TOKEN; }} catch(e) {{}}
                                        }}
                                    }}
                                    if (!state.token) {{
                                        try {{ state.token = TOKEN; }} catch(e) {{}}
                                    }}
                                }}

                                // 延迟查找 Vue 实例
                                let _attempts = 0;
                                const _interval = setInterval(() => {{
                                    _attempts++;
                                    if (_attempts > 30) {{ clearInterval(_interval); return; }}
                                    const el = document.querySelector('[data-v-app]') || document.querySelector('#app');
                                    if (el && el.__vue__) {{
                                        _tryInjectStore(el.__vue__);
                                        clearInterval(_interval);
                                    }}
                                }}, 100);
                            }})();
                        """)
                        self._report(f"  🏪 已注入 Vuex Store 拦截器，自动写入 token")
            except Exception as e:
                self._report(f"  ⚠️ Header 注入失败: {e}")

        page = await ctx.new_page()

        # 请求监听
        captured: list[dict] = []
        # ★ 后端菜单 API 响应缓存（用于回流入队驱动爬取）
        menu_paths_from_api: set[str] = set()
        # ★ ID 池：从 URL 中收集到的真实 ID（按"前缀"分组）
        # 例如 /api/users/123 → id_pool["/api/users"] = {"123", "456", ...}
        id_pool: dict[str, set[str]] = {}

        # 菜单 API 关键词：使用模块级常量 MENU_API_KEYWORDS（定义在文件顶部）

        # ★ 2026-05-28 新增：菜单树 JSON 缓存（完整响应体，不截断）
        # 用于 parse_menu_tree 方式 1 直接读取，解决 captured 中无 response_body 的问题
        # 使用实例变量，跨轮次累积
        _menu_tree_responses = self._menu_tree_responses

        def _collect_paths_from_menu_node(node, out: set[str]):
            """递归从菜单树节点中提取 path 字段。"""
            if not isinstance(node, (dict, list)):
                return
            if isinstance(node, list):
                for item in node:
                    _collect_paths_from_menu_node(item, out)
                return
            # dict：尝试常见的 path 字段名
            for key in ("path", "url", "router", "route", "menuUrl", "menuPath"):
                v = node.get(key)
                if isinstance(v, str) and v.strip() and not v.startswith(("http://", "https://", "javascript:", "#")):
                    # 排除明显的非路径值（如全大写组件名）
                    p = v.strip()
                    if p.startswith("/") or "/" in p:
                        out.add(p if p.startswith("/") else "/" + p)
            # 递归 children/childList/subMenus 等
            for ckey in ("children", "childList", "subMenus", "subList", "items", "nodes", "menus"):
                if ckey in node:
                    _collect_paths_from_menu_node(node[ckey], out)

        def _collect_ids_from_url(url: str):
            """从 URL 中提取数字/UUID ID，按前缀分组存入 id_pool。"""
            try:
                from urllib.parse import urlparse, parse_qs
                p = urlparse(url)
                # 1. query 参数里的 id
                qs = parse_qs(p.query)
                for k, vs in qs.items():
                    if k.lower() in ("id", "userid", "user_id", "uid", "rid", "role_id",
                                     "menu_id", "menuid", "data_id", "dataid", "biz_id",
                                     "parent_id", "parentid", "row_id", "record_id", "key"):
                        for v in vs:
                            if v and (v.isdigit() or len(v) > 8):
                                # 用 path 作为前缀
                                prefix = p.path.rstrip("/")
                                id_pool.setdefault(prefix, set()).add(v)
                # 2. 路径中的纯数字段或 UUID 段：/api/users/123 → 把 /api/users 作为前缀
                segments = p.path.strip("/").split("/")
                for i, seg in enumerate(segments):
                    is_id = seg.isdigit() or (
                        len(seg) >= 8 and all(c in "0123456789abcdef-" for c in seg.lower())
                    )
                    if is_id and i > 0:
                        prefix = "/" + "/".join(segments[:i])
                        id_pool.setdefault(prefix, set()).add(seg)
            except Exception as _e:
                log.debug("URL ID 收集失败: %s", _e)

        def on_request(req):
            # ★ 2026-05-22 v3 修复：req.post_data 在 body 是二进制内容时
            # （如 gzip / protobuf / 二进制 multipart）会抛 UnicodeDecodeError，
            # 进而被 pyee 的 error handler 反复 emit，导致日志被刷屏数千行。
            # 修复：用 try/except 兜住，二进制 body 用 post_data_buffer 安全提取。
            if req.resource_type not in ("document", "xhr", "fetch", "websocket"):
                return
            # 安全提取 post_data
            post_data_str = ""
            try:
                post_data_str = (req.post_data or "")[:2000]
            except UnicodeDecodeError:
                # 二进制 body：尝试拿 buffer 后用 latin-1 / 标记保留
                try:
                    buf = req.post_data_buffer
                    if buf:
                        # latin-1 永远不会失败，能把任意字节当字符
                        post_data_str = "[binary body, len=%d, head=%s]" % (
                            len(buf), buf[:32].hex()
                        )
                except Exception:
                    post_data_str = "[binary body, decode failed]"
            except Exception:
                # 其他罕见错误也兜住，避免 pyee 递归刷屏
                post_data_str = ""

            try:
                headers_dict = dict(req.headers)
            except Exception:
                headers_dict = {}

            try:
                captured.append({
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                    "post_data": post_data_str,
                    "headers": headers_dict,
                })
                channels = classify_realtime_flow(
                    method=req.method,
                    url=req.url,
                    request_headers=headers_dict,
                    request_body=post_data_str,
                    discovered_by="crawler_request",
                )
                if channels:
                    result.realtime_channels.extend(channels)
                # 顺带从 URL 收集 ID
                _collect_ids_from_url(req.url)
            except Exception as _e:
                # 永远不要让 listener 抛异常（会污染日志）
                log.debug("on_request 监听器异常: %s", _e)

        # ★ API 文档发现命中列表（轻量检测，提取延迟到 session.py）
        # 使用实例变量，以便 _build_final_result 也能访问
        if not hasattr(self, "_api_doc_hits"):
            self._api_doc_hits: list[dict] = []
        api_doc_hits = self._api_doc_hits

        def _is_menu_tree_structure(data) -> bool:
            """启发式检测：判断一个 JSON 数据是否是菜单树结构。

            判定条件（满足全部）：
            1. 是 list[dict] 且节点数 >= 3
            2. 每个节点有 name/title/label 类字段
            3. 至少 30% 的节点有 path/url/route 类字段
            4. 至少 20% 的节点有 children/items 类递归字段（树深度 >= 2）
            """
            if not isinstance(data, list) or len(data) < 3:
                return False
            name_keys = ("name", "title", "label", "menuName", "meta")
            path_keys = ("path", "url", "route", "router", "menuUrl", "menuPath", "component")
            children_keys = ("children", "childList", "subMenus", "subList", "items", "nodes", "menus", "routes")

            has_name = 0
            has_path = 0
            has_children = 0
            sample = data[:20]  # 只检查前 20 个节点（性能考虑）
            for node in sample:
                if not isinstance(node, dict):
                    return False
                if any(k in node for k in name_keys):
                    has_name += 1
                if any(k in node for k in path_keys):
                    has_path += 1
                if any(k in node and isinstance(node[k], list) and node[k] for k in children_keys):
                    has_children += 1

            total = len(sample)
            # 至少 60% 有名称字段，30% 有路径字段，20% 有子节点
            return (has_name / total >= 0.6 and
                    has_path / total >= 0.3 and
                    has_children / total >= 0.2)

        async def on_response(resp):
            """监听响应：菜单树 API 解析 + 启发式菜单树检测 + API 文档指纹检测。"""
            try:
                url = resp.url
                ct = (resp.headers.get("content-type") or "").lower()

                # ---- GraphQL / SSE 响应拆解（不影响后续菜单树和文档发现） ----
                try:
                    response_text = ""
                    if any(marker in ct for marker in ("json", "graphql")):
                        response_text = (await resp.text())[:5000]
                    matched_req = next((r for r in reversed(captured) if r.get("url") == url), {})
                    if matched_req:
                        matched_req["status_code"] = resp.status
                        matched_req["response_headers"] = dict(resp.headers)
                        matched_req["response_body"] = response_text
                    channels = classify_realtime_flow(
                        method=matched_req.get("method", "GET"),
                        url=url,
                        request_headers=matched_req.get("headers", {}),
                        request_body=matched_req.get("post_data", ""),
                        response_headers=dict(resp.headers),
                        response_body=response_text,
                        status_code=resp.status,
                        discovered_by="crawler_response",
                    )
                    if channels:
                        result.realtime_channels.extend(channels)
                except Exception as _e:
                    log.debug("GraphQL/SSE 响应拆解失败: %s", _e)

                # ---- 菜单树 API 解析（关键词匹配 + 启发式检测） ----
                url_lower = url.lower()
                is_menu_api = any(kw.lower() in url_lower for kw in MENU_API_KEYWORDS)

                if "json" in ct and resp.status == 200:
                    # 对所有 JSON 响应尝试解析（关键词命中优先，否则启发式检测）
                    try:
                        body = await resp.json()
                    except Exception:
                        body = None

                    if body is not None:
                        root = body.get("data") if isinstance(body, dict) and "data" in body else body

                        if is_menu_api:
                            # 关键词命中：提取 path 回流 + 保存完整响应
                            paths: set[str] = set()
                            _collect_paths_from_menu_node(root, paths)
                            if paths:
                                menu_paths_from_api.update(paths)
                            # ★ 保存完整菜单树 JSON（不截断）
                            import json as _json
                            try:
                                body_str = _json.dumps(body, ensure_ascii=False)
                            except Exception:
                                body_str = ""
                            if body_str:
                                role = getattr(self, "_current_role", "anonymous") or "anonymous"
                                account = getattr(self, "_current_account", "") or ""
                                credential_id = getattr(self, "_current_credential_id", "") or role
                                _menu_tree_responses.append({
                                    "url": url,
                                    "response_body": body_str,
                                    "source": "keyword_match",
                                    "role": role,
                                    "account": account,
                                    "credential_id": credential_id,
                                    "auth_context": {
                                        "role": role,
                                        "account": account,
                                        "credential_id": credential_id,
                                    },
                                })
                                self._report(f"  🗺️ 菜单树 API 命中: {url[:80]} (角色 {role}, 响应 {len(body_str)} 字符)")

                        elif not is_menu_api and isinstance(root, list) and len(root) >= 3:
                            # ★ 启发式检测：对非关键词命中的 JSON 响应检测树形结构
                            if _is_menu_tree_structure(root):
                                paths_h: set[str] = set()
                                _collect_paths_from_menu_node(root, paths_h)
                                if paths_h:
                                    menu_paths_from_api.update(paths_h)
                                import json as _json
                                try:
                                    body_str = _json.dumps(body, ensure_ascii=False)
                                except Exception:
                                    body_str = ""
                                if body_str:
                                    role = getattr(self, "_current_role", "anonymous") or "anonymous"
                                    account = getattr(self, "_current_account", "") or ""
                                    credential_id = getattr(self, "_current_credential_id", "") or role
                                    _menu_tree_responses.append({
                                        "url": url,
                                        "response_body": body_str,
                                        "source": "heuristic_detect",
                                        "role": role,
                                        "account": account,
                                        "credential_id": credential_id,
                                        "auth_context": {
                                            "role": role,
                                            "account": account,
                                            "credential_id": credential_id,
                                        },
                                    })
                                    self._report(
                                        f"  🗺️ 启发式菜单树发现: {url[:80]} "
                                        f"(角色 {role}, {len(root)} 节点, {len(paths_h)} 路径, {len(body_str)} 字符)"
                                    )

                # ---- API 文档指纹检测（轻量，只记录命中） ----
                if api_doc_hits is not None and ("html" in ct or "json" in ct or "javascript" in ct):
                    try:
                        from core.api_doc_discovery import _match_fingerprints
                        body_text = await resp.text()
                        hits = _match_fingerprints(url, body_text[:5000])
                        if hits:
                            for h in hits:
                                api_doc_hits.append({
                                    "url": url,
                                    "category": h.category,
                                    "name": h.name,
                                })
                            self._report(f"  🔍 API 文档发现: {url[:80]} → {', '.join(h.name for h in hits)}")
                    except Exception as _e:
                        log.debug("API 文档发现失败 (不影响主流程): %s", _e)

            except Exception as _e:
                log.debug("on_response 监听器异常: %s", _e)

        page.on("request", on_request)
        # ★ 异步监听响应（菜单 API 路径回流）
        # 用 create_task 包一层避免阻塞 Playwright 事件循环
        def _on_response_sync(r):
            try:
                asyncio.create_task(on_response(r))
            except RuntimeError as _e:
                log.debug("event loop 关闭时静默: %s", _e)
        page.on("response", _on_response_sync)

        def _on_websocket(ws):
            try:
                result.realtime_channels.append(websocket_event(ws.url, page_url=page.url, discovered_by="crawler_websocket"))
            except Exception as _e:
                log.debug("websocket 监听器异常: %s", _e)

        try:
            page.on("websocket", _on_websocket)
        except Exception as _e:
            log.debug("注册 websocket 监听器失败: %s", _e)

        # ★ 2026-05-28 新增：新 Tab/Popup 页面监听
        # 某些系统点击菜单会 target="_blank" 打开新标签页，需要捕获新页面的流量
        self._new_tab_pages: list = []  # 记录新打开的页面

        def _on_new_page(new_page):
            """监听浏览器上下文中新打开的页面（target=_blank / window.open）。"""
            self._new_tab_pages.append(new_page)
            # 为新页面也注册请求监听，收集流量
            new_page.on("request", on_request)
            new_page.on("response", _on_response_sync)
            try:
                new_page.on("websocket", _on_websocket)
            except Exception as _e:
                log.debug("新页面注册 websocket 监听器失败: %s", _e)

        ctx.on("page", _on_new_page)

        try:
            # 登录（如果有账号且没注入 cookie）
            login_success = False
            if login_info and not cookies_injected:
                # ★ 只有真正有用户名/密码时才尝试表单登录；
                # 纯 cookie 凭证（无 username/password）注入失败时不应走表单登录
                has_form_creds = bool(login_info.get("username") or login_info.get("password"))
                if has_form_creds:
                    login_success = await self._attempt_login(page, login_info, captured)
                else:
                    self._report("  ⚠️ 凭证注入失败且无用户名密码，跳过表单登录")
                result.login_success = login_success
                if login_success:
                    self._progress_tick += 1  # 登录成功 → 重置静默计时器
            elif cookies_injected:
                # ★ Cookie/Header 注入后验证：导航到 target 页面，检查是否被重定向到登录页
                # 这是通用验证，适用于所有网站（不仅仅是飞书）
                login_success = await self._verify_cookie_login(page, captured)
                result.login_success = login_success
                if login_success:
                    self._report("  ✅ Cookie 注入验证通过 — 页面正常加载，确认登录态有效")
                else:
                    self._report("  ⚠️ Cookie 注入后页面被重定向到登录页 — 凭证可能已过期或无效")
                    self._report("     → 后续爬取将以未登录态进行，功能清单可能不完整")

            # 先抓 robots.txt 和 sitemap.xml
            seed_urls = await self._get_seed_urls(page)
            spa_routes = []  # 初始化，登录成功后可能被覆盖

            # ★ 登录成功后自动发现后台入口（SPA 场景关键）
            if login_success:
                post_login_url = page.url
                if post_login_url != self.target:
                    self._report(f"  登录后页面: {post_login_url[:80]}")

                # ★ 推断关联域名（从已抓流量 + Cookie 分析）
                # ★ 同时保存登录 cookie 到环境变量，供后续 Phase 1 BrowseWorker 的新浏览器实例使用
                try:
                    browser_cookies = await page.context.cookies()
                    self.infer_extra_scope(captured, browser_cookies)

                    # ★ 将登录后的 cookie 回写到 PENTEST_INJECT_COOKIES，
                    #   这样 Phase 1 的 _ensure_browser() 启动新浏览器时会自动注入
                    if browser_cookies:
                        from urllib.parse import urlparse as _urlparse
                        target_domain = _urlparse(self.target).netloc
                        # 只保留目标域及父域的 cookie，避免注入无关域
                        relevant = [
                            c for c in browser_cookies
                            if target_domain.endswith(c.get("domain", "").lstrip("."))
                            or c.get("domain", "").lstrip(".").endswith(target_domain)
                        ]
                        if relevant:
                            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in relevant)
                            os.environ["PENTEST_INJECT_COOKIES"] = cookie_str
                            os.environ.setdefault("PENTEST_TARGET_URL", self.target)
                            self._report(f"  🍪 已保存 {len(relevant)} 个登录 Cookie 到环境变量，后续浏览器实例将自动注入")

                    # ★ 同时提取 localStorage 中的 token（SPA/JWT 场景）
                    #   写入 PENTEST_INJECT_AUTH（供 proxy 请求用）+ PENTEST_INJECT_LOCAL_STORAGE（供浏览器注入用）
                    #   注意必须与既有注入项 merge，不能覆盖掉 showcon_xxx / 自定义 key。
                    try:
                        local_storage_items = await page.evaluate("""() => {
                            const result = {};
                            for (const key of Object.keys(localStorage)) {
                                const val = localStorage.getItem(key);
                                if (!val || val.length <= 10) continue;
                                const kl = String(key).toLowerCase();
                                const vl = String(val);
                                if (vl.startsWith('eyJ') || kl.includes('token') || kl.includes('auth') || kl.includes('jwt') || kl.includes('session')) {
                                    result[key] = val;
                                }
                            }
                            return Object.keys(result).length > 0 ? result : null;
                        }""")
                        if local_storage_items:
                            import json as _json
                            # 供 proxy_mcp HTTP 请求注入 Authorization 头
                            first_token = next((v for v in local_storage_items.values() if isinstance(v, str) and v.startswith("eyJ")), None)
                            if first_token and not os.getenv("PENTEST_INJECT_AUTH"):
                                os.environ["PENTEST_INJECT_AUTH"] = f"Bearer {first_token}"
                            # 供 browser_mcp 浏览器 localStorage 注入：保留任务启动时已推导的自定义 key。
                            existing_ls = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
                            try:
                                existing_items = _json.loads(existing_ls) if existing_ls else {}
                            except Exception:
                                existing_items = {}
                            if not isinstance(existing_items, dict):
                                existing_items = {}
                            merged_items = {**existing_items, **local_storage_items}
                            os.environ["PENTEST_INJECT_LOCAL_STORAGE"] = _json.dumps(
                                merged_items, ensure_ascii=False
                            )
                            self._report(f"  🔑 已保存 {len(merged_items)} 个 localStorage Token，后续浏览器实例将自动注入")
                    except Exception as _e:
                        log.debug("保存 localStorage Token 失败: %s", _e)
                except Exception as _e:
                    log.debug("localStorage 提取失败: %s", _e)

                # 尝试从 SPA 框架提取所有前端路由（Vue Router / React Router）
                # 同时检测路由模式（hash 或 history）
                try:
                    spa_info = await page.evaluate("""() => {
                        const result = {routes: [], mode: 'hash'};
                        try {
                            // Vue 3
                            const app = document.querySelector('#app');
                            if (app && app.__vue_app__) {
                                const router = app.__vue_app__.config.globalProperties.$router;
                                if (router) {
                                    result.routes = router.getRoutes().map(r => r.path).filter(p => p && p !== '/');
                                    // 检测 history 模式：vue-router 4.x
                                    const opt = router.options || {};
                                    const hist = opt.history;
                                    if (hist) {
                                        // createWebHashHistory → base 含 #；createWebHistory → 不含
                                        const histStr = String(hist.createCurrentLocation || hist.location || '');
                                        if (location.hash && location.hash.startsWith('#/')) {
                                            result.mode = 'hash';
                                        } else {
                                            result.mode = 'history';
                                        }
                                    }
                                    return result;
                                }
                            }
                            // Vue 2
                            if (app && app.__vue__ && app.__vue__.$router) {
                                const router = app.__vue__.$router;
                                result.routes = router.options.routes.map(r => r.path).filter(p => p && p !== '/');
                                result.mode = router.mode || (location.hash.startsWith('#/') ? 'hash' : 'history');
                                return result;
                            }
                            // React Router (v6 没有公开 API，但 history 对象常被挂在 window)
                            // 试着从 window.__REACT_ROUTER_HISTORY__ 或 window.history.state.routes 读取
                            if (window.__reactRouterHistory__) {
                                // 这个 API 不稳定，留空
                            }
                            // 兜底：根据当前 URL 判断模式
                            result.mode = location.hash && location.hash.startsWith('#/') ? 'hash' : 'history';
                        } catch(e) {}
                        return result;
                    }""")
                    if spa_info and isinstance(spa_info, dict):
                        spa_routes = spa_info.get("routes", []) or []
                        # 根据检测到的模式覆盖 _is_spa（如果检测到 history 模式且有路由，强制设为非 hash 模式）
                        detected_mode = spa_info.get("mode", "hash")
                        if spa_routes and detected_mode == "history":
                            self._is_spa = False  # history 模式不应该拼 #/
                            self._report(f"  🗺️ 检测到 SPA history 模式")
                    else:
                        spa_routes = spa_info if isinstance(spa_info, list) else []
                    if spa_routes:
                        self._report(f"  🗺️ 从 SPA Router 提取到 {len(spa_routes)} 个前端路由")
                except Exception:
                    spa_routes = []

            # 开始爬取
            visited: set[str] = set()
            to_visit = [self.target] + seed_urls
            # ★ SPA 登录后：把当前页面 URL（含 hash）加入种子
            if login_success:
                post_url = page.url
                if post_url not in to_visit:
                    to_visit.insert(0, post_url)
            # ★ SPA 路由无条件加入种子（匿名爬取同样需要遍历前端路由发现功能页面）
            base_no_hash = self.target.split("#")[0].rstrip("/")
            if self._is_spa and spa_routes:
                for route in spa_routes:
                    route_url = f"{base_no_hash}#/{route.lstrip('/')}"
                    if route_url not in to_visit:
                        to_visit.append(route_url)
            page_count = 0
            # ★ 标记是否已对菜单 API 响应做过回流（避免重复处理）
            menu_api_consumed: set[str] = set()

            while to_visit and page_count < self.max_pages:
                # ★ 协作式停止：每页前检查 stop flag，及时退出 BFS（保数据用）
                # 之前漏了这里，导致 silent_timeout / hard_timeout 后还要等整轮 BFS 跑完才生效
                if self._stop_requested:
                    self._report(f"  [{role}] ⏸ 收到停止信号，BFS 中断 (已爬 {page_count} 页, 剩 {len(to_visit)} 条未访问)")
                    break

                # ★ 每轮循环：把新捕获的菜单 API 路径回流入队
                # （菜单 API 响应是异步触发的，可能在第 N 页加载后才到）
                base_no_hash = self.target.split("#")[0].rstrip("/")
                new_menu_paths = menu_paths_from_api - menu_api_consumed
                if new_menu_paths:
                    menu_api_consumed.update(new_menu_paths)
                    added_from_menu = 0
                    for mp in new_menu_paths:
                        if self._is_spa:
                            route_url = f"{base_no_hash}#/{mp.lstrip('/')}"
                        else:
                            route_url = f"{base_no_hash}{mp if mp.startswith('/') else '/' + mp}"
                        if self._normalize_url(route_url) not in visited and route_url not in to_visit:
                            to_visit.append(route_url)
                            added_from_menu += 1
                    if added_from_menu:
                        self._report(f"  [{role}] 🗺️ 菜单 API 回流: 新增 {added_from_menu} 条待爬路径")

                url = to_visit.pop(0)
                normalized = self._normalize_url(url)
                if normalized in visited:
                    continue
                if not self._is_in_scope(url):
                    continue

                visited.add(normalized)
                page_count += 1
                self._report(f"  [{role}] 页面 {page_count}: {url[:80]}")
                # ★ 2026-05-27: 页面加载成功 → tick+1，防止页面导航阶段 silent_timeout 误判
                self._progress_tick += 1

                # ★ 2026-05-22 v2: 自适应超时（soft 60s 检查噪音 → 无噪音延长到 hard 180s）
                try:
                    crawled = await _run_crawl_page_with_adaptive_timeout(
                        coro_factory=lambda: self._crawl_page(page, url, captured),
                        detector_getter=lambda: self._current_page_noise_detector,
                        soft_timeout_s=NOISE_PAGE_SOFT_TIMEOUT_S,
                        hard_timeout_s=NOISE_PAGE_HARD_TIMEOUT_S,
                    )
                except asyncio.TimeoutError as _te:
                    reason = str(_te) if str(_te) else "超时"
                    self._report(
                        f"  ⚠️ 页面爬取{reason}已强制跳过: {url[:80]}"
                    )
                    crawled = None
                except Exception as _e:
                    self._report(f"  ⚠️ _crawl_page 调用异常: {type(_e).__name__}: {str(_e)[:160]}")
                    crawled = None
                if crawled:
                    result.pages[url] = crawled

                    # ★ 增量推断关联域：每页爬完看流量中是否出现新的同公司体系域名，
                    #   出现就立刻加入 scope，让后续循环的链接过滤能放行它们。
                    #   这是为了覆盖"爬到才知道的多产品 SaaS 域"场景。
                    try:
                        new_scope = self._infer_scope_incremental(captured)
                        if new_scope:
                            self.extra_scope |= new_scope
                            self._report(f"  🔗 新增关联域: {', '.join(sorted(new_scope))}")
                    except Exception as _e:
                        log.debug("关联域推断失败 (不影响主流程): %s", _e)

                    for link in crawled.links:
                        norm = self._normalize_url(link)
                        if norm not in visited and self._is_in_scope(link):
                            # ★ 过滤列表详情子页：跳过已访问过同类路径模式的 ID 子页
                            # 例如已爬过 /users/111/accounts，跳过 /users/222/accounts
                            # 策略：把路径中的纯数字段替换为 {id} 作为模式，相同模式最多入队 3 次
                            if not self._is_duplicate_id_page(link, visited):
                                to_visit.append(link)

            # ★ ID 池回填：为带占位符的路径（如 /admin/user/{id}、/edit/:id 等）
            # 用真实 ID 拼出 URL 进入第二轮爬取
            if id_pool and page_count < self.max_pages:
                placeholder_routes = self._collect_placeholder_routes(spa_routes, menu_paths_from_api, result)
                if placeholder_routes:
                    backfilled = self._backfill_with_ids(placeholder_routes, id_pool, base_no_hash, visited)
                    if backfilled:
                        self._report(f"  [{role}] 🔑 ID 池回填: 收集 {sum(len(v) for v in id_pool.values())} 个 ID, 生成 {len(backfilled)} 条详情/编辑页 URL")
                        backfill_count = 0
                        for burl in backfilled:
                            if page_count >= self.max_pages:
                                break
                            normalized = self._normalize_url(burl)
                            if normalized in visited or not self._is_in_scope(burl):
                                continue
                            visited.add(normalized)
                            page_count += 1
                            backfill_count += 1
                            self._report(f"  [{role}] 页面 {page_count} (回填): {burl[:80]}")
                            try:
                                crawled = await _run_crawl_page_with_adaptive_timeout(
                                    coro_factory=lambda u=burl: self._crawl_page(page, u, captured),
                                    detector_getter=lambda: self._current_page_noise_detector,
                                    soft_timeout_s=NOISE_PAGE_SOFT_TIMEOUT_S,
                                    hard_timeout_s=NOISE_PAGE_HARD_TIMEOUT_S,
                                )
                            except asyncio.TimeoutError as _te:
                                reason = str(_te) if str(_te) else "超时"
                                self._report(
                                    f"  ⚠️ 页面爬取{reason}已强制跳过: {burl[:80]}"
                                )
                                crawled = None
                            except Exception as _e:
                                self._report(f"  ⚠️ _crawl_page 回填异常: {type(_e).__name__}: {str(_e)[:160]}")
                                crawled = None
                            if crawled:
                                result.pages[burl] = crawled
                        if backfill_count:
                            self._report(f"  [{role}] ✓ ID 回填完成: 实际爬取 {backfill_count} 个详情/编辑页")

            # JS 深度分析（替代原来的简单正则提取）
            # ★ 静默超时且非用户主动中止时跳过 JS 分析，让 _crawl_round 尽快返回
            #   以便外层 crawl() 能执行 Step 1→Step 2 的 _stop_requested 重置逻辑
            #   否则 chat_loop 的 GRACE_AFTER_STOP(30s) 会 cancel 整个 crawl_task
            skip_js = self._stop_requested and not self._user_aborted
            if not skip_js:
                from core.js_analyzer import analyze_page_js, js_result_to_crawl_data, JSAnalysisResult
                base_url = f"{urlparse(self.target).scheme}://{self.target_domain}"
                self._report(f"  [{role}] 📦 JS 深度分析中...")
                # ★ JS 分析入口 1 次重试：page 临时状态失败 / 空结果时有机会恢复
                js_analysis = None
                for _js_attempt in range(2):
                    try:
                        js_analysis = await analyze_page_js(
                            page, base_url, llm_chat_fn=self._llm_chat_fn)
                    except Exception as _js_e:
                        log.warning("JS 分析第 %d 次失败: %s", _js_attempt + 1, _js_e)
                        js_analysis = None
                    # 检测是否拿到有效内容（js_files_analyzed > 0 或有 api_calls/routes）
                    if js_analysis and (
                        getattr(js_analysis, "js_files_analyzed", 0) > 0
                        or getattr(js_analysis, "api_calls", None)
                        or getattr(js_analysis, "routes", None)
                    ):
                        break
                    if _js_attempt == 0:
                        log.warning("JS 分析返回空结果，重试一次")
                        import asyncio as _aio
                        await _aio.sleep(0.5)
                if js_analysis is None:
                    js_analysis = JSAnalysisResult()
            else:
                from core.js_analyzer import JSAnalysisResult
                js_analysis = JSAnalysisResult()
                self._report(f"  [{role}] ⏩ 跳过 JS 深度分析（静默超时，优先让 Step 2 启动）")
            result.js_analysis = js_analysis
            # ★ 将 JS 分析发现的自定义 token storage key + auth state key
            #   回写到后续浏览器注入环境，解决 Phase 1 丢登录态。
            try:
                storage_keys: set[str] = set()
                for auth in getattr(js_analysis, "auth_patterns", []) or []:
                    storage_keys.update(getattr(auth, "storage_keys", []) or [])
                if storage_keys and headers_to_inject:
                    from core.intent import jwt_headers_to_local_storage
                    from core.js_analyzer import _looks_like_auth_state_key, _looks_like_auth_storage_key
                    # token 类 key → 映射 JWT 值；auth state 类 key → 设置合理默认值
                    token_keys = [k for k in storage_keys if _looks_like_auth_storage_key(k) and not _looks_like_auth_state_key(k)]
                    auth_state_defaults: dict[str, str] = {}
                    for k in storage_keys:
                        if _looks_like_auth_state_key(k):
                            if "tenant" in k.lower() or "enterprise" in k.lower() or "company" in k.lower():
                                auth_state_defaults[k] = "tenant_user_pass"
                            elif "sso" in k.lower():
                                auth_state_defaults[k] = "user_sso"
                            else:
                                auth_state_defaults[k] = "tenant_user_pass"
                    ls_items = jwt_headers_to_local_storage(headers_to_inject, storage_keys=list(token_keys))
                    # merge auth state defaults
                    for k, v in auth_state_defaults.items():
                        if k not in ls_items:
                            ls_items[k] = v
                    if ls_items:
                        existing_ls = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
                        try:
                            existing_items = json.loads(existing_ls) if existing_ls else {}
                        except Exception:
                            existing_items = {}
                        if not isinstance(existing_items, dict):
                            existing_items = {}
                        merged_items = {**existing_items, **ls_items}
                        os.environ["PENTEST_INJECT_LOCAL_STORAGE"] = json.dumps(merged_items, ensure_ascii=False)
                        self._report(
                            f"  [{role}] 🔑 JS 分析发现 {len(storage_keys)} 个 auth storage key，"
                            f"已合并 {len(merged_items)} 个 localStorage 注入项"
                        )
            except Exception as _e:
                log.debug("JS 分析失败: %s", _e)
            # 兼容旧字段
            result.js_endpoints = [api.path for api in js_analysis.api_calls]
            # ★ 输出 JS 分析结果摘要
            if js_analysis.api_calls or js_analysis.routes:
                self._report(
                    f"  [{role}] 📦 JS 分析完成: {js_analysis.js_files_analyzed} 个文件, "
                    f"发现 {len(js_analysis.api_calls)} 个 API 路径, "
                    f"{len(js_analysis.routes)} 个前端路由"
                )

            # 汇总 API
            # ★ 区分业务 API 和其他请求，给用户更丰富的信息
            api_count = 0
            other_count = 0
            api_prefixes = set()
            for req in captured:
                req_url = req.get('url', '')
                key = f"{req['method']} {req_url.split('?')[0]}"
                if key not in result.api_endpoints:
                    result.api_endpoints[key] = req
                # 统计
                if '/api/' in req_url or '/api-' in req_url:
                    api_count += 1
                    # 提取前缀（如 /api/enerdigit/system）
                    parts = req_url.split('/api/')[-1].split('/') if '/api/' in req_url else []
                    if len(parts) >= 2:
                        api_prefixes.add(f"/api/{parts[0]}/{parts[1]}")
                    elif parts:
                        api_prefixes.add(f"/api/{parts[0]}")
                else:
                    other_count += 1

            self._report(f"  [{role}] 爬取完成: {len(result.pages)} 个页面, "
                        f"{len(captured)} 条请求 (业务API: {api_count}, 其他: {other_count})")
            if api_prefixes:
                self._report(f"  [{role}] API 模块: {', '.join(sorted(api_prefixes)[:10])}"
                            f"{'...' if len(api_prefixes) > 10 else ''}")

        finally:
            # ★ 兜底 API 汇总：如果因超时/cancel导致正常汇总代码被跳过，
            # 在 finally 中把 captured 中的请求补录到 result.api_endpoints，
            # 确保 get_partial_result() 能拿到已抓的 API 数据。
            if not result.api_endpoints and captured:
                for req in captured:
                    req_url = req.get('url', '')
                    key = f"{req['method']} {req_url.split('?')[0]}"
                    if key not in result.api_endpoints:
                        result.api_endpoints[key] = req
            await browser.close()
            await pw.stop()

        return result


    async def _crawl_page(self, page, url: str, captured: list) -> CrawledPage | None:
        """爬取单个页面。"""
        # ★ 2026-05-22: 引入轮询噪音探测器，识别 refetchInterval/WebSocket 重连/
        # 热门内容轮询等永不停歇的请求，避免 networkidle 永远不触发导致超时。
        # 仅在本页内生效，不污染外层 captured 与 mitmproxy 数据。
        _noise = _NoiseDetector(enabled=_NOISE_DETECT_ENABLED)
        # ★ 2026-05-22 v2: 把当前页噪音探测器暴露给主循环的自适应超时机制
        self._current_page_noise_detector = _noise

        def _noise_listener(req):
            try:
                _noise.record(req.url, req.resource_type)
            except Exception as _e:
                log.debug("噪音探测器记录失败: %s", _e)

        try:
            page.on("request", _noise_listener)
        except Exception as _e:
            log.debug("注册噪音监听器失败: %s", _e)

        # ★ 2026-05-22 v2: 用 try/finally 确保监听器一定被清理
        # 避免 task.cancel() 抛 CancelledError 时绕过所有 cleanup，导致监听器泄漏
        # （同一 page 累积监听器会让性能下降）
        result_to_return: CrawledPage | None = None
        try:
            result_to_return = await self._crawl_page_inner(
                page, url, captured, _noise, _noise_listener
            )
        finally:
            try:
                page.remove_listener("request", _noise_listener)
            except Exception as _e:
                log.debug("移除噪音监听器失败: %s", _e)
            # 清空 detector 引用，避免外层 detector_getter 拿到上一页的探测器
            self._current_page_noise_detector = None
        return result_to_return

    async def _crawl_page_inner(
        self, page, url: str, captured: list,
        _noise, _noise_listener,
    ) -> CrawledPage | None:
        """爬取单页的主体逻辑（被 _crawl_page 包了 try/finally cleanup）。"""
        try:
            before_count = len(captured)
            # ★ page.goto 带重试（2 次，退避 1s/3s），仅对暂时性错误重试；
            # TargetClosed/Browser closed 等不可恢复错误立即放弃。
            resp = None
            for _goto_attempt in range(3):
                try:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    break
                except Exception as _goto_e:
                    _goto_err = str(_goto_e)
                    # 不可重试：page/browser 已关闭
                    if ("Target page has been closed" in _goto_err
                            or "Browser has been closed" in _goto_err
                            or "Target closed" in _goto_err):
                        raise
                    if _goto_attempt < 2:
                        import asyncio as _aio
                        _wait_s = 1.0 * (_goto_attempt + 1)
                        log.warning("page.goto 失败(%d/2)，%0.1fs 后重试: %s",
                                    _goto_attempt + 1, _wait_s, _goto_err[:120])
                        await _aio.sleep(_wait_s)
                    else:
                        raise
            # ★ 2026-05-20 修复：之前 `status >= 400 直接 return None` 太激进
            # 实际场景中：
            # 1) SPA hash URL（如 #/login）服务端拿到的是 / 后的资源路径，可能配置异常返回 500
            # 2) 某些站对 robots.txt / favicon 等返回 5xx，连带影响入口判断
            # 3) page.goto 对 same-origin hash 跳转可能返回非典型 status
            # 但页面其实正常渲染（主 Agent 用 browser_goto 不判 status 就能继续操作即为证据）
            # 修复策略：resp 为 None 才放弃；status >= 400 时先用 JS 探页面是否真有内容，
            # 有内容就继续爬取，避免因 HTTP status 异常导致整轮 0 页面
            if not resp:
                # page.goto 返回 None 通常是 same-origin hash 跳转不发新请求
                # 对于 hash 路由：用 JS 直接修改 location.hash 并等待渲染，然后继续爬
                try:
                    parsed_hash = ""
                    if "#" in url:
                        parsed_hash = url.split("#", 1)[1]
                    if parsed_hash:
                        await page.evaluate(f"() => {{ location.hash = '/{parsed_hash.lstrip('/')}'; }}")
                        await asyncio.sleep(1)
                        await _smart_wait_for_idle(page, _noise, max_wait_s=2.0)
                        self._report(f"  [hash路由] 已跳转: #{parsed_hash[:50]}, 当前: {page.url[:60]}")
                    else:
                        # 非 hash 路由但 goto 返回 None，通常是同域重复请求，继续处理当前页面
                        self._report(f"  ⚠️ _crawl_page: page.goto 返回 None, url={url[:60]}, page.url={page.url[:60]}")
                except Exception as _e:
                    log.debug("hash 路由跳转失败: %s", _e)
                # 不 return None，继续往下爬取当前渲染出的内容
            elif resp.status >= 400:
                try:
                    # 给 SPA 一点渲染时间
                    await asyncio.sleep(2)
                    body_size = await page.evaluate(
                        "() => document.body ? (document.body.innerText || '').length : 0"
                    )
                    elem_count = await page.locator("input, button, a, [role='button']").count()
                    # 页面没内容（如真 404/503 错误页） → 放弃
                    if body_size < 50 and elem_count < 2:
                        try:
                            page.remove_listener("request", _noise_listener)
                        except Exception as _e:
                            log.debug("移除噪音监听器失败 (空页面): %s", _e)
                        return None
                    # 有内容 → 继续爬取（仅记录一行日志，不打断流程）
                    self._report(
                        f"  ⚠️ HTTP {resp.status} 但页面已渲染（{body_size} 字符 / "
                        f"{elem_count} 元素），继续爬取: {url[:60]}"
                    )
                except Exception:
                    try:
                        page.remove_listener("request", _noise_listener)
                    except Exception as _e:
                        log.debug("移除噪音监听器失败 (HTTP 异常页): %s", _e)
                    return None
            # ★ 智能等待：噪音页面立刻退出，正常页面照常等 networkidle
            await _smart_wait_for_idle(page, _noise, max_wait_s=5.0)
        except Exception as _e_outer:
            # ★ 临时调试 2026-05-20：原来这里只是 return None，导致看不见真实异常
            # 把异常类型和消息打出来，方便定位 0 页面 bug 的真实原因
            # ★ 2026-05-22 v2: Playwright 底层在某些边界 URL（404/XML 等）会抛
            # `TypeError: function takes exactly 5 arguments (N given)`，
            # 这是 Playwright greenlet 协程的内部一致性错误，已被外层 except 捕获，
            # 不影响后续爬取。降级为 debug 日志，避免污染前端。
            _err_msg = str(_e_outer)
            _err_type = type(_e_outer).__name__
            _is_playwright_internal = (
                _err_type == "TypeError"
                and "takes exactly" in _err_msg
                and "arguments" in _err_msg
            )
            try:
                if _is_playwright_internal:
                    # 已知噪音 → 写 log 文件但不推送到前端
                    import logging
                    logging.getLogger("auto_crawler").debug(
                        "Playwright 底层异常 (已忽略): %s, url=%s", _err_msg, url
                    )
                else:
                    self._report(f"  ⚠️ _crawl_page 外层异常: {_err_type}: {_err_msg[:200]}, url={url[:60]}")
            except Exception as _e:
                log.debug("异常上报失败: %s", _e)
            try:
                page.remove_listener("request", _noise_listener)
            except Exception as _e:
                log.debug("移除噪音监听器失败 (外层异常): %s", _e)
            return None

        # ★ 滚动到底部触发懒加载/无限滚动（最多 5 次，每次抓 1 秒新增请求）
        try:
            for _ in range(5):
                prev_height = await page.evaluate("() => document.body.scrollHeight")
                await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(0.8)
                await _smart_wait_for_idle(page, _noise, max_wait_s=2.0)
                new_height = await page.evaluate("() => document.body.scrollHeight")
                if new_height <= prev_height:
                    # 没有新内容加载了
                    break
            # 滚回顶部，确保后续按钮点击不被遮挡
            await page.evaluate("() => window.scrollTo(0, 0)")
        except Exception as _e:
            log.debug("滚动触发懒加载失败: %s", _e)

        # ★ 主动点击"加载更多"类按钮（常见无限滚动替代实现）
        try:
            for _ in range(3):
                clicked = await page.evaluate("""() => {
                    const texts = ['加载更多', '查看更多', '更多', '下一页', 'Load more', 'More', 'Next'];
                    const btns = document.querySelectorAll('button, a, [role="button"]');
                    for (const btn of btns) {
                        const t = (btn.textContent || '').trim();
                        if (texts.some(x => t === x || t.includes(x)) && btn.offsetParent !== null) {
                            btn.click();
                            return true;
                        }
                    }
                    return false;
                }""")
                if not clicked:
                    break
                await asyncio.sleep(0.6)
                await _smart_wait_for_idle(page, _noise, max_wait_s=2.0)
        except Exception as _e:
            log.debug("点击加载更多失败: %s", _e)

        title = await page.title()
        load_requests = captured[before_count:]

        page_info = await page.evaluate("""() => {
            const result = {links: [], forms: [], clickables: [], menus: []};

            document.querySelectorAll('a[href]').forEach(a => {
                if (a.href && a.href.startsWith('http')) result.links.push(a.href);
            });
            result.links = [...new Set(result.links)];

            document.querySelectorAll('form').forEach((f, i) => {
                result.forms.push({
                    action: f.action, method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.elements).map(e => ({
                        tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '',
                        id: e.id || '', placeholder: e.placeholder || '', required: e.required,
                    })).filter(e => e.name),
                    selector: f.id ? `#${f.id}` : `form:nth-of-type(${i+1})`,
                });
            });

            // 全量可点击元素（不限数量）
            // ★ 2026-05-28: 补充更多 UI 框架的可点击元素选择器
            const sels = 'button, input[type=submit], input[type=button], [role=button], [onclick], [role=tab], .nav-link, .menu-item, [data-toggle], [aria-haspopup], [role=menuitem], .el-menu-item, .ant-menu-item, .sidebar-item, .nav-item a, .el-submenu__title, .ant-menu-submenu-title, .MuiListItem-root, .MuiMenuItem-root, .MuiButton-root, .v-list-item, .v-btn, .n-menu-item, .arco-menu-item, .t-menu__item, .ivu-menu-item, [class*="menu-item"], [class*="nav-item"], [data-menu-item]';
            // 导航容器判断：覆盖主流框架 + Web Component + 通用属性特征
            const NAV_CTX = 'nav, [role=navigation], .sidebar, .el-menu, .ant-menu, .nav-menu, ' +
                '.ant-layout-sider, .el-aside, ' +
                // Web Component 自定义导航（Freshworks/各类 SaaS）
                '[class*="sidebar"], [class*="nav-"], [class*="-nav"], [id*="sidebar"], [id*="nav-menu"], ' +
                '[class*="NavigationMenu"], [class*="SideNav"], [class*="AppNav"], ' +
                // ★ 2026-05-28 新增：更多 UI 框架
                // Material UI / MUI
                '.MuiDrawer-root, .MuiList-root, [class*="MuiNav"], [class*="MuiDrawer"], ' +
                // Chakra UI
                '[class*="chakra-sidebar"], [class*="chakra-nav"], ' +
                // Vuetify
                '.v-navigation-drawer, .v-list, [class*="v-navigation"], ' +
                // Naive UI / Arco Design
                '.n-menu, .n-layout-sider, .arco-menu, .arco-layout-sider, ' +
                // TDesign / iView / View Design
                '.t-menu, .t-aside, .ivu-menu, .ivu-layout-sider, ' +
                // Bootstrap
                '.navbar-nav, .nav-sidebar, .offcanvas, ' +
                // Tailwind UI / Headless UI
                '[class*="Sidebar"], [class*="sidebar-nav"], [class*="side-nav"], ' +
                // 通用属性特征
                '[data-sidebar], [data-nav], [aria-label*="navigation" i], [aria-label*="sidebar" i], ' +
                '[aria-label*="menu" i], [data-testid*="nav" i], [data-testid*="sidebar" i], [data-testid*="menu" i]';
            // ★ 2026-05-28 新增：底部固定导航 / TabBar 检测函数
            // 覆盖移动端 H5 底部 TabBar、管理后台底部固定操作栏
            function isInFixedBottomNav(el) {
                let node = el;
                for (let i = 0; i < 8; i++) {
                    if (!node || node === document.body || node === document.documentElement) break;
                    const style = window.getComputedStyle(node);
                    const pos = style.position;
                    // fixed/sticky 且贴近底部的容器
                    if ((pos === 'fixed' || pos === 'sticky') && 
                        (style.bottom === '0px' || parseInt(style.bottom) <= 10)) {
                        return true;
                    }
                    // 常见 TabBar class 名
                    const cls = (node.className || '').toString().toLowerCase();
                    if (cls.includes('tabbar') || cls.includes('tab-bar') || 
                        cls.includes('bottom-nav') || cls.includes('footer-nav') ||
                        cls.includes('dock') || cls.includes('bottom-menu')) {
                        return true;
                    }
                    node = node.parentElement;
                }
                return false;
            }

            let idx = 0;
            document.querySelectorAll(sels).forEach((el) => {
                const text = (el.textContent || el.value || '').trim().slice(0, 50);
                if (!text) return;
                // ★ 2026-05-28 修复：过滤不可见元素（解决标记了隐藏菜单导致选择器失效的问题）
                const rect = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                if (el.offsetParent === null && style.position !== 'fixed' && style.position !== 'sticky') return;
                if (style.display === 'none' || style.visibility === 'hidden') return;
                if (rect.width <= 0 || rect.height <= 0) return;
                if (parseFloat(style.opacity) === 0) return;
                // ★ 2026-05-28 修复：过滤 CSS/SVG 垃圾文本（如 "#eQCu9oBhsxn1{pointer-ev"）
                if (/[{}]/.test(text) || /^[#.][a-zA-Z0-9_-]+\{/.test(text)) return;
                // 过滤纯符号/数字文本（不太可能是菜单项）
                if (/^[^a-zA-Z\u4e00-\u9fff]+$/.test(text) && text.length < 3) return;
                el.setAttribute('data-crawl-idx', String(idx));
                result.clickables.push({
                    tag: el.tagName.toLowerCase(), text: text,
                    type: el.type || '', id: el.id || '',
                    selector: el.id ? `#${el.id}` : `[data-crawl-idx="${idx}"]`,
                    isMenu: !!(el.closest(NAV_CTX)) || isInFixedBottomNav(el),
                });
                idx++;
            });

            // ★ 2026-05-28 新增：专门提取底部固定导航栏（TabBar）中的菜单项
            // 移动端 H5 / 混合 App 常见底部 TabBar，不在 NAV_CTX 覆盖范围内
            const fixedBottomEls = document.querySelectorAll(
                '[class*="tabbar"], [class*="tab-bar"], [class*="bottom-nav"], ' +
                '[class*="footer-nav"], [class*="dock"], [class*="bottom-menu"], ' +
                '.van-tabbar, .nut-tabbar, .weui-tabbar, .mint-tabbar, ' +
                '.uni-tabbar, .taro-tabbar'
            );
            fixedBottomEls.forEach((container) => {
                // 也检查 position:fixed + bottom:0 的通用容器
                const style = window.getComputedStyle(container);
                const isFixed = (style.position === 'fixed' || style.position === 'sticky') &&
                    (style.bottom === '0px' || parseInt(style.bottom) <= 10);
                const clsMatch = (container.className || '').toString().toLowerCase();
                const isTabBar = clsMatch.includes('tabbar') || clsMatch.includes('tab-bar') ||
                    clsMatch.includes('bottom-nav') || clsMatch.includes('dock');
                if (!isFixed && !isTabBar) return;
                // 提取 TabBar 内的可点击项
                const items = container.querySelectorAll('a, [role=tab], [role=button], button, .van-tabbar-item, .nut-tabbar-item, [class*="tab-item"], [class*="tabbar-item"]');
                items.forEach((item, i) => {
                    const text = (item.textContent || '').trim().slice(0, 40);
                    if (!text || text.length < 1) return;
                    item.setAttribute('data-tabbar-idx', String(i));
                    // 避免重复添加（已被 sels 选中的跳过）
                    if (item.hasAttribute('data-crawl-idx')) return;
                    result.clickables.push({
                        tag: item.tagName.toLowerCase(), text: text,
                        type: item.type || '', id: item.id || '',
                        selector: item.id ? `#${item.id}` : `[data-tabbar-idx="${i}"]`,
                        isMenu: true,  // TabBar 项视为菜单
                        isTabBar: true,
                    });
                });
            });

            // ★ 2026-05-28 新增：position:fixed + bottom 的通用容器也作为菜单容器
            document.querySelectorAll('*').forEach((el) => {
                if (el.children.length < 2 || el.children.length > 12) return;
                const style = window.getComputedStyle(el);
                if ((style.position === 'fixed' || style.position === 'sticky') &&
                    (style.bottom === '0px' || parseInt(style.bottom) <= 10) &&
                    el.offsetHeight > 30 && el.offsetHeight < 120) {
                    // 这是一个底部固定导航栏，提取其中的菜单项
                    const items = [];
                    el.querySelectorAll('a, button, [role=tab], [role=button], span, div').forEach((child, i) => {
                        const text = (child.textContent || '').trim().slice(0, 40);
                        if (!text || text.length < 1 || child.children.length > 3) return;
                        // 只取叶子节点或浅层节点
                        if (child.querySelector('a, button, [role=tab]') && child.tagName !== 'A' && child.tagName !== 'BUTTON') return;
                        items.push({
                            text: text, tag: child.tagName.toLowerCase(),
                            selector: child.id ? `#${child.id}` : `[data-crawl-idx="${child.getAttribute('data-crawl-idx') || ''}"]`,
                            hasChildren: false,
                        });
                    });
                    if (items.length >= 2) {
                        result.menus.push({container: 'FIXED_BOTTOM_NAV', items: items});
                    }
                }
            });

            // 识别导航菜单容器（用于二三级菜单展开）
            // ★ 2026-05-28: 与 NAV_CTX 保持同步，覆盖更多 UI 框架
            const menuSels = 'nav, [role=navigation], .sidebar, .el-menu, .ant-menu, .nav-menu, ' +
                '.ant-layout-sider, .el-aside, ' +
                '[class*="sidebar"], [class*="nav-"], [class*="-nav"], [id*="sidebar"], [id*="nav-menu"], ' +
                '[class*="NavigationMenu"], [class*="SideNav"], [class*="AppNav"], ' +
                // Material UI / MUI
                '.MuiDrawer-root, .MuiList-root, [class*="MuiNav"], [class*="MuiDrawer"], ' +
                // Vuetify / Naive UI / Arco Design
                '.v-navigation-drawer, .v-list, .n-menu, .n-layout-sider, .arco-menu, .arco-layout-sider, ' +
                // TDesign / iView / Bootstrap
                '.t-menu, .t-aside, .ivu-menu, .ivu-layout-sider, .navbar-nav, .nav-sidebar, ' +
                // Tailwind / Headless UI
                '[class*="Sidebar"], [class*="sidebar-nav"], [class*="side-nav"], ' +
                '[data-sidebar], [data-nav], [aria-label*="navigation" i], [aria-label*="sidebar" i], ' +
                '[aria-label*="menu" i], [data-testid*="nav" i], [data-testid*="sidebar" i], [data-testid*="menu" i]';
            // 过滤掉内容像用户名/邮箱/纯数字ID的误识别文本
            const EMAIL_RE = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
            const NUMERIC_RE = /^[0-9\\-_]{4,}$/;
            const SKIP_TEXT_RE = /^(loading|spinner|tooltip|placeholder)$/i;
            document.querySelectorAll(menuSels).forEach((m) => {
                const items = m.querySelectorAll('a, [role=menuitem], .el-menu-item, .ant-menu-item, .el-submenu__title, .ant-menu-submenu-title, li > span, li > div, .MuiListItem-root, .MuiMenuItem-root, .v-list-item, .n-menu-item, .arco-menu-item, .t-menu__item, .ivu-menu-item, .nav-link, .navbar-nav .nav-item');
                const menuItems = [];
                items.forEach((item, i) => {
                    const text = (item.textContent || '').trim().slice(0, 40);
                    if (!text || text.length < 2) return;
                    // 过滤邮箱、纯数字ID、无意义占位文本
                    if (EMAIL_RE.test(text) || NUMERIC_RE.test(text) || SKIP_TEXT_RE.test(text)) return;
                    // 过滤包含邮箱的混合文本（如 "Andreaandrea@freshse..."）
                    if (text.includes('@') && text.includes('.')) return;
                    item.setAttribute('data-menu-idx', String(i));
                    menuItems.push({
                        text: text, tag: item.tagName.toLowerCase(),
                        selector: item.id ? `#${item.id}` : `[data-menu-idx="${i}"]`,
                        hasChildren: !!(item.querySelector('ul, .el-submenu, .ant-menu-sub, .v-list-group, .n-submenu, .arco-menu-inline, .MuiCollapse-root, [aria-haspopup], [aria-expanded]')),
                    });
                });
                if (menuItems.length > 0) {
                    result.menus.push({container: m.tagName, items: menuItems});
                }
            });

            // ★ Shadow DOM 穿透：递归遍历所有 Shadow Root，提取其中的导航/链接/表单
            // 覆盖 Salesforce、ServiceNow、Workday、各类 Web Component 框架
            function extractFromShadowRoot(root, depth) {
                if (depth > 5) return;  // 最多 5 层，防止无限递归
                root.querySelectorAll('*').forEach(el => {
                    // 递归进入子 Shadow Root
                    if (el.shadowRoot) extractFromShadowRoot(el.shadowRoot, depth + 1);

                    // 提取链接
                    if (el.tagName === 'A' && el.href && el.href.startsWith('http')) {
                        result.links.push(el.href);
                    }

                    // 提取表单
                    if (el.tagName === 'FORM') {
                        result.forms.push({
                            action: el.action || '', method: (el.method || 'GET').toUpperCase(),
                            inputs: Array.from(el.elements || []).map(e => ({
                                tag: e.tagName.toLowerCase(), type: e.type || '',
                                name: e.name || '', id: e.id || '',
                                placeholder: e.placeholder || '', required: e.required,
                            })).filter(e => e.name),
                            selector: el.id ? `#${el.id}` : 'shadow-form',
                        });
                    }

                    // 提取可点击元素
                    const tag = el.tagName.toLowerCase();
                    const isClickable = (
                        tag === 'button' || tag === 'a' ||
                        el.getAttribute('role') === 'button' ||
                        el.getAttribute('role') === 'menuitem' ||
                        el.getAttribute('role') === 'tab' ||
                        el.hasAttribute('onclick') ||
                        (el.className && typeof el.className === 'string' && (
                            el.className.includes('menu-item') ||
                            el.className.includes('nav-item') ||
                            el.className.includes('sidebar-item')
                        ))
                    );
                    if (isClickable) {
                        const text = (el.textContent || el.value || '').trim().slice(0, 50);
                        if (text && text.length >= 2 && !EMAIL_RE.test(text) && !NUMERIC_RE.test(text)) {
                            // Shadow DOM 内元素无法用普通选择器定位，记录为特殊标记
                            result.clickables.push({
                                tag: tag, text: text, type: el.type || '', id: el.id || '',
                                selector: el.id ? `#${el.id}` : `shadow::${tag}[text="${text.slice(0,20)}"]`,
                                isMenu: true,  // Shadow DOM 内的导航项优先视为菜单
                                isShadow: true,
                            });
                        }
                    }
                });
            }
            // 遍历所有顶层 Shadow Host
            document.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) extractFromShadowRoot(el.shadowRoot, 0);
            });
            // links 去重
            result.links = [...new Set(result.links)];

            return result;
        }""")

        # ★ iframe 遍历：在所有 iframe 内执行同样的提取，合并到主结果
        # 注：page.frames 第一个是主 frame（已经 evaluate 过了），从第二个开始才是 iframe
        try:
            iframe_results = []
            for frame in page.frames[1:]:  # 跳过主 frame
                try:
                    if not frame.url or frame.url.startswith(("about:", "javascript:", "data:")):
                        continue
                    # 跨域 iframe 直接 evaluate 会被浏览器拦，try 一下即可
                    sub_info = await frame.evaluate("""() => {
                        const result = {links: [], forms: [], clickables: []};
                        document.querySelectorAll('a[href]').forEach(a => {
                            if (a.href && a.href.startsWith('http')) result.links.push(a.href);
                        });
                        result.links = [...new Set(result.links)];
                        document.querySelectorAll('form').forEach((f, i) => {
                            result.forms.push({
                                action: f.action, method: (f.method || 'GET').toUpperCase(),
                                inputs: Array.from(f.elements).map(e => ({
                                    tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '',
                                    id: e.id || '', placeholder: e.placeholder || '', required: e.required,
                                })).filter(e => e.name),
                                selector: f.id ? `#${f.id}` : `form:nth-of-type(${i+1})`,
                            });
                        });
                        const sels = 'button, input[type=submit], input[type=button], [role=button], [role=tab], .nav-link, .menu-item, .el-menu-item, .ant-menu-item';
                        document.querySelectorAll(sels).forEach((el, i) => {
                            const text = (el.textContent || el.value || '').trim().slice(0, 50);
                            if (text) result.clickables.push({
                                tag: el.tagName.toLowerCase(), text: text,
                                selector: el.id ? `#${el.id}` : `${el.tagName.toLowerCase()}:nth-of-type(${i+1})`,
                            });
                        });
                        return result;
                    }""")
                    if sub_info and (sub_info.get("links") or sub_info.get("forms") or sub_info.get("clickables")):
                        iframe_results.append({"url": frame.url, "info": sub_info})
                except Exception:
                    # 跨域 iframe 或访问失败，静默跳过
                    continue

            # 把 iframe 的内容合并到主 page_info
            if iframe_results:
                self._report(f"  [{url[:40]}] 🖼️ 发现 {len(iframe_results)} 个 iframe，提取了内嵌内容")
                for ifr in iframe_results:
                    info = ifr["info"]
                    page_info["links"] = page_info.get("links", []) + info.get("links", [])
                    page_info["forms"] = page_info.get("forms", []) + info.get("forms", [])
                    page_info["clickables"] = page_info.get("clickables", []) + info.get("clickables", [])
                # 去重 links
                page_info["links"] = list(set(page_info["links"]))
        except Exception as _e:
            log.debug("iframe 内容提取失败: %s", _e)

        crawled = CrawledPage(
            url=url, title=title,
            links=page_info.get("links", []),
            requests_during_load=[dict(r) for r in load_requests],
        )

        # ---- Phase A: 展开全部菜单（递归多层），收集所有可见菜单项 ----
        # ★ 2026-05-28 改造：支持递归展开最多 3 层子菜单（原来只展开 1 层）
        self._report(f"  [{url[:40]}] 展开菜单...")
        _expanded_selectors: set[str] = set()  # 已展开的选择器（避免重复展开）
        MAX_EXPAND_DEPTH = 3

        async def _expand_menu_level(menus_data: list, depth: int = 0):
            """递归展开菜单层级。"""
            if depth >= MAX_EXPAND_DEPTH:
                return
            for menu in menus_data:
                items = menu.get("items", []) if isinstance(menu, dict) else []
                for item in items:
                    if not item.get("hasChildren"):
                        continue
                    sel = item.get("selector", "")
                    if not sel or sel in _expanded_selectors:
                        continue
                    _expanded_selectors.add(sel)
                    try:
                        await page.hover(sel, timeout=2000)
                        await asyncio.sleep(0.4)
                    except Exception:
                        try:
                            await page.click(sel, timeout=2000)
                            await asyncio.sleep(0.4)
                        except Exception:
                            continue

            # 展开后检测是否有新的子菜单出现（递归下一层）
            if depth < MAX_EXPAND_DEPTH - 1:
                new_children = await page.evaluate("""() => {
                    const results = [];
                    const sels = '.el-submenu.is-opened .el-submenu__title, ' +
                        '.ant-menu-submenu-open .ant-menu-submenu-title, ' +
                        '[aria-expanded="true"] [aria-haspopup], ' +
                        '.el-submenu.is-opened .el-submenu .el-submenu__title, ' +
                        '.ant-menu-submenu-open .ant-menu-submenu .ant-menu-submenu-title';
                    document.querySelectorAll(sels).forEach((el) => {
                        const text = (el.textContent || '').trim().slice(0, 40);
                        if (!text || text.length < 2) return;
                        const hasKids = !!(el.querySelector('ul, .el-submenu, .ant-menu-sub') ||
                            el.closest('[aria-haspopup]'));
                        if (hasKids) {
                            const idx = 20000 + results.length;
                            el.setAttribute('data-expand-idx', String(idx));
                            results.push({
                                text: text,
                                selector: `[data-expand-idx="${idx}"]`,
                                hasChildren: true,
                            });
                        }
                    });
                    return [{items: results}];
                }""")
                if new_children and new_children[0].get("items"):
                    new_items = [i for i in new_children[0]["items"]
                                 if i.get("selector") not in _expanded_selectors]
                    if new_items:
                        await _expand_menu_level(new_children, depth + 1)

        await _expand_menu_level(page_info.get("menus", []), 0)

        # 菜单展开后重新提取（可能有新的子菜单项出现）
        expanded_info = await page.evaluate("""() => {
            const items = [];
            const sels = '[role=menuitem], .el-menu-item, .ant-menu-item, a[href], .el-submenu .el-menu-item, .ant-menu-sub .ant-menu-item, .sidebar a, .nav-item a, .menu-item a';
            let idx = 10000;
            document.querySelectorAll(sels).forEach((el) => {
                if (el.getAttribute('data-crawl-idx')) return;
                const text = (el.textContent || '').trim().slice(0, 50);
                if (!text || text.length < 2) return;
                // 跳过不可见元素
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return;
                el.setAttribute('data-crawl-idx', String(idx));
                // ★ 2026-05-22 v3: 一并采集 href（任务级菜单去重需要）
                let href = '';
                try {
                    if (el.tagName === 'A' && el.href) {
                        href = el.href;
                    } else {
                        const a = el.closest('a[href]') || el.querySelector('a[href]');
                        if (a && a.href) href = a.href;
                    }
                } catch (e) {}
                items.push({
                    tag: el.tagName.toLowerCase(), text: text,
                    selector: `[data-crawl-idx="${idx}"]`,
                    href: href,
                    isMenu: true,
                });
                idx++;
            });
            return items;
        }""")
        page_info["clickables"].extend(expanded_info)

        # ---- Phase B: SPA 菜单遍历模式 ----
        # 策略：先收集所有菜单项 → 逐个点击 → 在子页面停留等待 API 加载 → 收集请求 → 再点下一个
        # 不再用 goto(url) 跳回原页面（SPA 中这会重置状态）
        menu_items = [e for e in page_info.get("clickables", []) if e.get("isMenu")]
        non_menu_items = [e for e in page_info.get("clickables", []) if not e.get("isMenu")]

        # ★ 2026-05-29 降级策略：当标准选择器只识别到很少的菜单项时（≤3 个），
        # 自动扩大搜索范围，从页面中识别更多可能的导航元素。
        # 典型场景：Vue/React 自定义组件用 <div>/<span> + @click 做导航，
        # 不匹配标准 sels 选择器也不在 NAV_CTX 容器内。
        if len(menu_items) <= 3:
            try:
                fallback_nav_items = await page.evaluate("""() => {
                    const result = [];
                    const existingTexts = new Set();
                    // 收集已识别的菜单项文本，避免重复
                    document.querySelectorAll('[data-crawl-idx]').forEach(el => {
                        const t = (el.textContent || '').trim().slice(0, 50);
                        if (t) existingTexts.add(t);
                    });

                    // 策略1：查找页面侧边栏/顶部区域中的短文本可点击元素
                    // 这些元素通常是导航菜单但使用了自定义组件
                    const candidates = [];
                    document.querySelectorAll('div, span, li, a, p').forEach(el => {
                        const text = (el.textContent || '').trim();
                        // 菜单项特征：短文本（2-15字符）、无子元素或子元素很少、可见
                        if (!text || text.length < 2 || text.length > 15) return;
                        // 排除包含换行的（说明是容器而非叶子节点）
                        if (text.includes('\\n') && text.split('\\n').filter(s => s.trim()).length > 1) return;
                        // 排除已识别的
                        if (existingTexts.has(text)) return;
                        // 排除不可见元素
                        const rect = el.getBoundingClientRect();
                        if (rect.width <= 0 || rect.height <= 0) return;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') return;
                        if (parseFloat(style.opacity) === 0) return;
                        // 排除有太多子元素的容器（不是叶子节点）
                        if (el.querySelectorAll('div, span, li, a, p').length > 3) return;
                        // 排除纯数字/符号
                        if (/^[^a-zA-Z\\u4e00-\\u9fff]+$/.test(text)) return;
                        // 排除 CSS/SVG 垃圾
                        if (/[{}]/.test(text)) return;
                        candidates.push({
                            el: el, text: text,
                            rect: rect, tag: el.tagName.toLowerCase(),
                        });
                    });

                    if (candidates.length < 3) return result;

                    // 策略2：找到"成群出现"的短文本元素（同一父容器下多个相似元素）
                    // 这是导航菜单的典型特征
                    const parentGroups = new Map();
                    candidates.forEach(c => {
                        const parent = c.el.parentElement;
                        if (!parent) return;
                        // 用父元素的 DOM 路径作为分组 key
                        const key = parent.tagName + '#' + (parent.id || '') + '.' + (parent.className || '').toString().slice(0, 50);
                        if (!parentGroups.has(key)) parentGroups.set(key, []);
                        parentGroups.get(key).push(c);
                    });

                    // 找到包含 ≥3 个候选项的父容器组（很可能是导航菜单）
                    let bestGroup = null;
                    let bestSize = 0;
                    for (const [key, group] of parentGroups) {
                        if (group.length >= 3 && group.length > bestSize) {
                            bestGroup = group;
                            bestSize = group.length;
                        }
                    }

                    if (!bestGroup || bestGroup.length < 3) return result;

                    // 为这些元素生成选择器并标记
                    let fallbackIdx = 9000;  // 用高索引避免与已有的冲突
                    bestGroup.forEach(c => {
                        c.el.setAttribute('data-crawl-idx', String(fallbackIdx));
                        result.push({
                            tag: c.tag, text: c.text,
                            type: '', id: c.el.id || '',
                            selector: c.el.id ? '#' + c.el.id : '[data-crawl-idx="' + fallbackIdx + '"]',
                            isMenu: true,
                            isFallback: true,
                        });
                        fallbackIdx++;
                    });
                    return result;
                }""")
                if fallback_nav_items and len(fallback_nav_items) >= 3:
                    self._report(
                        f"  [{url[:40]}] 🔄 菜单降级识别: 标准选择器仅发现 {len(menu_items)} 项，"
                        f"降级扫描发现 {len(fallback_nav_items)} 个可能的导航项"
                    )
                    # 把降级发现的菜单项加入 menu_items
                    menu_items.extend(fallback_nav_items)
                    page_info["clickables"].extend(fallback_nav_items)
            except Exception as _fallback_err:
                self._report(f"  [{url[:40]}] ⚠️ 菜单降级扫描异常: {str(_fallback_err)[:100]}")

        # ★ 2026-05-22 v3: 任务级菜单指纹去重（修复"全站导航条循环点击"）
        # 旧逻辑：seen_texts 是单页局部 set —— 每个新页面都把全站共享的导航菜单（Platform/
        #   Solutions/Pricing/Sign in...）从头点一遍，刷出大量重复 API（mutinyhq、linkedin
        #   ccm 等第三方追踪），导致整个 BFS 陷入"22菜单×N页面"的伪循环。
        # 新逻辑：用 (text, href_path) 作为任务级指纹，整个 AutoCrawler 实例内只点一次。
        #   - 有 href：标准化为 host+path+fragment（去 query 追踪参数）。
        #     ★ 2026-05-22 v3.1: 不带 query。原因：launchdarkly 这种官网每个页面的导航
        #       链接带不同 utm_source / source 追踪参数（utm_source=homepage vs
        #       utm_source=maintenance），同一个"Platform"按钮被当成不同菜单。
        #       query 99% 是追踪参数，对"链接到哪里"没语义贡献；保留 fragment 是因为
        #       SPA 用 hash 路由。
        #   - 无 href（按钮型菜单 / hover 触发型）：仅用 text 做全站指纹
        #     ★ 2026-05-22 v3.2: 实测发现 launchdarkly 的 "Platform/Solutions/
        #       Resources/Developers" 都是 hover 按钮（无 href），原 fallback 用
        #       page_path 隔离 → 每页都被当作新按钮 → 全站导航条仍循环点击。
        #       Phase B 是菜单遍历，按钮型菜单出现在这里 99% 是全站导航触发器，
        #       同名 text 在不同页面行为基本一致。同名"提交"等通用按钮的损失由
        #       Phase C（按钮专属循环）兜底，不影响菜单遍历的核心目标。
        def _menu_fingerprint(item: dict, page_url: str) -> tuple[str, str] | None:
            text = (item.get("text") or "").strip()
            if not text:
                return None
            href = (item.get("href") or "").strip()
            if href:
                try:
                    p = urlparse(href)
                    # host + path + fragment（不带 query 追踪参数）
                    # 跨域链接保留 host（不同域同 path 不应去重）
                    host = (p.netloc or "").lower()
                    path = p.path or "/"
                    frag = ("#" + p.fragment) if p.fragment else ""
                    key = f"{host}{path}{frag}"
                    return (text, key)
                except Exception:
                    return (text, href)
            else:
                # 无 href 按钮：仅 text 做全站指纹
                return (text, "@btn")

        unique_menu_items = []
        local_seen: set[tuple[str, str]] = set()  # 单页内同样要去重，避免页内同名菜单重复入列
        local_dup_skipped = 0
        for item in menu_items:
            fp = _menu_fingerprint(item, url)
            if fp is None:
                continue
            # 单页内去重（同一页面同样指纹只保留第一个）
            if fp in local_seen:
                continue
            local_seen.add(fp)
            # 任务级去重：上一个页面已经点过的菜单项，本页直接跳过
            if fp in self._global_clicked_menu_fingerprints:
                local_dup_skipped += 1
                continue
            unique_menu_items.append(item)
            # 关键：把指纹写在 item 里，点击成功后再 commit 到全局 set（失败不写入，下次还能重试）
            item["_fingerprint"] = fp

        if local_dup_skipped:
            self._global_menu_dedup_skipped += local_dup_skipped
            self._report(
                f"  [{url[:40]}] 🔁 任务级菜单去重: 跳过 {local_dup_skipped} 个已点过的导航项 "
                f"(累计已跳过 {self._global_menu_dedup_skipped})"
            )

        self._report(f"  [{url[:40]}] 发现 {len(unique_menu_items)} 个菜单项, {len(non_menu_items)} 个按钮")
        # ★ 2026-05-27: 菜单分析完成 → tick+1，防止菜单展开/去重/排序阶段 silent_timeout 误判
        self._progress_tick += 1

        # ★ 2026-05-22 v4: 菜单优先级排序
        # 痛点：99 个菜单按 DOM 顺序点 → "登录"排第 50 → 预算耗尽时未爬到关键入口
        # 方案：根据当前角色 + 营销特征词占比识别模式（marketing / business / post_login），
        # 用 200+ 关键词 + href 模式打分，把高价值菜单提到前面。
        # 详见 core/crawler/menu_ranker.py。
        try:
            _menu_mode = detect_menu_mode(
                self._current_role, unique_menu_items
            )
            _ranked = rank_menus(unique_menu_items, mode=_menu_mode, page_url=url)
            # 仅当排序确实改变了顺序时打印日志（避免业务系统全 0 分时刷屏）
            if _ranked and _ranked != unique_menu_items:
                top5 = get_top_n_summary(_ranked, _menu_mode, n=5)
                top5_str = ", ".join(f"「{t}」({s:+d})" for t, s in top5)
                self._report(
                    f"  [{url[:40]}] 📊 菜单模式: {_menu_mode}，"
                    f"按价值排序后前 5: {top5_str}"
                )
            unique_menu_items = _ranked
        except Exception as _e:
            # 排序失败不影响爬取，回退到原顺序
            self._report(f"  [{url[:40]}] ⚠️ 菜单排序失败，回退原顺序: {type(_e).__name__}")

        # 记录初始 hash（SPA 用 hash 路由）
        initial_hash = await page.evaluate("() => location.hash") or ""
        initial_url = page.url

        max_menu_clicks = 300  # SPA 菜单项可能很多（后台系统 50-300 个）
        clicked_count = 0
        total_menu = len(unique_menu_items[:max_menu_clicks])

        # ★ 2026-05-22 v3: 单菜单"业务请求自适应等待"
        # 旧逻辑：每个菜单点击后 sleep(0.5) + smart_wait_for_idle(5s) + sleep(0.3) ≈ 5.8s
        #   → 49 个菜单 × 5.8s ≈ 284s 远超 180s 硬超时 → 22/49 被强制 cancel 丢数据
        #   → 直接砍超时会误伤业务慢响应（企业后台 XHR 3-5s 才回是常态）
        # 新逻辑：监控 captured 长度变化 + 业务 host 命中（in-scope）来决定等多久
        #   - 0.5s 静默期内没有任何 in-scope 请求 → 静态/锚点跳转，立刻退出
        #   - 有 in-scope 请求 → 等到 0.8s 内不再有新业务请求 / 上限 4s（保慢业务）
        #   - 第三方 SDK 请求（不在 in-scope）不计入等待，避免 mutinyhq/linkedin 拖累
        async def _smart_wait_business_xhr(
            captured_ref: list,
            before_idx: int,
            *,
            initial_quiet_s: float = 5.0,
            settle_quiet_s: float = 0.8,
            max_wait_s: float = 9.0,
        ) -> int:
            """点击菜单后，自适应等待业务 API 完成。
            返回：等待结束时新增的业务（in-scope）请求数。

            2026-05-23: initial_quiet_s 从 0.5 → 5.0，max_wait_s 从 4.0 → 9.0
            原因：SPA hash 路由跳转后，前端需要 解析路由→挂载组件→useEffect发XHR，
            整个链路 1-3 秒是常态。0.5s 静默期导致大量菜单点击被判"0 个 API"，
            实际 API 请求在 0.5s 后才发出但已经没人等了。
            5s 是最大等待，发现 xhr/fetch 后立刻进第二阶段。
            """
            loop = asyncio.get_event_loop()
            deadline = loop.time() + max_wait_s
            last_business_count = 0
            last_business_ts = loop.time()

            # 第一阶段：先给 initial_quiet_s 静默期，观察是否有 in-scope 请求触发
            t0 = loop.time()
            while loop.time() - t0 < initial_quiet_s:
                # 数 in-scope 请求
                cnt = 0
                for r in captured_ref[before_idx:]:
                    if r.get("resource_type") in ("xhr", "fetch") and self._is_in_scope(r.get("url", "")):
                        cnt += 1
                if cnt > last_business_count:
                    last_business_count = cnt
                    last_business_ts = loop.time()
                    break  # 业务请求已开始 → 进第二阶段
                await asyncio.sleep(0.1)

            if last_business_count == 0:
                # 静默期内无业务请求 → 大概率静态/锚点跳转，无需再等
                return 0

            # 第二阶段：业务请求已触发，等待"settle_quiet_s 内无新请求"
            while loop.time() < deadline:
                cnt = 0
                for r in captured_ref[before_idx:]:
                    if r.get("resource_type") in ("xhr", "fetch") and self._is_in_scope(r.get("url", "")):
                        cnt += 1
                if cnt > last_business_count:
                    last_business_count = cnt
                    last_business_ts = loop.time()
                # 业务请求 settle_quiet_s 内无新增 → 认为完成
                if loop.time() - last_business_ts >= settle_quiet_s:
                    return last_business_count
                await asyncio.sleep(0.15)

            # 总等待上限到了，强制返回（保护慢业务也得让步）
            return last_business_count

        # ★ 2026-05-22 v4: 进度感知静默检测（取代 v3 的"整页时间预算"）
        # ----------------------------------------------------------
        # 痛点：v3 用 "hard - 30 = 150s" 时间预算 break，导致 bitget 99 个菜单
        #       点到第 5 个就被时间算尽强退，丢 94 个菜单。即使爬虫还在持续产 API。
        # v4 哲学：只要爬虫"在工作"，就让它继续。"不在工作"才 break。
        # 进度信号（任一增加都重置静默计时器）：
        #   - len(captured) 增加      → 仍在抓 API
        #   - clicked_count 增加      → 仍在点菜单
        #   - _iter_count 增加        → 仍在循环（即使 wait_for_selector 失败 continue）
        #     ★ 这一项是 v4.1 修复 — 避免"页面跳走后剩余菜单 selector 失效，
        #     连续 wait_for_selector 在 networkidle 之前等满 timeout"被误判为卡死
        # 阈值：
        #   - PAGE_PROGRESS_SILENCE_S = 30s  → 30 秒无任何上述信号判定卡死
        #   - PAGE_MENU_LOOP_HARD_S   = 30min 绝对兜底（任务级 25min 会先兜住）
        #
        # ★ v4.1 关键修复：页面跳走早退
        # 实测现象（bitget 任务）：点击「登录」按钮后 page.url 跳到 /login，
        # 后续 97 个菜单的 selector 都基于首页 DOM，全部失效。
        # wait_for_selector(timeout=2000) 在 page 还在加载时会等到 networkidle
        # 才返回，实测耗时 30s+（不是 2000ms），整个循环表现为"卡住不动"。
        # 处理：在每轮循环顶部检查 page.url，离开 initial_url 即早退。
        _loop = asyncio.get_event_loop()
        _last_progress_ts = _loop.time()
        _menu_absolute_deadline = _loop.time() + PAGE_MENU_LOOP_HARD_S
        _last_captured_len = len(captured)
        _last_clicked = 0
        _last_iter = 0       # 循环迭代计数也算进度信号
        _iter_count = 0
        _nav_consecutive_fail = 0  # SPA 跳转后连续失败计数
        _selector_consecutive_fail = 0  # 连续选择器失败计数（弹窗/跳转导致 DOM变化）
        self._remark_attempted = False  # 是否已尝试过重新标记 DOM
        _last_heartbeat_ts = _loop.time()  # ★ 心跳计时器：防止外层 silent_timeout 误判
        # ★ 2026-05-22 v2: 菜单点击批次让步参数
        # - 每 5 个菜单 yield 一次（让外层 wait_for 看到进度）
        # - 同时检查噪音：累计噪音命中 ≥ 3 个 path → 该页面噪音严重，剩余菜单跳过
        _BATCH_YIELD_EVERY = 5
        _NOISE_ABORT_THRESHOLD = 3  # 噪音 path 数 ≥ 3 → 中断剩余菜单点击

        for el in unique_menu_items[:max_menu_clicks]:
            _iter_count += 1

            # ★ 心跳：每 30s 发一次进度消息，防止外层 silent_timeout 误判
            # 场景：选择器失效重试、wait_for_selector 超时等导致长时间无 _report
            _hb_now = _loop.time()
            if _hb_now - _last_heartbeat_ts >= 30:
                self._report(
                    f"  [{url[:40]}] 💓 菜单点击进行中 "
                    f"({clicked_count}/{total_menu}，迭代 {_iter_count})..."
                )
                _last_heartbeat_ts = _hb_now

            # 每点一个就检查停止信号，及时退出
            if self._stop_requested:
                self._report(f"  [{url[:40]}] ⏸ 收到停止信号，菜单点击中断 ({clicked_count}/{total_menu})")
                break
            # ★ 2026-05-28 改造：连续选择器失败时先尝试重新标记 DOM（而不是直接退出）
            # 原因：React/SPA 重渲染会清除 data-crawl-idx 属性，重新标记可恢复
            if _selector_consecutive_fail >= 5:
                if not getattr(self, '_remark_attempted', False):
                    # 第一次达到阈值：尝试重新标记 DOM
                    self._remark_attempted = True
                    self._report(
                        f"  [{url[:40]}] 🔄 连续 {_selector_consecutive_fail} 个选择器失效，"
                        f"尝试重新标记 DOM..."
                    )
                    try:
                        # 等待页面稳定
                        await asyncio.sleep(2.0)
                        # 重新执行标记脚本
                        re_mark_result = await page.evaluate(f"""() => {{
                            // 清除旧标记
                            document.querySelectorAll('[data-crawl-idx]').forEach(el => {{
                                el.removeAttribute('data-crawl-idx');
                            }});
                            const sels = '{self._get_clickable_sels()}';
                            const NAV_CTX = '{self._get_nav_ctx()}';
                            let idx = 0;
                            const items = [];
                            document.querySelectorAll(sels).forEach((el) => {{
                                const text = (el.textContent || el.value || '').trim().slice(0, 50);
                                if (!text) return;
                                const rect = el.getBoundingClientRect();
                                const style = window.getComputedStyle(el);
                                if (el.offsetParent === null && style.position !== 'fixed' && style.position !== 'sticky') return;
                                if (style.display === 'none' || style.visibility === 'hidden') return;
                                if (rect.width <= 0 || rect.height <= 0) return;
                                if (parseFloat(style.opacity) === 0) return;
                                if (/[{{}}]/.test(text)) return;
                                const isMenu = !!(el.closest(NAV_CTX));
                                if (!isMenu) return;  // 重新标记时只关注菜单项
                                el.setAttribute('data-crawl-idx', String(idx));
                                items.push({{
                                    tag: el.tagName.toLowerCase(), text: text,
                                    selector: `[data-crawl-idx="${{idx}}"]`,
                                    isMenu: true,
                                }});
                                idx++;
                            }});
                            return items;
                        }}""")
                        if re_mark_result and len(re_mark_result) > 0:
                            # 用新标记的菜单项替换剩余未点击的项
                            new_items = [
                                item for item in re_mark_result
                                if item.get('text', '')[:20] not in
                                   {el.get('text', '')[:20] for el in unique_menu_items[:_iter_count]}
                            ]
                            if new_items:
                                # ★ 重新标记成功：把新菜单项追加到当前 for 循环的迭代列表末尾
                                # 由于 for 循环用的是切片副本，无法直接修改
                                # 解决方案：直接 break 出 for 循环，在外层重新开始
                                _selector_consecutive_fail = 0
                                self._report(
                                    f"  [{url[:40]}] ✅ 重新标记成功: {len(new_items)} 个菜单项"
                                )
                                # 把新菜单项存到实例变量，外层 while 循环会检测并继续
                                self._remark_new_items = new_items
                                break  # 跳出 for 循环
                            else:
                                self._report(
                                    f"  [{url[:40]}] ⚠️ 重新标记后无新菜单项，结束菜单阶段"
                                )
                        else:
                            self._report(
                                f"  [{url[:40]}] ⚠️ 重新标记失败（页面无可见菜单元素），结束菜单阶段"
                            )
                    except Exception as _re_err:
                        self._report(
                            f"  [{url[:40]}] ⚠️ 重新标记异常: {_re_err}，结束菜单阶段"
                        )
                    # 重新标记失败或无新项 → 退出
                    self._report(
                        f"  [{url[:40]}] 🔇 连续 {_selector_consecutive_fail} 个菜单项选择器失效"
                        f"（弹窗/跳转导致 DOM 变化），提前结束菜单阶段 "
                        f"({clicked_count}/{total_menu} 完成，剩 {total_menu - clicked_count} 个延后)"
                    )
                    break
                else:
                    # 已经尝试过重新标记了，直接退出
                    self._report(
                        f"  [{url[:40]}] 🔇 连续 {_selector_consecutive_fail} 个菜单项选择器失效"
                        f"（重新标记后仍失败），提前结束菜单阶段 "
                        f"({clicked_count}/{total_menu} 完成，剩 {total_menu - clicked_count} 个延后)"
                    )
                    break
            # ★ v4.2: 页面跳转后区分同域(SPA) vs 跨域，采取不同策略
            # - 同域路由变化（SPA hash/history）：侧边栏通常还在，继续点下一个菜单
            # - 跨域跳转（如 Login→SSO）：菜单 selector 必然失效，应 goto 回去再继续
            try:
                _current_page_url = page.url
            except Exception:
                _current_page_url = initial_url
            try:
                _norm_initial = self._normalize_url(initial_url)
                _norm_current = self._normalize_url(_current_page_url)
            except Exception:
                _norm_initial = initial_url
                _norm_current = _current_page_url
            if _norm_current and _norm_current != _norm_initial:
                # 区分同域(SPA) vs 跨域跳转
                _cross_domain = False
                try:
                    from urllib.parse import urlparse as _urlparse
                    _parsed_cur = _urlparse(_current_page_url)
                    _parsed_ini = _urlparse(initial_url)
                    # ★ 比较完整 origin（hostname + port），避免同 hostname 不同端口被误判为同域
                    _cur_origin = (_parsed_cur.hostname, _parsed_cur.port or (443 if _parsed_cur.scheme == 'https' else 80))
                    _ini_origin = (_parsed_ini.hostname, _parsed_ini.port or (443 if _parsed_ini.scheme == 'https' else 80))
                    _cross_domain = _cur_origin != _ini_origin
                except Exception:
                    _cross_domain = True
                if _cross_domain:
                    # 跨域跳转 → 尝试回初始页，后续菜单 selector 才能生效
                    try:
                        await page.goto(initial_url, wait_until="domcontentloaded", timeout=8000)
                        await asyncio.sleep(1.0)
                        # ★ 2026-05-29 修复：goto 回来后 DOM 已重新渲染，data-crawl-idx 丢失
                        # 需要重新标记 DOM，否则后续菜单项选择器全部失效
                        await _smart_wait_for_idle(page, self._current_page_noise_detector, max_wait_s=3.0)
                        _nav_consecutive_fail = 0  # 成功回去 → 重置
                        _selector_consecutive_fail = 0  # 重置选择器失败计数
                    except Exception:
                        _nav_consecutive_fail += 1
                        if _nav_consecutive_fail >= 3:
                            self._report(
                                f"  [{url[:40]}] 🔀 跨域跳转 → {_current_page_url[:60]}，"
                                f"连续 3 次无法回到初始页，提前结束 "
                                f"({clicked_count}/{total_menu} 完成)"
                            )
                            break
                else:
                    # ★ v4.3: 同域 SPA 路由变化 → 回到初始页面再继续点击下一个菜单
                    # 修复：之前只检测侧边栏是否还在，但即使侧边栏在，
                    # data-crawl-idx 属性也可能因 SPA 重渲染而丢失
                    # 正确做法：先回到初始页面，确保菜单项选择器有效
                    try:
                        await page.goto(initial_url, wait_until="domcontentloaded", timeout=8000)
                        await asyncio.sleep(1.0)
                        await _smart_wait_for_idle(page, self._current_page_noise_detector, max_wait_s=3.0)
                        _nav_consecutive_fail = 0
                        _selector_consecutive_fail = 0
                    except Exception:
                        _nav_consecutive_fail += 1
                        if _nav_consecutive_fail >= 3:
                            self._report(
                                f"  [{url[:40]}] 🔀 SPA 路由变化后无法回到初始页，"
                                f"连续 3 次失败，提前结束 "
                                f"({clicked_count}/{total_menu} 完成)"
                            )
                            break
            else:
                _nav_consecutive_fail = 0  # 仍在初始页 → 重置计数

            # ★ 2026-05-22 v4: 进度感知静默检测
            # 进度信号：captured 增加 / clicked_count 增加 / 循环迭代增加 → 任一重置计时器
            _now = _loop.time()
            if (len(captured) > _last_captured_len
                    or clicked_count > _last_clicked
                    or _iter_count > _last_iter):
                _last_progress_ts = _now
                _last_captured_len = len(captured)
                _last_clicked = clicked_count
                _last_iter = _iter_count

            _silence_s = _now - _last_progress_ts
            if _silence_s > PAGE_PROGRESS_SILENCE_S:
                remain = total_menu - clicked_count
                self._report(
                    f"  [{url[:40]}] ⏸ {int(_silence_s)}s 无进度（无新 API、无新点击、循环未推进），"
                    f"判定卡死，提前结束 ({clicked_count}/{total_menu} 完成，剩 {remain} 个延后)"
                )
                break

            if _now > _menu_absolute_deadline:
                # 30 分钟绝对兜底（实际由任务级 25min 先兜住，此处只防溢出）
                remain = total_menu - clicked_count
                self._report(
                    f"  [{url[:40]}] ⏱ 单页绝对兜底 {PAGE_MENU_LOOP_HARD_S//60} 分钟到达，强制结束 "
                    f"({clicked_count}/{total_menu} 完成，剩 {remain} 个延后)"
                )
                break

            selector = el.get("selector", "")
            if not selector:
                continue

            before = len(captured)
            menu_text = el.get("text", "")[:20]
            is_shadow = el.get("isShadow", False)
            try:
                # Shadow DOM 元素：用 pierce 选择器或 JS 文本匹配点击
                if is_shadow:
                    text = el.get("text", "")
                    clicked_shadow = False
                    if text:
                        try:
                            # Playwright pierce 选择器可穿透 Shadow DOM
                            pierce_sel = f"pierce/[role=menuitem]:has-text('{text[:30]}')"
                            el_handle = await page.wait_for_selector(pierce_sel, timeout=1500, state="visible")
                            await el_handle.click(timeout=2000)
                            clicked_shadow = True
                        except Exception as _e:
                            log.debug("Shadow DOM pierce 点击失败: %s", _e)
                        if not clicked_shadow:
                            try:
                                # fallback：JS 递归查找 Shadow DOM 内匹配文本的元素并 click
                                js_clicked = await page.evaluate(f"""() => {{
                                    function findAndClick(root, targetText, depth) {{
                                        if (depth > 5) return false;
                                        for (const el of root.querySelectorAll('a, button, [role=menuitem], [role=tab], [role=button]')) {{
                                            if ((el.textContent || '').trim().startsWith(targetText.slice(0, 20))) {{
                                                el.click();
                                                return true;
                                            }}
                                            if (el.shadowRoot && findAndClick(el.shadowRoot, targetText, depth+1)) return true;
                                        }}
                                        for (const el of root.querySelectorAll('*')) {{
                                            if (el.shadowRoot && findAndClick(el.shadowRoot, targetText, depth+1)) return true;
                                        }}
                                        return false;
                                    }}
                                    return findAndClick(document, {repr(text[:30])}, 0);
                                }}""")
                                if js_clicked:
                                    clicked_shadow = True
                            except Exception as _e:
                                log.debug("Shadow DOM JS 点击失败: %s", _e)
                    if not clicked_shadow:
                        _selector_consecutive_fail += 1
                        continue
                    clicked_count += 1
                    # ★ v3: 业务请求自适应等待（替代 sleep+networkidle）
                    await _smart_wait_business_xhr(captured, before)
                else:
                    # 先尝试重新获取元素（SPA 中 DOM 可能已更新）
                    try:
                        el_handle = await page.wait_for_selector(selector, timeout=3000, state="visible")
                    except Exception:
                        # ★ 2026-05-28 改进：增大超时 + 多级回退策略
                        await asyncio.sleep(2.0)
                        try:
                            el_handle = await page.wait_for_selector(selector, timeout=5000, state="visible")
                        except Exception:
                            # 选择器确实失效，尝试用文本重新定位
                            text = el.get("text", "")
                            if text:
                                # ★ 2026-05-28 修复：清理文本中的特殊字符（换行符、引号等）
                                clean_text = text.replace('\n', ' ').replace('\r', '').strip()
                                clean_text = ' '.join(clean_text.split())  # 合并多余空格
                                if clean_text and len(clean_text) >= 2:
                                    found = False
                                    # 策略 1：精确文本匹配
                                    try:
                                        alt_sel = f'text="{clean_text}"'
                                        el_handle = await page.wait_for_selector(alt_sel, timeout=3000, state="visible")
                                        selector = alt_sel
                                        found = True
                                    except Exception as _e:
                                        log.debug("精确文本匹配定位失败: %s", _e)
                                    # 策略 2：部分文本匹配（取前 15 个字符）
                                    if not found and len(clean_text) > 5:
                                        try:
                                            partial = clean_text[:15]
                                            alt_sel = f'text=/{partial}/i'
                                            el_handle = await page.wait_for_selector(alt_sel, timeout=3000, state="visible")
                                            selector = alt_sel
                                            found = True
                                        except Exception as _e:
                                            log.debug("部分文本匹配定位失败: %s", _e)
                                    # 策略 3：getByRole + name（适用于 aria-label 菜单）
                                    if not found:
                                        try:
                                            loc = page.get_by_role("menuitem", name=clean_text[:20])
                                            if await loc.count() > 0:
                                                el_handle = await loc.first.element_handle()
                                                found = True
                                        except Exception as _e:
                                            log.debug("getByRole 定位失败: %s", _e)
                                    if not found:
                                        _selector_consecutive_fail += 1
                                        continue
                                else:
                                    _selector_consecutive_fail += 1
                                    continue
                            else:
                                _selector_consecutive_fail += 1
                                continue

                    await page.click(selector, timeout=3000)
                    clicked_count += 1

                    # ★ v3: 业务请求自适应等待
                    # - 静态/锚点跳转：~0.5s 退出（旧版要 5.8s）
                    # - 业务 XHR 触发：等到业务请求 settle，最长 4s
                    # - 第三方 SDK 不计入，避免 mutinyhq/linkedin/ccm 拖累
                    await _smart_wait_business_xhr(captured, before)

            except Exception:
                # ★ v4.3: click 异常 → SPA 可能正在渲染，等 1s 再继续下一轮
                await asyncio.sleep(1.0)
                _selector_consecutive_fail += 1
                continue

            # ★ 2026-05-28 新增：新 Tab/Popup 处理
            # 如果点击菜单后打开了新标签页，等待其加载并收集流量，然后关闭
            if self._new_tab_pages:
                for new_tab in self._new_tab_pages:
                    try:
                        # 等待新页面加载完成（最多 8s）
                        await new_tab.wait_for_load_state("domcontentloaded", timeout=8000)
                        await asyncio.sleep(1.0)  # 等待 XHR 请求完成
                        new_tab_url = new_tab.url
                        if self._is_in_scope(new_tab_url) and new_tab_url not in crawled.links:
                            crawled.links.append(new_tab_url)
                            self._report(f"  🆕 新标签页: {new_tab_url[:80]}")
                    except Exception as _e:
                        log.debug("新标签页处理失败: %s", _e)
                    finally:
                        try:
                            await new_tab.close()
                        except Exception as _e:
                            log.debug("关闭新标签页失败: %s", _e)
                self._new_tab_pages.clear()

            # 收集该菜单项触发的请求，并把触发上下文写回 captured，供 api_endpoints/evidence 复用
            current_page_url = page.url  # 当前页面URL（含 hash）
            trigger_context = {
                "page_url": current_page_url,
                "element_text": menu_text,
                "selector": selector,
                "action": "menu_click",
            }
            for req in captured[before:]:
                req.setdefault("trigger_context", trigger_context)
            triggered = [dict(r) for r in captured[before:]]
            api_triggered = len([r for r in triggered if r.get("resource_type") in ("xhr", "fetch")])

            # 进度报告
            self._report(
                f"  菜单 [{clicked_count}/{total_menu}] 「{menu_text}」→ {api_triggered} 个API, "
                f"累计 {len(captured)} 条请求"
            )

            # ★ 每点完一个菜单 → progress_tick++，外部据此判断"还在产新东西"
            self._progress_tick += 1
            _nav_consecutive_fail = 0  # ★ 菜单点击成功 → 重置跳转失败计数
            _selector_consecutive_fail = 0  # ★ 2026-05-27: 选择器成功 → 重置连续失败计数
            self._remark_attempted = False  # ★ 2026-05-28: 成功后允许下次再重新标记

            crawled.elements.append(CrawledElement(
                page_url=current_page_url, tag=el.get("tag", ""), text=el.get("text", ""),
                selector=selector, triggered_requests=triggered,
            ))

            # ★ 2026-05-22 v3: 点击成功 → commit 指纹到任务级 set
            # 失败路径（continue/异常）不会走到这里，下次还能重试这个菜单
            _fp = el.get("_fingerprint")
            if _fp:
                self._global_clicked_menu_fingerprints.add(_fp)

            # 记录新发现的 URL（SPA hash 路由变化）
            # ★ 只收录同 origin（scheme+host+port）的 URL，避免跨端口跳转污染 BFS 队列
            if current_page_url != initial_url:
                _same_origin = False
                try:
                    from urllib.parse import urlparse as _urlparse
                    _p_cur = _urlparse(current_page_url)
                    _p_ini = _urlparse(initial_url)
                    _cur_o = (_p_cur.hostname, _p_cur.port or (443 if _p_cur.scheme == 'https' else 80))
                    _ini_o = (_p_ini.hostname, _p_ini.port or (443 if _p_ini.scheme == 'https' else 80))
                    _same_origin = (_cur_o == _ini_o)
                except Exception:
                    _same_origin = False
                if _same_origin and self._is_in_scope(current_page_url) and current_page_url not in crawled.links:
                    crawled.links.append(current_page_url)

            # ★ 2026-05-27: 菜单点击后遮挡检测+关闭（通用+UI框架两层防御）
            # 点击「登录」「注册」等菜单常触发弹窗/遮罩层，遮盖后续菜单 selector，导致连续失效
            # 第一层：通用遮挡检测（elementFromPoint，不依赖特定 UI 框架）
            # 第二层：UI 框架弹窗检测（枚举已知选择器，提取弹窗内容）
            _overlay_detected = False
            try:
                _overlay_result = await page.evaluate("""() => {
                    // 通用遮挡检测：取侧边栏/菜单区域的中心点，检查是否被其他元素遮盖
                    const navContainers = document.querySelectorAll(
                        'nav, aside, [role="navigation"], .sidebar, .side-bar, ' +
                        '.menu, .nav, #sidebar, #nav, #menu, ' +
                        '[class*="sidebar"], [class*="side-bar"], [class*="menu"], [class*="nav-"]'
                    );
                    for (const nav of navContainers) {
                        if (nav.offsetParent === null || nav.children.length === 0) continue;
                        const rect = nav.getBoundingClientRect();
                        if (rect.width < 30 || rect.height < 30) continue;
                        // 检查导航区域中心点是否被遮挡
                        const cx = rect.left + rect.width / 2;
                        const cy = rect.top + rect.height / 2;
                        const topEl = document.elementFromPoint(cx, cy);
                        if (topEl && topEl !== nav && !nav.contains(topEl)) {
                            // 导航区域被其他元素遮挡了
                            // 尝试找遮挡元素（高 z-index 的遮罩层/弹窗）
                            let overlay = topEl;
                            // 向上找到最顶层的遮罩容器
                            for (let i = 0; i < 5; i++) {
                                if (overlay.parentElement && overlay.parentElement !== document.body) {
                                    const parentRect = overlay.parentElement.getBoundingClientRect();
                                    // 父元素几乎覆盖全屏 → 这就是遮罩容器
                                    if (parentRect.width > window.innerWidth * 0.5 &&
                                        parentRect.height > window.innerHeight * 0.3) {
                                        overlay = overlay.parentElement;
                                        continue;
                                    }
                                }
                                break;
                            }
                            // 提取遮挡元素信息
                            const overlayRect = overlay.getBoundingClientRect();
                            const inputs = Array.from(overlay.querySelectorAll(
                                'input:not([type="hidden"]), textarea, select'
                            )).map(e => ({
                                type: e.type || e.tagName.toLowerCase(),
                                name: e.name || '',
                                placeholder: e.placeholder || '',
                                required: e.required || false,
                            }));
                            const buttons = Array.from(overlay.querySelectorAll(
                                'button, [role="button"], .el-button, .ant-btn'
                            )).map(b => ({
                                text: (b.textContent || '').trim().slice(0, 30),
                                type: b.type || '',
                            })).filter(b => b.text);
                            const links = Array.from(overlay.querySelectorAll('a[href]'))
                                .map(a => a.href)
                                .filter(h => h && !h.startsWith('javascript:'));
                            const title = (overlay.querySelector(
                                '.el-dialog__title, .ant-modal-title, .modal-title, ' +
                                'h1, h2, h3, [class*="title"], [class*="header"]'
                            )?.textContent || '').trim().slice(0, 60);
                            // 检测关闭按钮
                            const closeSelectors = [
                                '.el-dialog__close', '.ant-modal-close',
                                '.el-drawer__close-btn', '.ant-drawer-close',
                                '.modal-header .close', '[aria-label="Close"]',
                                '[aria-label="关闭"]', '.layui-layer-close',
                                '[class*="close"]', '[class*="Close"]',
                                'button[class*="cancel"]',
                            ];
                            let closeButton = null;
                            for (const sel of closeSelectors) {
                                const btn = overlay.querySelector(sel);
                                if (btn) { closeButton = sel; break; }
                            }
                            // 检测是否可以点击遮罩空白区关闭（遮罩覆盖导航区但弹窗在中间）
                            const isBackdrop = overlayRect.width > window.innerWidth * 0.7 &&
                                               overlayRect.height > window.innerHeight * 0.5;
                            return {
                                blocked: true,
                                title: title,
                                selector: overlay.tagName.toLowerCase() +
                                    (overlay.className ? '.' + overlay.className.split(' ')[0] : ''),
                                inputs: inputs.slice(0, 30),
                                buttons: buttons.slice(0, 20),
                                links: links.slice(0, 20),
                                closeButton: closeButton,
                                isBackdrop: isBackdrop,
                                overlayRect: {
                                    x: overlayRect.x, y: overlayRect.y,
                                    w: overlayRect.width, h: overlayRect.height
                                },
                            };
                        }
                    }
                    return { blocked: false };
                }""")

                if _overlay_result and _overlay_result.get("blocked"):
                    _overlay_detected = True
                    _overlay_sel = _overlay_result.get("selector", "unknown")
                    _overlay_title = _overlay_result.get("title", "")

                    # 记录弹窗/遮罩内容
                    crawled.elements.append(CrawledElement(
                        page_url=current_page_url,
                        tag="dialog",
                        text=f"[弹窗] {_overlay_title} <- 来自菜单: {menu_text}",
                        selector=_overlay_sel,
                        triggered_requests=[],
                    ))
                    for link in _overlay_result.get("links", []):
                        if self._is_in_scope(link) and link not in crawled.links:
                            crawled.links.append(link)
                    if _overlay_result.get("inputs"):
                        crawled.forms.append(CrawledForm(
                            page_url=current_page_url,
                            action=f"[dialog: {_overlay_title}]",
                            method="POST",
                            inputs=_overlay_result["inputs"],
                            selector=_overlay_sel,
                        ))

                    self._report(
                        f"  菜单 [{clicked_count}/{total_menu}] 「{menu_text}」触发遮挡: "
                        f"{_overlay_title[:30] or _overlay_sel}，尝试关闭"
                    )

                    # 通用关闭策略（按优先级尝试）
                    _closed = False

                    # 策略1: 点击弹窗内的关闭按钮（如果检测到）
                    _close_btn = _overlay_result.get("closeButton")
                    if _close_btn:
                        try:
                            _closed = await page.evaluate(f"""() => {{
                                const btn = document.querySelector('{_close_btn}');
                                if (btn) {{ btn.click(); return true; }}
                                return false;
                            }}""")
                        except Exception as _e:
                            log.debug("点击弹窗关闭按钮失败: %s", _e)

                    # 策略2: 按 ESC（最通用，绝大多数弹窗支持）
                    if not _closed:
                        try:
                            await page.keyboard.press("Escape")
                            await asyncio.sleep(0.3)
                            # 验证遮挡是否消失
                            _still_blocked = await page.evaluate("""() => {
                                const nav = document.querySelector(
                                    'nav, aside, [role="navigation"], .sidebar, .menu'
                                );
                                if (!nav || nav.offsetParent === null) return false;
                                const rect = nav.getBoundingClientRect();
                                const topEl = document.elementFromPoint(
                                    rect.left + rect.width / 2,
                                    rect.top + rect.height / 2
                                );
                                return topEl && topEl !== nav && !nav.contains(topEl);
                            }""")
                            if not _still_blocked:
                                _closed = True
                        except Exception as _e:
                            log.debug("按 ESC 关闭遮挡失败: %s", _e)

                    # 策略3: 点击遮罩层空白区域（某些弹窗点击外部关闭）
                    if not _closed and _overlay_result.get("isBackdrop"):
                        try:
                            _rect = _overlay_result.get("overlayRect", {})
                            # 点击遮罩边缘（远离弹窗中心，更可能命中空白遮罩）
                            _click_x = _rect.get("x", 0) + 5
                            _click_y = _rect.get("y", 0) + 5
                            await page.mouse.click(_click_x, _click_y)
                            await asyncio.sleep(0.3)
                            _closed = True  # 无法精确验证，假设成功
                        except Exception as _e:
                            log.debug("点击遮罩层关闭弹窗失败: %s", _e)

                    if _closed:
                        self._report(f"  ✅ 遮挡已关闭，继续点击后续菜单")
                    else:
                        self._report(f"  ⚠️ 未能关闭遮挡，后续菜单 selector 可能失效")

                    await asyncio.sleep(0.3)

            except Exception as _e:
                log.debug("遮挡处理失败: %s", _e)

            # ★ 2026-05-22 v2: 批次让步 + 噪音中断
            if clicked_count % _BATCH_YIELD_EVERY == 0:
                # yield 给事件循环，让外层 wait_for/asyncio.shield 能看到进度
                await asyncio.sleep(0)
                # 检查噪音状态（如该页面有大量轮询 API → 加速放弃）
                if _noise.has_noise():
                    noise_count = len(_noise.blacklist_snapshot())
                    if noise_count >= _NOISE_ABORT_THRESHOLD:
                        self._report(
                            f"  [{url[:40]}] ⚠️ 检测到 {noise_count} 个噪音 API,"
                            f"剩余 {total_menu - clicked_count} 个菜单跳过"
                        )
                        break

            # SPA 场景：不要 goto 回去！直接继续点下一个菜单项
            # 菜单通常是固定在侧边栏/导航栏的，切换页面不影响菜单可见性

        # ★ 2026-05-28: 重新标记后有新菜单项，继续点击
        if getattr(self, '_remark_new_items', None):
            _new_menu_items = self._remark_new_items
            self._remark_new_items = None
            self._report(f"  [{url[:40]}] 🔄 继续点击重新标记的 {len(_new_menu_items)} 个菜单项...")
            _selector_consecutive_fail = 0
            for el in _new_menu_items[:max_menu_clicks - clicked_count]:
                if self._stop_requested:
                    break
                selector = el.get("selector", "")
                if not selector:
                    continue
                before = len(captured)
                menu_text = el.get("text", "")[:20]
                try:
                    el_handle = await page.wait_for_selector(selector, timeout=5000, state="visible")
                    await page.click(selector, timeout=3000)
                    clicked_count += 1
                    _selector_consecutive_fail = 0
                    await _smart_wait_business_xhr(captured, before)
                    trigger_context = {
                        "page_url": page.url,
                        "element_text": menu_text,
                        "selector": selector,
                        "action": "menu_click",
                    }
                    for req in captured[before:]:
                        req.setdefault("trigger_context", trigger_context)
                    triggered = [dict(r) for r in captured[before:]]
                    api_triggered = len([r for r in triggered if r.get("resource_type") in ("xhr", "fetch")])
                    self._report(
                        f"  菜单 [{clicked_count}/{total_menu}] 「{menu_text}」→ {api_triggered} 个API, "
                        f"累计 {len(captured)} 条请求"
                    )
                    self._progress_tick += 1
                    crawled.elements.append(CrawledElement(
                        page_url=page.url, tag=el.get("tag", ""), text=el.get("text", ""),
                        selector=selector, triggered_requests=triggered,
                    ))
                except Exception:
                    _selector_consecutive_fail += 1
                    if _selector_consecutive_fail >= 5:
                        self._report(f"  [{url[:40]}] 🔇 重新标记的菜单项也连续失效，结束")
                        break
                    continue

        self._report(f"  [{url[:40]}] 菜单项点击完成: {clicked_count}/{len(unique_menu_items)}")

        # ---- Phase C: 非菜单按钮点击（在当前最后停留的页面上）----
        # 回到初始页面，点击非菜单按钮
        if non_menu_items:
            self._report(f"  [{url[:40]}] ▶️ 进入按钮点击阶段（共 {len(non_menu_items)} 个候选按钮）")
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                await _smart_wait_for_idle(page, _noise, max_wait_s=5.0)
            except Exception as _e:
                log.debug("按钮阶段回到初始页面失败: %s", _e)

            max_btn_clicks = 100
            # ★ v4.1: 按钮循环也用进度感知静默 + page.url 早退（同菜单循环）
            _btn_loop = asyncio.get_event_loop()
            _btn_last_progress_ts = _btn_loop.time()
            _btn_absolute_deadline = _btn_loop.time() + PAGE_MENU_LOOP_HARD_S
            _btn_last_captured_len = len(captured)
            _btn_clicked_count = 0
            _btn_last_clicked = 0
            _btn_iter_count = 0
            _btn_last_iter = 0
            _btn_total = len(non_menu_items[:max_btn_clicks])
            _btn_report_every = max(5, _btn_total // 10)  # 每 N 个按钮报一次进度
            _btn_last_heartbeat_ts = _btn_loop.time()  # ★ 心跳计时器

            for el in non_menu_items[:max_btn_clicks]:
                _btn_iter_count += 1

                # ★ 心跳：每 30s 发一次进度消息，防止外层 silent_timeout 误判
                _btn_hb_now = _btn_loop.time()
                if _btn_hb_now - _btn_last_heartbeat_ts >= 30:
                    self._report(
                        f"  [{url[:40]}] 💓 按钮点击进行中 "
                        f"({_btn_clicked_count}/{_btn_total}，迭代 {_btn_iter_count})..."
                    )
                    _btn_last_heartbeat_ts = _btn_hb_now

                # 每点一个就检查停止信号
                if self._stop_requested:
                    self._report(f"  [{url[:40]}] ⏸ 收到停止信号，按钮点击中断 ({_btn_clicked_count}/{_btn_total})")
                    break
                # ★ v4.1: 页面跳走早退（避免点击按钮跳转后剩余按钮 selector 失效卡 30s）
                try:
                    _cur = page.url
                    if (_cur and self._normalize_url(_cur) != self._normalize_url(url)):
                        # 已离开 url（菜单循环里已回过 goto，这里再发现说明刚被某个按钮带跳走）
                        # 跳回 url 继续，不 break（按钮循环里允许跳回）
                        try:
                            await page.goto(url, wait_until="domcontentloaded", timeout=8000)
                        except Exception:
                            self._report(
                                f"  [{url[:40]}] 🔀 页面跳走且回不来，剩余 {_btn_total - _btn_clicked_count} 个按钮放弃"
                            )
                            break
                except Exception as _e:
                    log.debug("按钮循环页面跳转检测失败: %s", _e)

                # ★ v4.1: 进度感知静默检测
                _btn_now = _btn_loop.time()
                if (len(captured) > _btn_last_captured_len
                        or _btn_clicked_count > _btn_last_clicked
                        or _btn_iter_count > _btn_last_iter):
                    _btn_last_progress_ts = _btn_now
                    _btn_last_captured_len = len(captured)
                    _btn_last_clicked = _btn_clicked_count
                    _btn_last_iter = _btn_iter_count

                _btn_silence = _btn_now - _btn_last_progress_ts
                if _btn_silence > PAGE_PROGRESS_SILENCE_S:
                    self._report(
                        f"  [{url[:40]}] ⏸ 按钮阶段 {int(_btn_silence)}s 无进度，"
                        f"判定卡死 ({_btn_clicked_count}/{_btn_total})"
                    )
                    break
                if _btn_now > _btn_absolute_deadline:
                    self._report(
                        f"  [{url[:40]}] ⏱ 按钮阶段绝对兜底到达 ({_btn_clicked_count}/{_btn_total})"
                    )
                    break

                selector = el.get("selector", "")
                if not selector:
                    continue
                before = len(captured)
                try:
                    await page.click(selector, timeout=3000)
                    _btn_clicked_count += 1
                    await asyncio.sleep(0.3)
                    await _smart_wait_for_idle(page, _noise, max_wait_s=3.0)
                except Exception:
                    continue

                # ★ 周期进度日志（避免按钮阶段长时间静默看起来像卡死）
                if _btn_clicked_count > 0 and _btn_clicked_count % _btn_report_every == 0:
                    self._report(
                        f"  [{url[:40]}] 🔘 按钮点击进度 {_btn_clicked_count}/{_btn_total}，"
                        f"累计 {len(captured)} 条请求"
                    )

                # ★ 每点完一个按钮 → progress_tick++
                self._progress_tick += 1

                trigger_context = {
                    "page_url": page.url or url,
                    "element_text": el.get("text", ""),
                    "selector": selector,
                    "action": "button_click",
                }
                for req in captured[before:]:
                    req.setdefault("trigger_context", trigger_context)

                crawled.elements.append(CrawledElement(
                    page_url=url, tag=el.get("tag", ""), text=el.get("text", ""),
                    selector=selector, triggered_requests=[dict(r) for r in captured[before:]],
                ))

                # ★ 检测是否触发了弹窗（modal/dialog）
                # 常见弹窗容器：Element UI/Ant Design/Bootstrap/原生 dialog
                dialog_extracted = False
                try:
                    dialog_info = await page.evaluate("""() => {
                        const dialogSelectors = [
                            '.el-dialog__wrapper:not([style*="display: none"]) .el-dialog',
                            '.el-drawer__wrapper:not([style*="display: none"]) .el-drawer',
                            '.ant-modal-wrap:not([style*="display: none"]) .ant-modal',
                            '.ant-drawer-open .ant-drawer',
                            '.modal.show, .modal[style*="display: block"]',
                            'dialog[open]',
                            '[role="dialog"]:not([aria-hidden="true"])',
                            '.v-dialog--active',
                            '.layui-layer',
                        ];
                        for (const sel of dialogSelectors) {
                            const dlg = document.querySelector(sel);
                            if (dlg) {
                                const rect = dlg.getBoundingClientRect();
                                if (rect.width < 50 || rect.height < 50) continue;
                                // 提取弹窗内的可交互元素
                                const inputs = Array.from(dlg.querySelectorAll('input:not([type="hidden"]), textarea, select'))
                                    .map(e => ({
                                        type: e.type || e.tagName.toLowerCase(),
                                        name: e.name || '',
                                        placeholder: e.placeholder || '',
                                        required: e.required || false,
                                    }));
                                const buttons = Array.from(dlg.querySelectorAll('button, [role="button"], .el-button, .ant-btn'))
                                    .map(b => ({
                                        text: (b.textContent || '').trim().slice(0, 30),
                                        type: b.type || '',
                                    }))
                                    .filter(b => b.text);
                                const links = Array.from(dlg.querySelectorAll('a[href]'))
                                    .map(a => a.href)
                                    .filter(h => h && !h.startsWith('javascript:'));
                                const title = (dlg.querySelector('.el-dialog__title, .ant-modal-title, .modal-title, h1, h2')?.textContent || '').trim();
                                return {
                                    title: title,
                                    selector: sel,
                                    inputs: inputs.slice(0, 30),
                                    buttons: buttons.slice(0, 20),
                                    links: links.slice(0, 20),
                                };
                            }
                        }
                        return null;
                    }""")
                    if dialog_info:
                        # 把弹窗内容作为该按钮的"次级元素"记录
                        crawled.elements.append(CrawledElement(
                            page_url=url,
                            tag="dialog",
                            text=f"[弹窗] {dialog_info.get('title','')} <- 来自按钮: {el.get('text','')[:20]}",
                            selector=dialog_info.get("selector", ""),
                            triggered_requests=[],
                        ))
                        # 把弹窗里的链接加入待爬队列（在 _crawl_page 外，这里直接放 crawled.links）
                        for link in dialog_info.get("links", []):
                            if self._is_in_scope(link) and link not in crawled.links:
                                crawled.links.append(link)
                        # 把弹窗里的 form 当作一个特殊 form 记录（如果有 input）
                        if dialog_info.get("inputs"):
                            dialog_form = CrawledForm(
                                page_url=url,
                                action=f"[dialog: {dialog_info.get('title','')}]",
                                method="POST",
                                inputs=dialog_info["inputs"],
                                selector=dialog_info.get("selector", ""),
                            )
                            crawled.forms.append(dialog_form)
                        dialog_extracted = True
                        # 提取完毕，关闭弹窗（避免遮挡后续按钮点击）
                        try:
                            close_clicked = await page.evaluate("""() => {
                                const closeSelectors = [
                                    '.el-dialog__close', '.ant-modal-close',
                                    '.el-drawer__close-btn', '.ant-drawer-close',
                                    '.modal-header .close', '[aria-label="Close"]',
                                    '[aria-label="关闭"]', '.layui-layer-close',
                                ];
                                for (const sel of closeSelectors) {
                                    const btn = document.querySelector(sel);
                                    if (btn) { btn.click(); return true; }
                                }
                                return false;
                            }""")
                            if not close_clicked:
                                # 兜底：按 ESC
                                await page.keyboard.press("Escape")
                            await asyncio.sleep(0.3)
                        except Exception as _e:
                            log.debug("关闭弹窗失败: %s", _e)
                except Exception as _e:
                    log.debug("弹窗提取失败: %s", _e)

                # 按钮可能导致路由跳转，跳回来继续
                current_url = self._normalize_url(page.url)
                if current_url != self._normalize_url(url):
                    new_url = page.url
                    if self._is_in_scope(new_url) and new_url not in crawled.links:
                        crawled.links.append(new_url)
                    # ★ 只有在没有弹窗（弹窗已提取并关闭）且 URL 真的变了时才 goto 回去
                    if not dialog_extracted:
                        try:
                            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                        except Exception:
                            break

        # 智能填写并提交表单
        for form_info in page_info.get("forms", []):
            crawled_form = await self._fill_and_submit_form(page, url, form_info, captured)
            if crawled_form:
                crawled.forms.append(crawled_form)

        # ★ 2026-05-22 v2: 监听器移除已在 _crawl_page 的 finally 中统一处理
        # 这里只打印噪音命中名单（用于诊断）
        if _noise.has_noise():
            try:
                names = _noise.blacklist_snapshot()
                self._report(
                    f"  [噪音页面] 命中 {len(names)} 个高频 API，已切快照模式: "
                    f"{', '.join(n[-60:] for n in names[:3])}"
                    + (f" 等共 {len(names)} 个" if len(names) > 3 else "")
                )
            except Exception as _e:
                log.debug("噪音快照报告失败: %s", _e)

        return crawled

