"""
SupplementalTestAgent — Phase 2.55 补测 Agent

设计目标（2026-05-22）：
=================================================================
问题背景：
  Phase 2 主测试期间，子 Agent 通过 proxy_send_request 等工具会触发大量
  新流量。其中部分流量打到了「之前 sitemap 里没有的 API」（典型场景：
  fuzz /users/1 时从响应里发现了 /users/1/orgs，去 GET 了一下）。这些
  新发现的 API 当前不会被自动测试，会被遗漏。

本 Agent 的职责：
  1. 扫描 flows.jsonl 里 Phase 2 之后产生的全部流量
  2. 严格按 scope（target host + extra_scope）过滤
  3. 排除已在 sitemap.apis 里的（A 类 PoC 变体）
  4. 仅保留 2xx 响应的活 API
  5. 对每个新 API：
     - 优先挂到 path 前缀最相似的 feature；找不到才建新 feature
     - 走主 sitemap.add_feature 路径，自动建 checklist
  6. 启动 WorkerAgent 独立子 Agent，复用主 Agent 的 SKILL/工具/流程
  7. 单 API 超时 60s，总预算 30min；失败兜底，绝不阻塞 Phase 2.6

不递归：补测过程中再发现的新 API 只记录、不再测，写入报告附录。
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Callable
from urllib.parse import urlparse

from core.log import get_logger
from core.sitemap import Sitemap, Priority

log = get_logger("supplemental")


# ============================================================
# 配置
# ============================================================

# 每个新 API 的单测试预算（秒）
PER_API_TIMEOUT_S = 60.0

# 整个 Phase 2.55 的总预算（秒）
TOTAL_BUDGET_S = 30 * 60.0

# 单个 worker 同时测多少个新 feature
FEATURES_PER_WORKER = 5

# 已知第三方 SDK / 监控 / 基础设施域黑名单（绝不补测）
_THIRD_PARTY_BLACKLIST = {
    # ================================================================
    # Google 系
    # ================================================================
    "google-analytics.com", "googletagmanager.com", "googleapis.com",
    "doubleclick.net", "google.com", "recaptcha.net", "gstatic.com",
    "android.clients.google.com", "content-autofill.googleapis.com",
    "googleadservices.com", "googlesyndication.com",
    "firebase.google.com", "firebase.io", "firebaseapp.com",
    # ================================================================
    # 社交/登录 CDN
    # ================================================================
    "facebook.com", "facebook.net", "fbcdn.net",
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
    "akamai.net", "akamaihd.net", "akamaized.net",
    "fastly.net", "fastlylb.net",
    "amazonaws.com", "azureedge.net", "cloudfront.net",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
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


# ============================================================
# 数据结构
# ============================================================

class _DiscoveredAPI:
    """从 flows.jsonl 扫出来的待补测 API。"""

    __slots__ = ("method", "url", "host", "path", "status_code",
                 "response_body_preview", "content_type", "timestamp",
                 "flow_id", "request_body")

    def __init__(self, flow: dict):
        self.method = (flow.get("method") or "").upper()
        self.url = flow.get("url") or ""
        parsed = urlparse(self.url)
        self.host = parsed.netloc.lower()
        self.path = parsed.path or "/"
        self.status_code = int(flow.get("status_code") or 0)
        self.response_body_preview = (flow.get("response_body") or "")[:200]
        self.content_type = flow.get("content_type") or ""
        self.timestamp = float(flow.get("timestamp") or 0)
        self.flow_id = flow.get("id", "")
        self.request_body = (flow.get("request_body") or "")[:500]

    @property
    def key(self) -> str:
        """归一化键：METHOD host+path（去 query）。"""
        return f"{self.method} {self.host}{self.path}"


# ============================================================
# L1: 自动发现层 — 从 flows.jsonl 扫描新 API
# ============================================================

def discover_new_apis_from_flows(
    sitemap: Sitemap,
    target_url: str,
    phase2_started_at: float,
    flows_path: Path | None = None,
    task_id: str | None = None,
) -> tuple[list[_DiscoveredAPI], dict[str, int]]:
    """从 flows.jsonl 扫出 Phase 2 期间产生的、scope 内的、2xx 响应的、
    且不在 sitemap.apis 里的新 API。

    Args:
        task_id: 可选，如果指定则只保留归属该任务的流量（避免跨任务污染）。

    Returns:
        (apis, stats)：apis 是去重后的新 API 列表，stats 是过滤统计信息。
    """
    stats = {
        "total_scanned": 0,
        "before_phase2": 0,
        "other_task": 0,
        "out_of_scope": 0,
        "third_party": 0,
        "not_2xx": 0,
        "non_business": 0,
        "already_known": 0,
        "duplicate": 0,
        "kept": 0,
        "flow_file": "",
    }

    if flows_path is None:
        flows_path = Path(
            os.getenv("PROXY_FLOW_FILE",
                      "data/pentest_agent_flows.jsonl")
        )
    stats["flow_file"] = str(flows_path)

    if not flows_path.exists():
        log.warning("supplemental: flows.jsonl 不存在: %s", flows_path)
        stats["flow_file_missing"] = 1
        return [], stats

    # 计算 scope
    target_host = urlparse(target_url).netloc.lower() if target_url else ""
    extra_scope = set()
    try:
        ex = getattr(sitemap, "extra_scope", None)
        if ex:
            extra_scope = {d.lower().lstrip(".") for d in ex if d}
    except Exception:
        pass
    in_scope_hosts = ({target_host} | extra_scope) if target_host else extra_scope

    # 计算已知 API 集合（用于 dedup）
    known_keys: set[str] = set()
    try:
        for api_key in (sitemap.apis or {}).keys():
            # api_key 格式 "METHOD url"，取 method + host+path
            parts = api_key.split(" ", 1)
            if len(parts) == 2:
                m = parts[0].upper()
                u = parts[1].strip()
                pu = urlparse(u)
                if pu.netloc:
                    known_keys.add(f"{m} {pu.netloc.lower()}{pu.path}")
                else:
                    # 只有 path
                    known_keys.add(f"{m} {pu.path}")
    except Exception:
        pass

    seen: dict[str, _DiscoveredAPI] = {}

    try:
        # ★ 使用 errors="replace" 容错：flows.jsonl 可能因 mitmproxy 写入时
        # 含非 UTF-8 字节（如二进制响应体被误记），不能因一行解码失败
        # 就放弃整个文件，导致 Phase 2.55 补测全部跳过。
        with open(flows_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stats["total_scanned"] += 1
                try:
                    flow = json.loads(line)
                except Exception:
                    # 单行 JSON 解析失败（可能因 errors=replace 引入的 U+FFFD）
                    # 跳过这一行继续，而不是整体抛出
                    stats.setdefault("parse_failed", 0)
                    stats["parse_failed"] = stats.get("parse_failed", 0) + 1
                    continue

                ts = float(flow.get("timestamp") or 0)
                if ts < phase2_started_at:
                    stats["before_phase2"] += 1
                    continue

                # ★ 2026-05-29: 按 task_id 过滤，避免跨任务污染
                if task_id:
                    flow_task_id = flow.get("task_id", "")
                    if flow_task_id and flow_task_id != task_id:
                        stats["other_task"] += 1
                        continue

                api = _DiscoveredAPI(flow)

                # scope 过滤
                if not api.host:
                    stats["out_of_scope"] += 1
                    continue
                if not _host_in_scope(api.host, in_scope_hosts):
                    stats["out_of_scope"] += 1
                    continue
                # 第三方黑名单
                if _is_third_party(api.host):
                    stats["third_party"] += 1
                    continue

                # 仅 2xx 响应
                if not (200 <= api.status_code < 300):
                    stats["not_2xx"] += 1
                    continue

                # 排除静态资源、非业务路径
                if _is_non_business_path(api.path):
                    stats["non_business"] += 1
                    continue

                # 已知 API（带 host+path 的精确归一化键）
                norm_key = f"{api.method} {api.host}{api.path}"
                if norm_key in known_keys:
                    stats["already_known"] += 1
                    continue
                # 兼容只存 path 的旧 key
                path_only_key = f"{api.method} {api.path}"
                if path_only_key in known_keys:
                    stats["already_known"] += 1
                    continue

                # 去重（同一新 API 多次出现只保留第一条 2xx）
                if api.key in seen:
                    stats["duplicate"] += 1
                    continue

                seen[api.key] = api
                stats["kept"] += 1
    except OSError as e:
        # 仅捕获文件级 IO 错误（文件不存在/权限等），其他异常向上抛出
        # 触发任务级告警，避免因单点异常导致 Phase 2.55 补测全部静默跳过。
        log.warning("supplemental: 读取 flows.jsonl IO 错误: %s", e)
        stats["io_error"] = str(e)[:200]
        return list(seen.values()), stats
    except Exception as e:
        # 非预期异常：记录详细堆栈并向上抛出，由调用方决定是否终止 Phase 2.55
        log.exception("supplemental: 扫描 flows.jsonl 发生非预期异常（已收集 %d 条）", len(seen))
        stats["unexpected_error"] = str(e)[:200]
        # 返回已收集的部分结果，而非空列表，最大限度保留补测数据
        return list(seen.values()), stats

    return list(seen.values()), stats


def _host_in_scope(host: str, in_scope_hosts: set[str]) -> bool:
    """host 是否落在 scope 内（精确或后缀匹配）。"""
    if not host:
        return False
    if host in in_scope_hosts:
        return True
    # 后缀匹配（如 in_scope = {jd.com}，host=qw.jd.com → 命中）
    for sc in in_scope_hosts:
        if sc and (host == sc or host.endswith("." + sc)):
            return True
    return False


def _is_third_party(host: str) -> bool:
    host = (host or "").lower().lstrip(".")
    for bl in _THIRD_PARTY_BLACKLIST:
        if host == bl or host.endswith("." + bl):
            return True
    return False


_NON_BUSINESS_PATH_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
)
_NON_BUSINESS_PATH_SEGMENTS = (
    "/assets/", "/static/", "/dist/", "/_next/static/", "/_nuxt/",
)


def _is_non_business_path(path: str) -> bool:
    p = (path or "").lower().rstrip("/")
    if any(p.endswith(s) for s in _NON_BUSINESS_PATH_SUFFIXES):
        return True
    if any(seg in p for seg in _NON_BUSINESS_PATH_SEGMENTS):
        return True
    return False


# ============================================================
# L2: 挂载新 API 到 sitemap（优先挂现有 feature，找不到才建新的）
# ============================================================

def attach_apis_to_sitemap(
    sitemap: Sitemap,
    apis: list[_DiscoveredAPI],
) -> tuple[list, list]:
    """把新 API 挂载到 sitemap。

    Returns:
        (new_features, attached_features)：分别是新建的 feature 列表和挂到现有 feature 上的列表。
    """
    new_features = []
    attached_features = []

    for api in apis:
        api_str = f"{api.method} {api.url.split('?')[0]}"
        attached_to = _find_best_matching_feature(sitemap, api)
        if attached_to is not None:
            # 挂到现有 feature
            if api_str not in attached_to.related_apis:
                attached_to.related_apis.append(api_str)
                attached_features.append((attached_to, api))
            # 也记录到 sitemap.apis（供 packet_merger 等模块识别）
            try:
                sitemap.add_api(api.method, api.url.split("?")[0], discovered_by="phase2_flow")
            except Exception:
                pass
            continue

        # 新建 feature
        name = _gen_feature_name(api)
        desc = _gen_feature_desc(api)
        try:
            fp = sitemap.add_feature(
                name=name,
                description=desc,
                page_url=f"{api.method} {api.host}{api.path}",
                priority=Priority.MEDIUM,
                related_apis=[api_str],
                requires_auth=True,
                module="补测发现",
            )
            if fp is not None:
                # 加 tag 便于报告区分
                try:
                    fp.findings.append("[supplemental] 由 Phase 2.55 补测 Agent 发现")
                except Exception:
                    pass
                new_features.append(fp)
                # 也记录到 sitemap.apis
                try:
                    sitemap.add_api(api.method, api.url.split("?")[0], discovered_by="phase2_flow")
                except Exception:
                    pass
        except Exception as e:
            log.warning("supplemental: 新建 feature 失败: %s（API: %s）", e, api.key)

    try:
        sitemap.save()
    except Exception:
        pass

    return new_features, attached_features


def _find_best_matching_feature(sitemap: Sitemap, api: _DiscoveredAPI):
    """找 path 前缀最相似的 feature。

    匹配规则：
      - 候选 feature 必须有 related_apis
      - 比较 api.path 和 fp.related_apis 中每个 api 的 path
      - 共同前缀段数 >= 2 即认为相似（如 /api/users/1 vs /api/users/list 共享 /api/users）
      - 取共同段最多的 feature
    """
    api_segments = [s for s in api.path.split("/") if s]
    if len(api_segments) < 2:
        return None

    best_feature = None
    best_score = 1  # 至少要有 2 段共同前缀

    for fp in (sitemap.features or {}).values():
        for related in (fp.related_apis or []):
            try:
                related_url = related.split(" ", 1)[-1] if " " in related else related
                related_path = urlparse(related_url).path or related_url
                related_segments = [s for s in related_path.split("/") if s]
                # 计算共同前缀长度
                common = 0
                for a, b in zip(api_segments, related_segments):
                    if a == b:
                        common += 1
                    else:
                        break
                if common > best_score:
                    best_score = common
                    best_feature = fp
            except Exception:
                continue

    return best_feature


def _gen_feature_name(api: _DiscoveredAPI) -> str:
    """从 API 生成功能点名称。"""
    # 取 path 最后两段作为名称
    segs = [s for s in api.path.split("/") if s]
    if len(segs) >= 2:
        return f"{api.method} /{segs[-2]}/{segs[-1]}"
    elif segs:
        return f"{api.method} /{segs[-1]}"
    return f"{api.method} {api.host}"


def _gen_feature_desc(api: _DiscoveredAPI) -> str:
    """从 API 生成功能点描述。"""
    parts = [
        f"补测发现的新 API（{api.method} {api.host}{api.path}）",
        f"首次响应: HTTP {api.status_code}",
    ]
    if api.content_type:
        parts.append(f"Content-Type: {api.content_type.split(';')[0]}")
    if api.response_body_preview:
        preview = api.response_body_preview[:80].replace("\n", " ")
        parts.append(f"响应预览: {preview}")
    return "；".join(parts)


def _normalize_related_api_for_scan(api_ref: str, target_url: str) -> tuple[str, str] | None:
    """把 feature.related_apis 里的条目规范成 (method, url)。

    related_apis 常见格式包括：
      - "GET https://example.com/api/user"
      - "POST /api/user"
      - "https://example.com/api/user"
      - "/api/user"

    本地补测此前只判断字符串是否以 http 开头，导致
    "GET https://..." 被拼成 "https://target/GET https://..."，
    FastScanner 实际收到非法 URL。这里统一拆出 method 和 URL。
    """
    raw = (api_ref or "").strip()
    if not raw:
        return None

    method = "GET"
    url_part = raw
    if " " in raw:
        first, rest = raw.split(" ", 1)
        if first.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = first.upper()
            url_part = rest.strip()

    if not url_part:
        return None

    parsed = urlparse(url_part)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return method, url_part

    if url_part.startswith("//"):
        scheme = urlparse(target_url).scheme or "http"
        return method, f"{scheme}:{url_part}"

    if not target_url:
        return None

    base = target_url.rstrip("/")
    if not url_part.startswith("/"):
        url_part = "/" + url_part
    return method, f"{base}{url_part}"


# ============================================================
# 主入口：运行 Phase 2.55 补测 Agent
# ============================================================

async def run_supplemental_test(
    session: "Any",
) -> AsyncGenerator[dict, None]:
    """运行 Phase 2.55 补测 Agent。

    yield 字典格式的事件，由调用方（parallel.py）转成 session._event 推送给前端。

    事件类型：
      - {"type": "info", "msg": ...}        — 一般信息
      - {"type": "warn", "msg": ...}        — 警告（继续）
      - {"type": "error", "msg": ...}       — 失败但已兜底（跳过补测）
      - {"type": "worker_event", "evt": ..} — 子 Agent 产生的事件（透传给前端）
      - {"type": "done", "summary": {...}}  — 全部完成
    """
    started = time.time()
    summary: dict[str, Any] = {
        "discovered": 0,
        "new_features": 0,
        "attached_features": 0,
        "tested_features": 0,
        "skipped_features": 0,
        "elapsed": 0.0,
        "error": None,
    }

    try:
        # ---- Step 1: 获取关键参数 ----
        sitemap = getattr(session, "sitemap", None)
        if sitemap is None:
            yield {"type": "error", "msg": "sitemap 未初始化，跳过补测"}
            summary["error"] = "sitemap 未初始化"
            yield {"type": "done", "summary": summary}
            return

        target_url = getattr(session, "target_url", "") or ""
        phase2_started_at = getattr(session, "_phase2_started_at", 0.0) or 0.0
        if phase2_started_at <= 0:
            yield {
                "type": "warn",
                "msg": "未记录 Phase 2 起点时间戳，将扫描全部 flows.jsonl（可能包含 Phase 0/1 流量）",
            }
            phase2_started_at = 0.0

        # ---- Step 2: 扫描新 API ----
        try:
            # ★ 2026-05-29: 传入 task_id 过滤，避免读到其他并发任务的流量
            current_task_id = getattr(session, "task_id", None) or ""
            apis, scan_stats = discover_new_apis_from_flows(
                sitemap=sitemap,
                target_url=target_url,
                phase2_started_at=phase2_started_at,
                task_id=current_task_id or None,
            )
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"扫描 flows.jsonl 失败（{type(e).__name__}: {str(e)[:120]}），跳过补测",
            }
            summary["error"] = f"scan_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        summary["discovered"] = len(apis)
        summary["scan_stats"] = scan_stats

        # ★ 检测补测扫描阶段是否发生异常（IO 错误或非预期错误）
        # 即使返回了部分结果，也要把错误记录到 summary，供下游报告体现
        if scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
            err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
            summary["warning"] = f"flows_scan_partial: {err_msg}"
            yield {
                "type": "warn",
                "msg": f"扫描 flows.jsonl 过程中发生异常（已收集部分结果）: {err_msg[:120]}",
            }

        yield {
            "type": "info",
            "msg": (
                f"扫描完成: 共 {scan_stats['total_scanned']} 条流量, "
                f"保留 {scan_stats['kept']} 个新 API "
                f"(scope外 {scan_stats['out_of_scope']}, 第三方 {scan_stats['third_party']}, "
                f"非2xx {scan_stats['not_2xx']}, 已知 {scan_stats['already_known']}, "
                f"非业务 {scan_stats['non_business']}, 重复 {scan_stats['duplicate']})"
            ),
        }

        if not apis:
            # ★ 区分"真的没有新 API"和"因异常导致结果为空"
            if scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
                err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
                yield {
                    "type": "error",
                    "msg": f"扫描 flows.jsonl 异常导致未发现新 API，Phase 2.55 补测失败: {err_msg[:120]}",
                }
                summary["error"] = f"flows_scan_failed: {err_msg}"
            else:
                yield {"type": "info", "msg": "未发现需要补测的新 API，跳过 Phase 2.55"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- Step 3: 挂载到 sitemap ----
        try:
            new_features, attached_features = attach_apis_to_sitemap(sitemap, apis)
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"挂载新 API 到 sitemap 失败（{type(e).__name__}: {str(e)[:120]}），跳过补测",
            }
            summary["error"] = f"attach_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        summary["new_features"] = len(new_features)
        summary["attached_features"] = len(attached_features)

        yield {
            "type": "info",
            "msg": (
                f"挂载完成: 新建 {len(new_features)} 个 feature, "
                f"挂到现有 feature {len(attached_features)} 个 API"
            ),
        }

        # ---- Step 4: 整理待测 feature 列表 ----
        # 新建的 feature 一定要测；挂到现有 feature 的 API 不重新测（避免重复）
        features_to_test = [fp for fp in new_features if fp.checklist]

        if not features_to_test:
            yield {
                "type": "info",
                "msg": "所有新 API 都挂到了现有 feature 上（或新 feature 无 checklist），无需启动补测 Agent",
            }
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        yield {
            "type": "info",
            "msg": f"准备启动补测 Agent 测试 {len(features_to_test)} 个新 feature",
        }

        # ---- Step 5: 启动 WorkerAgent 进行测试 ----
        # 按 FEATURES_PER_WORKER 分组，每组一个 worker
        try:
            from core.worker_agent import WorkerAgent
            from core.parallel import get_session_info
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"导入 WorkerAgent 失败（{type(e).__name__}: {e}），跳过补测",
            }
            summary["error"] = f"import_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        try:
            session_info = await get_session_info()
        except Exception as e:
            yield {
                "type": "warn",
                "msg": f"获取 session_info 失败（{type(e).__name__}），使用空配置继续",
            }
            session_info = {}

        # 分组
        groups: list[list] = []
        for i in range(0, len(features_to_test), FEATURES_PER_WORKER):
            groups.append(features_to_test[i:i + FEATURES_PER_WORKER])

        # 标记测试开始
        for fp in features_to_test:
            try:
                sitemap.start_test(fp.id)
            except Exception:
                pass

        # 总预算控制
        budget_deadline = started + TOTAL_BUDGET_S

        for idx, group in enumerate(groups):
            remaining = budget_deadline - time.time()
            if remaining < 30:
                # 时间不够了，剩余 feature 标记为 skipped
                skipped = sum(len(g) for g in groups[idx:])
                summary["skipped_features"] = skipped
                yield {
                    "type": "warn",
                    "msg": f"⏱️ 补测总预算 {TOTAL_BUDGET_S/60:.0f}min 即将耗尽，跳过剩余 {skipped} 个 feature",
                }
                for g in groups[idx:]:
                    for fp in g:
                        try:
                            fp.test_status = sitemap.features[fp.id].test_status
                            from core.sitemap import TestStatus
                            sitemap.features[fp.id].test_status = TestStatus.SKIPPED
                        except Exception:
                            pass
                break

            group_name = f"补测组_{idx+1}"
            try:
                worker = WorkerAgent(
                    worker_id=f"supp{idx+1}",
                    llm=session.llm,
                    features=group,
                    group_name=group_name,
                    sitemap=sitemap,
                    session_info=session_info,
                )
            except Exception as e:
                yield {
                    "type": "warn",
                    "msg": f"创建补测 Agent {group_name} 失败（{type(e).__name__}: {str(e)[:100]}），跳过该组",
                }
                summary["skipped_features"] += len(group)
                continue

            yield {
                "type": "info",
                "msg": f"🚀 启动补测 Agent [{worker.worker_id}] 测试 {len(group)} 个新 feature（{group_name}）",
            }

            # 单组超时 = 单 API 预算 × feature 数
            group_timeout = min(
                PER_API_TIMEOUT_S * len(group) * 3,  # 给 worker 多轮工具调用预留时间
                remaining,
            )

            try:
                async for evt in _run_worker_with_timeout(worker, group_timeout):
                    # 透传给前端
                    yield {"type": "worker_event", "evt": evt}
                summary["tested_features"] += len(group)
            except asyncio.TimeoutError:
                yield {
                    "type": "warn",
                    "msg": f"⏱️ 补测组 {group_name} 超时（{group_timeout:.0f}s），标记为已部分测试",
                }
                summary["tested_features"] += len(group)  # 部分测过也算
            except Exception as e:
                yield {
                    "type": "warn",
                    "msg": f"⚠️ 补测组 {group_name} 异常（{type(e).__name__}: {str(e)[:120]}），跳过该组",
                }
                summary["skipped_features"] += len(group)
                continue

        summary["elapsed"] = time.time() - started
        yield {"type": "done", "summary": summary}

    except Exception as e:
        # 终极兜底：任何异常都不能影响 Phase 2.6
        log.warning("supplemental: 顶层异常: %s", e, exc_info=True)
        summary["error"] = f"top_level: {type(e).__name__}: {str(e)[:200]}"
        summary["elapsed"] = time.time() - started
        yield {
            "type": "error",
            "msg": f"补测 Agent 顶层异常（{type(e).__name__}: {str(e)[:160]}），已跳过",
        }
        yield {"type": "done", "summary": summary}


async def _run_worker_with_timeout(
    worker,
    timeout_s: float,
) -> AsyncGenerator[dict, None]:
    """运行 worker 并加超时控制。"""
    queue: asyncio.Queue = asyncio.Queue()
    done_flag = asyncio.Event()

    async def _drain():
        try:
            async for evt in worker.run():
                await queue.put(evt)
        except Exception as e:
            await queue.put({"type": "worker_error", "error": str(e)})
        finally:
            done_flag.set()

    drain_task = asyncio.create_task(_drain())
    deadline = asyncio.get_event_loop().time() + timeout_s

    try:
        while not done_flag.is_set():
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=min(remaining, 5.0))
                yield evt
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= deadline:
                    raise
                continue
        # done 后 drain 队列里残留事件
        while not queue.empty():
            yield queue.get_nowait()
    finally:
        if not drain_task.done():
            drain_task.cancel()
            try:
                await drain_task
            except (asyncio.CancelledError, Exception):
                pass


# ============================================================
# P2-A: 本地规则版补测（FAST 模式专用，不依赖 LLM）
# ============================================================

async def run_supplemental_test_local(
    session: "Any",
) -> AsyncGenerator[dict, None]:
    """Phase 2.55 本地规则版补测（FAST 模式专用）。

    与 run_supplemental_test 的区别：
    - L1 发现新 API：相同（纯本地规则）
    - L2 挂载到 sitemap：相同（纯本地规则）
    - L3 测试新 feature：用 FastScanner 替代 WorkerAgent（不依赖 LLM）

    这样 FAST 模式也能覆盖爬取后新发现的 API，不增加 LLM 成本。
    """
    started = time.time()
    summary: dict[str, Any] = {
        "discovered": 0,
        "new_features": 0,
        "attached_features": 0,
        "tested_features": 0,
        "vulns_found": 0,
        "elapsed": 0.0,
        "error": None,
        "mode": "local",
    }

    try:
        sitemap = getattr(session, "sitemap", None)
        if sitemap is None:
            yield {"type": "error", "msg": "sitemap 未初始化，跳过补测"}
            summary["error"] = "sitemap 未初始化"
            yield {"type": "done", "summary": summary}
            return

        target_url = getattr(session, "target_url", "") or ""
        phase2_started_at = getattr(session, "_phase2_started_at", 0.0) or 0.0

        # ---- L1: 扫描新 API（纯本地规则） ----
        current_task_id = getattr(session, "task_id", None) or ""
        apis, scan_stats = discover_new_apis_from_flows(
            sitemap=sitemap,
            target_url=target_url,
            phase2_started_at=phase2_started_at,
            task_id=current_task_id or None,
        )

        summary["discovered"] = len(apis)
        summary["scan_stats"] = scan_stats

        if scan_stats.get("flow_file_missing"):
            summary["error"] = f"flow_file_missing: {scan_stats.get('flow_file', '')}"
            yield {
                "type": "error",
                "msg": f"[本地补测] flows.jsonl 不存在: {scan_stats.get('flow_file', '')}",
            }
        elif scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
            err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
            summary["warning"] = f"flows_scan_partial: {err_msg}"
            yield {
                "type": "warn",
                "msg": f"[本地补测] 扫描 flows.jsonl 过程中发生异常（已收集部分结果）: {err_msg[:120]}",
            }

        yield {
            "type": "info",
            "msg": (
                f"[本地补测] 扫描完成: {scan_stats.get('total_scanned', 0)} 条流量, "
                f"保留 {len(apis)} 个新 API "
                f"(早于Phase2 {scan_stats.get('before_phase2', 0)}, "
                f"其他任务 {scan_stats.get('other_task', 0)}, "
                f"scope外 {scan_stats.get('out_of_scope', 0)}, "
                f"第三方 {scan_stats.get('third_party', 0)}, "
                f"非2xx {scan_stats.get('not_2xx', 0)}, "
                f"已知 {scan_stats.get('already_known', 0)}, "
                f"非业务 {scan_stats.get('non_business', 0)}, "
                f"重复 {scan_stats.get('duplicate', 0)})"
            ),
        }
        if scan_stats.get("total_scanned", 0) == 0 and not scan_stats.get("flow_file_missing"):
            summary["warning"] = "no_phase2_flows"
            yield {
                "type": "warn",
                "msg": (
                    "[本地补测] 没有可分析的新流量，因此不会产生新 API。"
                    "如果预期应有补测结果，请检查浏览器代理/mitmproxy 是否生效，"
                    "或确认 Phase 2 期间是否实际产生了目标站点请求。"
                ),
            }

        if not apis:
            if summary.get("error"):
                yield {"type": "error", "msg": "[本地补测] 未获得可补测 API，补测失败但不阻塞后续阶段"}
            elif scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
                err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
                summary["error"] = f"flows_scan_failed: {err_msg}"
                yield {
                    "type": "error",
                    "msg": f"[本地补测] 扫描异常导致未发现新 API: {err_msg[:120]}",
                }
            else:
                yield {"type": "info", "msg": "[本地补测] 未发现新 API，跳过"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- L2: 挂载到 sitemap（纯本地规则） ----
        new_features, attached_features = attach_apis_to_sitemap(sitemap, apis)
        summary["new_features"] = len(new_features)
        summary["attached_features"] = len(attached_features)

        yield {
            "type": "info",
            "msg": (
                f"[本地补测] 挂载完成: 新建 {len(new_features)} 个 feature, "
                f"挂到现有 feature {len(attached_features)} 个 API"
            ),
        }

        features_to_test = [fp for fp in new_features if fp.checklist]
        if not features_to_test:
            yield {"type": "info", "msg": "[本地补测] 无需测试的新 feature"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- L3: FastScanner 本地规则测试（替代 WorkerAgent） ----
        from core.fast_scanner import quick_scan, convert_findings_to_checklist_results
        from core.sitemap import CheckResult

        # 收集认证头
        auth_headers = {}
        cookies = getattr(session, "_inject_cookies", "") or ""
        if cookies:
            auth_headers["Cookie"] = cookies
        inject_headers = getattr(session, "_inject_headers", {}) or {}
        auth_headers.update(inject_headers)

        total_vulns = 0
        for fp in features_to_test:
            # 收集该 feature 的所有 API URL
            api_targets: list[tuple[str, str]] = []
            for api_path in getattr(fp, "related_apis", []) or []:
                normalized = _normalize_related_api_for_scan(api_path, target_url)
                if normalized:
                    api_targets.append(normalized)

            if not api_targets:
                yield {
                    "type": "warn",
                    "msg": f"[本地补测] {fp.name} 没有可解析的 API URL，跳过",
                }
                continue

            yield {
                "type": "info",
                "msg": f"[本地补测] FastScanner 测试 {fp.name}: {len(api_targets)} 个 URL",
            }

            # 对每个 URL 跑 FastScanner
            for method, url in api_targets[:10]:  # 限制每 feature 最多 10 个 URL
                try:
                    result = await quick_scan(
                        url=url,
                        method=method,
                        auth_headers=auth_headers or None,
                        max_workers=5,
                    )
                    if result.vuln_count > 0:
                        total_vulns += result.vuln_count
                        # 回写 checklist
                        cl_results = convert_findings_to_checklist_results(result.findings)
                        for finding in cl_results:
                            vuln_type = finding.get("vuln_type", "")
                            # 匹配 checklist 中的对应项
                            for c in fp.checklist:
                                if c.result == CheckResult.PENDING and vuln_type in c.vuln_type:
                                    c.result = CheckResult.VULN
                                    c.detail = finding.get("detail", "")
                                    c.evidence = finding.get("evidence", "")
                                    c.fix_suggestion = finding.get("fix_suggestion", "")
                                    c.source = "fast_scanner_supplemental"
                                    break
                except Exception as e:
                    log.warning("[本地补测] FastScanner 扫描 %s 失败: %s", url, e)

            summary["tested_features"] += 1

        summary["vulns_found"] = total_vulns
        summary["elapsed"] = time.time() - started

        if total_vulns > 0:
            yield {
                "type": "info",
                "msg": f"[本地补测] 完成: 测试 {summary['tested_features']} 个 feature, "
                       f"发现 {total_vulns} 个漏洞",
            }
        else:
            yield {
                "type": "info",
                "msg": f"[本地补测] 完成: 测试 {summary['tested_features']} 个 feature, 未发现漏洞",
            }

        # 保存 sitemap
        try:
            sitemap.save()
        except Exception:
            pass

        yield {"type": "done", "summary": summary}

    except Exception as e:
        log.warning("supplemental_local: 顶层异常: %s", e, exc_info=True)
        summary["error"] = f"top_level: {type(e).__name__}: {str(e)[:200]}"
        summary["elapsed"] = time.time() - started
        yield {
            "type": "error",
            "msg": f"[本地补测] 异常（{type(e).__name__}: {str(e)[:160]}），已跳过",
        }
        yield {"type": "done", "summary": summary}
