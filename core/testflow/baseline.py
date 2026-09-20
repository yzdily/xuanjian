"""testflow 基线层 — WAF 预检 + 环境一致性采样 + catch-all 共享（v3 §五 Stage 2.1/2.2）。

教训锚点：
- memblaze：2988 次空打 WAF 全拦 → 普查前必须先 WAF 预检（benign vs 攻击对比），
  拦截率超阈值时注入类域降权 / dry-run。
- xindai：LB 200/302 交替被误判鉴权漏洞 → 复采 N≥6 先判负载均衡，不轻易下结论。

设计：与 core/loops/env_sampling.py / identify_waf.py 同构 —— http 为可注入
async callable，不模块级依赖 httpx，纯逻辑可单测。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from core.loops.env_sampling import sample_endpoint, is_load_balanced
from core.loops.identify_waf import identify

__all__ = [
    "WafBaseline",
    "waf_probe",
    "env_consistency_probe",
    "catch_all_baseline",
    "baseline_events",
]

log = logging.getLogger("testflow.baseline")

# WAF 预检的攻击探针（只 1 发，够定性即可——预检不是攻击）
_ATTACK_PROBES: tuple[tuple[str, str], ...] = (
    ("sql", "?id=1%27%20AND%201%3D1--"),
    ("xss", "?q=%3Cscript%3Ealert(1)%3C/script%3E"),
)
# 拦截率 ≥ 该值 → WAF 生效
BLOCK_RATIO_THRESHOLD = 0.5


@dataclass
class WafBaseline:
    """WAF 预检结论（普查注入类域的降权依据）。"""

    waf_detected: bool = False
    vendor: str = ""
    block_ratio: float = 0.0        # 攻击探针被拦比例（0~1）
    benign_blocked: bool = False    # 良性请求也被拦 → 误拦率过高，普查数据不可信
    samples: int = 0
    details: list[str] = field(default_factory=list)

    @property
    def injection_domains_degrade(self) -> bool:
        """注入类（injection/ssrf/xss payload）是否应降权。"""
        return self.waf_detected and self.block_ratio >= BLOCK_RATIO_THRESHOLD

    def to_dict(self) -> dict[str, Any]:
        return {
            "waf_detected": self.waf_detected,
            "vendor": self.vendor,
            "block_ratio": round(self.block_ratio, 2),
            "benign_blocked": self.benign_blocked,
            "samples": self.samples,
        }


async def waf_probe(
    http: Callable[..., Any],
    sample_urls: list[str],
    *,
    auth_headers: dict[str, str] | None = None,
) -> WafBaseline:
    """WAF 预检：对抽样端点发 benign + 攻击对比请求（每端点 ≤3 请求）。

    Args:
        http: async callable，签名 ``http(method, url, headers) -> resp``；
              resp 需有 ``status_code`` / ``headers``（dict）/ ``text``（str）。
        sample_urls: 抽样端点 URL（建议 3~5 个业务 API 即可定性）
        auth_headers: 认证头（有凭证用凭证测，避免 401 干扰判定）

    Returns:
        WafBaseline（纯数据，普查层消费）
    """
    baseline = WafBaseline()
    headers = dict(auth_headers or {})
    if not sample_urls:
        return baseline

    attack_blocked = 0
    attack_total = 0
    for url in sample_urls[:5]:
        # benign：无参数正常 GET
        try:
            resp = await http("GET", url, headers)
            baseline.samples += 1
            if resp is not None and resp.status_code in (403, 406, 429, 501):
                baseline.benign_blocked = True
                baseline.details.append(f"benign 被拦 {resp.status_code}: {url[:80]}")
            elif resp is not None:
                _fill_vendor(baseline, resp)
        except Exception as exc:  # 网络失败不阻塞普查
            log.debug("waf_probe benign 失败 %s: %s", url[:80], exc)
            continue

        # 攻击探针：每端点 1 发 SQLi 探针（攻击面最小化）
        probe_kind, probe_qs = _ATTACK_PROBES[0]
        sep = "&" if "?" in url else "?"
        probe_url = f"{url}{sep}{probe_qs}"
        try:
            resp = await http("GET", probe_url, headers)
            attack_total += 1
            if resp is not None and _looks_blocked(resp):
                attack_blocked += 1
                if not baseline.vendor:
                    _fill_vendor(baseline, resp)
        except Exception as exc:
            log.debug("waf_probe attack 失败 %s: %s", probe_url[:80], exc)

    baseline.block_ratio = (attack_blocked / attack_total) if attack_total else 0.0
    baseline.waf_detected = baseline.block_ratio >= BLOCK_RATIO_THRESHOLD or baseline.benign_blocked
    return baseline


def _looks_blocked(resp: Any) -> bool:
    """启发式拦截判定：典型 WAF 拒绝状态码或响应体风控特征。"""
    if resp.status_code in (403, 406, 418, 429, 501):
        return True
    text = (getattr(resp, "text", "") or "")[:2000].lower()
    return any(kw in text for kw in (
        "waf", "blocked", "防火墙", "拦截", "forbidden by",
        "request denied", "security notice", "cloudflare",
    ))


def _fill_vendor(baseline: WafBaseline, resp: Any) -> None:
    """复用 core/loops/identify_waf 指纹识别（headers+body）。"""
    try:
        info = identify(
            status=resp.status_code,
            headers=dict(getattr(resp, "headers", {}) or {}),
            body=(getattr(resp, "text", "") or "")[:2000],
        )
        vendor = (info or {}).get("waf")
        if vendor:
            baseline.vendor = str(vendor)
    except Exception as exc:
        log.debug("identify_waf 失败: %s", exc)


@dataclass
class EnvConsistency:
    """环境一致性采样结论（xindai 教训：LB 交替 ≠ 鉴权漏洞）。"""

    is_lb: bool = False             # 状态码交替 → LB 不一致，鉴权结论需降权
    authz_consistent: bool = False  # N 次全一致 → 可下稳定结论
    codes: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"is_lb": self.is_lb, "authz_consistent": self.authz_consistent,
                "codes": self.codes}


async def env_consistency_probe(
    http: Callable[..., Any],
    req: dict[str, Any],
    *,
    n: int = 6,
) -> EnvConsistency:
    """环境一致性采样：同接口固定 N≥6 复采（复用 loops/env_sampling）。

    Args:
        http: async callable，``http(req) -> resp_dict``（resp_dict 含 http_code）
        req: 请求构造 dict（url/method/headers）
        n: 采样次数，默认 6（xindai §3.6）
    """
    result = await sample_endpoint(http, req, n=n)
    codes = [int(r.get("http_code") or r.get("status") or 0) if isinstance(r, dict) else int(r)
             for r in result.responses]
    return EnvConsistency(
        is_lb=result.is_lb,
        authz_consistent=result.authz_consistent,
        codes=codes,
    )


@dataclass
class CatchAllBaseline:
    """catch-all / soft-404 全局共享基线（G1 端点真实性门用）。"""

    detected: bool = False
    rate: float = 0.0            # 相同内容比例 %
    fingerprint: str = ""        # 归一化后的 catch-all 响应指纹（SPA fallback 对照）

    def matches(self, body: str, normalize: Callable[[str], str] | None = None) -> bool:
        """响应体是否命中 catch-all 指纹（幻影端点判定）。"""
        if not self.detected or not self.fingerprint:
            return False
        if normalize is not None:
            return normalize(body) == self.fingerprint
        return (body or "").strip() == self.fingerprint


def catch_all_baseline(*, detected: bool = False, rate: float = 0.0,
                       sample_body: str = "", normalize: Callable[[str], str] | None = None) -> CatchAllBaseline:
    """从 dir_scanner 的 OPT5 catch-all 检测结果构造共享基线。

    chat_loop/_run_parallel_test 已有 catch_all_detected/catch_all_rate 产出；
    此处只做指纹固化（把"catch-all 响应长什么样"存下来供 G1 复用）。
    """
    fp = normalize(sample_body) if (normalize and sample_body) else (sample_body or "").strip()
    return CatchAllBaseline(detected=detected, rate=rate, fingerprint=fp)


def baseline_events(baseline: WafBaseline, env: EnvConsistency | None = None) -> list[str]:
    """终端事件文案（📋 Stage 2.1/2.2，用户视角）。"""
    events: list[str] = []
    if baseline.waf_detected:
        degrade = "，注入类域降权" if baseline.injection_domains_degrade else ""
        events.append(
            f"📋 WAF 预检: 检测到 WAF"
            f"{'（' + baseline.vendor + '）' if baseline.vendor else ''}"
            f"，拦截率 {baseline.block_ratio:.0%}{degrade}")
    else:
        events.append(
            f"📋 WAF 预检: 良性 + 攻击请求对比 → {baseline.block_ratio:.0%} 拦截 → 无 WAF"
            f"（注入类全开）")
    if env is not None:
        if env.is_lb:
            events.append(f"📋 环境采样: 状态码交替 {env.codes} → 负载均衡不一致，鉴权结论降权")
        elif env.authz_consistent:
            events.append(f"📋 环境采样: {len(env.codes)} 次全一致 → 可下稳定结论")
    return events
