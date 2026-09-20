"""
core/loops/identify_waf.py — WAF 厂商签名识别（§2.7 / 技术方案 3.12.1）。

## 玄鉴现状（grep 核验）
`core/fuzz/base.py:309 _detect_waf()` **只返回布尔**（有/无 WAF），
无法归因厂商 → 也无法"按厂商选绕过原语"。本模块把布尔升级为厂商归因。

## 零依赖 + 配置驱动
签名库外置为同目录 `waf_signatures.json`（23 家，可改配置扩厂商，无需改代码）；
文件缺失/损坏时**回退本模块内置副本**，保证能力不回退。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SIG_FILE = Path(__file__).with_name("waf_signatures.json")

# vendor -> (header 名 -> 值特征) / body 特征串（内置副本 = 兜底，与 JSON 同源）
WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {"headers": {"server": "cloudflare", "cf-ray": ""}, "body": []},
    "AWS WAF": {"headers": {"x-amzn-waf": "", "x-aws-waf": ""}, "body": []},
    "ModSecurity": {"headers": {"server": "mod_security"}, "body": ["mod_security", "not acceptable"]},
    "Akamai": {"headers": {"x-akamai": ""}, "body": ["akamai"]},
    "Imperva": {"headers": {"x-iinfo": ""}, "body": ["incapsula"]},
    "F5 BIG-IP": {"headers": {"server": "big-ip"}, "body": ["the requested url was rejected"]},
    "Sucuri": {"headers": {"x-sucuri-id": ""}, "body": ["sucuri"]},
    "SafeDog": {"headers": {"server": "safedog"}, "body": ["safedog"]},
    "YunSuo": {"headers": {}, "body": ["yunsuo", "云锁"]},
    "360": {"headers": {}, "body": ["360webscan", "360网站卫士"]},
    "Alibaba Cloud WAF": {"headers": {"server": "aqs"}, "body": ["aliyun", "waf"]},
    "Tencent Cloud WAF": {"headers": {}, "body": ["tencent", "waf.tencent"]},
    "Huawei Cloud WAF": {"headers": {}, "body": ["huawei", "huaweicloud"]},
    "DenyAll": {"headers": {}, "body": ["denyall"]},
    "Naxsi": {"headers": {}, "body": ["naxsi"]},
    "Wallarm": {"headers": {"x-wallarm": ""}, "body": []},
    "Reblaze": {"headers": {"x-reblaze": ""}, "body": []},
    "Citrix NSP": {"headers": {"server": "citrix"}, "body": []},
    "Varnish": {"headers": {"server": "varnish"}, "body": []},
    "Profense": {"headers": {}, "body": ["profense"]},
    "Powerful": {"headers": {}, "body": ["powerful"]},
    "Airlock": {"headers": {}, "body": ["airlock"]},
    "Barracuda": {"headers": {"server": "barracuda"}, "body": []},
}

BLOCK_STATUS_DEFAULT: tuple[int, ...] = (403, 406, 418, 429, 503)

# 厂商 → 推荐绕过原语（驱动 injection_tamper 选链）
_SUGGESTED: dict[str, list[str]] = {
    "Cloudflare": ["space2comment", "random_case"],
    "ModSecurity": ["versioned_comment", "random_comments"],
    "SafeDog": ["space2comment", "equal_to_like"],
    "YunSuo": ["random_comments", "random_case"],
}


@dataclass
class _SigState:
    """签名库加载态（D7 holder 模式：不用 `global`）。"""
    loaded: bool = False
    block_status: tuple[int, ...] = BLOCK_STATUS_DEFAULT
    source: str = "builtin"


_state = _SigState()


def effective_block_status() -> tuple[int, ...]:
    """当前生效的 WAF 拦截状态码（JSON 可覆盖，默认内置元组）。"""
    _load_signatures()
    return _state.block_status


def _load_signatures() -> None:
    """从 ``waf_signatures.json`` 覆盖内置副本（失败则保留内置）。"""
    if _state.loaded:
        return
    _state.loaded = True
    try:
        raw = json.loads(_SIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    vendors = raw.get("vendors")
    if isinstance(vendors, dict) and vendors:
        # 校验结构最小完整性：每家必须有 headers/body 字段
        ok = all(isinstance(v, dict) and ("headers" in v or "body" in v) for v in vendors.values())
        if ok:
            # 原地 mutation（dict.clear/update 不涉及名字重绑定，无需 global）
            WAF_SIGNATURES.clear()
            WAF_SIGNATURES.update(vendors)
            _state.source = "json"
    sug = raw.get("suggested_tamper")
    if isinstance(sug, dict):
        _SUGGESTED.update({str(k): list(v) for k, v in sug.items() if isinstance(v, (list, tuple))})
    bs = raw.get("block_status")
    if isinstance(bs, list) and bs:
        try:
            _state.block_status = tuple(int(x) for x in bs)
        except (TypeError, ValueError):
            pass


def signature_source() -> str:
    """当前签名库来源（``json`` / ``builtin``），供自检与回归钉使用。"""
    _load_signatures()
    return _state.source


def _match_header(headers: dict[str, Any], vendor: str, sig: dict[str, Any]) -> float:
    """值感知 header 匹配：命中厂商专属 header 名 → 高置信；仅 server 名匹配 → 中。"""
    lowered = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for hname, hval in (sig.get("headers") or {}).items():
        if hname in lowered:
            if not hval or hval in lowered[hname]:
                return 0.95 if hname != "server" else 0.9
    return 0.0


def _match_body(body: str, sig: dict[str, Any]) -> float:
    text = (body or "").lower()
    for token in sig.get("body") or []:
        if token and token in text:
            return 0.85
    return 0.0


def identify(status: int = 0, headers: dict[str, Any] | None = None,
             body: str = "") -> dict[str, Any]:
    """识别目标前置 WAF 厂商。

    Returns:
        {"waf": str|None, "confidence": float, "suggested_tamper": list[str],
         "blocked": bool, "vendor_count": int}
    """
    _load_signatures()   # 优先外部配置（缺失/损坏 → 内置副本）
    headers = headers or {}
    best_vendor, best_score = None, 0.0

    for vendor, sig in WAF_SIGNATURES.items():
        score = max(_match_header(headers, vendor, sig), _match_body(body, sig))
        if score > best_score:
            best_vendor, best_score = vendor, score

    blocked = status in effective_block_status()

    # 命中 block 状态码但没匹配到厂商 → 通用兜底 0.5
    if best_vendor is None and blocked:
        return {
            "waf": "Unknown WAF (generic block page)",
            "confidence": 0.5,
            "suggested_tamper": ["space2comment"],
            "blocked": True,
            "vendor_count": len(WAF_SIGNATURES),
        }

    if best_vendor is None:
        return {"waf": None, "confidence": 0.0, "suggested_tamper": [],
                "blocked": blocked, "vendor_count": len(WAF_SIGNATURES)}

    return {
        "waf": best_vendor,
        "confidence": round(best_score, 2),
        "suggested_tamper": _SUGGESTED.get(best_vendor, ["space2comment"]),
        "blocked": blocked,
        "vendor_count": len(WAF_SIGNATURES),
    }


def detect_and_identify(
    status: int = 0, headers: dict[str, Any] | None = None, body: str = "",
) -> dict[str, Any]:
    """`core.fuzz.base._detect_waf` 的厂商归因版（bool → 厂商）。

    供 fuzz 引擎把"有没有 WAF"升级为"是哪家 WAF + 该用哪些绕过原语"。
    """
    info = identify(status=status, headers=headers, body=body)
    info["is_waf"] = bool(info.get("blocked") or info.get("waf"))
    return info


__all__ = [
    "WAF_SIGNATURES",
    "BLOCK_STATUS_DEFAULT",
    "effective_block_status",
    "identify",
    "detect_and_identify",
    "signature_source",
]
