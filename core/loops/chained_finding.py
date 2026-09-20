"""
core/loops/chained_finding.py — 跨域链路漏洞登记（§1.5）。

## 解决什么
"上传 → 下载 → 弹 XSS"这类多阶段链，会在 upload / xss / authz 多个域各产生
一条 finding，统计时被**重复计数**。本模块把链登记一次，各域只挂引用。

## 用法
    cid = register_chain({"steps": ["upload", "download", "xss"]})
    attach_domain_ref(cid, "upload", finding_a)
    attach_domain_ref(cid, "xss", finding_b)
    count_unique_chains()   # -> 1（只计一次）
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CHAIN_REGISTRY: dict[str, dict[str, Any]] = {}


def _chain_id(chain: dict[str, Any]) -> str:
    """用链内容做稳定 hash，保证同链重复登记得到同一 id（幂等）。"""
    raw = json.dumps(
        {
            "steps": chain.get("steps") or [],
            "key": chain.get("key") or chain.get("name") or "",
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return "chain-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def register_chain(chain: dict[str, Any]) -> str:
    """登记一条利用链（幂等：同链返回同一 id）。返回 chain_id。"""
    cid = chain.get("chain_id") or _chain_id(chain)
    if cid not in CHAIN_REGISTRY:
        CHAIN_REGISTRY[cid] = {
            "chain_id": cid,
            "steps": list(chain.get("steps") or []),
            "domains": [],
            "finding_refs": [],
        }
    return cid


def attach_domain_ref(chain_id: str, domain: str, finding: Any = None) -> bool:
    """给链挂一个域级引用（多域引用同一链时统计只算一次）。"""
    entry = CHAIN_REGISTRY.get(chain_id)
    if entry is None:
        return False
    if domain and domain not in entry["domains"]:
        entry["domains"].append(domain)
    if finding is not None:
        entry["finding_refs"].append(finding)
    return True


def count_unique_chains() -> int:
    """登记的唯一链数量（跨域去重后的计数口径）。"""
    return len(CHAIN_REGISTRY)


def domains_of(chain_id: str) -> list[str]:
    entry = CHAIN_REGISTRY.get(chain_id)
    return list(entry["domains"]) if entry else []


def reset_registry() -> None:
    """清空登记表（仅供测试/单次扫描初始化）。"""
    CHAIN_REGISTRY.clear()


__all__ = [
    "CHAIN_REGISTRY",
    "register_chain",
    "attach_domain_ref",
    "count_unique_chains",
    "domains_of",
    "reset_registry",
]
