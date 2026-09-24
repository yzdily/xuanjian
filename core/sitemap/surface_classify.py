"""Sitemap — 端点来源分类与证据强度（924 抽出的纯函数集合）。

## 为什么单独成模块

两个原因：

1. **可复用**：这些判定被"覆盖矩阵渲染"（`coverage.py`）与"报告横幅"
   （`report.py`）共同消费，放在任一消费方都会产生第二份实现。
2. **行数闸门**：`tests/unit/test_giant_file_gate.py` 要求 `core/` 下 `.py ≤ 800 行`，
   `coverage.py` 加了这些判定后到 852 行 —— 抽出来同时解决两件事。

## 924 教训（这些函数存在的原因）

- **`_ep_attr` 必须用**：旧代码用 `isinstance(a, dict)` 遍历 `sitemap.apis`，
  但那里存的是 `APIEndpoint` **对象** → 条件恒 False → "业务 API 仅 0 个"的横幅
  **永远显示**，变成"狼来了"，读者学会忽略。
- **`business` 要求"观察到内容"**：本任务 `/images` `/lib` `/css` 都是 `real_flow`
  （真实流量），但只是静态目录的 301 跳转、`response_sample` 为空 ——
  把它们算成"业务 API"会让覆盖率告警彻底失效。
- **`_is_probe_api`**：`..;/` / `;/` / `%2e` 这类构造不是目标的真实接口，
  与 `core/dir_scanner/_finding_policy.py` 的归一化探针特征同一族。
"""
from __future__ import annotations

from typing import Any, Mapping

# ---- 证据强度 ----

#: 弱证据标记 —— 只有响应头、没有可复现的响应体/行为证据的条目，
#: 不应出现在报告头条的"发现漏洞"计数里（否则「nginx 版本头」会被读成真漏洞）。
_WEAK_EVIDENCE_MARKERS = (
    "evidence_quality=header_only",
    "仅响应头证据",
    "仅头部证据",
    "header_only",
)


def evidence_quality_of(c: Any) -> str:
    """判定一条 checklist 结论的证据强度：``header_only`` / ``content`` / ``""``。"""
    _blob = f"{getattr(c, 'evidence_response', '') or ''}\n{getattr(c, 'detail', '') or ''}"
    if any(_m in _blob for _m in _WEAK_EVIDENCE_MARKERS):
        return "header_only"
    return "content" if (getattr(c, "evidence_response", "") or "").strip() else ""


def split_by_strength(vuln_list: list[dict]) -> dict[str, int]:
    """把 vuln_list 拆成「可入头条」与「弱证据待复核」两组计数。"""
    _weak = sum(1 for v in (vuln_list or [])
                if str(v.get("evidence_quality") or "") == "header_only")
    return {"accepted": len(vuln_list or []) - _weak, "weak": _weak}


# ---- 端点来源分类 ----

#: 路径归一化绕过探针特征（与 dir_scanner._finding_policy 同一族）
_PROBE_PATH_MARKERS = ("..;/", ";/", "%2e", "....//", "%252e")

#: 静态资源扩展名 —— 命中即不属于"业务 API"
_STATIC_API_EXTS = (
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".pdf", ".zip", ".txt",
)


def is_probe_api(api_str: str) -> bool:
    """该 API 字符串是否为路径归一化探针（``..;/`` / ``;/`` / ``%2e``）。"""
    _s = str(api_str or "").lower()
    return any(_m in _s for _m in _PROBE_PATH_MARKERS)


def ep_attr(ep: Any, name: str, default: Any = "") -> Any:
    """从端点条目取字段 —— 兼容 ``dict`` 与 ``APIEndpoint`` 对象两种形态。

    ★ 924 教训：旧代码直接写 `isinstance(a, dict)`，而 ``sitemap.apis`` 里存的
    **是 ``APIEndpoint`` 对象**，条件恒为 False —— 于是"业务 API 仅 0 个"的横幅
    **永远显示**。任何遍历 apis 的统计都必须走这里。
    """
    if isinstance(ep, Mapping):
        return ep.get(name, default)
    return getattr(ep, name, default)


def classify_api_surface(apis: Any) -> dict[str, int]:
    """按来源把 API 面分类计数（"业务 API 个数"的**唯一权威实现**）。

    分类规则（顺序即优先级）：

    ``static``       路径以静态资源扩展名结尾 → 不是业务面
    ``probe``        路径归一化探针（``..;/`` 等）或 ``discovered_by == dir_scan_active``
    ``speculative``  ``source_type == js_static`` / ``discovered_by == js_analysis``（未验证推测）
    ``business``     ``source_type == real_flow`` **且确实观察到响应体/请求体/参数**
    ``unverified``   其余（含只看过 301/302 跳转、无任何观测内容的目录类端点）
    """
    out = {"business": 0, "speculative": 0, "probe": 0,
           "static": 0, "unverified": 0, "total": 0}
    for ep in (apis or {}).values():
        out["total"] += 1
        url = str(ep_attr(ep, "url", "") or "")
        path = url.split("?", 1)[0].lower()
        if path.endswith(_STATIC_API_EXTS):
            out["static"] += 1
            continue
        if is_probe_api(url) or str(ep_attr(ep, "discovered_by", "") or "") == "dir_scan_active":
            out["probe"] += 1
            continue
        _st = str(ep_attr(ep, "source_type", "") or "")
        _db = str(ep_attr(ep, "discovered_by", "") or "")
        if _st == "js_static" or _db == "js_analysis":
            out["speculative"] += 1
            continue
        _observed = bool(
            str(ep_attr(ep, "response_sample", "") or "").strip()
            or str(ep_attr(ep, "request_body_sample", "") or "").strip()
            or (ep_attr(ep, "params", None) or [])
        )
        if (_st == "real_flow" or _db == "phase2_flow") and _observed:
            out["business"] += 1
            continue
        out["unverified"] += 1
    return out


def api_source_label(api_str: str, apis: Mapping | None) -> str:
    """给覆盖矩阵里的 API 行加**来源角标**（消除"探针=真实端点"的误读）。

    实测 task_1790223312_c75b16：矩阵同一行并列 `GET /` 与
    `GET /..;/actuator/env` 并共享一个 🔴，读者会把 🔴 归因到 actuator 上
    （实际 🔴 属于根路径的 nginx 版本头）。

    Returns:
        ``'[探针]'`` / ``'[未验证推测]'`` / ``''``（真实流量或未知但非探针）。
    """
    if is_probe_api(api_str):
        return "[探针]"
    if not apis:
        return ""
    _parts = str(api_str or "").split(" ", 1)
    _method = _parts[0].upper() if len(_parts) > 1 else "GET"
    _url = _parts[1].strip() if len(_parts) > 1 else str(api_str or "").strip()
    _key = f"{_method} {_url}"
    _ep = None
    try:
        _ep = apis.get(_key)
        if _ep is None:
            for _k, _v in apis.items():
                if str(_k).strip() == _key:
                    _ep = _v
                    break
    except Exception:
        _ep = None
    if _ep is None:
        return ""
    _db = str(ep_attr(_ep, "discovered_by", "") or "")
    _st = str(ep_attr(_ep, "source_type", "") or "")
    _conf = float(ep_attr(_ep, "confidence", 0) or 0)
    if _db == "dir_scan_active":
        return "[探针]"
    if _st == "js_static" and _conf < 0.6:
        return "[未验证推测]"
    return ""


__all__ = [
    "api_source_label",
    "classify_api_surface",
    "ep_attr",
    "evidence_quality_of",
    "is_probe_api",
    "split_by_strength",
]
