"""G1 — 端点风险域识别（domain × interface 骨架的底座）。

对标参考：H:\\api-pentest-extension\\skills\\api-pentest-workflow\\scripts\\endpoint_analyzer.py
  - RISK_DOMAIN_RULES：8 域关键字匹配（upload/ssrf/injection/authz/csrf/file/business/config）
  - classify_risk_domain(path, method)：返回 List[str]，多域并集（一个端点可属多域）
  - tag_endpoints(endpoints)：给每个端点打 _tags.risk_domain 标签

设计原则（Security Engineer 视角）：
  1. 与业务域 domain_label（business_understanding.py，"Web 应用" 级）**解耦并存** ——
     风险域管"该测什么漏洞"，业务域管"这是什么系统"，二者不冲突。
  2. 纯 stdlib，零外部依赖（对齐 api-pentest-extension 约束 XIV 的零依赖精神）。
  3. 默认安全：POST/PUT/DELETE/PATCH 无关键字匹配时归 "authz"（越权优先关注），
     而非 "general"——写入类端点的鉴权面是高频漏洞源。
  4. 中文同义词纳入（玄鉴目标多为国内系统，路径含中文/拼音很常见）。

F14 覆盖账本（core/loops/coverage_tracker.py）的 risk_area 字段消费本模块的域标签，
G3 coverage_derive 也以 (端点 × 风险域) 为输入推导期望漏洞类型。
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# 8 风险域规则表
#   顺序即优先展示顺序；一个端点可命中多域（多域并集，保序去重）。
#   关键字统一小写匹配；中文同义词与英文等价。
# ---------------------------------------------------------------------------
RISK_DOMAIN_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("upload", (
        "upload", "uploads", "file", "files", "attachment", "attachments",
        "media", "import", "avatar", "头像", "oss", "s3", "上传",
    )),
    ("ssrf", (
        "url", "fetch", "proxy", "webhook", "redirect", "callback",
        "remote", "预览", "代理",
        # 注：原 "link"/"load" 过宽——"load" 会子串误命中 "upload"（upload 域），
        # "link" 会误命中 "unlink"/"flink" 等；二者均移除以消 SSRF 假阳（Security 修正）。
    )),
    ("injection", (
        "query", "search", "sql", "report", "export", "exec",
        "cmd", "inject", "render", "template", "查询", "导出",
    )),
    ("authz", (
        "user", "users", "order", "orders", "role", "roles", "admin",
        "permission", "account", "tenant", "org", "profile", "member",
        "customer", "agent", "dept", "用户", "订单", "权限", "租户",
    )),
    ("csrf", (
        "conf", "config", "setting", "settings", "csrf", "token",
        "password", "reset", "oauth", "sso", "配置", "重置",
    )),
    ("file", (
        "export", "download", "getfile", "path", "temp",
        "read", "document", "下载", "读取",
        # 注：不加裸 "file"——upload 域已含 "file"/"files"（文件上传语义），
        # setdefault 会让 "file" 归属 upload，与 file 域冲突（Security 修正）。
    )),
    ("business", (
        "pay", "transfer", "stock", "coupon", "code", "batch", "recharge",
        "支付", "转账", "库存", "充值",
    )),
    ("config", (
        "getparamconfiglist", "getconfig", "queryconfig", "actuator",
        "swagger", "rememberme", "env", "heapdump",
    )),
]

# 反查表：关键字 -> 域（仅用于 DOMAIN_LABELS 反查等；分类不用它，
# 因为同一关键字可属多域，setdefault 会把多域关键字折叠到首个域，
# 破坏多域并集语义——分类走逐域直查，见 classify_risk_domain）。
_KEYWORD_INDEX: dict[str, list[str]] = {}
for _dom, _kws in RISK_DOMAIN_RULES:
    for _kw in _kws:
        _KEYWORD_INDEX.setdefault(_kw, []).append(_dom)

# 域级中文标签（报告"域级结论表"用）
DOMAIN_LABELS: dict[str, str] = {
    "upload": "文件上传",
    "ssrf": "服务端请求伪造",
    "injection": "注入类",
    "authz": "越权/鉴权",
    "csrf": "跨站请求伪造/配置面",
    "file": "文件读取/下载",
    "business": "业务逻辑",
    "config": "配置/信息泄露",
    "general": "通用",
    "authz_default": "越权/鉴权(写操作默认)",
}

# 写操作集合：无关键字命中时，写类端点默认归 authz（越权优先关注）
_WRITE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# 显式风险域清单（保序，与 RISK_DOMAIN_RULES 同序）。
# 供编排按域派活（Track A）与 UI 共用——**只含 8 个显式域**，
# 不含 "general"/"authz_default" 这类兜底域：兜底域不是"要按域派活的目标"，
# 混入会让派活覆盖度统计虚高。需要兜底域的消费方请自行处理空集。
DOMAIN_LIST: list[str] = [d for d, _ in RISK_DOMAIN_RULES]


def classify_risk_domain(path: str | None, method: str = "GET") -> list[str]:
    """返回端点命中的风险域列表（多域并集，保序去重）。

    Args:
        path: URL path（含 query 也兼容，取 ? 前部分小写）。
        method: HTTP 方法。

    Returns:
        list[str]：命中的风险域；无命中时，写操作归 ["authz"]，读操作归 ["general"]。
        多域并集（如 /api/users/file/upload -> ["upload","authz","file"]）。
    """
    p = (path or "").lower().split("?", 1)[0]
    matched: list[str] = []
    # 逐域直查（不用 _KEYWORD_INDEX，否则共享关键字如 "export" 会被
    # 折叠到首个域，破坏多域并集——injection 与 file 都含 export，需都命中）
    for dom, kws in RISK_DOMAIN_RULES:
        if any(kw in p for kw in kws):
            matched.append(dom)
    if matched:
        return matched
    if str(method).upper() in _WRITE_METHODS:
        return ["authz"]
    return ["general"]


def _extract_method_url(endpoint: Any) -> tuple[str, str]:
    """从端点 dict/对象/键 三种形态提取 (method, url)。

    玄鉴 sitemap.apis 的 api_info 有三种形态（见 business_understanding.py:111-125）：
      - 对象：hasattr(api_info, "url") / .method
      - dict：api_info["url"] / ["method"]
      - 键即 "GET http://..."：api_key.split(" ", 1)
    本函数统一归一，供 tag_endpoints 复用。
    """
    if isinstance(endpoint, Mapping):
        if endpoint.get("url") or endpoint.get("method"):
            return str(endpoint.get("method", "GET")).upper(), str(endpoint.get("url", ""))
        # 兜底：用 api_key 字段
        key = str(endpoint.get("api_key") or endpoint.get("key") or "")
    elif hasattr(endpoint, "url"):
        return str(getattr(endpoint, "method", "GET")).upper(), str(getattr(endpoint, "url", ""))
    else:
        key = str(endpoint)  # api_key 本身
    if " " in key:
        m, _, u = key.partition(" ")
        return m.upper(), u
    return "GET", key


def tag_endpoints(
    endpoints: Iterable[Any],
    *,
    host: str | None = None,
) -> list[dict[str, Any]]:
    """给端点列表打风险域标签（+ 主机/静态资产标记）。

    在端点清单产出后、编排/覆盖推导前调用。标签写入端点 dict 的 ``_tags`` 字段，
    供 G3 coverage_derive 与 G4 覆盖账本消费。

    Args:
        endpoints: 可迭代的端点（dict / 对象 / api_key 字符串）。
        host: 目标主域，用于判定 is_same_host / is_static_asset。

    Returns:
        list[dict]：每个元素含原端点信息 + ``_tags``（risk_domain / is_static_asset /
        is_same_host）。返回统一为 dict 形态，便于下游消费。
    """
    host_lc = (host or "").lower()
    out: list[dict[str, Any]] = []
    for ep in endpoints:
        method, url = _extract_method_url(ep)
        path = url.split("?", 1)[0]
        risk_domain = classify_risk_domain(path, method)
        url_lc = url.lower()
        # 静态资产判定：常见静态后缀（js/css/png/jpg/svg/woff/ico/map/json）
        static_exts = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                       ".woff", ".woff2", ".ttf", ".ico", ".map")
        is_static = any(path.lower().endswith(ext) for ext in static_exts)
        is_same_host = bool(host_lc) and (
            host_lc in url_lc or not url_lc.startswith("http")
        )
        ep_dict = dict(ep) if isinstance(ep, Mapping) else {"method": method, "url": url}
        ep_dict.setdefault("_tags", {})
        ep_dict["_tags"]["risk_domain"] = risk_domain
        ep_dict["_tags"]["is_static_asset"] = is_static
        if host_lc:
            ep_dict["_tags"]["is_same_host"] = is_same_host
        out.append(ep_dict)
    return out


def group_by_risk_domain(endpoints: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """按风险域分组（编排轨道 A：按域分批派活用）。

    一个端点命中多域时，会出现在多个分组中（与多域并集语义一致）。
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for ep in endpoints:
        doms = (ep.get("_tags") or {}).get("risk_domain") or ["general"]
        if isinstance(doms, str):
            doms = [doms]
        for d in doms:
            groups.setdefault(d, []).append(ep)
    return groups


__all__ = [
    "RISK_DOMAIN_RULES",
    "DOMAIN_LIST",
    "DOMAIN_LABELS",
    "classify_risk_domain",
    "tag_endpoints",
    "group_by_risk_domain",
]
