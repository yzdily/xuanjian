"""G? — 漏洞分类跨映射表（漏8 / 漏V3-8 / 漏V3-1 修正）。

把"三套并存"的分类体系统一为单一权威跨映射，供链模板 hop 匹配 / 覆盖矩阵 /
STRIDE 对拍复用，消除"模板写的类型名 finding 里没有"的口径断裂。

四套词表（权威源，禁止各自手维护）：
  A. 8 风险域            core.endpoint.risk_domain.RISK_DOMAIN_RULES
  B. 11 组 / 18 类型     core.testflow.coverage_derive.VULN_TYPE_GROUPS
  C. strix 29 类         hollowing-optimization-plan/strix-main/strix/skills/vulnerabilities/*.md
                        （该目录被 .gitignore 忽略，故 29 类清单固化进本文件 = "strix 借鉴到 xuanjian 源码"）
  D. CheckItem 运行时中文标准名  core.scripted_scan.types.VULN_TYPE_MAP

铁律：
  - 中文标准名（D）方向**复用** ``VULN_TYPE_MAP`` 反向派生，禁止在本文件再写一张中→英表。
  - strix（C）是真正的新词表，固化进 ``STRIX_INDEX``；其到 xuanjian 类型/域的映射是本文件
    唯一新增的跨轴数据，单点维护。
  - 8 域 / 18 类型直接从 A、B 权威源导入，不抄写。

兼容性：仅依赖 stdlib + 上述三个轻量模块；``scripted_scan`` 重型依赖做降级导入，
缺依赖环境（如纯 stdlib 校验）仍可 import，仅中文标准名解析降级。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

# --- A. 8 风险域（权威源，原样导入，不抄写）-------------------------------
from core.endpoint.risk_domain import RISK_DOMAIN_RULES  # noqa: E402

RISK_DOMAINS: List[str] = [d for d, _ in RISK_DOMAIN_RULES]  # 8 个：upload/ssrf/injection/authz/csrf/file/business/config

# --- B. 11 组 / 18 类型（权威源，原样导入，不抄写）-----------------------
from core.testflow.coverage_derive import VULN_TYPE_GROUPS  # noqa: E402

# 11 组 → 成员类型（保序）
VULN_GROUPS: Dict[str, List[str]] = {g: sorted(t) for g, t in VULN_TYPE_GROUPS.items()}
# 18 个扁平类型（跨组去重保序）
XUANJIAN_VULN_TYPES: List[str] = sorted({t for ts in VULN_TYPE_GROUPS.values() for t in ts})

# --- C. strix 29 类（固化进源码；来自被 gitignore 的 strix-main）---------
# 每条：slug（技能文件名去 .md）= strix 类标识；xuanjian_type = 对应的 18 类型键
#       （无直接对应则 None，作为 strix 扩展能力独立存在）；domains = 落入的 8 域；
#       group = 对应的 11 组（无则 "strix_ext"）。
STRIX_INDEX: List[Dict[str, Any]] = [
    {"slug": "agentic_system_security", "xuanjian_type": None, "domains": ["authz", "config"], "group": "strix_ext"},
    {"slug": "argument_injection", "xuanjian_type": None, "domains": ["injection"], "group": "strix_ext"},
    {"slug": "authentication_jwt", "xuanjian_type": "auth_bypass", "domains": ["authz"], "group": "auth"},
    {"slug": "broken_function_level_authorization", "xuanjian_type": "privilege_escalation", "domains": ["authz"], "group": "privilege"},
    {"slug": "browser_security", "xuanjian_type": None, "domains": ["config"], "group": "strix_ext"},
    {"slug": "business_logic", "xuanjian_type": "logic", "domains": ["business"], "group": "business"},
    {"slug": "csrf", "xuanjian_type": "csrf", "domains": ["csrf"], "group": "request_forgery"},
    {"slug": "header_injection", "xuanjian_type": "header_injection", "domains": ["injection"], "group": "injection"},
    {"slug": "http_request_smuggling", "xuanjian_type": None, "domains": ["injection"], "group": "strix_ext"},
    {"slug": "idor", "xuanjian_type": "idor", "domains": ["authz", "business"], "group": "idor"},
    {"slug": "information_disclosure", "xuanjian_type": "sensitive_response", "domains": ["config", "file", "ssrf"], "group": "info"},
    {"slug": "insecure_deserialization", "xuanjian_type": None, "domains": ["injection", "config"], "group": "strix_ext"},
    {"slug": "insecure_file_uploads", "xuanjian_type": "upload", "domains": ["upload"], "group": "file"},
    {"slug": "llm_prompt_injection", "xuanjian_type": None, "domains": ["config", "business"], "group": "strix_ext"},
    {"slug": "mass_assignment", "xuanjian_type": "privilege_escalation", "domains": ["authz"], "group": "privilege"},
    {"slug": "nosql_injection", "xuanjian_type": "nosqli", "domains": ["injection"], "group": "injection"},
    {"slug": "open_redirect", "xuanjian_type": None, "domains": ["ssrf"], "group": "strix_ext"},
    {"slug": "path_traversal_lfi_rfi", "xuanjian_type": "lfi", "domains": ["upload", "file", "ssrf"], "group": "lfi"},
    {"slug": "prototype_pollution", "xuanjian_type": None, "domains": ["injection", "config"], "group": "strix_ext"},
    {"slug": "race_conditions", "xuanjian_type": None, "domains": ["business"], "group": "strix_ext"},
    {"slug": "rce", "xuanjian_type": None, "domains": ["injection", "config"], "group": "strix_ext"},
    {"slug": "semantic_confusion", "xuanjian_type": None, "domains": ["authz", "config"], "group": "strix_ext"},
    {"slug": "sql_injection", "xuanjian_type": "sqli", "domains": ["injection"], "group": "injection"},
    {"slug": "ssrf", "xuanjian_type": "ssrf", "domains": ["ssrf"], "group": "ssrf"},
    {"slug": "ssti", "xuanjian_type": "ssti", "domains": ["injection"], "group": "injection"},
    {"slug": "subdomain_takeover", "xuanjian_type": None, "domains": ["config"], "group": "strix_ext"},
    {"slug": "weak_password_detection", "xuanjian_type": "auth_bypass", "domains": ["authz"], "group": "auth"},
    {"slug": "xss", "xuanjian_type": "xss", "domains": ["upload", "injection"], "group": "xss"},
    {"slug": "xxe", "xuanjian_type": "xxe", "domains": ["injection"], "group": "injection"},
]

# 18 类型 → 8 域（由 G3 coverage_derive._DOMAIN_VULN_TYPES 反推，单点维护）
TYPE_DOMAINS: Dict[str, List[str]] = {
    "sqli": ["injection"],
    "cmdi": ["injection"],
    "ssti": ["injection"],
    "xxe": ["injection"],
    "nosqli": ["injection"],
    "ldap": ["injection"],
    "expression_injection": ["injection"],
    "header_injection": ["injection"],
    "sensitive_response": ["config", "file", "ssrf"],
    "logic": ["business"],
    "csrf": ["csrf"],
    "privilege_escalation": ["authz"],
    "idor": ["authz", "business"],
    "auth_bypass": ["authz"],
    "upload": ["upload"],
    "xss": ["upload", "injection"],
    "ssrf": ["ssrf"],
    "lfi": ["upload", "file"],
}

# playbook 直接引用的 strix 技能 id（连字符复合形式）→ xuanjian 类型键
_STRIX_SKILL_IDS: Dict[str, str] = {
    "idor-broken-object-authorization": "idor",
    "insecure-file-upload": "upload",
    "sqli-sql-injection": "sqli",
    "ssti-server-side-template-injection": "ssti",
    "ssrf-server-side-request-forgery": "ssrf",
    "privilege-escalation": "privilege_escalation",
}

_STRIX_BY_SLUG: Dict[str, Dict[str, Any]] = {e["slug"]: e for e in STRIX_INDEX}
_STRIX_SLUGS: List[str] = [e["slug"] for e in STRIX_INDEX]


# --- D. CheckItem 运行时中文标准名（复用 VULN_TYPE_MAP，禁止第三张表）----
try:  # 降级：缺 scripted_scan 依赖时（纯 stdlib 校验环境）仍可 import
    from core.scripted_scan.types import VULN_TYPE_MAP  # noqa: E402
except Exception:  # pragma: no cover - 仅在缺依赖环境降级
    VULN_TYPE_MAP: Dict[str, str] = {}


def _canon_target(en: str) -> str | None:
    """把 VULN_TYPE_MAP 的英文键归一到本映射已知的 canonical 键。"""
    low = en.lower()
    if low in VULN_TYPE_ALIAS:  # type: ignore[name-defined]
        return VULN_TYPE_ALIAS[low]  # type: ignore[name-defined]
    under = low.replace(" ", "_")
    if under in VULN_TYPE_ALIAS:  # type: ignore[name-defined]
        return VULN_TYPE_ALIAS[under]  # type: ignore[name-defined]
    # 前缀桥：VULN_TYPE_MAP 英文键 → strix 复合 slug 前缀
    # （path traversal → path_traversal_lfi_rfi → lfi），不新建第三张映射表
    for _e in STRIX_INDEX:
        if _e["slug"].startswith(under + "_"):
            return _e["xuanjian_type"] or _e["slug"]
    return None


# 别名 → canonical 键 的总表（契约测试与解析的统一入口）
VULN_TYPE_ALIAS: Dict[str, str] = {}
for _t in XUANJIAN_VULN_TYPES:
    VULN_TYPE_ALIAS[_t] = _t
for _e in STRIX_INDEX:
    _key = _e["xuanjian_type"] or _e["slug"]
    VULN_TYPE_ALIAS.setdefault(_e["slug"], _key)
    _hyphen = _e["slug"].replace("_", "-")
    if _hyphen != _e["slug"]:
        VULN_TYPE_ALIAS.setdefault(_hyphen, _key)
for _skill_id, _key in _STRIX_SKILL_IDS.items():
    VULN_TYPE_ALIAS.setdefault(_skill_id, _key)
# 中文标准名（D）反向并入——复用 VULN_TYPE_MAP，不新建表
for _en, _zh in VULN_TYPE_MAP.items():
    _target = _canon_target(_en)
    if _target:
        VULN_TYPE_ALIAS.setdefault(_zh, _target)
        VULN_TYPE_ALIAS.setdefault(_en.lower(), _target)
        VULN_TYPE_ALIAS.setdefault(_en.lower().replace("_", " "), _target)
        VULN_TYPE_ALIAS.setdefault(_en.lower().replace(" ", "_"), _target)

# 中文标准名 → canonical 键（运行时解析用，避免每次重算）
CHINESE_TO_CANON: Dict[str, str] = {
    _zh: _target for _en, _zh in VULN_TYPE_MAP.items() if (_target := _canon_target(_en))
}


def resolve_vuln_type(raw: str) -> str:
    """把任意（中文标准名 / 英文 / strix 类 / 技能 id）归一为 canonical 键。

    解析优先级：直接别名 → 连字符/下划线归一 → 中文标准名（复用 VULN_TYPE_MAP）
    → 未知则原样返回小写（交下游/契约测试标记，不静默吞）。
    """
    if not raw:
        return ""
    s = raw.strip().lower()
    if s in VULN_TYPE_ALIAS:
        return VULN_TYPE_ALIAS[s]
    norm = s.replace("-", "_")
    if norm in VULN_TYPE_ALIAS:
        return VULN_TYPE_ALIAS[norm]
    zh = CHINESE_TO_CANON.get(raw.strip())
    if zh:
        return zh
    return s


def vuln_type_domains(key: str) -> List[str]:
    """canonical 键 → 落入的 8 域（保序去重）。"""
    k = resolve_vuln_type(key)
    if k in TYPE_DOMAINS:
        return list(TYPE_DOMAINS[k])
    e = _STRIX_BY_SLUG.get(k)
    if e:
        return list(e["domains"])
    return []


def vuln_type_group(key: str) -> str:
    """canonical 键 → 11 组名（strix 独立类返回其 group，含 strix_ext）。"""
    k = resolve_vuln_type(key)
    for g, members in VULN_GROUPS.items():
        if k in members:
            return g
    e = _STRIX_BY_SLUG.get(k)
    return e["group"] if e else ""


def vuln_type_strix(key: str) -> List[str]:
    """canonical 键 → 对应的 strix 类 slug 列表（可能多对一）。"""
    k = resolve_vuln_type(key)
    out: List[str] = []
    for e in STRIX_INDEX:
        if e["xuanjian_type"] == k or e["slug"] == k:
            out.append(e["slug"])
    return out


def strix_to_xuanjian(slug: str) -> str:
    """strix 类 slug → xuanjian 类型键（无直接对应则返回 slug 自身）。"""
    e = _STRIX_BY_SLUG.get(slug)
    return e["xuanjian_type"] or slug if e else slug


def validate_chain_template(template: Mapping[str, Any]) -> tuple[bool, str]:
    """契约门（漏8 · §5.3 / §8）：链模板引用的 vuln_type / domain 必须都在映射表内。

    Returns:
        (True, "") 通过；(False, reason) 不通过。
    """
    vts = template.get("vuln_types") or []
    doms = template.get("domains") or []
    if isinstance(vts, str):
        vts = [vts]
    if isinstance(doms, str):
        doms = [doms]
    for vt in vts:
        r = resolve_vuln_type(str(vt))
        if not r:
            return False, f"unknown vuln_type: {vt!r}"
        if r not in XUANJIAN_VULN_TYPES and r not in _STRIX_SLUGS:
            return False, f"vuln_type not in taxonomy: {vt!r}"
    for d in doms:
        if str(d) not in RISK_DOMAINS:
            return False, f"unknown domain: {d!r}"
    return True, ""


__all__ = [
    "RISK_DOMAINS",
    "VULN_GROUPS",
    "XUANJIAN_VULN_TYPES",
    "STRIX_INDEX",
    "TYPE_DOMAINS",
    "VULN_TYPE_ALIAS",
    "CHINESE_TO_CANON",
    "resolve_vuln_type",
    "vuln_type_domains",
    "vuln_type_group",
    "vuln_type_strix",
    "strix_to_xuanjian",
    "validate_chain_template",
]
