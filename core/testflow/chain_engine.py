"""testflow 链引擎 — 跨域利用链匹配（链式规则 v4 §5）。

职责（纯函数，不依赖 LLM/网络）：
- to_three_state: 四源归一（漏V3-1/2/3/4）— verdict dict / verdict 字符串 /
  CheckResult / 缺省，统一为 confirmed / ruled_out / open_proof_gap / ""（不参与）
- validate_chain: 链模板准入（§8 "模板词表越界即红"），词表校验复用
  chain_rules.validate_chain_template（单点维护，不重复实现）
- match_chain / match_all: 拓扑序贪心匹配，含 GATE-PAIR 值池联动
  （value_pool > capability > implicit，隐式联动强制 open_proof_gap）
- score_chain: severity 权重 × completeness 排序键（§5.5）
- load_all_chains / load_capabilities: 链模板与能力表加载

数据结构（§5.2）：
- Finding: 归一化 finding（四源归一后的三态视图，保留 raw 供登记引用）
- ChainHop: 链跳（匹配前的模板声明 + 匹配后的运行态）
- ChainMatch: 匹配结果（completeness / severity / value_pool）
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import yaml

from core.testflow.chain_rules import resolve_vuln_type, validate_chain_template
from core.testflow.gates import gate_pair

try:  # validator.py 顶层 import core.llm（重依赖）；纯 stdlib 校验环境降级
    from core.harm_validation.validator import Verdict, three_state_verdict

    _VALID_VERDICTS = {v.value for v in Verdict}
except Exception:  # pragma: no cover - 降级路径
    _VALID_VERDICTS = {"confirmed", "ruled_out", "open_proof_gap"}
    three_state_verdict = None


def _reviewer_fallback(v: str, reason: str) -> str:
    """validator 不可用时的保守降级（第四套词表：accepted→confirmed，其余→open_proof_gap）。"""
    return "confirmed" if v == "accepted" else "open_proof_gap"

log = logging.getLogger(__name__)

__all__ = [
    "Finding",
    "ChainHop",
    "ChainMatch",
    "to_three_state",
    "validate_chain",
    "match_chain",
    "match_all",
    "score_chain",
    "load_all_chains",
    "load_capabilities",
]

# ============================================================
# 四源归一（漏V3-1/2/3/4，§5.3）
# ============================================================

# CheckResult → 三态（漏V3-2）
_RESULT_MAP = {
    "VULNERABLE": "confirmed",
    "NEEDS_REVIEW": "open_proof_gap",
    "NOT_VULN": "ruled_out",
    "SKIPPED": "ruled_out",
}

# verdict dict 子键 → 三态（漏V3-1，build_verdict().to_dict() 口径）
_VERDICT_SUBKEY_MAP = {
    "vulnerable": "confirmed",
    "safe": "ruled_out",
    "needs_follow_up": "open_proof_gap",
    "unknown": "open_proof_gap",
}


def to_three_state(f: dict[str, Any]) -> str:
    """finding dict → 三态（confirmed / ruled_out / open_proof_gap / ""）。

    解析优先级（§5.3 四源直通）：
      1. verdict dict（run_triage_gate 产物）→ ``verdict`` 子键映射（漏V3-2）
      2. verdict 字符串：Verdict enum 值直通；accepted/rejected/borderline
         （第四套词表，harm_validation 审核员）复用 three_state_verdict 不重复实现
      3. result（CheckResult）→ _RESULT_MAP（漏V3-6 对齐官方桥语义）
      4. 全缺 → ""（不参与匹配，GATE-TRI 关闭兜底漏V3-3）
    CONFIDENCES 永不读（漏3）。

    降级铁律（漏V3-4）：severity=="" 或 "info"，或 detail 带 [GATE-TRI] 前缀
    （降级 finding，gates.py:144 severity="info"）→ confirmed 封顶为
    open_proof_gap（证明不完整，不得当 confirmed 跳）；ruled_out 不受影响。
    """
    base = ""
    v = f.get("verdict")
    if isinstance(v, dict):
        sub = str(v.get("verdict") or "").strip().lower()
        base = _VERDICT_SUBKEY_MAP.get(sub, "")
    elif v is not None:
        s = str(getattr(v, "value", v)).strip().lower()
        if s in _VALID_VERDICTS:
            base = s  # Verdict enum 值直通（Verdict 是 str Enum，实例同走此支）
        elif s in ("accepted", "rejected", "borderline"):
            reason = str(f.get("reason") or f.get("evidence") or "")
            if three_state_verdict is not None:
                base = three_state_verdict(s, reason).value
            else:  # pragma: no cover - 降级
                base = _reviewer_fallback(s, reason)
    if not base:
        r = f.get("result")
        rname = getattr(r, "name", None) or str(r or "")
        base = _RESULT_MAP.get(str(rname).strip().upper(), "")

    sev = str(f.get("severity") or "").strip().lower()
    detail = str(f.get("detail") or "").strip().lower()
    demoted = sev in ("", "info") or detail.startswith("[gate-tri]")
    if base == "confirmed" and demoted:
        return "open_proof_gap"
    return base


# ============================================================
# 数据结构（§5.2）
# ============================================================


@dataclass
class Finding:
    """归一化 finding（四源归一后的三态视图）。"""

    raw: dict[str, Any]
    vuln_type: str  # canonical 键（resolve_vuln_type 归一）
    domains: tuple[str, ...]
    feature_id: str
    url: str
    method: str
    severity: str
    three_state: str  # confirmed / ruled_out / open_proof_gap / ""
    response: dict[str, Any]
    evidence: str
    evidence_flow_id: str

    @property
    def key(self) -> str:
        """finding 稳定标识（链内一跳一 finding 去重键）。"""
        return f"{self.feature_id}|{self.vuln_type}|{self.url}"


@dataclass
class ChainHop:
    """链跳：匹配前的模板声明 + 匹配后的运行态。"""

    id: str
    role: str = ""
    domains: tuple[str, ...] = ()
    vuln_types: tuple[str, ...] = ()
    verdicts: tuple[str, ...] = ("confirmed", "open_proof_gap")
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    counter_evidence: tuple[str, ...] = ()
    fan_in: tuple[str, ...] = ()
    # 运行态
    matched: Finding | None = None
    state: str = "missing"  # confirmed / open_proof_gap / missing
    link_kind: str = "none"  # value_pool / capability / implicit / none（入口跳）
    evidence: str = ""
    evidence_flow_id: str = ""


@dataclass
class ChainMatch:
    """链匹配结果（§5.2）。"""

    chain_id: str
    name: str
    hops: list[ChainHop]
    completeness: float
    severity: str
    value_pool: list[dict[str, Any]] = field(default_factory=list)


# ============================================================
# 模板准入（§8 "模板词表越界即红"）
# ============================================================

_HOP_OPTIONAL_LISTS = ("consumes", "produces", "counter_evidence", "fan_in")


def validate_chain(template: Any) -> tuple[bool, str]:
    """链模板准入：结构完备（§8 缺 hops/min_hops/verdicts → 拒绝）+ 词表越界即红。

    词表校验复用 chain_rules.validate_chain_template（模板级与逐 hop match）。
    """
    if not isinstance(template, dict):
        return False, "chain template 不是 dict"
    cid = template.get("chain")
    if not cid or not isinstance(cid, str):
        return False, "缺 chain id"
    if not template.get("name"):
        return False, f"链 {cid} 缺 name"
    raw_hops = template.get("hops")
    if not isinstance(raw_hops, list) or len(raw_hops) < 2:
        return False, f"链 {cid} 缺 hops 或 hops < 2"
    min_hops = template.get("min_hops")
    if not isinstance(min_hops, int) or min_hops < 2:
        return False, f"链 {cid} 缺 min_hops 或 min_hops < 2"
    if min_hops > len(raw_hops):
        return False, f"链 {cid} min_hops({min_hops}) > hops({len(raw_hops)})"

    # 模板级词表（若声明）也过契约门
    if template.get("vuln_types") or template.get("domains"):
        ok, reason = validate_chain_template(template)
        if not ok:
            return False, f"链 {cid}: {reason}"

    hop_ids: set[str] = set()
    for i, h in enumerate(raw_hops):
        if not isinstance(h, dict) or not h.get("id"):
            return False, f"链 {cid} hop#{i} 缺 id"
        hid = str(h["id"])
        if hid in hop_ids:
            return False, f"链 {cid} hop id 重复: {hid}"
        hop_ids.add(hid)
        role = h.get("role") or ""
        if role and role not in ("entry", "relay", "sink"):
            return False, f"链 {cid} hop {hid} 未知 role: {role!r}"
        m = h.get("match")
        if not isinstance(m, dict):
            return False, f"链 {cid} hop {hid} 缺 match"
        if not (m.get("domains") or m.get("vuln_types")):
            return False, f"链 {cid} hop {hid} match 缺 domains/vuln_types"
        ok, reason = validate_chain_template(m)
        if not ok:
            return False, f"链 {cid} hop {hid}: {reason}"
        verdicts = m.get("verdicts")
        if not isinstance(verdicts, list) or not verdicts:
            return False, f"链 {cid} hop {hid} 缺 verdicts"
        for vd in verdicts:
            if str(vd) not in _VALID_VERDICTS:
                return False, f"链 {cid} hop {hid} 非法 verdict: {vd!r}"
        for fname in _HOP_OPTIONAL_LISTS:
            val = h.get(fname)
            if val is not None and not isinstance(val, list):
                return False, f"链 {cid} hop {hid} {fname} 应为 list"

    # fan_in 引用存在性（允许前向引用，统一后置校验）
    for h in raw_hops:
        for fid in h.get("fan_in") or []:
            if str(fid) not in hop_ids:
                return False, f"链 {cid} hop {h['id']} fan_in 引用不存在: {fid!r}"
    return True, ""


# ============================================================
# 匹配内核（§5.4）
# ============================================================

_LINK_PRIORITY = {"none": 0, "implicit": 1, "capability": 2, "value_pool": 3}
_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SEV_NAME = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _parse_hop(h: dict[str, Any]) -> ChainHop:
    """模板 hop dict → ChainHop（vuln_types 经 resolve_vuln_type 归一，§12.5-1）。"""
    m = h.get("match") or {}
    vts_raw = m.get("vuln_types") or []
    if isinstance(vts_raw, str):
        vts_raw = [vts_raw]
    doms_raw = m.get("domains") or []
    if isinstance(doms_raw, str):
        doms_raw = [doms_raw]
    verdicts_raw = m.get("verdicts") or ["confirmed", "open_proof_gap"]
    return ChainHop(
        id=str(h["id"]),
        role=str(h.get("role") or ""),
        domains=tuple(str(d) for d in doms_raw),
        vuln_types=tuple(resolve_vuln_type(str(v)) for v in vts_raw),
        verdicts=tuple(str(v) for v in verdicts_raw),
        consumes=tuple(str(c) for c in h.get("consumes") or []),
        produces=tuple(str(p) for p in h.get("produces") or []),
        counter_evidence=tuple(str(c) for c in h.get("counter_evidence") or []),
        fan_in=tuple(str(f) for f in h.get("fan_in") or []),
    )


def _norm_finding(raw: dict[str, Any]) -> Finding | None:
    """异构 finding dict → 归一化 Finding（Finding schema normalization，§5.2）。"""
    if not isinstance(raw, dict):
        return None
    vt = resolve_vuln_type(str(raw.get("vuln_type") or ""))
    doms_raw = raw.get("domains") or raw.get("risk_domains") or []
    if isinstance(doms_raw, str):
        doms_raw = [doms_raw]
    doms = tuple(str(d) for d in doms_raw)
    if not vt and not doms:
        return None  # 既无类型也无域，任何 hop 都匹配不上
    resp = raw.get("response")
    return Finding(
        raw=raw,
        vuln_type=vt,
        domains=doms,
        feature_id=str(raw.get("feature_id") or raw.get("feature") or ""),
        url=str(raw.get("url") or ""),
        method=str(raw.get("method") or "GET"),
        severity=str(raw.get("severity") or "").strip().lower(),
        three_state=to_three_state(raw),
        response=resp if isinstance(resp, dict) else {},
        evidence=str(raw.get("evidence") or raw.get("detail") or ""),
        evidence_flow_id=str(raw.get("evidence_flow_id") or ""),
    )


def _url_prefix(url: str) -> str:
    """URL → 首段路径（隐式联动的同前缀判定）。"""
    path = urlsplit(url).path or ""
    segs = [s for s in path.split("/") if s]
    return segs[0] if segs else ""


def _query_params(url: str) -> list[str]:
    """URL → query 参数名列表（GATE-PAIR target_params 来源之一）。"""
    try:
        q = urlsplit(url).query
    except Exception:  # pragma: no cover - urlsplit 极少失败
        return []
    return [k for k, _v in parse_qsl(q, keep_blank_values=True)]


def _counter_hit(hop: ChainHop, f: Finding) -> bool:
    """反证命中：detail/响应文本包含任一反证 pattern → 排除该候选（§3.3）。"""
    if not hop.counter_evidence:
        return False
    text = f"{f.evidence} {f.response}".lower()
    return any(str(p).lower() in text for p in hop.counter_evidence)


def _candidates(hop: ChainHop, findings: list[Finding]) -> list[Finding]:
    """hop 的候选 findings：域/类型交集 ∧ 三态 ∈ verdicts ∧ 未被反证。"""
    doms = set(hop.domains)
    vts = set(hop.vuln_types)
    verdicts = set(hop.verdicts)
    out: list[Finding] = []
    for f in findings:
        if doms and not (set(f.domains) & doms):
            continue
        if vts and f.vuln_type not in vts:
            continue
        if verdicts and f.three_state not in verdicts:
            continue
        if _counter_hit(hop, f):
            continue
        out.append(f)
    return out


def _topo_order(hops: list[ChainHop]) -> list[ChainHop]:
    """consumes/fan_in 依赖的拓扑序（Kahn，模板序稳定 tiebreak）。"""
    idx = {h.id: i for i, h in enumerate(hops)}
    deps: dict[str, set[str]] = {h.id: set() for h in hops}
    for h in hops:
        for fid in h.fan_in:
            if fid != h.id and fid in idx:
                deps[h.id].add(fid)
        for other in hops:
            if other.id != h.id and set(other.produces) & set(h.consumes):
                deps[h.id].add(other.id)
    order: list[str] = []
    done: set[str] = set()
    pending = [h.id for h in hops]
    while pending:
        progressed = False
        for hid in list(pending):
            if deps[hid] <= done:
                order.append(hid)
                done.add(hid)
                pending.remove(hid)
                progressed = True
        if not progressed:  # 环（模板准入不应出现）：按模板序兜底
            order.extend(pending)
            break
    return [hops[idx[hid]] for hid in order]


def _best_link(
    matched: list[ChainHop], hop: ChainHop, cand: Finding, implicit_allowed: bool
) -> tuple[str, list[dict[str, Any]]]:
    """已匹配跳 → 候选 finding 的最强联动（value_pool > capability > implicit）。

    - value_pool: GATE-PAIR 显式命中（A 响应字段 ↔ B consumes/URL 参数）
    - capability: 前 hop produces ∩ 本 hop consumes 能力跃迁
    - implicit:   同 URL 首段前缀（同凭据/同前缀），仅模板声明 implicit_link 时
                  启用，强制 open_proof_gap（§4v3 / §5.1）
    """
    best, pairs_out = "none", []
    for m in matched:
        prev = m.matched
        if prev is None:
            continue
        kind, pairs = "none", []
        target_params = list(hop.consumes) + _query_params(cand.url)
        hit = gate_pair(prev.response, target_params)
        if hit:
            kind, pairs = "value_pool", hit
        elif set(m.produces) & set(hop.consumes):
            kind = "capability"
        elif implicit_allowed and _url_prefix(prev.url) and (
            _url_prefix(prev.url) == _url_prefix(cand.url)
        ):
            kind = "implicit"
        if _LINK_PRIORITY[kind] > _LINK_PRIORITY[best]:
            best, pairs_out = kind, pairs
    return best, pairs_out


def _hop_state(hop: ChainHop, cand: Finding, link_kind: str) -> str:
    """跳状态（§5.3 降级铁律）：ruled_out→missing；隐式联动强制 open_proof_gap。"""
    if cand.three_state == "ruled_out":
        return "missing"
    if link_kind == "implicit" or cand.three_state == "open_proof_gap":
        return "open_proof_gap"
    return "confirmed"


def _chain_severity(matched: list[ChainHop]) -> str:
    """链式放大（§5.5）：max(hop.severity) + confirmed 跳数 + 强联动跨度。"""
    weights = [
        _SEV_WEIGHT.get(h.matched.severity, 0)
        for h in matched
        if h.matched is not None
    ]
    w = max(weights) if weights else 0
    if sum(1 for h in matched if h.state == "confirmed") >= 2:
        w += 1
    if sum(1 for h in matched if h.link_kind in ("value_pool", "capability")) >= 2:
        w += 1
    if any(h.link_kind == "implicit" for h in matched):
        w -= 1  # 弱链接整链降一档（§5.4）
    return _SEV_NAME[max(min(w, 4), 0)]


def _build_chain(
    raw_hops: list[dict[str, Any]],
    entry_id: str,
    entry_finding: Finding,
    findings: list[Finding],
    template: dict[str, Any],
    implicit_allowed: bool,
) -> ChainMatch | None:
    """从入口候选出发的贪心建链（§5.4 拓扑序 + fan_in 前置 + 找最强联动）。"""
    hops = [_parse_hop(h) for h in raw_hops]
    by_id = {h.id: h for h in hops}
    order = _topo_order(hops)
    used: set[str] = {entry_finding.key}

    if entry_finding.three_state == "ruled_out":
        return None  # 降级铁律：入口跳 ruled_out 链不成立
    entry = by_id[entry_id]
    entry.matched = entry_finding
    entry.state = (
        entry_finding.three_state
        if entry_finding.three_state == "confirmed"
        else "open_proof_gap"
    )
    entry.link_kind = "none"  # 入口跳无联动

    value_pool: list[dict[str, Any]] = []
    for hop in order:
        if hop.id == entry_id:
            continue
        # fan_in 前置：声明的全部父跳必须已匹配
        if hop.fan_in and not all(
            by_id.get(fid) is not None and by_id[fid].matched is not None
            for fid in hop.fan_in
        ):
            continue  # 保持 missing
        best_cand: Finding | None = None
        best_kind, best_pairs, best_state = "none", [], ""
        for cand in _candidates(hop, findings):
            if cand.key in used:
                continue
            kind, pairs = _best_link(
                [m for m in hops if m.matched is not None], hop, cand, implicit_allowed
            )
            if kind == "none":
                continue  # 非入口跳必须有联动，否则不成链
            state = _hop_state(hop, cand, kind)
            if state == "missing":
                continue  # 降级铁律：ruled_out 跳不挂载
            rank = (_LINK_PRIORITY[kind], state == "confirmed")
            cur_rank = (_LINK_PRIORITY[best_kind], best_state == "confirmed")
            if best_cand is None or rank > cur_rank:
                best_cand, best_kind, best_pairs, best_state = cand, kind, pairs, state
        if best_cand is None:
            continue  # 保持 missing
        hop.matched = best_cand
        hop.state = best_state
        hop.link_kind = best_kind
        hop.evidence = best_cand.evidence
        hop.evidence_flow_id = best_cand.evidence_flow_id
        used.add(best_cand.key)
        if best_kind == "value_pool":
            value_pool.extend(best_pairs)

    matched = [h for h in hops if h.matched is not None]
    min_hops = int(template.get("min_hops") or 2)
    if len(matched) < min_hops:
        return None

    total = len(hops)
    score_sum = sum(
        1.0 if h.state == "confirmed" else 0.5 if h.state == "open_proof_gap" else 0.0
        for h in hops
    )
    return ChainMatch(
        chain_id=str(template["chain"]),
        name=str(template.get("name") or template["chain"]),
        hops=hops,
        completeness=round(score_sum / total, 4),
        severity=_chain_severity(matched),
        value_pool=value_pool,
    )


def match_chain(
    template: dict[str, Any],
    findings: list[dict[str, Any]],
    caps: dict[str, Any] | None = None,
) -> ChainMatch | None:
    """单链匹配：拓扑序贪心，多入口取 (completeness, score) 最高的路径（§5.2）。

    Args:
        template: 链模板 dict（须过 validate_chain 准入）。
        findings: 异构 finding dict 列表（内部做 Finding 归一化）。
        caps: 能力表 dict（预留契约校验，匹配内核当前不依赖）。

    Returns:
        ChainMatch（matched < min_hops 时为 None）。
    """
    ok, reason = validate_chain(template)
    if not ok:
        log.debug("链模板未过准入，跳过: %s", reason)
        return None
    norm = [f for f in (_norm_finding(x) for x in findings) if f is not None]
    if not norm:
        return None
    hops = template["hops"]
    entry_ids = [str(h["id"]) for h in hops if h.get("role") == "entry"]
    if not entry_ids or template.get("multi_entry"):
        entry_ids = [str(h["id"]) for h in hops]

    best: ChainMatch | None = None
    for eid in entry_ids:
        ehop = next(h for h in hops if str(h["id"]) == eid)
        for cand in _candidates(_parse_hop(ehop), norm):
            cm = _build_chain(
                hops, eid, cand, norm, template, bool(template.get("implicit_link"))
            )
            if cm is None:
                continue
            if best is None or (cm.completeness, score_chain(cm)) > (
                best.completeness,
                score_chain(best),
            ):
                best = cm
    return best


def score_chain(cm: ChainMatch) -> int:
    """排序键（§5.5）：severity 权重 × completeness，上限 100。"""
    w = _SEV_WEIGHT.get(cm.severity, 0)
    return min(int(round(w * 25 * cm.completeness)), 100)


def match_all(
    chains: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    caps: dict[str, Any] | None = None,
    *,
    register: bool = True,
) -> list[ChainMatch]:
    """全链匹配 + 跨域登记（漏5：模板 id 与 register_chain 映射一致，幂等不双计数）。

    排序：score 降序、chain_id 升序（稳定）。登记复用
    core/loops/chained_finding.register_chain（显式 chain_id 幂等），
    各域只挂引用（domains_of 已含的域不重复 attach）。
    """
    from core.loops.chained_finding import attach_domain_ref, domains_of, register_chain

    out: list[ChainMatch] = []
    for tpl in chains:
        cm = match_chain(tpl, findings, caps)
        if cm is None:
            continue
        if register:
            cid = register_chain(
                {
                    "chain_id": cm.chain_id,
                    "steps": [h.id for h in cm.hops if h.matched is not None],
                    "name": cm.name,
                }
            )
            known = set(domains_of(cid))
            for h in cm.hops:
                if h.matched is None:
                    continue
                for dom in h.domains:
                    if dom not in known:
                        attach_domain_ref(cid, dom, h.matched.raw)
        out.append(cm)
    out.sort(key=lambda cm: (-score_chain(cm), cm.chain_id))
    return out


# ============================================================
# 加载（沿用 matrix_render / engine._load_playbook 落盘范式）
# ============================================================


def load_all_chains(dir_path: str | Path | None = None) -> list[dict[str, Any]]:
    """加载并准入全部链模板（core/testflow/chains/*.yaml，跳过 _ 前缀）。

    未过 validate_chain 准入的模板跳过并告警（§8 "模板词表越界即红"）。
    """
    d = Path(dir_path) if dir_path else Path(__file__).parent / "chains"
    out: list[dict[str, Any]] = []
    if not d.is_dir():
        log.warning("链模板目录不存在: %s", d)
        return out
    for p in sorted(d.glob("*.yaml")):
        if p.name.startswith("_"):
            continue
        try:
            tpl = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as e:
            log.warning("链模板解析失败 %s: %s", p.name, e)
            continue
        ok, reason = validate_chain(tpl)
        if not ok:
            log.warning("链模板未过准入，跳过 %s: %s", p.name, reason)
            continue
        out.append(tpl)
    return out


def load_capabilities(path: str | Path | None = None) -> dict[str, Any]:
    """加载能力表（core/testflow/chain_capabilities.yaml），失败返回空 dict。"""
    p = Path(path) if path else Path(__file__).parent / "chain_capabilities.yaml"
    if not p.is_file():
        log.warning("能力表不存在: %s", p)
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        log.warning("能力表解析失败 %s: %s", p, e)
        return {}
