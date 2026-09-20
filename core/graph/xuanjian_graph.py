"""
XuanJian 八阶段渗透流水线 —— LangGraph 编排
============================================

把玄鉴官方「8 阶段编排」真·画成 LangGraph StateGraph：

      P0 站点探索 (AutoCrawler)
       │
       ├─(FAST)──────────────────────────────┐
       └─(非FAST)─▶ P0.5 业务理解             │
                        │                     │
                        ▼                     │
                     P1 功能分析              │
                        │                     │
       ┌────────────────┤                     │
       ├─(FAST)─────────┘                     │
       └─(非FAST)─▶ P1.5 业务对账             │
                        │                     │
                        ▼                     ▼
      P2_dispatch ◀───────────────┘
       ├─▶ P2a HTTP 测试 (WorkerAgent×3 并行)
       └─▶ P2b 浏览器测试 (主 Agent 串行)
            │            │
            ▼            ▼
           P2_merge (fan-in 合并发现)
            │
       ├─(FAST)──────────────────────────────▶ P3 汇总报告
       ├─(发现新API)─▶ P2.55 补测 ─▶ P2.6 危害验证
       └─(否则)──────▶ P2.6 危害验证
                            │
            ┌───────────────┴───────────────────┐
            │ P2.6 三态闭包                         │
            │ OPEN_PROOF_GAP 且 retest_round<max   │
            │   → 回退重测                           │
            ▼                                       ▼
       P2_retest ─▶ P2_dispatch(重跑2a+2b,强证据)   (无GAP / 预算尽)
            │                                        │
            └────────────────────┐                  │
                                 ▼                  ▼
                       P2.9 人工复核 gate（interrupt_before P3）
                            ├─(approve)────────────▶ P3 汇总报告
                            └─(reject 且预算足)──────▶ P2_retest

  【三态闭包驱动的条件回边】
    P2.6 用 core.harm_validation.validator.three_state_verdict 把每个候选判为
    CONFIRMED / RULED_OUT / OPEN_PROOF_GAP：
      - 证据充分（content_match / body_confirmed）→ CONFIRMED，进 P3
      - 证据不足（header_only 等，理由命中 INSUFFICIENT 模式）→ OPEN_PROOF_GAP
        → 回退到 P2_retest 重新收集证据，直到 retest_round 用尽或证据充分。
    这是 F15「反误报三态闭包」在编排层的落地：看似证伪其实不够的，
    不草率判 RULED_OUT，而是回退补证。

与以下官方定义完全一致：
  - ARCHITECTURE.md:21   Phase 0 → 0.5 → 1 → 1.5 → 2a/2b → 2.55 → 2.6 → 3
  - README.zh.md:240     八阶段表
  - XUANJIAN_TESTFLOW_SKILLS.md:30  八阶段编排 + FAST 跳过 0.5/1.5/2.55/2.6

【编排要点 / LangGraph 坑位】
  * 并行分支（P2a / P2b）在同一个 superstep 内运行，若写同一普通 channel 会抛
    InvalidUpdateError。因此 `log` 用 `Annotated[list, operator.add]` 做并发追加；
    `current_phase` 由后续汇聚节点（P2_merge / 各顺序节点）单一写入，避免冲突。
  * 3 条条件边：route_after_p0（FAST 跳过 0.5）、route_after_p1（FAST 跳过 1.5）、
    route_after_p2_merge（FAST 跳过 2.55+2.6；非 FAST 按 new_apis_found 决定是否补测）。

【续跑能力 / 文件落盘 checkpointer】
默认用 SqliteSaver 文件落盘（xuanjian_graph_checkpoints.db），支持「跨进程」崩溃恢复：
  - 进程崩溃 / 主动 interrupt 后，任意新进程用**同一 db 文件 + 同一 thread_id** 重新
    invoke，从最后一个 checkpoint 自动续跑（不重跑已完成阶段）。
  - 演示见 demo.py 第 6 段：`interrupt_after=["p2_merge"]` 在 P2_merge 后暂停（模拟进程1
    崩溃落盘），再用一个全新的 Saver 实例 + 新建 graph 读同一 db 文件 `invoke(None)` 续跑。
  - 调用方也可传入 `sqlite3.connect(":memory:")` 获得纯进程内持久 checkpointer（demo 默认）。

【三态闭包条件回边（P2.6 → P2.retest）】
  - P2.6 用 core.harm_validation.validator.three_state_verdict 把每个候选判为
    CONFIRMED / RULED_OUT / OPEN_PROOF_GAP；存在 OPEN_PROOF_GAP 且 retest_round<max_retest
    时，条件边回退到 P2_retest（证据不足→回退重测），本轮 2a/2b 产出强证据后重新进 P2.6。
  - 这是 F15「反误报三态闭包」在编排层的落地：看似证伪其实不够的，不草率判 RULED_OUT，
    而是回退补证；预算用尽仍有证据不足则放行 P3 交人工复核（防死循环）。
  - 演示见 demo.py 第 5 / 5b 段。

【人工复核 gate（P2.9, interrupt_before P3）】
  - 三态回边 + 自动补测全部裁决之后、正式出报告之前，插入一道「人审」门：
    p2_9_human_review 节点调用 langgraph.types.interrupt() 暂停，把当前裁决摘要
    （确认数 / OPEN_PROOF_GAP / 重测轮次）交给人工；人工 resume 时传回
    {"action": "approve" | "reject", "note": "..."}。
      * approve → 放行 P3 汇总报告；
      * reject 且重测预算未用尽 → 回退 P2_retest 重新补证，再过本门；
      * reject 且预算已用尽 → 强制放行 P3 并告警（防死循环）。
  - 通过 build_graph(human_review=True) 开启；演示见 demo.py 第 7 段。
  - 与续跑/checkpointer 天然兼容：interrupt 的暂停点本身就是一个 checkpoint，
    因此「人工复核中途进程退出」也能用同一 thread_id 续回本门。

【节点实现策略】
本文件只负责「编排拓扑 + 续跑 + 三态回边」。各阶段的具体渗透逻辑通过 `_lazy_call`
lazy import 玄鉴真实入口（AutoCrawler / run_parallel_test / validate_harm ...）。
若运行环境缺浏览器 / LLM / mitmproxy，或真实入口返回非可序列化对象（类/协程/异步生成器），
节点会安全降级为带摘要的 stub 并记录日志，保证 graph 在任何环境都能端到端跑通
（拓扑、checkpoint 与三态回边才是本文件的价值；真实端到端实跑需在节点内正确 await 异步入口）。
"""

from __future__ import annotations

import importlib
import logging
import operator
import sqlite3
from typing import Annotated, Literal, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

logger = logging.getLogger("xuanjian.graph")

ScanMode = Literal["FAST", "STANDARD", "DEEP", "SMART"]


# --------------------------------------------------------------------------- #
# 状态（贯穿 8 阶段的共享上下文）
#   - log 用 operator.add reducer：P2a/P2b 并行写入时自动合并，不冲突
#   - current_phase 由单个节点（汇聚点或顺序节点）写入，避免并发写冲突
# --------------------------------------------------------------------------- #
class ScanState(TypedDict, total=False):
    target: str
    scan_mode: ScanMode              # 编排维度 (Batch/Realtime/Packet)
    user_scan_mode: ScanMode         # 深度维度：FAST 跳过 0.5/1.5/2.55/2.6

    crawl_result: dict               # P0
    business_understanding: dict     # P0.5
    checklist: dict                  # P1
    recon_result: dict               # P1.5
    http_findings: list              # P2a
    browser_findings: list           # P2b
    merged_findings: list            # P2 merge
    new_apis_found: bool             # 驱动 P2.55 条件边
    validated_vulns: list            # P2.6

    retest_round: int                # 回退重测轮次（三态闭包驱动）
    max_retest: int                  # 回退重测预算上限（防死循环）
    open_proof_gap: list             # P2.6 判为 OPEN_PROOF_GAP 的候选 id 列表

    report: dict                     # P3

    human_decision: str              # 人工复核 gate 决策：approve / reject
    human_note: str                  # 人工复核备注

    current_phase: str               # 可观测性：当前阶段（单一写入）
    log: Annotated[list, operator.add]  # 阶段流转日志（并发安全追加）


# --------------------------------------------------------------------------- #
# 适配器：lazy import 玄鉴真实入口；失败则降级为 stub（保证 graph 可跑通）
# --------------------------------------------------------------------------- #
def _lazy_call(dotted: str, fn: str, *args, **kwargs):
    """尝试调用玄鉴真实函数；任何异常/非可序列化返回都降级为 stub，不阻断 graph。

    关键守卫：真实入口可能返回「类对象 / 协程 / 异步生成器 / 函数」等非可序列化对象
    （如 run_parallel_test 是 async generator）。这类对象一旦写进 ScanState 会被
    checkpointer 的 msgpack 序列化拒绝，导致整个图（含续跑能力）崩溃。因此演示态下
    只保留可序列化摘要；真正端到端实跑需要在节点内正确 await 异步入口（见各节点 TODO）。
    """
    import types as _types
    try:
        mod = importlib.import_module(dotted)
        val = getattr(mod, fn)
        res = val(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 — 故意兜底，编排层不依赖具体运行时
        logger.warning("adapter stub: %s.%s 不可用 (%s)", dotted, fn, e)
        return {"_stub": True, "module": dotted, "fn": fn, "error": str(e)}

    # 守卫：非可序列化返回 → 不落盘，降级为摘要，保证 checkpointer 不崩
    if isinstance(res, (
        _types.CoroutineType, _types.AsyncGeneratorType, _types.GeneratorType,
        type, _types.FunctionType, _types.MethodType,
    )):
        logger.warning(
            "adapter: %s.%s 返回非可序列化对象(%s)，降级为摘要（真实端到端需正确 await）",
            dotted, fn, type(res).__name__,
        )
        return {"_stub": True, "module": dotted, "fn": fn,
                "note": f"real entry returned {type(res).__name__}; "
                        f"serializable end-to-end run needs proper async invocation"}
    return res


# --------------------------------------------------------------------------- #
# 三态闭包：优先用玄鉴真实实现，缺失时降级为等价镜像（保证 graph 在缺依赖环境可跑）
#   与 core/harm_validation/validator.py 的 F15 反误报三态闭包保持同构。
# --------------------------------------------------------------------------- #
try:
    from core.harm_validation.validator import (  # type: ignore
        Verdict as _Verdict,
        validate_ruled_out as _validate_ruled_out,
        three_state_verdict as _three_state_verdict,
    )
except Exception:  # noqa: BLE001 — 真实模块依赖 LLM/浏览器等，缺则镜像兜底
    from enum import Enum

    class _Verdict(str, Enum):
        CONFIRMED = "confirmed"
        RULED_OUT = "ruled_out"
        OPEN_PROOF_GAP = "open_proof_gap"

    _INSUFFICIENT = [
        "generic_library_trust", "control_on_other_path", "timing_mismatch",
        "fail_open_present", "safe_sibling_assumption", "missing_information",
        "difficulty_only", "configurability_only", "internal_only",
    ]

    def _validate_ruled_out(reason: str) -> bool:
        if not reason:
            return False
        rl = (reason or "").lower()
        return not any(p in rl for p in _INSUFFICIENT)

    def _three_state_verdict(verdict_str: str, reason: str = "") -> "_Verdict":
        if verdict_str == "accepted":
            return _Verdict.CONFIRMED
        if verdict_str == "rejected":
            return (_Verdict.RULED_OUT
                    if _validate_ruled_out(reason) else _Verdict.OPEN_PROOF_GAP)
        return _Verdict.OPEN_PROOF_GAP


def _classify_finding(f: dict) -> "_Verdict":
    """把单个候选漏洞（merged_findings 元素）映射到三态。

    evidence_quality 充分（content_match / body_confirmed）→ CONFIRMED；
    其余（header_only / 缺失）→ 视为证伪理由不充分 → OPEN_PROOF_GAP，
    触发回退重测而非草率判 RULED_OUT。
    """
    eq = (f.get("evidence_quality") or "header_only").lower()
    if eq in ("content_match", "body_confirmed"):
        return _three_state_verdict("accepted")
    # 证据不足：用命中 INSUFFICIENT 模式的理由，确保落到 OPEN_PROOF_GAP
    return _three_state_verdict("rejected", "missing_information or generic_library_trust")


# --------------------------------------------------------------------------- #
# 节点（每个 node = 一个阶段；返回 dict 与 ScanState 浅合并）
#   - log 返回「增量条目」，由 reducer 合并，节点内不读旧 log
# --------------------------------------------------------------------------- #
def p0_explore(state: ScanState) -> dict:
    logger.info("[P0] 站点探索: AutoCrawler(爬虫+JS分析+流量+SPA降级)")
    # 真实形态（需完整运行时）：crawler = AutoCrawler(target=...); crawler.crawl()
    res = _lazy_call("core.crawler.crawler_core", "AutoCrawler")
    if res.get("_stub"):  # 兼容顶层 auto_crawler 模块
        res = _lazy_call("core.auto_crawler", "AutoCrawler")
    return {
        "crawl_result": {"target": state["target"], "status": "explored", "_real": res},
        "current_phase": "P0",
        "log": ["P0 站点探索完成"],
    }


def p0_5_business(state: ScanState) -> dict:
    logger.info("[P0.5] 业务理解: BusinessUnderstanding(语义→攻击假设)")
    res = _lazy_call("core.business_understanding", "BusinessUnderstanding")
    return {
        "business_understanding": {"status": "understood", "_real": res},
        "current_phase": "P0.5",
        "log": ["P0.5 业务理解完成"],
    }


def p1_analyze(state: ScanState) -> dict:
    logger.info("[P1] 功能分析: AnalyzeWorker(功能点→Checklist)")
    res = _lazy_call("core.analyze_worker", "AnalyzeWorker")
    return {
        "checklist": {"status": "analyzed", "_real": res},
        "current_phase": "P1",
        "log": ["P1 功能分析完成"],
    }


def p1_5_reconcile(state: ScanState) -> dict:
    logger.info("[P1.5] 业务对账: reconcile_loop(Checklist × 业务理解交叉验证)")
    res = _lazy_call("core.reconcile", "reconcile_loop",
                     state.get("checklist"), state.get("business_understanding"))
    new_apis = False
    real = res.get("_real") if isinstance(res, dict) else None
    if isinstance(real, dict) and real.get("new_apis"):
        new_apis = True
    # 兜底：reconcile 为 stub 时，尊重显式传入的 hint（用于演示 P2.55 分支）
    if not new_apis:
        new_apis = bool(state.get("new_apis_found", False))
    return {
        "recon_result": {"status": "reconciled", "_real": res},
        "new_apis_found": new_apis,
        "current_phase": "P1.5",
        "log": ["P1.5 业务对账完成"],
    }


def p2_dispatch(state: ScanState) -> dict:
    logger.info("[P2] 漏洞测试调度 → 分叉 2a(HTTP 并行)/2b(浏览器串行)")
    return {"current_phase": "P2", "log": ["P2 调度: 2a+2b 并行"]}


def p2a_http_test(state: ScanState) -> dict:
    logger.info("[P2a] HTTP 漏洞测试: WorkerAgent×3 并行 (F2 认证探活)")
    res = _lazy_call("core.parallel._orch_phases._run_parallel_test",
                     "run_parallel_test", state.get("checklist"))
    # 回退重测轮次（retest_round>0）：本轮收集到强证据，模拟重测补证成功
    eq = "content_match" if state.get("retest_round", 0) > 0 else "header_only"
    # 不写 current_phase（与 P2b 并行会冲突），由 P2_merge 统一记录
    return {
        "http_findings": [{"track": "http", "stub": True,
                            "evidence_quality": eq, "_real": res}],
        "log": ["P2a HTTP 测试完成"],
    }


def p2b_browser_test(state: ScanState) -> dict:
    logger.info("[P2b] 浏览器漏洞测试: start_browser_feature_test(主 Agent 串行)")
    res = _lazy_call("core.parallel._orch_phases._browser_test",
                     "start_browser_feature_test", state.get("checklist"))
    eq = "content_match" if state.get("retest_round", 0) > 0 else "header_only"
    return {
        "browser_findings": [{"track": "browser", "stub": True,
                              "evidence_quality": eq, "_real": res}],
        "log": ["P2b 浏览器测试完成"],
    }


def p2_merge(state: ScanState) -> dict:
    logger.info("[P2 merge] 合并 HTTP / 浏览器发现 → 候选漏洞集")
    merged = (state.get("http_findings") or []) + (state.get("browser_findings") or [])
    return {
        "merged_findings": merged,
        "current_phase": "P2",
        "log": [f"P2 合并 {len(merged)} 项发现"],
    }


def p2_55_supplement(state: ScanState) -> dict:
    logger.info("[P2.55] 补测: SupplementalTestAgent(对账遗漏 API)")
    res = _lazy_call("core.supplemental_test_agent",
                     "run_supplemental_test", state.get("recon_result"))
    return {"current_phase": "P2.55", "log": ["P2.55 补测完成"]}


def p2_6_validate(state: ScanState) -> dict:
    logger.info("[P2.6] 危害验证: 三态闭包裁决 (CONFIRMED/RULED_OUT/OPEN_PROOF_GAP)")
    findings = state.get("merged_findings") or []
    confirmed, gap = [], []
    for f in findings:
        vid = f.get("vuln_id") or f.get("track") or f"finding-{len(gap) + len(confirmed)}"
        verdict = _classify_finding(f)
        if verdict == _Verdict.CONFIRMED:
            confirmed.append(f)
        else:  # OPEN_PROOF_GAP / RULED_OUT → 视为证据不足，需回退补证
            gap.append(vid)
    # 真实形态：这里应调用 core.harm_validation.validator.validate_harm 拿 LLM 裁决；
    # 编排层只负责「三态结果 → 条件回边」，裁决逻辑以 validator 为准。
    return {
        "validated_vulns": confirmed or findings,
        "open_proof_gap": gap,
        "current_phase": "P2.6",
        "log": [f"P2.6 危害验证: {len(confirmed)} 确认 / {len(gap)} 证据不足(OPEN_PROOF_GAP)"],
    }


def p2_retest(state: ScanState) -> dict:
    """P2.6 证据不足 → 回退重测（三态闭包驱动的循环节点）。"""
    n = int(state.get("retest_round", 0)) + 1
    logger.info("[P2.retest] 证据不足 %d 项 → 回退重测 (第 %d 轮)",
                len(state.get("open_proof_gap", [])), n)
    return {
        "retest_round": n,
        "current_phase": "P2.retest",
        "log": [f"P2.retest 回退重测(第{n}轮): 证据不足 {len(state.get('open_proof_gap', []))} 项"],
    }


def p3_report(state: ScanState) -> dict:
    logger.info("[P3] 汇总报告: _enter_report_phase + export_scan_artifacts + finish_scan")
    _lazy_call("core.parallel._orch_phases._report_phase",
               "_enter_report_phase", state)
    _lazy_call("core.loops.coverage_integration",
               "export_scan_artifacts", state)
    _lazy_call("core.scan_store", "finish_scan", state.get("target"))
    report = {
        "target": state["target"],
        "vulns": len(state.get("validated_vulns") or []),
        "status": "generated",
    }
    return {"report": report, "current_phase": "P3", "log": ["P3 报告完成"]}


# --------------------------------------------------------------------------- #
# 条件边路由函数（返回 path_map 中的 key）
# --------------------------------------------------------------------------- #
def _is_fast(state: ScanState) -> bool:
    return (state.get("user_scan_mode") or state.get("scan_mode")) == "FAST"


def route_after_p0(state: ScanState) -> str:
    return "p1_analyze" if _is_fast(state) else "p0_5_business"


def route_after_p1(state: ScanState) -> str:
    return "p2_dispatch" if _is_fast(state) else "p1_5_reconcile"


def route_after_p2_merge(state: ScanState) -> str:
    if _is_fast(state):
        return "p3_report"            # FAST 跳过 2.55 与 2.6
    if state.get("new_apis_found"):
        return "p2_55_supplement"     # 发现新 API → 先补测
    return "p2_6_validate"            # 否则直接危害验证


def route_after_p2_6(state: ScanState) -> str:
    """三态闭包条件回边：存在 OPEN_PROOF_GAP 且未用尽重测预算 → 回退重测。

    否则（证据充分 / 预算用尽）→ 进入 P3 汇总报告（或人工复核 gate，若开启）。
    """
    gap = state.get("open_proof_gap") or []
    round_n = int(state.get("retest_round", 0))
    max_n = int(state.get("max_retest", 2))
    if gap and round_n < max_n:
        return "p2_retest"
    if gap:
        # 预算用尽仍有证据不足：记日志后放行（避免死循环），交由人工复核
        logger.warning("[P2.6] 重测预算用尽仍有 %d 项证据不足，放行至 P3(人工复核)", len(gap))
    return "p3_report"


def p2_9_human_review(state: ScanState) -> dict:
    """人工复核 gate（interrupt_before P3）。

    在三态回边 + 自动补测全部裁决之后、正式出报告之前，插入一道「人审」门：
    调用 langgraph.types.interrupt() 暂停，把当前裁决摘要交给人工；人工 resume
    时传回 {"action": "approve"|"reject", "note": "..."}。
      - approve → 放行 P3
      - reject 且重测预算未用尽 → 回退 P2_retest 重新补证，再过本门
      - reject 且预算已用尽 → 强制放行 P3 并告警（防死循环）
    """
    logger.info("[P2.9] 人工复核 gate（interrupt_before P3）")
    summary = {
        "confirmed": len(state.get("validated_vulns") or []),
        "open_proof_gap": state.get("open_proof_gap", []),
        "retest_round": state.get("retest_round", 0),
        "max_retest": state.get("max_retest", 0),
    }
    # 暂停：把裁决摘要交给人工；resume 时传入的决策会作为本调用的返回值
    decision = interrupt(summary)
    action = (decision or {}).get("action", "approve")
    note = (decision or {}).get("note", "")
    return {
        "human_decision": action,
        "human_note": note,
        "current_phase": "P2.9",
        "log": [f"P2.9 人工复核 gate: {action}（{note or '无备注'}）"],
    }


def route_after_human_review(state: ScanState) -> str:
    """人工复核 gate 决策路由：approve → P3；reject → 预算足则回退重测。"""
    if state.get("human_decision") == "reject":
        if int(state.get("retest_round", 0)) < int(state.get("max_retest", 0)):
            return "p2_retest"
        # 预算已用尽仍被驳回：强制交付并标注，避免死循环
        logger.warning("[P2.9] 重测预算已用尽仍被人工驳回，强制放行 P3")
    return "p3_report"


# --------------------------------------------------------------------------- #
# 构图
# --------------------------------------------------------------------------- #
def build_graph(checkpointer=None, interrupt_after=None, *, human_review=False):
    """构建并编译 8 阶段 graph。

    Args:
        checkpointer: 持久化 checkpoint（默认 SqliteSaver 文件落盘）。
        interrupt_after: 可选，节点名列表，在该节点执行后暂停（演示续跑用）。
        human_review: 是否在 P2.6 之后、P3 之前插入人工复核 gate（interrupt）。
            开启后，P2.6 的 "p3_report" 分支改走 p2_9_human_review，
            由人工 approve / reject 决定放行或回退重测。
    """
    if checkpointer is None:
        # 文件落盘，支持跨进程 checkpoint 续跑；
        # 调用方可传入 sqlite3.connect(":memory:") 获得进程内持久 checkpointer。
        conn = sqlite3.connect("xuanjian_graph_checkpoints.db", check_same_thread=False)
        checkpointer = SqliteSaver(conn)

    g = StateGraph(ScanState)

    # —— 节点 ——
    g.add_node("p0_explore", p0_explore)
    g.add_node("p0_5_business", p0_5_business)
    g.add_node("p1_analyze", p1_analyze)
    g.add_node("p1_5_reconcile", p1_5_reconcile)
    g.add_node("p2_dispatch", p2_dispatch)
    g.add_node("p2a_http_test", p2a_http_test)
    g.add_node("p2b_browser_test", p2b_browser_test)
    g.add_node("p2_merge", p2_merge)
    g.add_node("p2_55_supplement", p2_55_supplement)
    g.add_node("p2_6_validate", p2_6_validate)
    g.add_node("p2_retest", p2_retest)        # 三态闭包回退重测
    g.add_node("p3_report", p3_report)
    if human_review:
        g.add_node("p2_9_human_review", p2_9_human_review)  # 人工复核 gate

    # —— START ——
    g.add_edge(START, "p0_explore")

    # —— 条件边：P0 之后（FAST 跳过 0.5）——
    g.add_conditional_edges(
        "p0_explore", route_after_p0,
        {"p1_analyze": "p1_analyze", "p0_5_business": "p0_5_business"},
    )
    g.add_edge("p0_5_business", "p1_analyze")

    # —— 条件边：P1 之后（FAST 跳过 1.5）——
    g.add_conditional_edges(
        "p1_analyze", route_after_p1,
        {"p2_dispatch": "p2_dispatch", "p1_5_reconcile": "p1_5_reconcile"},
    )
    g.add_edge("p1_5_reconcile", "p2_dispatch")

    # —— P2 分叉（2a / 2b 并行）→ fan-in 到 P2_merge ——
    g.add_edge("p2_dispatch", "p2a_http_test")
    g.add_edge("p2_dispatch", "p2b_browser_test")
    g.add_edge("p2a_http_test", "p2_merge")
    g.add_edge("p2b_browser_test", "p2_merge")

    # —— 条件边：P2_merge 之后（FAST / 新API / 否则）——
    g.add_conditional_edges(
        "p2_merge", route_after_p2_merge,
        {"p3_report": "p3_report",
         "p2_55_supplement": "p2_55_supplement",
         "p2_6_validate": "p2_6_validate"},
    )
    g.add_edge("p2_55_supplement", "p2_6_validate")

    # —— 条件回边：P2.6 之后（三态闭包：证据不足→回退重测；否则→P3 / 人工复核 gate）——
    if human_review:
        # P2.6 的 p3_report 分支改走人工复核 gate，由人工决策放行或回退重测
        g.add_conditional_edges(
            "p2_6_validate", route_after_p2_6,
            {"p2_retest": "p2_retest", "p3_report": "p2_9_human_review"},
        )
        g.add_conditional_edges(
            "p2_9_human_review", route_after_human_review,
            {"p3_report": "p3_report", "p2_retest": "p2_retest"},
        )
    else:
        g.add_conditional_edges(
            "p2_6_validate", route_after_p2_6,
            {"p2_retest": "p2_retest", "p3_report": "p3_report"},
        )
    # —— 回退重测 → 重新进入 P2 分叉（2a+2b 本轮产出强证据）→ fan-in → P2.6 ——
    g.add_edge("p2_retest", "p2_dispatch")

    # —— END ——
    g.add_edge("p3_report", END)

    return g.compile(checkpointer=checkpointer, interrupt_after=interrupt_after or [])
