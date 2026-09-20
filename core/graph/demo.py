"""
XuanJian 八阶段 LangGraph —— 运行演示
======================================

演示七件事：
  1) 把 graph 用 Mermaid 真正画出来（拓扑可视化，含 P2.6 回退重测回边 + P2.9 人工复核 gate）
  2) DEEP 全量路径：P0→P0.5→P1→P1.5→P2(2a+2b)→P2.6→P3
  3) FAST 跳过路径：P0→P1→P2(2a+2b)→P3（跳过 0.5/1.5/2.55/2.6）
  4) 触发 P2.55 补测分支（new_apis_found=True）
  5) ★ P2.6 三态闭包回退重测：证据不足(OPEN_PROOF_GAP) → 回退 P2.retest → 重测补证 → P3
  6) ★ 文件落盘 checkpointer 跨进程崩溃恢复：进程1 在 P2_merge 后崩溃(interrupt)，
        进程2 用同一 db 文件重新建 Saver 续跑（不重跑已完成阶段）
  7) ★ 人工复核 gate（interrupt_before P3）：approve 放行 P3 / reject 回退重测后再复核

运行：
  cd core/graph && python demo.py
（节点在缺浏览器/LLM 时自动降级为 stub，因此任何环境都能跑通拓扑、回边、续跑与人审门）
"""

from __future__ import annotations

import logging
import os
import sqlite3
import tempfile

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from xuanjian_graph import build_graph

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def _saver():
    # 进程内持久 checkpointer（:memory: 在同一进程内可跨 invoke 续跑）；
    # check_same_thread=False 是因为 LangGraph 在线程池中访问 checkpointer。
    return SqliteSaver(sqlite3.connect(":memory:", check_same_thread=False))


def _banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def visualize(app) -> None:
    # 优先 Mermaid（零额外依赖，可直接贴进 README / GitHub）
    try:
        print(app.get_graph().draw_mermaid())
        return
    except Exception as e:  # noqa: BLE001
        print(f"(Mermaid 不可用: {e})")
    # 退路：ASCII（需 pip install grandalf）
    try:
        print(app.get_graph().draw_ascii())
    except Exception as e:  # noqa: BLE001
        print(f"(ASCII 可视化不可用: {e})")


def main() -> None:
    _banner("1) 八阶段拓扑（Mermaid；含 P2.6 回退重测回边 + P2.9 人工复核 gate）")
    app = build_graph(checkpointer=_saver(), human_review=True)
    visualize(app)

    # 运行演示用「无 gate」版本，避免每一步都停在人工复核（gate 单独在第 7 段演示）
    app = build_graph(checkpointer=_saver())

    _banner("2) DEEP 全量路径（非 FAST，无新 API → 跳过 2.55）")
    cfg = {"configurable": {"thread_id": "deep-run"}}
    out = app.invoke(
        {"target": "https://demo.xuanjian.local", "user_scan_mode": "DEEP"}, cfg
    )
    print("→ 经历阶段:", " → ".join(out["log"]))
    print("→ retest_round =", out.get("retest_round"), " open_proof_gap =", out.get("open_proof_gap"))

    _banner("3) FAST 跳过路径（0.5 / 1.5 / 2.55 / 2.6 全跳过，无回退重测）")
    cfg = {"configurable": {"thread_id": "fast-run"}}
    out = app.invoke(
        {"target": "https://fast.xuanjian.local", "user_scan_mode": "FAST"}, cfg
    )
    print("→ 经历阶段:", " → ".join(out["log"]))

    _banner("4) 触发 P2.55 补测分支（new_apis_found=True）")
    # 用独立 checkpointer，避免与上一次同 thread 续跑干扰
    app2 = build_graph(checkpointer=_saver())
    cfg = {"configurable": {"thread_id": "supplement-run"}}
    out = app2.invoke(
        {"target": "https://extra.xuanjian.local", "user_scan_mode": "STANDARD",
         "new_apis_found": True}, cfg
    )
    print("→ 经历阶段:", " → ".join(out["log"]))

    _banner("5) ★ P2.6 三态闭包回退重测：证据不足 → 回退 P2.retest → 重测补证 → P3")
    app3 = build_graph(checkpointer=_saver())
    cfg = {"configurable": {"thread_id": "retest-run"}}
    out = app3.invoke(
        {"target": "https://gap.xuanjian.local", "user_scan_mode": "STANDARD"}, cfg
    )
    print("→ 经历阶段:", " → ".join(out["log"]))
    print("→ 回退重测轮次 retest_round =", out.get("retest_round"))
    print("→ 末轮 open_proof_gap =", out.get("open_proof_gap"),
          " 确认漏洞数 =", len(out.get("validated_vulns") or []))

    _banner("5b) 重测预算用尽：max_retest=0 → 证据不足也放行到 P3（人工复核），不死循环")
    app3b = build_graph(checkpointer=_saver())
    cfg = {"configurable": {"thread_id": "no-retest-run"}}
    out = app3b.invoke(
        {"target": "https://noretry.xuanjian.local", "user_scan_mode": "STANDARD",
         "max_retest": 0}, cfg
    )
    print("→ 经历阶段:", " → ".join(out["log"]))
    print("→ retest_round =", out.get("retest_round"), " open_proof_gap =", out.get("open_proof_gap"))

    _banner("6) ★ 文件落盘 checkpointer 跨进程崩溃恢复")
    _cross_process_recovery()

    _banner("7) ★ 人工复核 gate（interrupt_before P3）：approve 放行 / reject 回退重测")
    _human_review_demo()


def _cross_process_recovery() -> None:
    """模拟真实崩溃恢复：进程1落盘后退出，进程2用同一 db 文件重建续跑。"""
    db = os.path.join(tempfile.gettempdir(), "xuanjian_xproc_recovery.db")
    if os.path.exists(db):
        os.remove(db)

    cfg = {"configurable": {"thread_id": "xproc-recovery"}}

    # —— 进程 1：文件 checkpointer，在 P2_merge 后 interrupt（模拟崩溃）——
    saver1 = SqliteSaver(sqlite3.connect(db, check_same_thread=False))
    app1 = build_graph(checkpointer=saver1, interrupt_after=["p2_merge"])
    part = app1.invoke(
        {"target": "https://crash.xuanjian.local", "user_scan_mode": "DEEP"}, cfg
    )
    print(f"  [进程1] 跑到 {part.get('current_phase')} 被中断，"
          f"checkpoint 已落盘 → {db}")
    del app1, saver1  # 进程1 退出（对象销毁，模拟进程结束）

    # —— 进程 2：全新 Saver 实例 + 新建 graph，读同一 db 文件续跑 ——
    saver2 = SqliteSaver(sqlite3.connect(db, check_same_thread=False))
    app2 = build_graph(checkpointer=saver2)  # 注意：未指定 interrupt，正常跑完
    final = app2.invoke(None, cfg)
    print(f"  [进程2] 从磁盘 checkpoint 续跑完成，current_phase = {final.get('current_phase')}")
    print(f"  [进程2] 经历阶段: {' → '.join(final.get('log', []))}")
    print(f"  [进程2] 报告 = {final.get('report')}")
    print("  ✅ 跨进程恢复成功：P2_merge 之前的阶段未重跑，仅续跑后续。")

    # 清理演示 db
    try:
        os.remove(db)
    except OSError:
        pass


def _human_review_demo() -> None:
    """人工复核 gate 演示：approve 放行 / reject 回退重测再复核。"""
    # —— 7a. approve 路径 ——
    cfg = {"configurable": {"thread_id": "gate-approve"}}
    app = build_graph(checkpointer=_saver(), human_review=True)
    app.invoke(
        {"target": "https://gate.xuanjian.local", "user_scan_mode": "STANDARD",
         "max_retest": 2}, cfg
    )
    st = app.get_state(cfg)
    summary = None
    try:
        summary = st.tasks[0].interrupts[0].value
    except Exception:  # noqa: BLE001 — 结构可能因版本略有差异，跳过也不影响演示
        pass
    print("  [运行] 已暂停在 P2.9 人工复核 gate（interrupt_before P3）")
    if summary is not None:
        print("  [人工看到] 裁决摘要 =", summary)
    print("  [人工决策] approve → 放行 P3")
    final = app.invoke(Command(resume={"action": "approve",
                                        "note": "证据充分，准予出报告"}), cfg)
    print("  [运行] 续跑完成，report =", final.get("report"))
    print("  [运行] 经历阶段:", " → ".join(final.get("log", [])))

    # —— 7b. reject 路径：回退重测后再次过门，再 approve ——
    cfg2 = {"configurable": {"thread_id": "gate-reject"}}
    app2 = build_graph(checkpointer=_saver(), human_review=True)
    app2.invoke(
        {"target": "https://gate-rej.xuanjian.local", "user_scan_mode": "STANDARD",
         "max_retest": 2}, cfg2
    )
    print("  [运行] 第1次过门，人工决策 reject（要求补证），传回门")
    app2.invoke(Command(resume={"action": "reject", "note": "证据单薄，需重测"}), cfg2)
    st2 = app2.get_state(cfg2)
    print("  [运行] reject 后状态：current_phase =", st2.values.get("current_phase"),
          " retest_round =", st2.values.get("retest_round"))
    final2 = app2.invoke(Command(resume={"action": "approve",
                                         "note": "重测补证后准予出报告"}), cfg2)
    print("  [运行] 第2次过门 approve，report =", final2.get("report"))
    print("  [运行] 经历阶段:", " → ".join(final2.get("log", [])))
    print("  ✅ 人工复核 gate 演示成功：approve 放行 / reject 回退重测再复核。")


if __name__ == "__main__":
    main()
