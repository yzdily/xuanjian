"""cli.main — xuanjian 命令入口（短期 S3）。

按 XUANJIAN_ROADMAP_SHORT_TERM §4.3 落地：
- argparse 子命令：doctor / run / report / diff（增量回归）
- run 子命令支持 --mode / --vuln-class / --tenant / --url
- 委派到 cli/doctor 与 core.parallel.orchestrator
- 零外部依赖
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xuanjian",
        description="玄鉴 AI-native 安全测试平台",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # doctor ----------------------------------------------------------------
    sub.add_parser("doctor", help="自检环境/依赖/权限")

    # run -------------------------------------------------------------------
    r = sub.add_parser("run", help="启动一次扫描")
    r.add_argument(
        "--mode",
        choices=["fast", "standard", "deep"],
        default="standard",
        help="扫描模式（fast/standard/deep）",
    )
    r.add_argument(
        "--vuln-class",
        help="0827 E2 双维度筛选：按漏洞类型（sqli/bola/xss/...）",
    )
    r.add_argument(
        "--tenant",
        help="短期 S2 工作区 ID（默认读 XUANJIAN_TENANT，否则 default）",
    )
    r.add_argument(
        "--url",
        help="目标 URL（M3 IM 入口会传）",
    )
    r.add_argument(
        "--ci-gate",
        action="store_true",
        help="G8 CI 门禁：含 High+ 漏洞或覆盖门控未过则退出码 1（接入流水线）",
    )
    r.add_argument(
        "--scope-file",
        help="§3.8 授权 scope 文件（JSON: {signed, domains, expires_at}）。"
             "不传 → SOFT 门降级放行并告警；传了但越域/过期 → 阻断扫描。"
             "强制要求授权：XJ_AUTH_GATE_STRICT=1",
    )

    # report ---------------------------------------------------------------
    rp = sub.add_parser("report", help="渲染报告")
    rp.add_argument(
        "--task-id",
        help="任务 ID（默认取最新扫描产物）",
    )
    rp.add_argument(
        "--ci-gate",
        action="store_true",
        help="G8 CI 门禁：含 High+ 漏洞或覆盖门控未过则退出码 1",
    )

    # diff -----------------------------------------------------------------
    d = sub.add_parser(
        "diff",
        help="增量回归：对比目标两次快照，只对变化点做漏洞测试（经补测框架）",
    )
    d.add_argument(
        "--target",
        required=True,
        help="扫描目标 host（如 https://api.example.com）",
    )
    d.add_argument(
        "--baseline",
        help="基线快照 tag（默认取次新快照）",
    )
    d.add_argument(
        "--current",
        help="当前快照 tag（默认取最新快照）",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "doctor":
        from cli.doctor import run_doctor

        return run_doctor()

    if args.cmd == "run":
        # §3.8 授权门：把 scope 文件交给编排层。
        # 编排在 core 内运行，env 是跨层传递的最短路径（`apply_pre_scan_gate`
        # 读 `XUANJIAN_SCOPE_FILE`），避免 core→cli 的反向依赖。
        _scope = getattr(args, "scope_file", None)
        if _scope:
            if not os.path.exists(_scope):
                print(f"[ERR] scope 文件不存在: {_scope}", file=sys.stderr)
                return 2
            os.environ["XUANJIAN_SCOPE_FILE"] = os.path.abspath(_scope)
            print(f"[AUTH] 授权 scope 文件: {_scope}")
        else:
            print("[AUTH] 未提供 --scope-file → 授权门降级放行（SOFT）；"
                  "如需强制，置 XJ_AUTH_GATE_STRICT=1", file=sys.stderr)

        # 委派到 v1.6 公开 API
        try:
            from core.parallel.orchestrator import start_browser_feature_test
        except Exception as e:
            print(f"[ERR] 无法启动扫描：{e}", file=sys.stderr)
            return 2
        try:
            rc = start_browser_feature_test(
                mode=args.mode,
                vuln_class=args.vuln_class,
                tenant=args.tenant,
                url=args.url,
            ) or 0
        except TypeError:
            # 旧签名不接 kwargs；回退到位置参数或无参
            rc = start_browser_feature_test() or 0
        if args.ci_gate:
            return _apply_ci_gate(rc)
        return rc

    if args.cmd == "report":
        try:
            from core.cli_report import render_report
        except Exception as e:
            print(f"[ERR] 无法渲染报告：{e}", file=sys.stderr)
            return 2
        rc = render_report(getattr(args, "task_id", None)) or 0
        if args.ci_gate:
            return _apply_ci_gate(rc)
        return rc

    if args.cmd == "diff":
        return _run_diff(args)

    parser.print_help()
    return 1


def _apply_ci_gate(scan_rc: int) -> int:
    """G8：在扫描/报告退出码基础上叠加 CI 门禁判定。"""
    try:
        from core.ci_gate import evaluate_ci_gate

        code, res = evaluate_ci_gate()
        if code != 0:
            print(f"[CI-GATE] 阻断：{'; '.join(res.get('reasons', []))}", file=sys.stderr)
            return 1
        print(f"[CI-GATE] 通过：{'; '.join(res.get('reasons', []))}")
        return scan_rc
    except Exception as e:  # 门禁评估失败不应掩盖扫描本身结果
        print(f"[CI-GATE] 评估异常（不影响扫描结果）：{e}", file=sys.stderr)
        return scan_rc


def _run_diff(args) -> int:
    """1.2 增量回归 CLI：对比目标两次快照，只对变化点做漏洞测试。

    链路：list_snapshots → load_snapshot → diff_snapshots → build_regression_plan
    → save_regression_plan（落 data/regression_plans/<target>-<ts>.json）
    → run_regression_plan（翻译为补测框架可消费的 feature 任务）。
    """
    from core.diff import list_snapshots, load_snapshot, diff_snapshots
    from core.diff.regression import build_regression_plan, save_regression_plan
    from core.diff.runner import run_regression_plan

    target = args.target
    try:
        snaps = list_snapshots(host=target) or []
    except Exception as e:  # 列快照失败不崩，给出可读错误
        print(f"[diff] 列举快照失败: {e}", file=sys.stderr)
        return 2
    if not snaps:
        print(
            f"[diff] 目标 {target} 无历史快照，请先运行一次扫描生成 sitemap 快照",
            file=sys.stderr,
        )
        return 2

    # 选定 baseline / current：显式 tag 优先，否则取最新两条
    snaps_sorted = sorted(
        snaps, key=lambda s: s.get("created_at", 0) or 0, reverse=True
    )
    current = (
        _pick_snap(snaps_sorted, args.current) if args.current
        else snaps_sorted[0]
    )
    baseline = (
        _pick_snap(snaps_sorted, args.baseline) if args.baseline
        else (snaps_sorted[1] if len(snaps_sorted) > 1 else None)
    )
    if baseline is None or current is None:
        print(
            "[diff] 需要至少两条快照才能对比（baseline/current），"
            "请先对同一目标运行两次扫描",
            file=sys.stderr,
        )
        return 2

    try:
        b = load_snapshot(target, baseline["tag"])
        c = load_snapshot(target, current["tag"])
    except Exception as e:
        print(f"[diff] 加载快照失败: {e}", file=sys.stderr)
        return 2
    if not b or not c:
        print("[diff] 快照加载为空", file=sys.stderr)
        return 2

    diff = diff_snapshots(b, c, baseline["tag"], current["tag"])
    plan = build_regression_plan(diff)
    path = save_regression_plan(plan)
    tasks = run_regression_plan(target, plan)

    print(f"[diff] 目标 {target}")
    print(f"  baseline = {baseline['tag']}  current = {current['tag']}")
    print(f"  回归项   : {len(plan.items)} "
          f"(高优 {plan.summary.get('high_priority', 0)})")
    print(f"  补测任务 : {len(tasks)} 项（经补测框架消费）")
    print(f"  方案已存 : {path}")
    return 0


def _pick_snap(snaps: list, tag: str) -> dict | None:
    """按 tag 在快照列表中定位（tag 缺失时回退到索引匹配）。"""
    for s in snaps:
        if s.get("tag") == tag:
            return s
    return None


if __name__ == "__main__":
    sys.exit(main())
