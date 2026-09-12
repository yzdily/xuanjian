"""cli.main — xuanjian 命令入口（短期 S3）。

按 XUANJIAN_ROADMAP_SHORT_TERM §4.3 落地：
- argparse 三子命令：doctor / run / report
- run 子命令支持 --mode / --vuln-class / --tenant / --url
- 委派到 cli/doctor 与 core.parallel.orchestrator
- 零外部依赖
"""
from __future__ import annotations

import argparse
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

    # report ---------------------------------------------------------------
    rp = sub.add_parser("report", help="渲染报告")
    rp.add_argument(
        "--ci-gate",
        action="store_true",
        help="G8 CI 门禁：含 High+ 漏洞或覆盖门控未过则退出码 1",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "doctor":
        from cli.doctor import run_doctor

        return run_doctor()

    if args.cmd == "run":
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
            from core.session.report_mixin import render_report  # type: ignore
        except Exception as e:
            print(f"[ERR] 无法渲染报告：{e}", file=sys.stderr)
            return 2
        rc = render_report() or 0
        if args.ci_gate:
            return _apply_ci_gate(rc)
        return rc

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


if __name__ == "__main__":
    sys.exit(main())
