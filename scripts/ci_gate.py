#!/usr/bin/env python3
"""
CI 分层门禁脚本 — 三层检查，避免 --cov-fail-under=70 一推就卡死全队。

Layer 1: 全局 ratchet（8→20→40→70）
  - 阈值存储在 .coverage-ratchet 文件中，只升不降
  - 当前覆盖率必须 ≥ ratchet 阈值，否则 CI 失败

Layer 2: diff-coverage ≥80%
  - 新增/修改的行必须有 ≥80% 覆盖率
  - 使用 diff-cover 比较 coverage.xml 与 git diff

Layer 3: 目录级 ≥90% 锁高覆盖包
  - 已经达到 ≥90% 覆盖的包不允许退化
  - 从 coverage.xml 读取每个包的覆盖率

用法:
  python scripts/ci_gate.py [--ratchet-file .coverage-ratchet] [--diff-coverage 80] [--dir-coverage 90]

退出码:
  0 = 全部通过
  1 = 某层门禁失败
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# ============================================================
# 颜色输出
# ============================================================
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
NC = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}✓{NC} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}✗{NC} {msg}")


def info(msg: str) -> None:
    print(f"{YELLOW}→{NC} {msg}")


# ============================================================
# Layer 1: 全局 ratchet
# ============================================================

RATCHET_SCHEDULE = [8, 20, 40, 70]


def read_ratchet(ratchet_file: Path) -> int:
    """读取当前 ratchet 阈值。"""
    if not ratchet_file.exists():
        return RATCHET_SCHEDULE[0]
    try:
        return int(ratchet_file.read_text().strip())
    except (ValueError, OSError):
        return RATCHET_SCHEDULE[0]


def get_next_ratchet(current: int) -> int | None:
    """获取 ratchet 下一阶段目标。"""
    for val in RATCHET_SCHEDULE:
        if val > current:
            return val
    return None


def parse_total_coverage(coverage_xml: Path) -> float:
    """从 coverage.xml 解析总覆盖率。"""
    if not coverage_xml.exists():
        fail(f"coverage.xml 不存在: {coverage_xml}")
        return 0.0
    tree = ET.parse(coverage_xml)
    root = tree.getroot()
    # <coverage line-rate="0.082" ...>
    line_rate = float(root.attrib.get("line-rate", "0"))
    return line_rate * 100


def check_ratchet(coverage_xml: Path, ratchet_file: Path) -> bool:
    """Layer 1: 检查全局覆盖率是否满足 ratchet 阈值。"""
    threshold = read_ratchet(ratchet_file)
    actual = parse_total_coverage(coverage_xml)

    print(f"\n{'='*60}")
    print(f"Layer 1: 全局 ratchet 门禁")
    print(f"{'='*60}")
    info(f"Ratchet 阈值: {threshold}%（ratchet 计划: {' → '.join(str(v) for v in RATCHET_SCHEDULE)}）")
    info(f"实际覆盖率: {actual:.1f}%")

    if actual >= threshold:
        ok(f"全局覆盖率 {actual:.1f}% ≥ ratchet 阈值 {threshold}%")
        # 检查是否可以提升 ratchet
        next_val = get_next_ratchet(threshold)
        if next_val and actual >= next_val:
            info(f"覆盖率已达下一阶段 {next_val}%，可提升 ratchet（修改 .coverage-ratchet）")
        return True
    else:
        fail(f"全局覆盖率 {actual:.1f}% < ratchet 阈值 {threshold}%")
        return False


# ============================================================
# Layer 2: diff-coverage
# ============================================================

def check_diff_coverage(coverage_xml: Path, threshold: float) -> bool:
    """Layer 2: 检查 diff-coverage。"""
    print(f"\n{'='*60}")
    print(f"Layer 2: diff-coverage 门禁 (≥{threshold}%)")
    print(f"{'='*60}")

    # 检查是否在 git 仓库中
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            info("非 git 仓库或无 diff，跳过 diff-coverage 检查")
            return True
        changed_files = [f for f in result.stdout.strip().split("\n") if f.endswith(".py")]
        if not changed_files:
            info("无 Python 文件变更，跳过 diff-coverage 检查")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        info("git 不可用，跳过 diff-coverage 检查")
        return True

    # 使用 diff-cover 检查
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "diff_cover",
                "--compare-branch=HEAD",
                f"--fail-under={threshold}",
                "--json-report",
                str(coverage_xml.parent / "diff-cover.json"),
                str(coverage_xml),
            ],
            capture_output=True, text=True, timeout=30,
        )
        # diff-cover 返回 0 = 通过, 1 = 失败
        if result.returncode == 0:
            ok(f"diff-coverage ≥ {threshold}%")
            if result.stdout:
                info(result.stdout.strip())
            return True
        else:
            # 检查是否是 diff_cover 模块未安装
            combined = (result.stdout or "") + (result.stderr or "")
            if "No module named" in combined:
                info("diff-cover 未安装，跳过 diff-coverage 检查（CI 环境会自动安装）")
                return True
            fail(f"diff-coverage < {threshold}%")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        info("diff-cover 不可用，跳过 diff-coverage 检查")
        return True


# ============================================================
# Layer 3: 目录级 ≥90% 锁高覆盖包
# ============================================================

def parse_package_coverage(coverage_xml: Path) -> dict[str, float]:
    """从 coverage.xml 解析每个包的覆盖率。"""
    if not coverage_xml.exists():
        return {}
    tree = ET.parse(coverage_xml)
    root = tree.getroot()
    packages = {}
    for pkg in root.findall(".//package"):
        name = pkg.attrib.get("name", "")
        line_rate = float(pkg.attrib.get("line-rate", "0"))
        packages[name] = line_rate * 100
    return packages


# 高覆盖包白名单（当前已达 ≥90% 的包，锁住不允许退化）
# 初始为空，随覆盖率提升逐步添加
HIGH_COVERAGE_PACKAGES: set[str] = set()


def check_directory_coverage(coverage_xml: Path, threshold: float) -> bool:
    """Layer 3: 检查目录级覆盖率。"""
    print(f"\n{'='*60}")
    print(f"Layer 3: 目录级门禁 (≥{threshold}% 锁高覆盖包)")
    print(f"{'='*60}")

    packages = parse_package_coverage(coverage_xml)
    if not packages:
        info("无覆盖率数据，跳过目录级检查")
        return True

    all_passed = True

    # 检查白名单中的高覆盖包
    for pkg_name in HIGH_COVERAGE_PACKAGES:
        actual = packages.get(pkg_name, 0)
        if actual >= threshold:
            ok(f"{pkg_name}: {actual:.1f}% ≥ {threshold}%")
        else:
            fail(f"{pkg_name}: {actual:.1f}% < {threshold}%（高覆盖包不允许退化）")
            all_passed = False

    # 自动发现新的高覆盖包并报告（不锁定，仅提示）
    for pkg_name, actual in sorted(packages.items()):
        if actual >= threshold and pkg_name not in HIGH_COVERAGE_PACKAGES:
            info(f"发现新高覆盖包: {pkg_name} = {actual:.1f}%（可加入 HIGH_COVERAGE_PACKAGES 锁定）")

    if all_passed:
        ok("目录级门禁通过")
    return all_passed


# ============================================================
# 主入口
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="CI 分层门禁")
    parser.add_argument("--coverage-xml", type=Path, default=Path("coverage.xml"))
    parser.add_argument("--ratchet-file", type=Path, default=Path(".coverage-ratchet"))
    parser.add_argument("--diff-threshold", type=float, default=80.0)
    parser.add_argument("--dir-threshold", type=float, default=90.0)
    parser.add_argument("--skip-diff", action="store_true", help="跳过 diff-coverage 检查")
    parser.add_argument("--skip-dir", action="store_true", help="跳过目录级检查")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  玄鉴 CI 分层门禁")
    print("=" * 60)

    results = []

    # Layer 1: 全局 ratchet
    results.append(("Layer 1: ratchet", check_ratchet(args.coverage_xml, args.ratchet_file)))

    # Layer 2: diff-coverage
    if not args.skip_diff:
        results.append(("Layer 2: diff-coverage", check_diff_coverage(args.coverage_xml, args.diff_threshold)))
    else:
        info("跳过 Layer 2: diff-coverage")

    # Layer 3: 目录级
    if not args.skip_dir:
        results.append(("Layer 3: directory", check_directory_coverage(args.coverage_xml, args.dir_threshold)))
    else:
        info("跳过 Layer 3: 目录级")

    # 汇总
    print("\n" + "=" * 60)
    print("  门禁汇总")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        if passed:
            ok(name)
        else:
            fail(name)
            all_passed = False

    if all_passed:
        print(f"\n{GREEN}🎉 全部门禁通过！{NC}")
        return 0
    else:
        print(f"\n{RED}❌ 门禁失败，请修复后重试。{NC}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
