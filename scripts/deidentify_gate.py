#!/usr/bin/env python3
"""§4 Phase 2 item 2：发布前 7 项去标识化卡点。

对外发布前扫描全工程，识别以下 7 类 PII/敏感数据，任一命中 → 退出码 1 阻断发布：
  1. SECRET        — 真实密钥（AWS AKIA / GitHub PAT / JWT / PEM 私钥 / Slack token）
  2. INTERNAL_IP   — 私网 IP（10.x/172.16-31.x/192.168.x，允许 127.0.0.1/0.0.0.0）
  3. INTERNAL_HOST — 内部域名（*.internal/*.corp/*.local/*.lan/*.intranet）
  4. EMAIL         — 邮箱（允许 example.com 等占位域）
  5. PHONE_CN      — 中国手机号 1[3-9]\d{9}
  6. ID_CARD_CN    — 中国身份证号 18 位（末位 X/x 可）
  7. BANK_CARD     — 银行卡号 16-19 位（ID_CARD 命中段已消费，避免双计）

pre-commit 或 CI 阶段调用；默认排除 tests/、.git/、__pycache__/、data/scan_artifacts/。

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from dataclasses import dataclass
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
NC = "\033[0m"


@dataclass
class Violation:
    rule_id: str
    rule_name: str
    file: str
    line: int
    col: int
    match: str


@dataclass
class Rule:
    rule_id: str
    name: str
    pattern: re.Pattern
    allowlist: tuple[str, ...] = ()


# ---- 占位符白名单（不算 PII） ----
_PLACEHOLDER_DOMAINS = (
    "example.com", "example.org", "example.net",
    "test.com", "test.local", "localhost",
)
_PLACEHOLDER_EMAILS = (
    "user@example.com", "test@example.com", "admin@example.com",
    "noreply@example.com", "foo@example.com", "bar@example.com",
    "a@b.com", "x@y.com",
)


# ---- 7 项规则（顺序敏感：ID_CARD 必须在 BANK_CARD 之前以消费重叠段） ----
RULES: list[Rule] = [
    Rule(
        "SECRET",
        "真实密钥泄露（AWS AKIA / GitHub PAT / JWT / PEM / Slack）",
        re.compile(
            r"AKIA[0-9A-Z]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{36,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            r"|-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}"
        ),
    ),
    Rule(
        "INTERNAL_IP",
        "私网 IP 泄露（10.x / 172.16-31.x / 192.168.x）",
        re.compile(
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
        ),
        allowlist=("127.0.0.1", "0.0.0.0", "255.255.255.0", "255.255.0.0"),
    ),
    Rule(
        "INTERNAL_HOST",
        "内部域名泄露（*.internal / *.corp / *.local / *.lan / *.intranet）",
        re.compile(r"\b[\w.-]+\.(?:internal|corp|local|lan|intranet)\b"),
        allowlist=("test.local", "example.local"),
    ),
    Rule(
        "EMAIL",
        "邮箱地址 PII",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        allowlist=_PLACEHOLDER_EMAILS + _PLACEHOLDER_DOMAINS,
    ),
    Rule(
        "PHONE_CN",
        "中国手机号 PII（1[3-9]xxxxxxxxx）",
        re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    ),
    Rule(
        "ID_CARD_CN",
        "中国身份证号 PII（18 位）",
        re.compile(r"(?<!\d)[1-9]\d{16}[\dXx](?!\d)"),
    ),
    Rule(
        "BANK_CARD",
        "银行卡号 PII（16-19 位）",
        re.compile(r"(?<!\d)\d{16,19}(?!\d)"),
    ),
]


def _overlaps(s: int, e: int, spans: list[tuple[int, int]]) -> bool:
    for cs, ce in spans:
        if not (e <= cs or s >= ce):
            return True
    return False


def scan_text(text: str, file: str, rules: list[Rule]) -> list[Violation]:
    """对单段文本顺序扫描所有规则；ID_CARD 段被 BANK_CARD 跳过避免双计。"""
    consumed: list[tuple[int, int]] = []
    out: list[Violation] = []
    for rule in rules:
        for m in rule.pattern.finditer(text):
            s, e = m.start(), m.end()
            if _overlaps(s, e, consumed):
                continue
            hit = m.group(0)
            if any(a.lower() in hit.lower() for a in rule.allowlist):
                continue
            line_no = text.count("\n", 0, s) + 1
            col = s - (text.rfind("\n", 0, s) + 1) + 1
            display = hit if len(hit) <= 60 else hit[:57] + "..."
            # 注：len(hit) > 60 时截断至 57 字符 + "..." = 60 字符总宽
            out.append(Violation(rule.rule_id, rule.name, file,
                                 line_no, col, display))
            consumed.append((s, e))
    return out


def scan_file(path: Path, rules: list[Rule]) -> list[Violation]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(text, str(path).replace("\\", "/"), rules)


DEFAULT_EXCLUDE_DIRS: set[str] = {
    "tests", ".git", "node_modules", "__pycache__",
    "data", ".venv", "venv", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "htmlcov", "coverage_html",
}
DEFAULT_EXCLUDE_FILE_PATTERNS: list[str] = [
    "test_*.py", "*_test.py", "conftest.py", "*.pyc", "*.pyo",
]
_TEXT_SUFFIXES = frozenset({
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".html",
    ".js", ".ts", ".tsx", ".env", ".cfg", ".ini", ".toml",
    ".sh", ".sql", ".xml", ".csv",
})


def scan_tree(
    root: Path,
    rules: list[Rule] | None = None,
    exclude_dirs: set[str] | None = None,
    exclude_file_patterns: list[str] | None = None,
) -> list[Violation]:
    rules = rules if rules is not None else RULES
    excl_dirs = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    excl_pats = exclude_file_patterns if exclude_file_patterns is not None \
        else DEFAULT_EXCLUDE_FILE_PATTERNS
    out: list[Violation] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if any(seg in excl_dirs for seg in parts):
            continue
        if any(fnmatch.fnmatch(p.name, pat) for pat in excl_pats):
            continue
        if p.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        out.extend(scan_file(p, rules))
    return out


def render_report(violations: list[Violation]) -> str:
    if not violations:
        return f"{GREEN}PASS 去标识化通过：0 项违规{NC}"
    lines = [f"{RED}FAIL 去标识化失败：{len(violations)} 项违规{NC}", ""]
    by_rule: dict[str, list[Violation]] = {}
    for v in violations:
        by_rule.setdefault(v.rule_id, []).append(v)
    for rid, vs in by_rule.items():
        lines.append(f"{RED}[{rid}] {vs[0].rule_name} ({len(vs)}){NC}")
        for v in vs[:5]:
            lines.append(f"  {v.file}:{v.line}:{v.col}  {v.match}")
        if len(vs) > 5:
            lines.append(f"  ... 还有 {len(vs) - 5} 条")
    return "\n".join(lines)


def run_gate(
    root: Path,
    rules: list[Rule] | None = None,
    exclude_dirs: set[str] | None = None,
    exclude_file_patterns: list[str] | None = None,
) -> int:
    violations = scan_tree(root, rules, exclude_dirs, exclude_file_patterns)
    print(render_report(violations))
    return 0 if not violations else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="发布前 7 项去标识化卡点")
    parser.add_argument("--root", type=Path, default=Path("."),
                        help="扫描根目录（默认当前目录）")
    parser.add_argument("--exclude-dir", action="append", default=None,
                        help="追加排除目录名（可多次指定）")
    parser.add_argument("--exclude-pattern", action="append", default=None,
                        help="追加排除文件名 glob（可多次指定）")
    args = parser.parse_args()

    excl_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if args.exclude_dir:
        excl_dirs.update(args.exclude_dir)
    excl_pats = list(DEFAULT_EXCLUDE_FILE_PATTERNS)
    if args.exclude_pattern:
        excl_pats.extend(args.exclude_pattern)
    return run_gate(args.root, RULES, excl_dirs, excl_pats)


if __name__ == "__main__":
    sys.exit(main())
