"""§4 Phase 2 item 1：能力成熟度矩阵 + DoD 回归闸门。

L0–L3 成熟度档位定义见 ``core/capability_matrix.json``（与 §0.1 红线 +
产品方案 §2.4 + 技术方案 §4/§6 对齐）。DoD（Definition of Done）= 每项
至少有一条 pytest 回归。``gate_seal()`` 是 CI 封板唯一机制：全 L0–L3 项
均有 pytest 且 CI 绿方可封板（技术方案 §6）。

零外部依赖（纯 stdlib）。DoD 约束源自 §0.1 红线 + §2.4，未单独落
CONSTRAINTS.md（避免冗余文档）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

_DEFAULT_MATRIX_PATH = Path(__file__).parent / "capability_matrix.json"
_GLOB_META = frozenset("*?[")


def load_matrix(path: str | Path | None = None) -> dict:
    """加载能力矩阵 JSON。默认读 ``core/capability_matrix.json``。"""
    p = Path(path) if path else _DEFAULT_MATRIX_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "tiers" not in data:
        raise ValueError(f"capability matrix 非法：缺 tiers 字段 — {p}")
    return data


def iter_items(matrix: dict) -> Iterable[dict]:
    """展平 tiers，逐项 yield（带 level/tier_name 注入）。"""
    for tier in matrix.get("tiers", []):
        level = tier.get("level", "?")
        tname = tier.get("name", "")
        for item in tier.get("items", []):
            yield {
                "level": level,
                "tier_name": tname,
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "dod": item.get("dod", ""),
                "test_globs": item.get("test_globs", []),
            }


def validate_schema(matrix: dict) -> list[str]:
    """校验矩阵 schema，返回违规描述列表（空=合法）。"""
    errs: list[str] = []
    tiers = matrix.get("tiers")
    if not isinstance(tiers, list) or not tiers:
        return ["tiers 必须是非空 list"]
    seen_ids: set[str] = set()
    for i, tier in enumerate(tiers):
        if not isinstance(tier, dict):
            errs.append(f"tiers[{i}] 必须是 dict")
            continue
        if not tier.get("level") or not tier.get("name"):
            errs.append(f"tiers[{i}] 缺 level/name")
        items = tier.get("items")
        if not isinstance(items, list) or not items:
            errs.append(f"tier {tier.get('level', '?')} items 必须非空 list")
            continue
        for j, item in enumerate(items):
            if not isinstance(item, dict):
                errs.append(f"tiers[{i}].items[{j}] 必须是 dict")
                continue
            iid = item.get("id", "")
            if not iid:
                errs.append(f"tiers[{i}].items[{j}] 缺 id")
            elif iid in seen_ids:
                errs.append(f"item id 重复：{iid}")
            else:
                seen_ids.add(iid)
            for fld in ("name", "dod", "test_globs"):
                if fld not in item:
                    errs.append(f"{iid} 缺字段 {fld}")
            globs = item.get("test_globs")
            if not isinstance(globs, list) or not globs:
                errs.append(f"{iid} test_globs 必须是非空 list")
    return errs


def find_tests(item: dict, project_root: str | Path | None = None) -> list[str]:
    """对 item 的 test_globs 在 project_root 下做存在性匹配，返回命中的相对路径。

    支持普通 glob 元字符（``*``/``?``/``[``）；不含元字符的串按精确路径处理。
    """
    root = Path(project_root) if project_root else Path.cwd()
    matched: list[str] = []
    for pat in item.get("test_globs", []):
        if any(c in pat for c in _GLOB_META):
            hits = list(root.glob(pat))
        else:
            cand = root / pat
            hits = [cand] if cand.exists() else []
        for h in hits:
            if h.exists():
                rel = h.relative_to(root) if h.is_absolute() else h
                matched.append(str(rel).replace("\\", "/"))
    return sorted(set(matched))


def check_dod(
    matrix: dict, project_root: str | Path | None = None
) -> dict[str, dict[str, Any]]:
    """逐项检查 DoD 覆盖。返回 {item_id: {level,name,covered,matched}}。"""
    out: dict[str, dict[str, Any]] = {}
    for item in iter_items(matrix):
        matched = find_tests(item, project_root)
        out[item["id"]] = {
            "level": item["level"],
            "name": item["name"],
            "covered": bool(matched),
            "matched": matched,
        }
    return out


def gate_seal(
    matrix: dict | None = None, project_root: str | Path | None = None
) -> bool:
    """封板闸门：全 L0–L3 项均有 pytest 覆盖 → True。"""
    m = matrix if matrix is not None else load_matrix()
    report = check_dod(m, project_root)
    return all(r["covered"] for r in report.values())


def render_report(
    matrix: dict | None = None, project_root: str | Path | None = None
) -> str:
    """渲染 markdown 覆盖报告（终端可读）。"""
    m = matrix if matrix is not None else load_matrix()
    report = check_dod(m, project_root)
    lines = [
        "# 能力成熟度 DoD 覆盖报告",
        "",
        "| 层级 | ID | 名称 | 覆盖 | 命中测试 |",
        "|---|---|---|---|---|",
    ]
    for item in iter_items(m):
        r = report[item["id"]]
        mark = "PASS" if r["covered"] else "FAIL"
        matched = ", ".join(r["matched"]) or "—"
        lines.append(
            f"| {r['level']} | {item['id']} | {r['name']} | {mark} | {matched} |"
        )
    total = len(report)
    covered = sum(1 for r in report.values() if r["covered"])
    lines.append("")
    verdict = "可封板" if covered == total else "尚未封板（见上 FAIL 项）"
    lines.append(f"**总覆盖：{covered}/{total}** — {verdict}")
    return "\n".join(lines)
