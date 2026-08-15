"""语义等价 diff（D6 P1-2 选定策略）。

比对前，golden 与 actual 都已经过 ``serializer.serialize`` 规范化，因此本模块只做
**结构化比对**：不再处理时间戳/token（已占位化），只报「真实差异」。

比对维度：
  - ``output``：怪物方法的返回值（crawl 的 CrawlRoundResult / CrawledPage；chat 为 null）
  - ``events``：事件序列 —— 顺序 + type + 关键 payload（逐 index 比对规范化后的 event-dict）

``meta.progress``（crawler 的纯文本进度）仅落盘供人查阅，**不参与 diff**（含计时/计数噪声）。

返回 ``list[str]``：人类可读差异行；空列表 = 行为等价（闸门放行）。
"""
from __future__ import annotations

import json
from typing import Any


def _diff_values(path: str, g: Any, a: Any, out: list[str]) -> None:
    """递归比对两个已规范化的值，差异行追加到 ``out``。"""
    if type(g) is not type(a):
        out.append(f"{path}: 类型差异 golden={type(g).__name__} actual={type(a).__name__}")
        return
    if isinstance(g, dict):
        gk, ak = set(g.keys()), set(a.keys())
        for k in sorted(gk - ak):
            out.append(f"{path}.{k}: golden 有 / actual 缺")
        for k in sorted(ak - gk):
            out.append(f"{path}.{k}: actual 新增 / golden 无")
        for k in sorted(gk & ak):
            _diff_values(f"{path}.{k}", g[k], a[k], out)
        return
    if isinstance(g, list):
        if len(g) != len(a):
            out.append(f"{path}: 长度差异 golden={len(g)} actual={len(a)}")
        # ★ dict 列表做无序比较：网络响应顺序不确定（如 realtime_channels），
        # 按 JSON 规范化排序后再逐 index diff，避免顺序噪声产生假阳性。
        if g and all(isinstance(x, dict) for x in g) and a and all(isinstance(x, dict) for x in a):
            g_sorted = sorted(g, key=lambda x: json.dumps(x, ensure_ascii=False, sort_keys=True))
            a_sorted = sorted(a, key=lambda x: json.dumps(x, ensure_ascii=False, sort_keys=True))
        else:
            g_sorted, a_sorted = g, a
        for i in range(min(len(g_sorted), len(a_sorted))):
            _diff_values(f"{path}[{i}]", g_sorted[i], a_sorted[i], out)
        return
    if isinstance(g, (set, tuple)):
        _diff_values(path, list(g), list(a), out)
        return
    if g != a:
        out.append(f"{path}: 值差异 golden={g!r} actual={a!r}")


def diff_events(g_events: list, a_events: list, out: list[str]) -> None:
    """事件序列比对：顺序敏感，逐 index 比对规范化 event-dict（含 type + payload）。"""
    if len(g_events) != len(a_events):
        out.append(f"events: 序列长度差异 golden={len(g_events)} actual={len(a_events)}")
    for i in range(min(len(g_events), len(a_events))):
        ge, ae = g_events[i], a_events[i]
        # type 是主键，单独高亮
        gt = ge.get("type") if isinstance(ge, dict) else None
        at = ae.get("type") if isinstance(ae, dict) else None
        if gt != at:
            out.append(f"events[{i}].type: golden={gt!r} actual={at!r}")
        _diff_values(f"events[{i}]", ge, ae, out)


def semantic_diff(golden: dict, actual: dict) -> list[str]:
    """比对两个 GoldenSample dict（均含 output / events / meta）。

    Args:
        golden: 录制落盘的样本（已规范化）
        actual: 回放当前实现产出的样本（已规范化）
    Returns:
        差异行列表；空 = 行为等价。
    """
    out: list[str] = []
    # output（chat 为 None → 跳过）
    g_out, a_out = golden.get("output"), actual.get("output")
    if g_out is not None or a_out is not None:
        _diff_values("output", g_out, a_out, out)
    # events
    diff_events(golden.get("events", []), actual.get("events", []), out)
    return out
