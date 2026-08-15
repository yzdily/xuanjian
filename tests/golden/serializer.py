"""序列化与规范化 — golden 落盘与回放比对共用同一形态。

设计原则（D6 P1-2「语义等价」diff 策略）：
  - golden 与回放两侧都先 ``serialize()``（= ``_to_jsonable`` + ``canonicalize``），
    保证比对的是同一规范化形态，而非裸对象。
  - 易变字段（时间戳 / UUID / JWT / 长 hex token / 日志时分秒）替换为占位符，
    使「一次录制 → 长期回放」稳定可比；**不**归一化裸业务数字 ID（如 /users/123），
    避免掩盖真实差异。归一化规则集中在本文件，发现新易变模式时只改这里。
"""
from __future__ import annotations

import dataclasses
import datetime
import json
import re
from typing import Any

SCHEMA_VERSION = 1

# ------------------------------------------------------------------
# 易变字段规范化（保守：只处理「几乎一定是环境噪声」的子串）
# ------------------------------------------------------------------
_TS_ISO = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_TS_HMS = re.compile(r"(?<!\d)\d{2}:\d{2}:\d{2}(?!\d)")  # 日志时分秒 09:15:33
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# JWT / 三段点分 token：eyJ... . xxx . yyy
_DOT_TOKEN = re.compile(r"\b[0-9a-fA-F]{6,}\.[0-9a-fA-F]{6,}\.[0-9A-Za-z_-]{6,}\b")
# 长 hex token（>=32：sha256/随机串；不动 16 位以免误伤真实 hex ID）
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def _normalize_str(s: str) -> str:
    if not isinstance(s, str):
        return s
    s = _TS_ISO.sub("<TS>", s)
    s = _UUID.sub("<UUID>", s)
    s = _DOT_TOKEN.sub("<TOKEN>", s)
    s = _TS_HMS.sub("<TS>", s)
    s = _HEX_TOKEN.sub("<TOKEN>", s)
    return s


def canonicalize(obj: Any) -> Any:
    """递归规范化：dict/list/set/str 中的易变值 → 占位符。非易变值原样返回。"""
    if isinstance(obj, str):
        return _normalize_str(obj)
    if isinstance(obj, dict):
        return {k: canonicalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [canonicalize(v) for v in obj]
    if isinstance(obj, set):
        return sorted((canonicalize(v) for v in obj), key=lambda x: json.dumps(x, ensure_ascii=False, default=str))
    return obj


def _to_jsonable(obj: Any) -> Any:
    """转为 JSON 安全结构：dataclass / datetime / set / pydantic / 其它。"""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, set):
        return sorted(
            (_to_jsonable(v) for v in obj),
            key=lambda x: json.dumps(x, ensure_ascii=False, default=str),
        )
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return f"<bytes len={len(obj)}>"
    if hasattr(obj, "model_dump"):  # pydantic v2
        try:
            return _to_jsonable(obj.model_dump())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {
            str(k): _to_jsonable(v)
            for k, v in vars(obj).items()
            if not str(k).startswith("_")
        }
    return f"<unserializable:{type(obj).__name__}>"


def serialize(obj: Any) -> Any:
    """``_to_jsonable`` + ``canonicalize``。golden 落盘与回放比对都走这一步。"""
    return canonicalize(_to_jsonable(obj))


def parse_chat_event(yielded: Any) -> dict:
    """``chat()`` yield 的是 ``_event()`` 返回的字符串；解析为 event-dict。

    支持两种形态：
      - 裸 JSON：``{"type":"system","data":"..."}``
      - SSE 帧：``data: {"type":"system","data":"..."}``（chat_loop 实际产出形态）

    非字符串 / 非 JSON / 非对象 → 包装成统一结构，保证回放比对不丢帧。
    """
    if not isinstance(yielded, str):
        return {"type": "nonstr", "data": _to_jsonable(yielded)}
    s = yielded.strip()
    # SSE 帧：剥离 ``data: `` 前缀（chat_loop._event 的实际输出形态）
    if s.lower().startswith("data:"):
        s = s[5:].lstrip()
    if not s.startswith("{"):
        return {"type": "text", "data": s}
    try:
        ev = json.loads(s)
    except Exception:
        return {"type": "unparseable", "data": s}
    if isinstance(ev, dict):
        return ev
    return {"type": "raw", "data": _to_jsonable(ev)}
