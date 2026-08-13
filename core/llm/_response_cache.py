"""LLM 响应缓存（LRU + TTL），线程安全。

从 core.llm 拆分而来。
patch 兼容：time.time() 经由 core.llm 包命名空间访问
（tests/test_llm.py: patch("core.llm.time.time")）。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

import core.llm as _llm

if TYPE_CHECKING:
    from core.llm._config import Message

# ============================================================
# ★ LLM 响应缓存 — 避免测试中相同请求重复消耗 API
# ============================================================
# 测试场景中常出现相同 messages+tools 的重复调用（如重试、多 worker
# 并行测试相同 feature）。缓存命中时直接返回上次结果，不消耗 API 额度。
# 缓存 Key 基于 messages 内容 + model + tools 定向 hash，TTL 默认 300s。
# 可通过环境变量 XUANJIAN_LLM_CACHE_TTL 控制（0=禁用）。

class LLMResponseCache:
    """线程安全的 LLM 响应缓存（LRU + TTL）。"""

    def __init__(self, max_size: int = 128, ttl: float = 300.0):
        self._store: OrderedDict[str, tuple[float, Message]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size
        self._ttl = ttl
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(messages: list[Message], model: str, tools: list[dict] | None,
                  temperature: float, max_tokens: int) -> str:
        """根据请求参数生成缓存 key（SHA256 摘要）。"""
        parts = [model, f"{temperature:.2f}", str(max_tokens)]
        for m in messages:
            parts.append(f"{m.role}|{m.content or ''}|{m.tool_call_id or ''}")
            if m.tool_calls:
                parts.append(json.dumps(m.tool_calls, ensure_ascii=False, sort_keys=True))
        if tools:
            parts.append(json.dumps(tools, ensure_ascii=False, sort_keys=True))
        raw = "\x00".join(parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, messages: list[Message], model: str, tools: list[dict] | None,
            temperature: float, max_tokens: int) -> Message | None:
        if self._ttl <= 0:
            return None
        key = self._make_key(messages, model, tools, temperature, max_tokens)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            ts, cached_msg = entry
            if _llm.time.time() - ts > self._ttl:
                del self._store[key]
                self._misses += 1
                return None
            # LRU: move to end
            self._store.move_to_end(key)
            self._hits += 1
            return cached_msg

    def put(self, messages: list[Message], model: str, tools: list[dict] | None,
            temperature: float, max_tokens: int, response: Message) -> None:
        if self._ttl <= 0:
            return
        key = self._make_key(messages, model, tools, temperature, max_tokens)
        with self._lock:
            self._store[key] = (_llm.time.time(), response)
            self._store.move_to_end(key)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses,
                    "size": len(self._store), "ttl": self._ttl}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0


# 全局缓存实例
_response_cache = LLMResponseCache(
    max_size=int(os.getenv("XUANJIAN_LLM_CACHE_MAX_SIZE", "128")),
    ttl=float(os.getenv("XUANJIAN_LLM_CACHE_TTL", "300")),
)
