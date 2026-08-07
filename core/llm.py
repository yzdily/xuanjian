"""
LLM 客户端 — 统一封装 OpenAI 兼容协议 + Anthropic 原生协议
支持通过 .env 配置 1~3 个模型，运行时按名称切换。

兼容 DeepSeek V4 的 reasoning_content（思考模式）。
"""

from __future__ import annotations

import os
import base64
import hashlib
import hmac
import json
import re
import time
import threading
import contextvars
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

from dotenv import load_dotenv

from core.log import get_logger

log = get_logger("llm")

load_dotenv()

_current_task_id: contextvars.ContextVar[str] = contextvars.ContextVar("xuanjian_current_task_id", default="")


def set_current_task(task_id: str):
    return _current_task_id.set(task_id or "")


def reset_current_task(token) -> None:
    _current_task_id.reset(token)


def get_current_task() -> str:
    return _current_task_id.get() or ""


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
            if time.time() - ts > self._ttl:
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
            self._store[key] = (time.time(), response)
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


# ============================================================
# ★ Token 估算工具 — 无需 tiktoken，基于字符的启发式估算
# ============================================================
# 用于：
# 1. ContextManager.should_compress() 的 token 触发条件
# 2. LLMClient.chat() 发送前的 context 超限预检
#
# 启发式规则（与 tiktoken 误差通常 ±20%，足够用于预检和压缩触发）：
# - CJK 字符（中日韩）：每个约 1 token
# - ASCII/拉丁字符：每 4 个字符约 1 token

# 常见模型的上下文窗口大小（tokens），用于预检
_MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    # DeepSeek
    "deepseek-chat": 65536,
    "deepseek-coder": 16384,
    "deepseek-reasoner": 65536,
    "deepseek-r1": 65536,
    # Moonshot / Kimi
    "moonshot-v1-8k": 8192,
    "moonshot-v1-32k": 32768,
    "moonshot-v1-128k": 131072,
    "kimi": 131072,
    "kimi-k2": 131072,
    "kimi2": 131072,
    # Qwen
    "qwen2.5-coder": 32768,
    "qwen2.5": 32768,
    "qwen-plus": 131072,
    "qwen-max": 32768,
    "qwen-turbo": 8192,
    # OpenAI
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000,
    "gpt-4": 8192,
    "gpt-3.5-turbo": 16384,
    # Anthropic
    "claude-3-5-sonnet": 200000,
    "claude-3-5-haiku": 200000,
    "claude-3-opus": 200000,
    "claude-3-sonnet": 200000,
    "claude-3-haiku": 200000,
    # Meta
    "llama3": 8192,
    "llama3.1": 131072,
    # GLM
    "glm-4": 131072,
    "glm-4-flash": 131072,
}

# 默认上下文窗口（未匹配到已知模型时使用）
_DEFAULT_CONTEXT_WINDOW = int(os.getenv("XUANJIAN_LLM_DEFAULT_CONTEXT_WINDOW", "32768"))

# 预检安全系数：估算 token * 此系数 < 上下文窗口才放行
# 留出余量应对估算偏差 + max_tokens 预留
_CONTEXT_PRECHECK_SAFETY = 0.85


def get_model_context_window(model: str) -> int:
    """根据模型名推断上下文窗口大小（tokens）。

    先精确匹配，再模糊匹配（模型名包含 key），最后回退到默认值。
    """
    if not model:
        return _DEFAULT_CONTEXT_WINDOW
    model_lower = model.lower()
    # 精确匹配
    if model_lower in _MODEL_CONTEXT_WINDOWS:
        return _MODEL_CONTEXT_WINDOWS[model_lower]
    # 模糊匹配：模型名包含已知 key
    for key, window in _MODEL_CONTEXT_WINDOWS.items():
        if key in model_lower:
            return window
    return _DEFAULT_CONTEXT_WINDOW


def estimate_text_tokens(text: str) -> int:
    """估算文本的 token 数（无需 tokenizer）。

    启发式规则：
    - CJK 字符（中日韩统一表意文字、平假名、片假名、全角符号）：每个约 1 token
    - 其他字符（ASCII/拉丁/标点/空白）：每 4 个字符约 1 token

    对于混合中英文内容，误差通常在 ±20% 以内，足够用于预检和压缩触发。
    """
    if not text:
        return 0
    cjk_count = 0
    other_count = 0
    for ch in text:
        cp = ord(ch)
        if (0x4E00 <= cp <= 0x9FFF    # CJK Unified Ideographs
            or 0x3400 <= cp <= 0x4DBF  # CJK Extension A
            or 0x3000 <= cp <= 0x30FF  # CJK Symbols + Hiragana + Katakana
            or 0xFF00 <= cp <= 0xFFEF  # Fullwidth Forms
            or 0xF900 <= cp <= 0xFAFF  # CJK Compatibility Ideographs
        ):
            cjk_count += 1
        else:
            other_count += 1
    return cjk_count + (other_count // 4)


def estimate_messages_tokens(messages: list["Message"], tools: list[dict] | None = None) -> int:
    """估算消息列表的总 token 数（含工具定义开销）。

    每条消息的 token 开销：
    - role 标记：约 4 tokens
    - content 文本：estimate_text_tokens(content)
    - tool_calls JSON：estimate_text_tokens(json.dumps(...))
    - tool_call_id：约 3 tokens
    - reasoning_content：estimate_text_tokens(reasoning_content)

    工具定义开销：每个工具约 80 tokens（函数名 + 参数 schema 的保守估算）
    """
    total = 0
    for m in messages:
        total += 4  # role 标记开销
        if m.content:
            total += estimate_text_tokens(m.content)
        if m.tool_calls:
            total += estimate_text_tokens(json.dumps(m.tool_calls, ensure_ascii=False))
            total += len(m.tool_calls) * 3  # 每个 tool_call_id 约 3 tokens
        if m.tool_call_id:
            total += 3
        if m.reasoning_content:
            total += estimate_text_tokens(m.reasoning_content)

    if tools:
        # 每个工具定义约 50-100 tokens，保守取 80
        total += len(tools) * 80

    return total


class ContextLimitError(Exception):
    """输入 token 数估算超过模型上下文窗口时抛出。

    调用方（chat_loop / worker_agent）捕获后应触发 compress() 再重试。
    """

    def __init__(self, estimated_tokens: int, context_window: int, model: str):
        self.estimated_tokens = estimated_tokens
        self.context_window = context_window
        self.model = model
        super().__init__(
            f"上下文超限: 估算 {estimated_tokens} tokens > 可用 "
            f"{context_window} (model={model})"
        )


# ============================================================
# ★ #15 API Key 加密存储
# ============================================================
# data/llm_configs.json 里的 api_key 之前是明文存储，一旦文件泄露会
# 直接暴露用户密钥。这里用 AES-256-GCM（优先 cryptography 库）或
# stdlib HMAC-SHA256 keystream + XOR 兜底，对 api_key 做对称加密。
# 密钥从 core.auth 的 _SECRET_KEY 派生，避免引入新秘密。
# 存储格式: "enc$v1$<base64(nonce + ciphertext)>"
# 兼容：未加密的明文 key 仍能读取（首次加载后 save 时自动加密落盘）。

_ENC_PREFIX = "enc$v1$"
_ENC_KEY_INFO = b"xuanjian-llm-apikey-encryption-v1"


def _get_encryption_key() -> bytes:
    """从 auth secret 派生 32 字节加密密钥（PBKDF2-SHA256）。"""
    try:
        # 复用 core/auth.py 持久化在 data/.auth_secret 的密钥
        from core import auth as _auth
        secret = _auth._SECRET_KEY or ""
        if not secret:
            # 极端情况：auth 尚未初始化（不应发生，但兜底）
            secret = _auth._load_or_generate_secret()
    except Exception:
        secret = ""
    if not secret:
        # 最终兜底：用进程内固定盐 + 环境变量（安全性弱于持久化密钥，但优于明文）
        secret = os.getenv("AUTH_SECRET_KEY", "xuanjian-default-llm-secret")
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"),
                                _ENC_KEY_INFO, 100000)[:32]


def _encrypt_api_key(plaintext: str) -> str:
    """加密 api_key。已经是加密格式或为空则原样返回。"""
    if not plaintext:
        return plaintext
    if plaintext.startswith(_ENC_PREFIX):
        return plaintext
    try:
        # 优先使用 cryptography 库的 AES-256-GCM（mitmproxy 已传递依赖）
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = _get_encryption_key()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return _ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")
    except ImportError:
        # 兜底：HMAC-SHA256 keystream + XOR（stdlib only）
        # 注意：不带认证标签，理论上可被篡改；但好过明文存储
        key = _get_encryption_key()
        nonce = os.urandom(16)
        ct = _xor_stream(plaintext.encode("utf-8"), key, nonce)
        return _ENC_PREFIX + "xor$" + base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_api_key(stored: str) -> str:
    """解密 api_key。非加密格式（明文）原样返回，保证向后兼容。"""
    if not stored or not stored.startswith(_ENC_PREFIX):
        return stored
    payload = stored[len(_ENC_PREFIX):]
    try:
        # AES-GCM 路径
        if not payload.startswith("xor$"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = _get_encryption_key()
            raw = base64.b64decode(payload)
            nonce, ct = raw[:12], raw[12:]
            return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
        # XOR 兜底路径
        raw = base64.b64decode(payload[4:])
        nonce, ct = raw[:16], raw[16:]
        return _xor_stream(ct, _get_encryption_key(), nonce).decode("utf-8")
    except Exception as e:
        log.warning("API Key 解密失败，按明文返回: %s", e)
        return stored


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """HMAC-SHA256 keystream 生成 + XOR（stdlib 加密兜底）。"""
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"),
                         hashlib.sha256).digest()
        chunk = data[len(out):len(out) + 32]
        out.extend(b ^ k for b, k in zip(chunk, block))
        counter += 1
    return bytes(out)


# ============================================================
# LLM 使用监控
# ============================================================

class LLMMonitor:
    """LLM 调用监控：记录每次调用的模型、tokens、耗时，持久化到文件。"""

    _instance = None
    _init_lock = __import__("threading").Lock()

    def __new__(cls):
        # ★ 线程安全的单例：用锁保护 __new__ + __init__ 的竞态
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        # ★ __init__ 也需要锁保护，防止 __new__ 返回对象后、__init__ 执行前被其他线程抢先。
        # 关键：所有属性初始化必须在锁内完成，且 _initialized 标志放在最后置位，
        # 否则其他线程会看到 _initialized=True 但属性尚未赋值，引发 AttributeError。
        with self._init_lock:
            if self._initialized:
                return
            self._log_file = Path("data/logs/llm_usage.jsonl")
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            # ★ 线程安全：record() 加锁防止多 worker 并发写入竞态
            self._record_lock = threading.Lock()
            # 内存统计（当前进程生命周期）
            self.total_calls = 0
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_seconds = 0.0
            self.by_model: dict[str, dict] = {}  # model → {calls, input, output, seconds}
            self.by_caller: dict[str, dict] = {}  # caller → {calls, input, output}
            self.by_task: dict[str, dict] = {}    # task_id → {calls, input, output, seconds, started_at}
            # ★ 缓冲写入：攒够 _BUFFER_FLUSH 条或 _BUFFER_TIMEOUT 秒后批量 flush，减少 IO 次数
            self._buffer: list[str] = []
            self._buffer_flush_count = int(os.getenv("XUANJIAN_LLM_LOG_BUFFER", "50"))
            self._buffer_flush_timeout = 5.0
            self._buffer_last_flush = time.time()
            # ★ 日志轮转：超过 _MAX_LOG_SIZE_MB 时自动截断保留最新记录
            self._max_log_size = int(os.getenv("XUANJIAN_LLM_LOG_MAX_MB", "50")) * 1024 * 1024
            # ★ 标志放最后：确保上面所有属性都已赋值后，才允许其他线程跳过初始化
            self._initialized = True

    def record(self, model: str, input_tokens: int, output_tokens: int,
               elapsed: float, caller: str = "", has_tools: bool = False,
               task_id: str = "", call_id: str = "",
               is_error: bool = False, error: str = "",
               req_summary: str = "", resp_summary: str = ""):
        """记录一次 LLM 调用。

        task_id 优先使用显式传入的；否则自动从 ContextVar 读取（推荐方式）。

        新增字段（用于详细监控页）：
        - call_id: 单次调用唯一 ID（建议 uuid4 hex 8 位）
        - is_error: 是否调用异常
        - error: 异常 message（截断后）
        - req_summary: 请求摘要（messages 最后一条 user/system 截断 200 字）
        - resp_summary: 响应摘要（resp.content 截断 200 字）
        """
        if not task_id:
            task_id = get_current_task()

        # ★ 线程安全：整个 record 加锁，防止多 worker 并发自增竞态
        with self._record_lock:
            self.total_calls += 1
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_seconds += elapsed

            # 按模型聚合
            if model not in self.by_model:
                self.by_model[model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0}
            m = self.by_model[model]
            m["calls"] += 1
            m["input_tokens"] += input_tokens
            m["output_tokens"] += output_tokens
            m["seconds"] += elapsed

            # 按调用方聚合
            if caller:
                if caller not in self.by_caller:
                    self.by_caller[caller] = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
                c = self.by_caller[caller]
                c["calls"] += 1
                c["input_tokens"] += input_tokens
                c["output_tokens"] += output_tokens

            # ★ 按 task_id 聚合（本次会话维度）
            if task_id:
                if task_id not in self.by_task:
                    self.by_task[task_id] = {
                        "calls": 0, "input_tokens": 0, "output_tokens": 0,
                        "seconds": 0.0, "started_at": time.time(),
                        "last_at": time.time(),
                    }
                t = self.by_task[task_id]
                t["calls"] += 1
                t["input_tokens"] += input_tokens
                t["output_tokens"] += output_tokens
                t["seconds"] += elapsed
                t["last_at"] = time.time()

            # 持久化（缓冲写入）
            record = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp": time.time(),
                "call_id": call_id or "",
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "elapsed_s": round(elapsed, 2),
                "caller": caller,
                "has_tools": has_tools,
                "task_id": task_id,
                "is_error": bool(is_error),
                "error": (error or "")[:500],
                "req_summary": (req_summary or "")[:300],
                "resp_summary": (resp_summary or "")[:300],
            }
            self._buffer.append(json.dumps(record, ensure_ascii=False))
            need_flush = (
                len(self._buffer) >= self._buffer_flush_count
                or (time.time() - self._buffer_last_flush) > self._buffer_flush_timeout
            )
            if need_flush:
                self._flush_buffer()

    def _flush_buffer(self):
        """将缓冲区写入文件并执行轮转检查。"""
        if not self._buffer:
            return
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write("\n".join(self._buffer) + "\n")
            self._buffer.clear()
            self._buffer_last_flush = time.time()
            # ★ 日志轮转：文件过大时保留最新一半
            try:
                if self._log_file.stat().st_size > self._max_log_size:
                    lines = self._log_file.read_text(encoding="utf-8").splitlines()
                    keep = lines[-(len(lines) // 2):]
                    self._log_file.write_text("\n".join(keep) + "\n", encoding="utf-8")
                    log.info("LLM 日志轮转: %s 从 %d 行截断为 %d 行",
                             self._log_file, len(lines), len(keep))
            except Exception:
                pass
        except Exception:
            pass

    def get_summary(self) -> dict:
        """获取当前统计摘要。"""
        return {
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_seconds": round(self.total_cost_seconds, 1),
            "by_model": self.by_model,
            "by_caller": self.by_caller,
            "by_task": self.by_task,
        }

    def get_task_summary(self, task_id: str) -> dict:
        """获取单个 task 的统计摘要。"""
        if not task_id or task_id not in self.by_task:
            return {
                "task_id": task_id,
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "total_tokens": 0, "seconds": 0.0,
            }
        t = self.by_task[task_id]
        return {
            "task_id": task_id,
            "calls": t["calls"],
            "input_tokens": t["input_tokens"],
            "output_tokens": t["output_tokens"],
            "total_tokens": t["input_tokens"] + t["output_tokens"],
            "seconds": round(t["seconds"], 1),
            "started_at": t.get("started_at", 0),
            "last_at": t.get("last_at", 0),
        }


# 全局单例
_monitor = LLMMonitor()


@dataclass
class LLMConfig:
    provider: str  # "openai" | "anthropic"
    base_url: str
    api_key: str
    model: str
    name: str = ""
    is_primary: bool = False


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    reasoning_content: str | None = None  # DeepSeek V4 思考内容


class _SseToolCall:
    __slots__ = ("id", "function_name", "function_arguments", "type")
    def __init__(self, call_id, name, arguments, ctype="function"):
        self.id = call_id or ""
        self.function_name = name or ""
        self.function_arguments = arguments or ""
        self.type = ctype or "function"
    @property
    def function(self):
        return _ObjectProxy({"name": self.function_name, "arguments": self.function_arguments})


class _ObjectProxy:
    """把 dict 包装成支持属性访问的容器，供 SSE 解析后的对象模拟 openai 返回结构。"""
    __slots__ = ("_d",)
    def __init__(self, d: dict):
        self._d = d
    def __getattr__(self, item):
        val = self._d.get(item)
        if isinstance(val, dict):
            return _ObjectProxy(val)
        return val


def _parse_sse_chat_payload(raw: Any) -> Any:
    """兼容第三方代理强制 SSE 流式返回：把 str 类型的响应解析为可用的响应对象。

    正常返回（非 str）原样透传。若是 SSE 文本（data: {...} 逐行），则聚合
    content / reasoning_content / tool_calls / usage 生成模拟对象，
    使调用方继续按 resp.choices[0].message 的 openai 结构取值而不报错。
    """
    if not isinstance(raw, str):
        return raw

    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_calls_acc: dict[int, dict] = {}
    finish_reason = None
    usage = None

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        # usage（部分实现放在单独的 data 行）
        if isinstance(obj, dict) and isinstance(obj.get("usage"), dict):
            usage = obj["usage"]
        choices = obj.get("choices") if isinstance(obj, dict) else None
        if not choices:
            continue
        choice = choices[0]
        delta = choice.get("delta") or {}
        if isinstance(delta, dict):
            content = delta.get("content")
            if isinstance(content, str):
                content_parts.append(content)
            reasoning = delta.get("reasoning_content")
            if isinstance(reasoning, str):
                reasoning_parts.append(reasoning)
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                acc = tool_calls_acc.setdefault(idx, {})
                if tc.get("id"):
                    acc["id"] = tc["id"]
                acc.setdefault("type", tc.get("type") or "function")
                fn = tc.get("function") or {}
                acc["name"] = acc.get("name", "") + (fn.get("name") or "")
                acc["arguments"] = acc.get("arguments", "") + (fn.get("arguments") or "")
        rc = choice.get("finish_reason")
        if rc:
            finish_reason = rc

    tool_calls = []
    for idx in sorted(tool_calls_acc):
        acc = tool_calls_acc[idx]
        tool_calls.append(_SseToolCall(acc.get("id"), acc.get("name", ""), acc.get("arguments", ""), acc.get("type", "function")))

    full_content = "".join(content_parts)
    full_reasoning = "".join(reasoning_parts)
    message = _ObjectProxy({
        "content": full_content,
        "reasoning_content": full_reasoning or None,
        "tool_calls": tool_calls,
    })
    choice_obj = _ObjectProxy({"message": message, "finish_reason": finish_reason or None})
    resp_obj = _ObjectProxy({
        "choices": [choice_obj],
        "usage": _ObjectProxy(usage) if usage else None,
    })
    # 降级解析是兼容第三方代理强制 SSE 流式返回的预期路径，成功解析不打 WARNING 避免刷屏；
    # 仅当解析结果为空（既无 content 也无 tool_calls）才视为异常并告警。
    total_chars = len(full_content) + len(full_reasoning)
    if total_chars == 0 and not tool_calls:
        log.warning("LLM 返回非标准 SSE 但降级解析为空（0 content、0 tool_calls），原始 %d 字节",
                    len(raw))
    else:
        log.debug("LLM 非标准 SSE 降级解析: %d 字符 content、%d 个 tool_calls",
                  total_chars, len(tool_calls))
    return resp_obj


def _is_placeholder_key(api_key: str) -> bool:
    """判断 API Key 是否为占位符（非真实 key）。"""
    placeholders = [
        "sk-your", "your-key", "your_", "YOUR_",
        "xxx", "XXXX",
        "sk-xxx", "sk-xxxx",
        "sk-ant-xxx",
    ]
    # 精确匹配纯 "sk-"（长度刚好 3 且以 sk- 开头）
    if api_key.strip() == "sk-":
        return True
    key_lower = api_key.lower().strip()
    if len(api_key) < 8:
        return True
    for p in placeholders:
        if p in key_lower:
            return True
    return False


# ============================================================
# ★ #10 模型名纠正：常见错误模型名/provider 别名映射表
# ============================================================
# data/llm_configs.json 里出现过的错误配置实例：
#   - "kimi2" / "kimi-k2" 实际应为 "kimi-k3"（Moonshot 最新模型名）
#   - "deepseek-v4-pro" 实际应为 "deepseek-chat" 或 "deepseek-reasoner"
#   - provider "kni" 实际应为 "openai"（Moonshot 兼容 OpenAI 协议）
# 启动时检测并自动纠正，避免每次调用都 400 / model not found。
_PROVIDER_ALIASES = {
    "kni": "openai",      # Moonshot Kimi 兼容 OpenAI 协议
    "moonshot": "openai",
    "kimi": "openai",
    "deepseek": "openai",  # DeepSeek 兼容 OpenAI 协议
    "glm": "openai",       # 智谱 GLM 兼容 OpenAI 协议
    "zhipu": "openai",
    "qwen": "openai",      # 通义千问兼容 OpenAI 协议
    "dashscope": "openai",
    "ollama": "openai",
}

# (base_url 子串, 错误模型名) → 正确模型名
# 用 base_url 限定以避免误伤同名但不同厂商的模型
# ★ Moonshot 官方 API (api.moonshot.cn) 有效模型名（2026-08 更新）：
#   kimi-k3（最新旗舰）/ kimi-k2.7-code / kimi-k2.7-code-highspeed /
#   kimi-k2.6（通用版）/ kimi-k2.5（2026-08-31 下线）/ moonshot-v1-8k/32k/128k
#   以下模型已于 2026-05-25 全部下线（EOL），不可使用：
#   kimi-k2-0905-preview / kimi-k2-0711-preview / kimi-k2-turbo-preview /
#   kimi-k2-thinking / kimi-k2-thinking-turbo / kimi-latest / kimi-thinking-preview
_MODEL_NAME_CORRECTIONS = {
    # Moonshot 常见错误/已下线模型名 → 最新稳定版 kimi-k3
    ("moonshot.cn", "kimi2"): "kimi-k3",
    ("moonshot.cn", "kimi"): "kimi-k3",
    ("moonshot.cn", "kimi-k2"): "kimi-k3",           # 无版本后缀，API 不识别
    ("moonshot.cn", "kimi-k1.5"): "moonshot-v1-8k",
    ("moonshot.cn", "kimi-latest"): "kimi-k3",        # 已于 2026-01 下线
    # ★ 已下线的 kimi-k2-* preview 系列 → kimi-k3
    ("moonshot.cn", "kimi-k2-0905-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-0711-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-turbo-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-thinking"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-thinking-turbo"): "kimi-k3",
    ("moonshot.cn", "kimi-thinking-preview"): "kimi-k3",
    # DeepSeek 错误模型名
    ("deepseek.com", "deepseek-v4-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v3"): "deepseek-chat",
    ("deepseek.com", "deepseek-v4"): "deepseek-chat",
    ("deepseek.com", "deepseek-v5-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v5"): "deepseek-chat",
    ("deepseek.com", "deepseek-v6-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v6"): "deepseek-chat",
    ("deepseek.com", "deepseek-reasoner-v4"): "deepseek-reasoner",
    ("deepseek.com", "deepseek-reasoner-v5"): "deepseek-reasoner",
    # 智谱 GLM
    ("bigmodel.cn", "glm-4-pro"): "glm-4-plus",
    ("bigmodel.cn", "glm-4.6"): "glm-4-plus",
}

# ★ 通用兜底正则：DeepSeek 不存在 v* / *-flash / *-pro 后缀的官方模型名，
# 凡 base_url 命中 deepseek.com 且模型名形如 deepseek-vN(-xxx)? 一律纠正为 deepseek-chat。
import re as _re
_DEEPSEEK_WRONG_PATTERN = _re.compile(r"^deepseek-v\d+(-.*)?$", _re.IGNORECASE)

# ★ Moonshot 已下线模型匹配：kimi-k2-*-preview / kimi-k2-thinking* 等
_KIMI_DEPRECATED_PATTERN = _re.compile(
    r"^kimi-k2-(0905|0711|turbo)-preview$|^kimi-k2-thinking(-turbo)?$|^kimi-thinking-preview$",
    _re.IGNORECASE,
)


def _normalize_provider(provider: str) -> str:
    """规范化 provider：把别名映射到 openai/anthropic 之一。"""
    p = (provider or "").strip().lower()
    return _PROVIDER_ALIASES.get(p, p)


def _normalize_model_name(base_url: str, model: str) -> str:
    """根据 base_url 纠正常见错误模型名。无匹配则原样返回。"""
    if not model:
        return model
    base_lower = (base_url or "").lower()
    for (url_sub, wrong), right in _MODEL_NAME_CORRECTIONS.items():
        if url_sub in base_lower and model == wrong:
            if right != wrong:
                log.warning("⚠️ 模型名纠正: %r → %r (base_url 命中 %r)；建议在 WebUI 修正原始配置", wrong, right, url_sub)
            return right
    # ★ 通用兜底：DeepSeek 仅 deepseek-chat / deepseek-reasoner 两个官方模型，
    # 任何 deepseek-vN 或 deepseek-*-pro/flash 都是错误名，统一纠正为 deepseek-chat。
    if "deepseek.com" in base_lower and _DEEPSEEK_WRONG_PATTERN.match(model):
        log.warning("⚠️ DeepSeek 模型名 %r 不存在，自动纠正为 'deepseek-chat'；请改用官方模型名", model)
        return "deepseek-chat"
    # ★ Moonshot 已下线模型自动纠正：kimi-k2-*-preview 等已 EOL，统一纠正为 kimi-k3
    if "moonshot.cn" in base_lower and _KIMI_DEPRECATED_PATTERN.match(model):
        log.warning("⚠️ Moonshot 模型 %r 已下线(EOL)，自动纠正为 'kimi-k3'；请改用最新模型名", model)
        return "kimi-k3"
    # ★ 全局兜底：不依赖 base_url 的常见错误模型名纠正
    _GLOBAL_MODEL_FIXES = {
        "kimi2": "kimi-k3",
        "kimi": "kimi-k3",
        "kimi-k2": "kimi-k3",                # 无版本后缀，API 不识别
        "kimi-k1.5": "moonshot-v1-8k",
        "kimi-latest": "kimi-k3",             # 已于 2026-01 下线
        "kimi-k2-0905-preview": "kimi-k3",   # 已于 2026-05 下线
        "kimi-k2-0711-preview": "kimi-k3",   # 已于 2026-05 下线
        "kimi-k2-turbo-preview": "kimi-k3",  # 已于 2026-05 下线
        "kimi-k2-thinking": "kimi-k3",       # 已于 2026-05 下线
        "kimi-k2-thinking-turbo": "kimi-k3", # 已于 2026-05 下线
        "kimi-thinking-preview": "kimi-k3",  # 已于 2025-11 下线
    }
    if model.lower() in _GLOBAL_MODEL_FIXES:
        fixed = _GLOBAL_MODEL_FIXES[model.lower()]
        if fixed != model:
            log.warning("⚠️ 模型名全局纠正: %r → %r；建议在 WebUI 修正原始配置", model, fixed)
        return fixed
    return model


# ============================================================
# ★ #15 统一的安全 JSON 解析（LLM 输出兜底）
# ============================================================
# 项目里曾存在 6 套重复实现，质量参差不齐；最健壮的 harm_validation/parser.py
# 没被其他模块复用。这里把它的核心逻辑提取上来作为统一入口，所有 LLM JSON
# 解析都应调用本函数，避免工具调用 args 解析失败被静默吞掉等隐患。

_THINK_BLOCK_PATTERN = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)


def _strip_think_blocks(text: str) -> str:
    """剥离 LLM 思考块（<think>...</think>）。"""
    if not text:
        return text
    cleaned = _THINK_BLOCK_PATTERN.sub("", text).strip()
    return cleaned if cleaned else text


def _strip_code_fences(text: str) -> str:
    """剥离 markdown 代码围栏 ```json ... ``` 或 ``` ... ```。"""
    if not text:
        return text
    m = re.search(r"```(?:json)?\s*\n?([\s\S]+?)\n?```", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return text


def _extract_balanced(text: str, open_ch: str, close_ch: str) -> str | None:
    """从 text 中提取第一个平衡的 JSON 片段（字符串感知，支持嵌套）。"""
    start = text.find(open_ch)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _fix_trailing_commas(text: str) -> str:
    """修复 JSON 尾随逗号：`,]` → `]`、`,}` → `}`。"""
    return re.sub(r",(\s*[\]\}])", r"\1", text)


def parse_llm_json(
    text: str,
    *,
    expect: type = dict,
    strip_think: bool = True,
    repair: bool = True,
) -> dict | list | None:
    """统一安全的 LLM JSON 解析。

    解析步骤：
    1. 剥离 <think>...</think> 思考块（DeepSeek/QwQ/R1 类模型）
    2. 剥离 markdown 代码围栏 ```json ... ```
    3. 直接 json.loads
    4. 平衡括号提取（字符串感知，支持嵌套）
    5. 尾逗号修复后重试
    全部失败返回 None。

    Args:
        expect: 期望的类型（dict 或 list）。若解析结果类型不匹配返回 None。
        strip_think: 是否剥离思考块。
        repair: 是否尝试尾逗号修复。
    """
    if not text or not text.strip():
        return None
    raw = text
    cleaned = _strip_think_blocks(raw) if strip_think else raw
    cleaned = _strip_code_fences(cleaned)

    # 3. 直接 parse
    try:
        result = json.loads(cleaned)
        if isinstance(result, expect):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # 4. 平衡括号提取
    open_ch, close_ch = ("{", "}") if expect is dict else ("[", "]")
    candidate = _extract_balanced(cleaned, open_ch, close_ch)
    if candidate:
        try:
            result = json.loads(candidate)
            if isinstance(result, expect):
                return result
        except (json.JSONDecodeError, ValueError):
            pass
        # 5. 尾逗号修复
        if repair:
            fixed = _fix_trailing_commas(candidate)
            try:
                result = json.loads(fixed)
                if isinstance(result, expect):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass

    # 兜底：从原文再试一次（可能 cleaned 被错误剥离）
    if cleaned != raw:
        candidate = _extract_balanced(raw, open_ch, close_ch)
        if candidate:
            try:
                result = json.loads(candidate)
                if isinstance(result, expect):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass
    return None


def parse_tool_call_arguments(raw: str, *, caller: str = "") -> tuple[dict, bool]:
    """解析工具调用 arguments 字符串，失败时返回 ({}, True) 并记日志。

    Returns:
        (args_dict, failed): failed=True 表示解析失败（已尝试修复仍失败）。
        调用方应把失败信息回填给 LLM 让它重发工具调用，而不是带着空 args 继续执行。
    """
    if not raw or not raw.strip():
        return {}, False
    try:
        args = json.loads(raw)
        if isinstance(args, dict):
            return args, False
        if isinstance(args, list):
            # 极少数 LLM 会把 dict 包成 list
            return (args[0] if args and isinstance(args[0], dict) else {}), False
        return {}, True
    except (json.JSONDecodeError, ValueError) as e:
        # 尝试用 parse_llm_json 修复
        repaired = parse_llm_json(raw, expect=dict)
        if repaired is not None:
            log.warning("[%s] tool_call arguments JSON 修复成功: %s", caller or "?", str(e)[:120])
            return repaired, False
        log.warning("[%s] tool_call arguments JSON 解析失败（已尝试修复）: %s; raw=%r",
                    caller or "?", e, raw[:200])
        return {}, True


def load_llm_configs() -> list[LLMConfig]:
    """加载 LLM 配置。
    优先级：data/llm_configs.json （WebUI 管理） > .env （冷启动种子）。
    首次启动时如果 json 不存在但 .env 有配置，会自动从 .env 导入并生成 json。

    ★ #15: 读取后对 api_key 解密（解密失败回退明文）
    ★ #10: 自动纠正错误的 provider/model 名
    """
    runtime_path = Path("data/llm_configs.json")

    # 1) 优先读 runtime json
    if runtime_path.exists():
        try:
            data = json.loads(runtime_path.read_text(encoding="utf-8"))
            configs = []
            needs_reencrypt = False
            for item in data.get("models", []):
                if not item.get("name") or not item.get("provider"):
                    continue
                raw_key = item.get("api_key", "")
                # 解密（未加密的明文 key 会原样返回，向后兼容）
                api_key = _decrypt_api_key(raw_key)
                if api_key != raw_key:
                    # 已解密成功，但落盘的密文可能用了 XOR 兜底过，
                    # 下次 save 会重新用 AES-GCM 加密
                    pass
                # 如果落盘的是明文（旧版本数据），需要标记重新加密落盘
                elif raw_key and not raw_key.startswith(_ENC_PREFIX):
                    needs_reencrypt = True
                # 纠正 provider / model 名
                provider = _normalize_provider(item["provider"])
                base_url = item.get("base_url", "")
                model = _normalize_model_name(base_url, item.get("model", ""))
                configs.append(LLMConfig(
                    provider=provider,
                    base_url=base_url,
                    api_key=api_key,
                    model=model,
                    name=item["name"],
                    is_primary=item.get("is_primary", False),
                ))
            if configs:
                # ★ 旧版数据存在明文 key，重新加密落盘（迁移）
                if needs_reencrypt:
                    log.info("检测到 llm_configs.json 存在明文 API Key，正在加密后重新落盘...")
                    try:
                        save_llm_configs(configs)
                    except Exception as ex:
                        log.warning("重新加密落盘失败（不影响本次加载）: %s", ex)
                return configs
        except Exception as ex:
            # 损坏时退回 .env
            print(f"[!] 解析 {runtime_path} 失败: {ex}，回退 .env")

    # 2) 从 .env 加载（首次启动或 json 不可用）
    configs = []
    for i in range(1, 11):
        prefix = f"LLM_{i}_"
        provider = os.getenv(f"{prefix}PROVIDER")
        api_key = os.getenv(f"{prefix}API_KEY", "")
        if not provider:
            continue
        # 跳过空 key 或占位符 key（sk-your-xxx / your-key / xxx / YOUR_*）
        if not api_key or _is_placeholder_key(api_key):
            print(f"  [!] 跳过 {prefix}API_KEY：key 为空或为占位符，请在 WebUI 中配置真实 key")
            continue
        # 纠正 provider / model 名
        norm_provider = _normalize_provider(provider)
        base_url = os.getenv(f"{prefix}BASE_URL", "")
        model = _normalize_model_name(base_url, os.getenv(f"{prefix}MODEL", ""))
        configs.append(
            LLMConfig(
                provider=norm_provider,
                base_url=base_url,
                api_key=api_key,
                model=model,
                name=f"llm_{i}",
            )
        )
    if not configs:
        print("[!] 未从 .env 读取到有效 LLM 配置，请在启动后的 WebUI 中添加模型")
        return configs  # 返回空列表，让用户通过 WebUI 配置

    # 3) 自动落盘为 runtime json（迁移，会触发加密）
    try:
        save_llm_configs(configs)
    except Exception as ex:
        print(f"[!] 自动迁移 .env 到 {runtime_path} 失败: {ex}")

    return configs


def save_llm_configs(configs: list[LLMConfig]) -> None:
    """保存配置到 data/llm_configs.json。

    ★ #15: api_key 加密后落盘，避免明文存储
    """
    runtime_path = Path("data/llm_configs.json")
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "models": [
            {
                "name": c.name,
                "provider": c.provider,
                "base_url": c.base_url,
                # ★ 加密落盘；LLMConfig 内存里仍是明文，供 LLMClient 使用
                "api_key": _encrypt_api_key(c.api_key),
                "model": c.model,
            }
            | ({"is_primary": True} if c.is_primary else {})
            for c in configs
        ]
    }
    # 原子写：先写临时文件再 rename
    tmp = runtime_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    # 设置文件权限仅当前用户可读（Unix）
    try:
        if os.name != "nt":
            os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(runtime_path)


def mask_api_key(key: str) -> str:
    """对 api_key 进行掩码，只保留后 4 位（用于 WebUI 展示）。"""
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}{'*' * 6}{key[-4:]}"


# ============================================================
# 2026-05-20 修复（C）：XML 风格 tool_calls 兼容解析
# ============================================================
# 部分模型（DeepSeek / GLM / Claude 旧风格）会把工具调用塞进 content 文本，
# 而非标准 OpenAI tool_calls 字段。形如：
#   <function_calls>
#     <invoke name="checklist_mark">
#       <parameter name="vuln_type">SQL注入</parameter>
#       <parameter name="result">vulnerable</parameter>
#     </invoke>
#     <invoke name="sitemap_get_coverage"></invoke>
#   </function_calls>
# 如果不解析这种格式，标准 OpenAI 路径拿到的 tool_calls 是空的，工具完全不执行，
# 用户追问"为什么没验证"就再也得不到响应。
# 实测真实案例：deepseek-v4-pro 在 packet 测试结束被用户追问时输出此格式。
import re as _re_xml


def _parse_xml_tool_calls(content: str) -> tuple[list[dict], str]:
    """从 content 文本里解析 XML 风格的 tool_calls。

    返回 (tool_calls_list, cleaned_content)。
    - tool_calls_list: 标准 OpenAI tool_calls dict 列表
    - cleaned_content: 去掉 XML 块后的纯文本 content（保留 LLM 的自然语言部分）

    支持多种变体：
      <function_calls>...</function_calls>
      <invoke name="x">...<parameter name="y">val</parameter></invoke>
      <invoke name="x">...</invoke>  （无 wrapper 也行）
      <tool_call>{"name":"x","arguments":{...}}</tool_call>  （部分 GLM 风格）
    """
    import uuid as _uuid
    if not content:
        return [], content

    tool_calls: list[dict] = []
    cleaned = content

    # 变体 1: <function_calls>...<invoke name="x">...<parameter>...</parameter></invoke>...</function_calls>
    # 也兼容没有 <function_calls> 包裹的裸 <invoke> 块
    invoke_pattern = _re_xml.compile(
        r'<invoke\s+name="([^"]+)"\s*>(.*?)</invoke>',
        _re_xml.DOTALL | _re_xml.IGNORECASE,
    )
    param_pattern = _re_xml.compile(
        r'<parameter\s+name="([^"]+)"\s*>(.*?)</parameter>',
        _re_xml.DOTALL | _re_xml.IGNORECASE,
    )

    for m in invoke_pattern.finditer(content):
        func_name = m.group(1).strip()
        inner = m.group(2)
        args = {}
        for pm in param_pattern.finditer(inner):
            k = pm.group(1).strip()
            v = pm.group(2).strip()
            # 尝试解析数字/bool/json
            if v.lower() in ("true", "false"):
                args[k] = v.lower() == "true"
            elif v.lstrip("-").isdigit():
                try:
                    args[k] = int(v)
                except Exception:
                    args[k] = v
            elif v.startswith(("{", "[")):
                try:
                    args[k] = json.loads(v)
                except Exception:
                    args[k] = v
            else:
                args[k] = v
        tool_calls.append({
            "id": f"call_xml_{_uuid.uuid4().hex[:12]}",
            "function": {
                "name": func_name,
                "arguments": json.dumps(args, ensure_ascii=False),
            },
        })

    # 变体 2: <tool_call>{"name": "...", "arguments": {...}}</tool_call>（部分 GLM/Qwen 风格）
    if not tool_calls:
        tc_pattern = _re_xml.compile(
            r'<tool_call>(.*?)</tool_call>',
            _re_xml.DOTALL | _re_xml.IGNORECASE,
        )
        for m in tc_pattern.finditer(content):
            try:
                obj = json.loads(m.group(1).strip())
                if isinstance(obj, dict) and obj.get("name"):
                    args = obj.get("arguments", {}) or {}
                    if isinstance(args, dict):
                        args_str = json.dumps(args, ensure_ascii=False)
                    else:
                        args_str = str(args)
                    tool_calls.append({
                        "id": f"call_xml_{_uuid.uuid4().hex[:12]}",
                        "function": {"name": obj["name"], "arguments": args_str},
                    })
            except Exception:
                continue

    # 清理 content：去掉 <function_calls>、<invoke>、<tool_call> XML 块
    if tool_calls:
        cleaned = _re_xml.sub(
            r'<function_calls>.*?</function_calls>', '', cleaned, flags=_re_xml.DOTALL | _re_xml.IGNORECASE
        )
        cleaned = _re_xml.sub(
            r'<invoke\s+name="[^"]+"\s*>.*?</invoke>', '', cleaned, flags=_re_xml.DOTALL | _re_xml.IGNORECASE
        )
        cleaned = _re_xml.sub(
            r'<tool_call>.*?</tool_call>', '', cleaned, flags=_re_xml.DOTALL | _re_xml.IGNORECASE
        )
        cleaned = cleaned.strip()

    return tool_calls, cleaned


class LLMClient:
    """统一的 LLM 调用客户端，屏蔽 OpenAI/Anthropic/DeepSeek 协议差异。"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None

    # ★ LLM API 调用超时（秒）：防止 API 挂起导致 Worker 永久卡死
    # 连接超时 15s + 读取超时 120s（兼容慢模型如 DeepSeek-R1 思考模式）
    _LLM_CONNECT_TIMEOUT = 15.0
    _LLM_READ_TIMEOUT = 120.0

    def _get_openai_client(self):
        if self._client is None:
            from openai import OpenAI
            # ★ max_retries=0：由 LLMClient.chat() 统一负责重试 + Retry-After 自适应退避，
            # 避免 SDK 内置重试（默认 2 次）与上层重试叠加导致重试次数失控。
            # ★ timeout：防止 API 挂起导致 Worker 永久卡死
            self._client = OpenAI(
                base_url=self.config.base_url,
                api_key=self.config.api_key,
                max_retries=0,
                timeout=self._LLM_READ_TIMEOUT,
            )
        return self._client

    def _get_anthropic_client(self):
        if self._client is None:
            from anthropic import Anthropic
            # ★ max_retries=0：同上，统一由 LLMClient.chat() 负责重试
            # ★ timeout：防止 API 挂起导致 Worker 永久卡死
            self._client = Anthropic(
                base_url=self.config.base_url,
                api_key=self.config.api_key,
                max_retries=0,
                timeout=self._LLM_READ_TIMEOUT,
            )
        return self._client

    @property
    def _is_deepseek(self) -> bool:
        return "deepseek" in self.config.base_url.lower() or "deepseek" in self.config.model.lower()

    # 可重试的错误特征：429 限速、5xx 服务端错误、超时、连接错误
    _RETRYABLE_ERROR_KEYWORDS = (
        "429", "rate limit", "rate_limit", "too many requests",
        "500", "502", "503", "504", "internal server error",
        "bad gateway", "service unavailable", "gateway timeout",
        "timeout", "timed out", "connection error", "connection reset",
        "connection refused", "connection aborted", "read timeout",
        "api_connection_error", "overloaded", "server_error",
    )

    # 不可重试的错误特征：401/403 鉴权、400 请求格式、内容策略
    _NON_RETRYABLE_KEYWORDS = (
        "401", "unauthorized", "403", "forbidden", "access denied",
        "accessdenied", "invalid_api_key", "invalid api key",
        "authentication", "400", "bad request", "invalid_request",
        "content_policy", "content filter", "safety",
    )

    def _is_retryable_error(self, exc: Exception) -> bool:
        """判断异常是否值得重试。"""
        err_str = str(exc).lower()
        # 鉴权/权限错误不重试（重试也没用，得换 key/模型）
        for kw in self._NON_RETRYABLE_KEYWORDS:
            if kw in err_str:
                return False
        # 限速/服务端错误/超时/连接错误可重试
        for kw in self._RETRYABLE_ERROR_KEYWORDS:
            if kw in err_str:
                return True
        # 默认不重试未知错误（避免对 bug 死循环重试）
        return False

    def _extract_retry_after(self, exc: Exception) -> float | None:
        """从异常对象提取 Retry-After / Retry-After-ms 响应头（秒）。

        OpenAI / Anthropic SDK 抛出的 APIStatusError / RateLimitError 都带
        response.headers，但 SDK 内部已消耗 2 次重试后抛出，这里需要自己读。
        无响应头或解析失败返回 None。
        """
        resp = getattr(exc, "response", None)
        if resp is None:
            return None
        headers = getattr(resp, "headers", None)
        if not headers:
            return None
        # 优先 Retry-After-ms（毫秒级精度）
        try:
            ms = headers.get("retry-after-ms") or headers.get("Retry-After-ms")
            if ms:
                return float(ms) / 1000.0
        except (ValueError, TypeError):
            pass
        # 标准 Retry-After（秒，或 HTTP 日期）
        try:
            ra = headers.get("retry-after") or headers.get("Retry-After")
            if not ra:
                return None
            # 数值秒
            try:
                return float(ra)
            except ValueError:
                pass
            # HTTP-date 格式（RFC 7231）
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            dt = parsedate_to_datetime(ra)
            if dt is not None:
                now = datetime.now(timezone.utc)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                delta = (dt - now).total_seconds()
                if delta > 0:
                    return delta
        except Exception:
            pass
        return None

    def _check_task_budget(self, max_tokens: int, caller: str = "") -> None:
        """按任务限制 LLM 调用量，防止生产测试中无限消耗 API。"""
        task_id = get_current_task()
        if not task_id:
            return
        try:
            max_calls = int(os.getenv("XUANJIAN_LLM_MAX_CALLS_PER_TASK", "0") or "0")
        except (TypeError, ValueError):
            max_calls = 0
        try:
            max_task_tokens = int(os.getenv("XUANJIAN_LLM_MAX_TOKENS_PER_TASK", "0") or "0")
        except (TypeError, ValueError):
            max_task_tokens = 0
        if max_calls <= 0 and max_task_tokens <= 0:
            return

        summary = _monitor.get_task_summary(task_id)
        if max_calls > 0 and summary.get("calls", 0) >= max_calls:
            raise RuntimeError(
                f"LLM 任务预算已用尽: task={task_id}, calls={summary.get('calls', 0)}/{max_calls}, caller={caller or '?'}"
            )
        if max_task_tokens > 0:
            used = int(summary.get("total_tokens", 0) or 0)
            reserved = max(0, int(max_tokens or 0))
            if used + reserved > max_task_tokens:
                raise RuntimeError(
                    f"LLM Token 预算不足: task={task_id}, used={used}, reserve={reserved}, limit={max_task_tokens}, caller={caller or '?'}"
                )

    # ★ 已知不支持 temperature 参数的模型/平台（避免先失败再重试浪费一次 API 调用）
    _NO_TEMPERATURE_MODELS = {
        "deepseek-reasoner",  # DeepSeek 思考模式
        "o1", "o1-preview", "o1-mini", "o3", "o3-mini",  # OpenAI o 系列
        "o4-mini",
    }
    _NO_TEMPERATURE_URLS = (
        "deepseek.com",  # DeepSeek 全系思考模型
    )

    def _supports_temperature(self) -> bool:
        """预检当前模型是否支持 temperature 参数，避免浪费一次 API 调用。"""
        model_lower = self.config.model.lower()
        if model_lower in self._NO_TEMPERATURE_MODELS:
            return False
        base_lower = self.config.base_url.lower()
        # DeepSeek 的 reasoner 模型不支持 temperature
        if "deepseek.com" in base_lower and "reasoner" in model_lower:
            return False
        return True

    def chat(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        caller: str = "",
        max_retries: int = 3,
        use_cache: bool = True,
    ) -> Message:
        """调用 LLM，带指数退避重试。

        可重试错误（429/5xx/超时/连接错误）会自动重试 max_retries 次，
        每次间隔指数退避（1s, 2s, 4s）+ 随机抖动。
        不可重试错误（401/403/400）直接抛出，由上层 fallback 逻辑处理。

        ★ use_cache=True 时优先查响应缓存，命中则直接返回不消耗 API。
          测试场景中相同请求可复用结果，大幅减少 API 消耗。
        ★ 上层已自带重试时传 max_retries=0 可避免三层重试叠加。
        ★ Token 预检：缓存未命中时，发送前估算输入 token，超限抛
          ContextLimitError（不可重试），由上层捕获后触发 compress() 再重试。
        """
        self._check_task_budget(max_tokens=max_tokens, caller=caller)

        # ★ 响应缓存：相同请求直接返回上次结果，不消耗 API
        if use_cache:
            cached = _response_cache.get(messages, self.config.model, tools, temperature, max_tokens)
            if cached is not None:
                log.debug("[%s] LLM 缓存命中，跳过 API 调用", caller or "?")
                return cached

        # ★ Token 预检：缓存未命中 → 即将发起 API 调用，先估算输入 token
        # 避免浪费一次 API 往返（API 返回 400 context_length_exceeded）
        # 超限时抛 ContextLimitError，调用方应捕获后 compress() 再重试
        estimated_input = estimate_messages_tokens(messages, tools)
        context_window = get_model_context_window(self.config.model)
        available_for_input = int(context_window * _CONTEXT_PRECHECK_SAFETY) - max_tokens
        if estimated_input > available_for_input:
            log.warning(
                "[%s] Token 预检超限: 估算 %d tokens > 可用 %d (window=%d, model=%s)",
                caller or "?", estimated_input, available_for_input,
                context_window, self.config.model,
            )
            raise ContextLimitError(estimated_input, context_window, self.config.model)

        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                if self.config.provider == "anthropic":
                    resp = self._chat_anthropic(messages, tools, temperature, max_tokens, caller)
                else:
                    resp = self._chat_openai(messages, tools, temperature, max_tokens, caller)
                # ★ 成功调用写入缓存，后续相同请求可复用
                if use_cache:
                    _response_cache.put(messages, self.config.model, tools, temperature, max_tokens, resp)
                return resp
            except Exception as exc:
                last_exc = exc
                # 最后一次尝试不再等待
                if attempt >= max_retries:
                    raise
                # 不可重试错误直接抛出（交给上层 fallback）
                if not self._is_retryable_error(exc):
                    raise
                # ★ 自适应退避：取 max(Retry-After, 指数退避)，
                # 服务端明确告知冷却时间时以服务端为准，避免窗口内反复撞限流。
                import random
                exp_backoff = (2 ** attempt) + random.uniform(0, 0.5)
                retry_after = self._extract_retry_after(exc)
                if retry_after is not None:
                    # 上限 60s，防止异常 Retry-After 把任务挂死
                    backoff = min(max(retry_after, exp_backoff), 60.0)
                    log.warning(
                        "LLM 调用失败（第 %d/%d 次），服务端 Retry-After=%.1fs，%0.1fs 后重试: %s",
                        attempt + 1, max_retries, retry_after, backoff, str(exc)[:200],
                    )
                else:
                    backoff = exp_backoff
                    log.warning(
                        "LLM 调用失败（第 %d/%d 次），%0.1fs 后重试: %s",
                        attempt + 1, max_retries, backoff, str(exc)[:200],
                    )
                time.sleep(backoff)
        # 理论上不会走到这里
        raise last_exc  # type: ignore[misc]

    def _chat_openai(self, messages, tools, temperature, max_tokens, caller="") -> Message:
        import uuid
        client = self._get_openai_client()
        t0 = time.time()
        call_id = uuid.uuid4().hex[:12]

        # 提取请求摘要（最后一条 user/system 的 content）
        req_summary = ""
        for m in reversed(messages):
            if m.role in ("user", "system") and m.content:
                req_summary = m.content[:300]
                break

        api_messages = []
        for m in messages:
            msg_dict: dict[str, Any] = {"role": m.role}

            # DeepSeek 思考模式：assistant 消息需要回传 reasoning_content
            if m.role == "assistant" and m.reasoning_content and self._is_deepseek:
                msg_dict["content"] = m.content or ""
                msg_dict["reasoning_content"] = m.reasoning_content
            else:
                msg_dict["content"] = m.content

            # assistant 的 tool_calls
            if m.role == "assistant" and m.tool_calls:
                msg_dict["tool_calls"] = [
                    {"id": tc["id"], "type": "function", "function": tc["function"]}
                    for tc in m.tool_calls
                ]
                # 有 tool_calls 时 content 可以为 None（OpenAI 标准）
                # 但 Ollama 等本地模型不接受 null content
                is_local = "localhost" in self.config.base_url or "127.0.0.1" in self.config.base_url
                if not m.content:
                    msg_dict["content"] = "" if is_local else None

            # tool 消息必须带 tool_call_id
            if m.role == "tool" and m.tool_call_id:
                msg_dict["tool_call_id"] = m.tool_call_id

            api_messages.append(msg_dict)

        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": api_messages,
            "max_tokens": max_tokens,
        }

        # ★ temperature 预检：已知不支持 temperature 的模型直接跳过，避免浪费一次 API 调用
        # 旧逻辑：先带 temperature 调一次 → 报错 → 去掉 temperature 再调一次 = 2 次 API 消耗
        # 新逻辑：预检命中则直接不带 temperature = 1 次 API 消耗
        if not self._is_deepseek and self._supports_temperature():
            kwargs["temperature"] = temperature

        # Ollama 本地模型需要指定上下文窗口（默认 4096 不够用）
        is_local = "localhost" in self.config.base_url or "127.0.0.1" in self.config.base_url
        if is_local:
            kwargs["extra_body"] = {"options": {"num_ctx": 32768}}

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as ex:
            elapsed = time.time() - t0
            err_str = str(ex).lower()
            # 某些模型不支持自定义 temperature，自动降级重试
            if "temperature" in err_str and "temperature" in kwargs:
                del kwargs["temperature"]
                try:
                    resp = client.chat.completions.create(**kwargs)
                except Exception as ex2:
                    elapsed2 = time.time() - t0
                    _monitor.record(
                        model=self.config.model, input_tokens=0, output_tokens=0,
                        elapsed=elapsed2, caller=caller, has_tools=bool(tools),
                        call_id=call_id, is_error=True,
                        error=f"{type(ex2).__name__}: {ex2}",
                        req_summary=req_summary, resp_summary="",
                    )
                    raise
            else:
                _monitor.record(
                    model=self.config.model, input_tokens=0, output_tokens=0,
                    elapsed=elapsed, caller=caller, has_tools=bool(tools),
                    call_id=call_id, is_error=True,
                    error=f"{type(ex).__name__}: {ex}",
                    req_summary=req_summary, resp_summary="",
                )
                raise

        elapsed = time.time() - t0
        resp = _parse_sse_chat_payload(resp)
        choice = resp.choices[0]
        msg = choice.message

        # 提取响应摘要
        resp_summary = (msg.content or "")[:300]
        if not resp_summary and msg.tool_calls:
            tc_names = [tc.function.name for tc in msg.tool_calls if tc.function]
            resp_summary = f"[tool_calls: {', '.join(tc_names)}]"

        # ★ 监控埋点
        usage = getattr(resp, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0
        _monitor.record(
            model=self.config.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            elapsed=elapsed,
            caller=caller,
            has_tools=bool(tools),
            call_id=call_id,
            is_error=False,
            req_summary=req_summary,
            resp_summary=resp_summary,
        )

        # 提取 tool_calls
        tool_calls = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                })

        # 提取 reasoning_content（DeepSeek V4 特有）
        reasoning = getattr(msg, "reasoning_content", None) or None

        # ★ 2026-05-20 修复（C）：DeepSeek/Claude-style XML 函数调用降级解析
        # 部分模型（尤其 DeepSeek、glm、claude 旧风格）会把工具调用塞进 content 文本，
        # 形如：<function_calls><invoke name="xxx"><parameter name="y">val</parameter></invoke></function_calls>
        # 标准 OpenAI 解析拿不到这个，导致后续工具完全没执行，任务卡死。
        # 这里做一次降级：tool_calls 为空但 content 命中 XML 模式 → 解析成标准格式 + 清理 content。
        content_str = msg.content or ""
        if not tool_calls and content_str and ("<function_calls>" in content_str or "<invoke " in content_str
                                                or "<invoke name=" in content_str):
            try:
                parsed_calls, cleaned_content = _parse_xml_tool_calls(content_str)
                if parsed_calls:
                    tool_calls = parsed_calls
                    content_str = cleaned_content
                    log.warning("LLM 返回 XML 风格 tool_calls (非标准)，已降级解析 %d 个调用", len(parsed_calls))
            except Exception as _e:
                log.warning("XML tool_calls 降级解析失败: %s", _e)

        return Message(
            role="assistant",
            content=content_str,
            tool_calls=tool_calls,
            reasoning_content=reasoning,
        )

    def _chat_anthropic(self, messages, tools, temperature, max_tokens, caller="") -> Message:
        import uuid
        client = self._get_anthropic_client()
        t0 = time.time()
        call_id = uuid.uuid4().hex[:12]

        # 提取请求摘要
        req_summary = ""
        for m in reversed(messages):
            if m.role in ("user", "system") and m.content:
                req_summary = m.content[:300]
                break

        system_text = ""
        api_messages = []
        for m in messages:
            if m.role == "system":
                system_text += m.content + "\n"
            else:
                api_messages.append({"role": m.role, "content": m.content})

        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_text:
            kwargs["system"] = system_text.strip()
        if tools:
            kwargs["tools"] = self._convert_tools_to_anthropic(tools)

        try:
            resp = client.messages.create(**kwargs)
        except Exception as ex:
            elapsed = time.time() - t0
            _monitor.record(
                model=self.config.model,
                input_tokens=0,
                output_tokens=0,
                elapsed=elapsed,
                caller=caller,
                has_tools=bool(tools),
                call_id=call_id,
                is_error=True,
                error=f"{type(ex).__name__}: {ex}",
                req_summary=req_summary,
                resp_summary="",
            )
            raise

        elapsed = time.time() - t0

        content_text = ""
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "function": {"name": block.name, "arguments": json.dumps(block.input)},
                })

        # 响应摘要
        resp_summary = content_text[:300]
        if not resp_summary and tool_calls:
            tc_names = [tc["function"]["name"] for tc in tool_calls]
            resp_summary = f"[tool_calls: {', '.join(tc_names)}]"

        # ★ 监控埋点
        usage = getattr(resp, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        _monitor.record(
            model=self.config.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            elapsed=elapsed,
            caller=caller,
            has_tools=bool(tools),
            call_id=call_id,
            is_error=False,
            req_summary=req_summary,
            resp_summary=resp_summary,
        )

        return Message(role="assistant", content=content_text, tool_calls=tool_calls)

    @staticmethod
    def _convert_tools_to_anthropic(openai_tools: list[dict]) -> list[dict]:
        result = []
        for t in openai_tools:
            func = t.get("function", t)
            result.append({
                "name": func["name"],
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {}),
            })
        return result


class LLMPool:
    def __init__(self):
        self.configs = load_llm_configs()
        self.clients = {cfg.name: LLMClient(cfg) for cfg in self.configs}
        # 无有效配置时创建占位项目，提示用户在 WebUI 中配置
        if not self.configs:
            placeholder = LLMConfig(
                name="_unconfigured",
                provider="",
                base_url="",
                api_key="",
                model="(请先在 WebUI 设置中添加模型)",
            )
            self.configs = [placeholder]
            self.clients = {}

    @property
    def primary(self) -> LLMClient | None:
        # ★ 未配置任何 LLM 时返回 None，让 fast/无 LLM 模式可以创建会话；
        # 真正需要 LLM 的代码路径自行检查 None 并给出友好提示。
        if not self.clients:
            return None
        # 返回 is_primary=True 的模型；没有则用第一个
        for cfg in self.configs:
            if cfg.is_primary and cfg.name in self.clients:
                return self.clients[cfg.name]
        return self.clients[self.configs[0].name]

    def get(self, name: str) -> LLMClient:
        return self.clients[name]

    def all(self) -> list[LLMClient]:
        return list(self.clients.values())

    def chat_with_fallback(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        caller: str = "",
        exclude: set[str] | None = None,
        use_cache: bool = True,
    ) -> tuple[Message, str]:
        """带故障转移的 LLM 调用：主模型失败时自动切换备用模型。

        Returns:
            (response_message, model_name_used)
        Raises:
            RuntimeError: 所有模型都失败时抛出
        """
        exclude = exclude or set()
        # 候选顺序：primary 优先，然后其余按配置顺序
        candidates: list[LLMClient] = []
        primary = self.primary  # 未配置时为 None
        if primary is not None and primary.config.name not in exclude:
            candidates.append(primary)
        for client in self.clients.values():
            if client not in candidates and client.config.name not in exclude:
                candidates.append(client)

        if not candidates:
            raise RuntimeError("未配置任何可用的 LLM 模型")

        errors: list[str] = []
        for client in candidates:
            try:
                resp = client.chat(
                    messages=messages, tools=tools,
                    temperature=temperature, max_tokens=max_tokens,
                    caller=caller, use_cache=use_cache,
                )
                return resp, client.config.name
            except Exception as exc:
                err_msg = f"[{client.config.name}] {type(exc).__name__}: {str(exc)[:200]}"
                errors.append(err_msg)
                log.warning("LLM fallback: 模型 %s 失败，尝试下一个: %s",
                            client.config.name, str(exc)[:150])
                # 把这个模型加入 exclude，避免在同一轮里重复尝试
                exclude.add(client.config.name)

        all_errors = "; ".join(errors)
        raise RuntimeError(f"所有 LLM 模型均调用失败: {all_errors}")

    @property
    def count(self) -> int:
        return len(self.clients)

    # ============== 运行时管理（供 WebUI 使用）==============

    def reload(self) -> dict:
        """从 data/llm_configs.json 重新加载配置，并热更新现有 clients。
        策略：
        - 同名 client 复用对象，只更新其 config（已被 session 引用的连接不断链）
        - 新增 name：创建新 client
        - 消失 name：从 self.clients 删除（如果还有 session 持有引用，对象本身仍有效）
        返回 {added, updated, removed}。
        """
        new_configs = load_llm_configs()
        # 无有效配置时用占位符，提示用户配置
        if not new_configs:
            placeholder = LLMConfig(
                name="_unconfigured",
                provider="",
                base_url="",
                api_key="",
                model="(请先在 WebUI 设置中添加模型)",
            )
            new_configs = [placeholder]
        new_names = {c.name for c in new_configs}

        added, updated, removed = [], [], []

        # 更新或新增
        for cfg in new_configs:
            if cfg.name in self.clients:
                old_cfg = self.clients[cfg.name].config
                if (old_cfg.provider != cfg.provider or old_cfg.base_url != cfg.base_url
                        or old_cfg.api_key != cfg.api_key or old_cfg.model != cfg.model):
                    # 重置内部底层 client（base_url/key 变了必须重建）
                    self.clients[cfg.name].config = cfg
                    self.clients[cfg.name]._client = None
                    updated.append(cfg.name)
            else:
                self.clients[cfg.name] = LLMClient(cfg)
                added.append(cfg.name)

        # 删除
        for name in list(self.clients.keys()):
            if name not in new_names:
                del self.clients[name]
                removed.append(name)

        self.configs = new_configs
        return {"added": added, "updated": updated, "removed": removed,
                "total": len(self.configs)}

    def add_or_update(self, name: str, provider: str, base_url: str,
                      api_key: str, model: str,
                      is_primary: bool | None = None) -> tuple[bool, str]:
        """新增或更新一个模型配置，并落盘。
        返回 (success, message)。
        - api_key 传空字符串表示"保留原值"（仅在更新已有 name 时生效）。
        - is_primary=None 表示保留原值；True 会把此模型设为主要，其他模型取消。
        """
        name = (name or "").strip()
        if not name:
            return False, "name 不能为空"
        if not provider or provider.lower() not in ("openai", "anthropic"):
            return False, "provider 只支持 openai / anthropic"
        if not base_url:
            return False, "base_url 不能为空"
        if not model:
            return False, "model 不能为空"

        # 空 api_key + 已有 name → 保留原值
        existing = next((c for c in self.configs if c.name == name), None)
        if not api_key:
            if existing:
                api_key = existing.api_key
            else:
                return False, "新增模型必须填写 api_key"

        # 决定 is_primary 值
        if is_primary is None:
            is_primary_val = existing.is_primary if existing else False
        else:
            is_primary_val = is_primary

        new_cfg = LLMConfig(
            provider=provider.lower(),
            base_url=base_url.strip(),
            api_key=api_key.strip(),
            model=model.strip(),
            name=name,
            is_primary=is_primary_val,
        )

        if existing:
            # 替换原配置，同时移除占位符
            new_list = [new_cfg if c.name == name else c for c in self.configs
                        if c.name != "_unconfigured"]
        else:
            # 新增时排除占位符
            new_list = [c for c in self.configs if c.name != "_unconfigured"] + [new_cfg]

        # 如果设为 primary，取消其他模型的标记
        if is_primary_val:
            new_list = [
                LLMConfig(**{**c.__dict__, "is_primary": False})
                if c.name != name else c
                for c in new_list
            ]

        save_llm_configs(new_list)
        result = self.reload()
        return True, f"已保存（{result['added'] and '新增' or '更新'} {name}）"

    def delete(self, name: str, current_active: str = "") -> tuple[bool, str]:
        """删除一个模型配置。
        - 不允许删除当前正在使用的模型
        - 不允许删除最后一个模型
        """
        if name == current_active:
            return False, f"模型 {name} 正在使用中，请先切换到其他模型再删除"
        if name not in self.clients:
            return False, "模型不存在"
        if len(self.configs) <= 1:
            return False, "至少保留一个模型"

        removed_primary = any(c.name == name and c.is_primary for c in self.configs)
        new_list = [c for c in self.configs if c.name != name]
        # 删掉的是主模型→把剩余第一个设为 primary
        if removed_primary and new_list:
            new_list = [
                LLMConfig(**{**c.__dict__, "is_primary": True})
                if i == 0 else LLMConfig(**{**c.__dict__, "is_primary": False})
                for i, c in enumerate(new_list)
            ]
        save_llm_configs(new_list)
        self.reload()
        return True, f"已删除 {name}"

    def test_connection(self, name: str) -> tuple[bool, str]:
        """对指定模型发一个 ping 请求验证连通性。"""
        if name not in self.clients:
            return False, "模型不存在"
        client = self.clients[name]
        try:
            resp = client.chat(
                messages=[Message(role="user", content="ping")],
                temperature=0.0,
                max_tokens=16,
                caller="connection_test",
            )
            tail = (resp.content or "")[:40].strip() or "(空响应)"
            return True, f"连通正常 · 模型回复: {tail}"
        except Exception as ex:
            return False, f"{type(ex).__name__}: {str(ex)[:200]}"
