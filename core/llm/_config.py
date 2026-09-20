"""LLM 配置数据类、SSE 解析、模型名纠正、配置加载/保存、API Key 掩码、XML tool_calls 解析。

从 core.llm 拆分而来。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.log import get_logger
from core.llm._crypto import _ENC_PREFIX, _decrypt_api_key, _encrypt_api_key

log = get_logger("llm")

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
