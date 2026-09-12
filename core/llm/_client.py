"""统一的 LLM 调用客户端（屏蔽 OpenAI/Anthropic/DeepSeek 协议差异）。

从 core.llm 拆分而来。
patch 兼容：get_model_context_window 等经由 core.llm 包命名空间访问
（tests/test_llm.py: patch("core.llm.get_model_context_window")）。
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import core.llm as _llm
from core.llm._config import LLMConfig, Message
from core.llm._context import get_current_task
from core.log import get_logger

log = get_logger("llm")

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

        summary = _llm._monitor.get_task_summary(task_id)
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
        max_retries: int = 6,
        use_cache: bool = True,
    ) -> Message:
        """调用 LLM，带指数退避重试。

        可重试错误（429/5xx/超时/连接错误）会自动重试 max_retries 次，
        每次间隔指数退避（1s, 2s, 4s, 8s, 16s, 32s）+ 随机抖动。
        不可重试错误（401/403/400）直接抛出，由上层 fallback 逻辑处理。

        ★ use_cache=True 时优先查响应缓存，命中则直接返回不消耗 API。
          测试场景中相同请求可复用结果，大幅减少 API 消耗。
        ★ 上层已自带重试时传 max_retries=0 可避免三层重试叠加。
        ★ Token 预检：缓存未命中时，发送前估算输入 token，超限抛
          ContextLimitError（不可重试），由上层捕获后触发 compress() 再重试。
        ★ 并发隔离：harm_validation 等关键 caller 有独立信号量，
          避免与扫描阶段互相挤占导致 429（限流器，不增加总调用量）。
        """
        self._check_task_budget(max_tokens=max_tokens, caller=caller)

        # ★ 响应缓存：相同请求直接返回上次结果，不消耗 API
        if use_cache:
            cached = _llm._response_cache.get(messages, self.config.model, tools, temperature, max_tokens)
            if cached is not None:
                log.debug("[%s] LLM 缓存命中，跳过 API 调用", caller or "?")
                return cached

        # ★ Token 预检：缓存未命中 → 即将发起 API 调用，先估算输入 token
        # 避免浪费一次 API 往返（API 返回 400 context_length_exceeded）
        # 超限时抛 ContextLimitError，调用方应捕获后 compress() 再重试
        estimated_input = _llm.estimate_messages_tokens(messages, tools)
        context_window = _llm.get_model_context_window(self.config.model)
        available_for_input = int(context_window * _llm._CONTEXT_PRECHECK_SAFETY) - max_tokens
        if estimated_input > available_for_input:
            log.warning(
                "[%s] Token 预检超限: 估算 %d tokens > 可用 %d (window=%d, model=%s)",
                caller or "?", estimated_input, available_for_input,
                context_window, self.config.model,
            )
            raise _llm.ContextLimitError(estimated_input, context_window, self.config.model)

        # ★ 并发隔离：关键 caller（如 harm_validation）使用独立信号量，
        # 避免与扫描阶段 LLM 调用互相挤占 org concurrency 上限导致 429。
        # 信号量在整个重试循环外层获取，确保重试期间也持有限流槽位。
        sem = _llm._get_caller_semaphore(caller)
        if sem is not None:
            sem.acquire()
        try:
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    if self.config.provider == "anthropic":
                        resp = self._chat_anthropic(messages, tools, temperature, max_tokens, caller)
                    else:
                        resp = self._chat_openai(messages, tools, temperature, max_tokens, caller)
                    # ★ 成功调用写入缓存，后续相同请求可复用
                    if use_cache:
                        _llm._response_cache.put(messages, self.config.model, tools, temperature, max_tokens, resp)
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
                    # 抖动幅度从 0.5 扩大到 1.0，降低多 worker 同步重试撞限流概率。
                    import random
                    exp_backoff = (2 ** attempt) + random.uniform(0, 1.0)
                    retry_after = self._extract_retry_after(exc)
                    if retry_after is not None:
                        # 上限 120s，给 429 更充分冷却时间（原 60s 在高并发下仍会撞限流）
                        backoff = min(max(retry_after, exp_backoff), 120.0)
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
        finally:
            if sem is not None:
                sem.release()

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
                    _llm._monitor.record(
                        model=self.config.model, input_tokens=0, output_tokens=0,
                        elapsed=elapsed2, caller=caller, has_tools=bool(tools),
                        call_id=call_id, is_error=True,
                        error=f"{type(ex2).__name__}: {ex2}",
                        req_summary=req_summary, resp_summary="",
                    )
                    raise
            else:
                _llm._monitor.record(
                    model=self.config.model, input_tokens=0, output_tokens=0,
                    elapsed=elapsed, caller=caller, has_tools=bool(tools),
                    call_id=call_id, is_error=True,
                    error=f"{type(ex).__name__}: {ex}",
                    req_summary=req_summary, resp_summary="",
                )
                raise

        elapsed = time.time() - t0
        resp = _llm._parse_sse_chat_payload(resp)

        # ★ D8 防御：非标准/截断 SSE 响应可能返回空 choices（或根本不是 chat 结构）。
        # 原代码 resp.choices[0] 直接 IndexError 且不被 _monitor 记录，导致 worker_agent 无法走兜底。
        # 这里降级为「带监控的错误」，让上层显式处理而非静默崩溃（保持与上方 API 异常一致的 raise 契约）。
        _choices = getattr(resp, "choices", None)
        if not _choices:
            _llm._monitor.record(
                model=self.config.model, input_tokens=0, output_tokens=0,
                elapsed=elapsed, caller=caller, has_tools=bool(tools),
                call_id=call_id, is_error=True,
                error="LLM 返回空 choices（非标准/截断响应）",
                req_summary=req_summary, resp_summary=str(resp)[:300],
            )
            raise ValueError("LLM 返回空 choices：非标准或截断的响应，无法解析首选项")
        choice = _choices[0]
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
        _llm._monitor.record(
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
                parsed_calls, cleaned_content = _llm._parse_xml_tool_calls(content_str)
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
            _llm._monitor.record(
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
        _llm._monitor.record(
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
