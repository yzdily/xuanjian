"""
LLM 客户端模块测试

覆盖：Message 数据类、LLMConfig、LLMMonitor（线程安全/缓冲写入）、
      LLMResponseCache（LRU/TTL/禁用）、_parse_sse_chat_payload、
      parse_llm_json、parse_tool_call_arguments、temperature预检、
      错误分类重试、模型名纠正、API Key加解密、
      _parse_xml_tool_calls、mask_api_key、LLMClient.chat缓存集成
"""

import json
import os
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def _clear_response_cache():
    """每个测试前清空全局 LLM 响应缓存，避免测试间状态泄漏。"""
    from core.llm import _response_cache
    _response_cache.clear()
    yield
    _response_cache.clear()


class TestMessage:
    def test_basic_message(self):
        from core.llm import Message
        msg = Message(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"
        assert msg.tool_calls == []
        assert msg.tool_call_id is None

    def test_assistant_with_tool_calls(self):
        from core.llm import Message
        msg = Message(
            role="assistant",
            content="",
            tool_calls=[{"id": "call_1", "function": {"name": "test", "arguments": "{}"}}]
        )
        assert len(msg.tool_calls) == 1
        assert msg.tool_calls[0]["function"]["name"] == "test"

    def test_tool_message(self):
        from core.llm import Message
        msg = Message(role="tool", content="result", tool_call_id="call_1")
        assert msg.tool_call_id == "call_1"

    def test_reasoning_content(self):
        from core.llm import Message
        msg = Message(role="assistant", content="answer", reasoning_content="thinking...")
        assert msg.reasoning_content == "thinking..."


class TestLLMConfig:
    def test_config_fields(self):
        from core.llm import LLMConfig
        cfg = LLMConfig(
            provider="openai",
            base_url="https://api.example.com/v1",
            api_key="sk-test123",
            model="gpt-4",
            name="test_model"
        )
        assert cfg.provider == "openai"
        assert cfg.model == "gpt-4"
        assert cfg.name == "test_model"


class TestMaskApiKey:
    def test_normal_key(self):
        from core.llm import mask_api_key
        result = mask_api_key("sk-1234567890abcdef")
        assert result.startswith("sk-1")
        assert result.endswith("cdef")
        assert "******" in result

    def test_short_key(self):
        from core.llm import mask_api_key
        assert mask_api_key("short") == "****"

    def test_empty_key(self):
        from core.llm import mask_api_key
        assert mask_api_key("") == ""


class TestParseXmlToolCalls:
    def test_function_calls_format(self):
        from core.llm import _parse_xml_tool_calls
        content = '''我来帮你测试一下。
<function_calls>
<invoke name="proxy_send_request">
<parameter name="method">POST</parameter>
<parameter name="url">http://example.com/api</parameter>
<parameter name="body">{"id": 1}</parameter>
</invoke>
</function_calls>'''
        calls, cleaned = _parse_xml_tool_calls(content)
        assert len(calls) == 1
        assert calls[0]["function"]["name"] == "proxy_send_request"
        args = json.loads(calls[0]["function"]["arguments"])
        assert args["method"] == "POST"
        assert args["url"] == "http://example.com/api"
        assert "function_calls" not in cleaned
        assert "帮你测试" in cleaned

    def test_multiple_invokes(self):
        from core.llm import _parse_xml_tool_calls
        content = '''<function_calls>
<invoke name="tool_a">
<parameter name="x">1</parameter>
</invoke>
<invoke name="tool_b">
<parameter name="y">hello</parameter>
</invoke>
</function_calls>'''
        calls, _ = _parse_xml_tool_calls(content)
        assert len(calls) == 2
        assert calls[0]["function"]["name"] == "tool_a"
        assert calls[1]["function"]["name"] == "tool_b"

    def test_boolean_and_int_params(self):
        from core.llm import _parse_xml_tool_calls
        content = '''<invoke name="test">
<parameter name="flag">true</parameter>
<parameter name="count">42</parameter>
</invoke>'''
        calls, _ = _parse_xml_tool_calls(content)
        args = json.loads(calls[0]["function"]["arguments"])
        assert args["flag"] is True
        assert args["count"] == 42

    def test_tool_call_format(self):
        from core.llm import _parse_xml_tool_calls
        content = '<tool_call>{"name": "test_tool", "arguments": {"key": "value"}}</tool_call>'
        calls, _ = _parse_xml_tool_calls(content)
        assert len(calls) == 1
        assert calls[0]["function"]["name"] == "test_tool"

    def test_no_xml_returns_empty(self):
        from core.llm import _parse_xml_tool_calls
        content = "这是普通文本，没有任何 XML 工具调用。"
        calls, cleaned = _parse_xml_tool_calls(content)
        assert calls == []
        assert cleaned == content

    def test_empty_content(self):
        from core.llm import _parse_xml_tool_calls
        calls, cleaned = _parse_xml_tool_calls("")
        assert calls == []
        assert cleaned == ""


class TestLLMMonitor:
    def _make_clean_monitor(self):
        """创建干净的 LLMMonitor 实例（绕过单例），含新增的线程锁和缓冲属性。"""
        from core.llm import LLMMonitor
        monitor = LLMMonitor.__new__(LLMMonitor)
        monitor._initialized = False
        monitor.__init__()
        # 重置为干净状态
        monitor.total_calls = 0
        monitor.total_input_tokens = 0
        monitor.total_output_tokens = 0
        monitor.total_cost_seconds = 0.0
        monitor.by_model = {}
        monitor.by_caller = {}
        monitor.by_task = {}
        # ★ 新增属性初始化（缓冲写入 + 日志轮转）
        monitor._buffer = []
        monitor._buffer_flush_count = 2  # 小值便于测试触发 flush
        monitor._buffer_flush_timeout = 5.0
        monitor._buffer_last_flush = time.time()
        monitor._max_log_size = 50 * 1024 * 1024
        # 使用临时文件
        tmpdir = tempfile.mkdtemp()
        monitor._log_file = Path(tmpdir) / "test_usage.jsonl"
        return monitor

    def test_record_and_summary(self):
        monitor = self._make_clean_monitor()

        monitor.record(
            model="test-model",
            input_tokens=100,
            output_tokens=50,
            elapsed=1.5,
            caller="test_caller",
            task_id="task_1",
        )
        # 强制 flush 缓冲
        monitor._flush_buffer()
        summary = monitor.get_summary()
        assert summary["total_calls"] == 1
        assert summary["total_input_tokens"] == 100
        assert summary["total_output_tokens"] == 50
        assert "test-model" in summary["by_model"]

    def test_task_summary(self):
        monitor = self._make_clean_monitor()

        monitor.record(model="m", input_tokens=10, output_tokens=5, elapsed=0.5, task_id="t1")
        monitor.record(model="m", input_tokens=20, output_tokens=10, elapsed=1.0, task_id="t1")
        monitor._flush_buffer()
        ts = monitor.get_task_summary("t1")
        assert ts["calls"] == 2
        assert ts["input_tokens"] == 30
        assert ts["output_tokens"] == 15

    def test_task_summary_nonexistent(self):
        from core.llm import LLMMonitor
        monitor = LLMMonitor.__new__(LLMMonitor)
        monitor._initialized = False
        monitor.__init__()
        monitor.by_task = {}
        ts = monitor.get_task_summary("nonexistent")
        assert ts["calls"] == 0

    def test_buffered_writes(self):
        """测试缓冲写入：未达 flush 阈值时不写文件。"""
        monitor = self._make_clean_monitor()
        monitor._buffer_flush_count = 10  # 设大，不触发自动 flush
        monitor.record(model="m", input_tokens=1, output_tokens=1, elapsed=0.1)
        # 未 flush，文件不应存在或为空
        assert len(monitor._buffer) == 1
        # 手动 flush
        monitor._flush_buffer()
        assert len(monitor._buffer) == 0
        assert monitor._log_file.exists()
        lines = monitor._log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1

    def test_thread_safety(self):
        """测试多线程并发 record 不出错。"""
        import threading
        monitor = self._make_clean_monitor()
        monitor._buffer_flush_count = 1000  # 不触发自动 flush

        def worker():
            for i in range(50):
                monitor.record(model="m", input_tokens=1, output_tokens=1, elapsed=0.01,
                               caller=f"caller_{i % 3}")

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        monitor._flush_buffer()
        assert monitor.total_calls == 250  # 5 threads × 50 calls


class TestLoadLLMConfigs:
    def test_load_from_env(self, tmp_path, monkeypatch):
        """从环境变量加载配置。"""
        from core.llm import load_llm_configs, LLMConfig

        # 隔离：重定向 runtime json 到不存在的临时路径，强制走 .env 分支
        monkeypatch.chdir(tmp_path)

        env_vars = {
            "LLM_1_PROVIDER": "openai",
            "LLM_1_BASE_URL": "https://api.test.com/v1",
            "LLM_1_API_KEY": "sk-test-key-abcdef",
            "LLM_1_MODEL": "test-model",
            "LLM_1_NAME": "llm_1",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            configs = load_llm_configs()
            # 找到 LLM_1_NAME 对应的配置（避免被其他系统配置干扰）
            cfg = next((c for c in configs if c.name == "llm_1"), None)
            assert cfg is not None, f"未找到 llm_1 配置，实际配置: {[c.name for c in configs]}"
            assert cfg.provider == "openai"
            assert cfg.model == "test-model"
            assert cfg.api_key == "sk-test-key-abcdef"


class TestLLMResponseCache:
    """测试 LLM 响应缓存机制。"""

    def test_cache_hit_and_miss(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=10, ttl=60)
        msgs = [Message(role="user", content="hello")]
        tools = [{"type": "function", "function": {"name": "test", "parameters": {}}}]
        resp = Message(role="assistant", content="world")

        # 未缓存 → miss
        result = cache.get(msgs, "model-a", tools, 0.2, 4096)
        assert result is None
        assert cache.stats()["misses"] == 1

        # 写入缓存
        cache.put(msgs, "model-a", tools, 0.2, 4096, resp)

        # 相同请求 → hit
        result = cache.get(msgs, "model-a", tools, 0.2, 4096)
        assert result is not None
        assert result.content == "world"
        assert cache.stats()["hits"] == 1

    def test_cache_different_params_miss(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=10, ttl=60)
        msgs = [Message(role="user", content="hello")]
        resp = Message(role="assistant", content="world")
        cache.put(msgs, "model-a", None, 0.2, 4096, resp)

        # 不同 model → miss
        assert cache.get(msgs, "model-b", None, 0.2, 4096) is None
        # 不同 temperature → miss
        assert cache.get(msgs, "model-a", None, 0.5, 4096) is None
        # 不同 messages → miss
        other_msgs = [Message(role="user", content="different")]
        assert cache.get(other_msgs, "model-a", None, 0.2, 4096) is None

    def test_cache_ttl_expiry(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=10, ttl=0.1)
        msgs = [Message(role="user", content="hello")]
        resp = Message(role="assistant", content="world")
        cache.put(msgs, "m", None, 0.2, 4096, resp)

        # 模拟时间流逝，不实际 sleep
        with patch("core.llm.time.time", return_value=time.time() + 1):
            result = cache.get(msgs, "m", None, 0.2, 4096)
        assert result is None  # TTL 过期

    def test_cache_lru_eviction(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=2, ttl=60)
        for i in range(3):
            msgs = [Message(role="user", content=f"msg{i}")]
            resp = Message(role="assistant", content=f"resp{i}")
            cache.put(msgs, "m", None, 0.2, 4096, resp)

        # max_size=2，最老的 msg0 应被淘汰
        old_msgs = [Message(role="user", content="msg0")]
        assert cache.get(old_msgs, "m", None, 0.2, 4096) is None
        # msg2 仍在
        new_msgs = [Message(role="user", content="msg2")]
        assert cache.get(new_msgs, "m", None, 0.2, 4096) is not None

    def test_cache_disabled(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=10, ttl=0)  # TTL=0 禁用
        msgs = [Message(role="user", content="hello")]
        resp = Message(role="assistant", content="world")
        cache.put(msgs, "m", None, 0.2, 4096, resp)
        assert cache.get(msgs, "m", None, 0.2, 4096) is None

    def test_cache_clear(self):
        from core.llm import LLMResponseCache, Message
        cache = LLMResponseCache(max_size=10, ttl=60)
        msgs = [Message(role="user", content="hello")]
        cache.put(msgs, "m", None, 0.2, 4096, Message(role="assistant", content="x"))
        cache.clear()
        assert cache.stats()["size"] == 0
        assert cache.get(msgs, "m", None, 0.2, 4096) is None


class TestParseSseChatPayload:
    """测试 SSE 降级解析函数。"""

    def test_non_string_passthrough(self):
        from core.llm import _parse_sse_chat_payload
        obj = {"a": 1}
        assert _parse_sse_chat_payload(obj) is obj

    def test_empty_string(self):
        from core.llm import _parse_sse_chat_payload
        r = _parse_sse_chat_payload("")
        assert r.choices[0].message.content == ""

    def test_basic_sse_content(self):
        from core.llm import _parse_sse_chat_payload
        sse = (
            'data: {"choices":[{"index":0,"delta":{"content":"Hello "},"finish_reason":null}]}\n'
            'data: {"choices":[{"index":0,"delta":{"content":"world"},"finish_reason":null}]}\n'
            'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}\n'
            'data: [DONE]\n'
        )
        r = _parse_sse_chat_payload(sse)
        assert r.choices[0].message.content == "Hello world"
        assert r.choices[0].finish_reason == "stop"
        assert r.usage.prompt_tokens == 5
        assert r.usage.completion_tokens == 2

    def test_sse_with_reasoning_content(self):
        from core.llm import _parse_sse_chat_payload
        sse = (
            'data: {"choices":[{"index":0,"delta":{"reasoning_content":"think1","content":"ans"}}]}\n'
        )
        r = _parse_sse_chat_payload(sse)
        assert r.choices[0].message.reasoning_content == "think1"
        assert r.choices[0].message.content == "ans"

    def test_sse_with_tool_calls(self):
        from core.llm import _parse_sse_chat_payload
        sse = (
            'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_","arguments":"{\\"a\\"}"}}]},"finish_reason":null}]}\n'
            'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"time","arguments":":1"}}]},"finish_reason":null}]}\n'
        )
        r = _parse_sse_chat_payload(sse)
        tc = r.choices[0].message.tool_calls[0]
        assert tc.function.name == "get_time"
        assert tc.function.arguments == '{"a"}:1'
        assert tc.id == "call_1"

    def test_sse_ignores_non_data_lines(self):
        from core.llm import _parse_sse_chat_payload
        sse = (
            ': keep-alive\n\n'
            'data: {"choices":[{"index":0,"delta":{"content":"ok"}}]}\n'
        )
        r = _parse_sse_chat_payload(sse)
        assert r.choices[0].message.content == "ok"


class TestParseLLMJson:
    """测试统一 JSON 解析函数。"""

    def test_plain_json(self):
        from core.llm import parse_llm_json
        assert parse_llm_json('{"key": "value"}') == {"key": "value"}

    def test_with_code_fence(self):
        from core.llm import parse_llm_json
        assert parse_llm_json('```json\n{"key": "value"}\n```') == {"key": "value"}

    def test_with_think_block(self):
        from core.llm import parse_llm_json
        text = '<think>some reasoning</think>\n{"key": "value"}'
        assert parse_llm_json(text) == {"key": "value"}

    def test_with_trailing_comma(self):
        from core.llm import parse_llm_json
        assert parse_llm_json('{"key": "value",}') == {"key": "value"}

    def test_embedded_json(self):
        from core.llm import parse_llm_json
        text = 'Here is the result: {"key": "value"} done.'
        assert parse_llm_json(text) == {"key": "value"}

    def test_empty_input(self):
        from core.llm import parse_llm_json
        assert parse_llm_json("") is None
        assert parse_llm_json("   ") is None

    def test_invalid_input(self):
        from core.llm import parse_llm_json
        assert parse_llm_json("not json at all") is None

    def test_expect_list(self):
        from core.llm import parse_llm_json
        assert parse_llm_json('[1, 2, 3]', expect=list) == [1, 2, 3]
        assert parse_llm_json('{"key": "val"}', expect=list) is None


class TestToolCallArguments:
    """测试工具参数解析。"""

    def test_valid_json(self):
        from core.llm import parse_tool_call_arguments
        args, failed = parse_tool_call_arguments('{"method": "GET"}')
        assert args == {"method": "GET"}
        assert failed is False

    def test_empty_string(self):
        from core.llm import parse_tool_call_arguments
        args, failed = parse_tool_call_arguments("")
        assert args == {}
        assert failed is False

    def test_repairable_json(self):
        from core.llm import parse_tool_call_arguments
        args, failed = parse_tool_call_arguments('{"key": "value",}')
        assert args == {"key": "value"}
        assert failed is False

    def test_unrepairable_json(self):
        from core.llm import parse_tool_call_arguments
        args, failed = parse_tool_call_arguments("not json {{{")
        assert failed is True


class TestTemperaturePreCheck:
    """测试 temperature 预检逻辑（避免浪费 API 调用）。"""

    def test_deepseek_reasoner_no_temperature(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="https://api.deepseek.com/v1",
                        api_key="sk-test", model="deepseek-reasoner", name="ds")
        client = LLMClient(cfg)
        assert client._supports_temperature() is False

    def test_deepseek_chat_has_temperature(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="https://api.deepseek.com/v1",
                        api_key="sk-test", model="deepseek-chat", name="ds")
        client = LLMClient(cfg)
        assert client._supports_temperature() is True

    def test_o1_no_temperature(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="https://api.openai.com/v1",
                        api_key="sk-test", model="o1", name="o1")
        client = LLMClient(cfg)
        assert client._supports_temperature() is False

    def test_normal_model_has_temperature(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="https://api.example.com/v1",
                        api_key="sk-test", model="gpt-4", name="gpt4")
        client = LLMClient(cfg)
        assert client._supports_temperature() is True


class TestLLMClientChatWithCache:
    """测试 LLMClient.chat() 的缓存集成（不调真实 API）。"""

    def test_cache_hit_skips_api(self):
        """缓存命中时不调用真实 API。"""
        from core.llm import LLMClient, LLMConfig, Message, _response_cache

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        msgs = [Message(role="user", content="test cache")]
        expected = Message(role="assistant", content="cached response")
        # 预写入缓存
        _response_cache.put(msgs, cfg.model, None, 0.2, 4096, expected)

        # chat 应直接返回缓存，不调 API
        result = client.chat(msgs, caller="test", use_cache=True)
        assert result.content == "cached response"

    def test_cache_disabled_calls_api(self):
        """use_cache=False 时跳过缓存，调用 mock API。"""
        from core.llm import LLMClient, LLMConfig, Message

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        # mock _chat_openai 避免真实 API 调用
        mock_resp = Message(role="assistant", content="from api")
        with patch.object(client, "_chat_openai", return_value=mock_resp):
            result = client.chat([Message(role="user", content="no cache")],
                                 caller="test", use_cache=False)
            assert result.content == "from api"


class TestRetryableError:
    """测试错误分类逻辑（决定是否重试）。"""

    def test_rate_limit_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("429 rate limit exceeded")) is True

    def test_500_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("502 bad gateway")) is True

    def test_timeout_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("connection timeout")) is True

    def test_auth_not_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("401 unauthorized")) is False

    def test_bad_request_not_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("400 bad request")) is False

    def test_unknown_not_retryable(self):
        from core.llm import LLMClient, LLMConfig
        cfg = LLMConfig(provider="openai", base_url="", api_key="sk-test", model="m", name="t")
        client = LLMClient(cfg)
        assert client._is_retryable_error(Exception("something weird")) is False


class TestModelNameCorrection:
    """测试模型名自动纠正。"""

    def test_normalize_provider(self):
        from core.llm import _normalize_provider
        assert _normalize_provider("deepseek") == "openai"
        assert _normalize_provider("moonshot") == "openai"
        assert _normalize_provider("kimi") == "openai"
        assert _normalize_provider("openai") == "openai"
        assert _normalize_provider("anthropic") == "anthropic"

    def test_normalize_model_deepseek(self):
        from core.llm import _normalize_model_name
        assert _normalize_model_name("https://api.deepseek.com/v1", "deepseek-v4-pro") == "deepseek-chat"
        assert _normalize_model_name("https://api.deepseek.com/v1", "deepseek-v5") == "deepseek-chat"

    def test_normalize_model_kimi(self):
        from core.llm import _normalize_model_name
        assert _normalize_model_name("https://api.moonshot.cn/v1", "kimi2") == "kimi-k3"
        assert _normalize_model_name("https://api.moonshot.cn/v1", "kimi-k2-0905-preview") == "kimi-k3"

    def test_normalize_model_no_change(self):
        from core.llm import _normalize_model_name
        assert _normalize_model_name("https://api.example.com/v1", "gpt-4") == "gpt-4"


class TestApiKeyEncryption:
    """测试 API Key 加密/解密。"""

    def test_encrypt_decrypt_roundtrip(self):
        from core.llm import _encrypt_api_key, _decrypt_api_key
        plaintext = "sk-test1234567890abcdef"
        encrypted = _encrypt_api_key(plaintext)
        assert encrypted != plaintext
        assert encrypted.startswith("enc$v1$")
        decrypted = _decrypt_api_key(encrypted)
        assert decrypted == plaintext

    def test_decrypt_plaintext_passthrough(self):
        from core.llm import _decrypt_api_key
        # 明文 key 应原样返回（向后兼容）
        assert _decrypt_api_key("sk-plaintext123") == "sk-plaintext123"

    def test_encrypt_empty(self):
        from core.llm import _encrypt_api_key
        assert _encrypt_api_key("") == ""

    def test_encrypt_already_encrypted(self):
        from core.llm import _encrypt_api_key
        already = "enc$v1$someciphertext"
        assert _encrypt_api_key(already) == already


class TestTokenEstimation:
    """测试 token 估算工具函数。"""

    def test_estimate_text_tokens_empty(self):
        from core.llm import estimate_text_tokens
        assert estimate_text_tokens("") == 0
        assert estimate_text_tokens(None) == 0

    def test_estimate_text_tokens_ascii(self):
        from core.llm import estimate_text_tokens
        # 8 个 ASCII 字符 ≈ 2 tokens
        assert estimate_text_tokens("abcdefgh") == 2

    def test_estimate_text_tokens_cjk(self):
        from core.llm import estimate_text_tokens
        # 6 个中文字符 ≈ 6 tokens（每个 CJK 字符 1 token）
        assert estimate_text_tokens("你好世界测试") == 6

    def test_estimate_text_tokens_mixed(self):
        from core.llm import estimate_text_tokens
        # 4 个中文 + 8 个 ASCII = 4 + 2 = 6 tokens
        assert estimate_text_tokens("你好世界abcdefgh") == 6

    def test_estimate_messages_tokens_basic(self):
        from core.llm import estimate_messages_tokens, Message
        msgs = [Message(role="user", content="hello world")]
        tokens = estimate_messages_tokens(msgs)
        # role 开销 4 + content "hello world" = 11 chars / 4 = 2 → 6 tokens
        assert tokens > 0

    def test_estimate_messages_tokens_empty(self):
        from core.llm import estimate_messages_tokens
        assert estimate_messages_tokens([]) == 0

    def test_estimate_messages_tokens_with_tools(self):
        from core.llm import estimate_messages_tokens, Message
        msgs = [Message(role="user", content="test")]
        tools = [{"type": "function", "function": {"name": "f", "parameters": {}}}]
        tokens_without_tools = estimate_messages_tokens(msgs)
        tokens_with_tools = estimate_messages_tokens(msgs, tools)
        # 每个工具约 80 tokens
        assert tokens_with_tools == tokens_without_tools + 80

    def test_estimate_messages_tokens_with_tool_calls(self):
        from core.llm import estimate_messages_tokens, Message
        msgs = [
            Message(role="user", content="test"),
            Message(role="assistant", content="", tool_calls=[
                {"id": "call_1", "function": {"name": "fn", "arguments": "{}"}}
            ]),
            Message(role="tool", content="result", tool_call_id="call_1"),
        ]
        tokens = estimate_messages_tokens(msgs)
        assert tokens > 0
        # tool_calls 和 tool_call_id 都有额外开销
        assert tokens > estimate_messages_tokens([msgs[0]])


class TestModelContextWindow:
    """测试模型上下文窗口查询。"""

    def test_known_model_exact(self):
        from core.llm import get_model_context_window
        assert get_model_context_window("deepseek-chat") == 65536

    def test_known_model_case_insensitive(self):
        from core.llm import get_model_context_window
        assert get_model_context_window("DeepSeek-Chat") == 65536

    def test_known_model_fuzzy(self):
        from core.llm import get_model_context_window
        # 模型名包含 "deepseek-chat" 的变体
        assert get_model_context_window("deepseek-chat-v3") == 65536

    def test_unknown_model_default(self):
        from core.llm import get_model_context_window
        # 未知模型返回默认值
        result = get_model_context_window("totally-unknown-model-xyz")
        assert result > 0  # 默认 32768 或环境变量值

    def test_empty_model(self):
        from core.llm import get_model_context_window
        result = get_model_context_window("")
        assert result > 0


class TestContextLimitError:
    """测试 ContextLimitError 异常类。"""

    def test_error_attributes(self):
        from core.llm import ContextLimitError
        err = ContextLimitError(estimated_tokens=50000, context_window=32768, model="test-model")
        assert err.estimated_tokens == 50000
        assert err.context_window == 32768
        assert err.model == "test-model"

    def test_error_message_contains_values(self):
        from core.llm import ContextLimitError
        err = ContextLimitError(estimated_tokens=50000, context_window=32768, model="test-model")
        msg = str(err)
        assert "50000" in msg
        assert "32768" in msg
        assert "test-model" in msg

    def test_error_is_exception(self):
        from core.llm import ContextLimitError
        err = ContextLimitError(100, 50, "m")
        assert isinstance(err, Exception)


class TestChatPrecheck:
    """测试 chat() 方法的 token 预检逻辑。"""

    def test_precheck_raises_on_oversized_input(self):
        """输入 token 超限时抛出 ContextLimitError。"""
        from core.llm import LLMClient, LLMConfig, Message, ContextLimitError

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        # 构造超大消息（~12500 tokens）
        big_content = "A" * 50000
        msgs = [Message(role="user", content=big_content)]

        # mock 小上下文窗口
        with patch("core.llm.get_model_context_window", return_value=1000):
            with pytest.raises(ContextLimitError) as exc_info:
                client.chat(msgs, caller="test", use_cache=False, max_tokens=100)
            assert exc_info.value.estimated_tokens > 1000
            assert exc_info.value.context_window == 1000

    def test_precheck_passes_small_input(self):
        """输入 token 未超限时正常调用 API。"""
        from core.llm import LLMClient, LLMConfig, Message

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        msgs = [Message(role="user", content="small message")]
        mock_resp = Message(role="assistant", content="response")
        with patch.object(client, "_chat_openai", return_value=mock_resp):
            result = client.chat(msgs, caller="test", use_cache=False)
            assert result.content == "response"

    def test_precheck_skipped_on_cache_hit(self):
        """缓存命中时跳过预检（不调 API，无需检查超限）。"""
        from core.llm import LLMClient, LLMConfig, Message, _response_cache

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        big_content = "A" * 50000
        msgs = [Message(role="user", content=big_content)]
        expected = Message(role="assistant", content="cached")
        _response_cache.put(msgs, cfg.model, None, 0.2, 4096, expected)

        # 即使输入超大 + 窗口极小，缓存命中也不应抛 ContextLimitError
        with patch("core.llm.get_model_context_window", return_value=100):
            result = client.chat(msgs, caller="test", use_cache=True)
            assert result.content == "cached"

    def test_context_limit_error_not_retryable(self):
        """ContextLimitError 不应触发重试（不可重试错误）。"""
        from core.llm import LLMClient, LLMConfig, Message, ContextLimitError

        cfg = LLMConfig(provider="openai", base_url="https://api.test.com/v1",
                        api_key="sk-test", model="test-model", name="test")
        client = LLMClient(cfg)

        big_content = "A" * 50000
        msgs = [Message(role="user", content=big_content)]

        # 即使 max_retries=3，预检超限也应立即抛出，不重试
        with patch("core.llm.get_model_context_window", return_value=100):
            with patch.object(client, "_chat_openai") as mock_api:
                with pytest.raises(ContextLimitError):
                    client.chat(msgs, caller="test", use_cache=False, max_retries=3)
                # API 不应被调用
                mock_api.assert_not_called()
