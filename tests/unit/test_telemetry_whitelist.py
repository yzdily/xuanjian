"""F18 遥测白名单 + PII 过滤单元测试。"""
from __future__ import annotations

import os
import sys

# Add web module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from web.server import filter_telemetry, TELEM_EVENT_WHITELIST, get_session_token


class TestTelemetryWhitelist:
    def test_whitelist_contains_core_events(self):
        assert "run_start" in TELEM_EVENT_WHITELIST
        assert "run_end" in TELEM_EVENT_WHITELIST
        assert "vuln_card" in TELEM_EVENT_WHITELIST
        assert "steer_request" in TELEM_EVENT_WHITELIST

    def test_whitelist_excludes_internal_events(self):
        assert "internal_log" not in TELEM_EVENT_WHITELIST
        assert "debug_data" not in TELEM_EVENT_WHITELIST


class TestFilterTelemetry:
    def test_empty_returns_none(self):
        assert filter_telemetry("") is None

    def test_none_returns_none(self):
        assert filter_telemetry(None) is None

    def test_heartbeat_passes(self):
        result = filter_telemetry(": heartbeat\n\n")
        assert result is not None

    def test_pii_password_redacted(self):
        event = 'data: {"password": "secret123"}'
        result = filter_telemetry(event)
        assert result is not None
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_pii_token_redacted(self):
        event = 'data: {"token": "eyJhbGciOiJIUzI1NiJ9"}'
        result = filter_telemetry(event)
        assert result is not None
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_non_pii_data_preserved(self):
        event = 'data: {"url": "http://target.com/api"}'
        result = filter_telemetry(event)
        assert result is not None
        assert "target.com" in result


class TestSessionToken:
    def test_token_is_string(self):
        token = get_session_token()
        assert isinstance(token, str)

    def test_token_is_long_enough(self):
        token = get_session_token()
        assert len(token) >= 32

    def test_token_is_constant_within_process(self):
        t1 = get_session_token()
        t2 = get_session_token()
        assert t1 == t2
