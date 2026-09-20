"""
XJ 安全加固修复的单元测试

覆盖项：
- XJ-01: 注册功能默认关闭（core/auth.py 中 XUANJIAN_DISABLE_REGISTER 默认 "1"）
- XJ-02: mitmproxy 仅绑定 127.0.0.1（start.py 所有 mitm_cmd 块含 --listen-host）
- XJ-03: 默认密码不再打印到控制台（core/auth.py init_default_user）
- XJ-05: 流量落盘前脱敏（mcp_servers/mitm_addon.py _redact_headers / _redact_body）

设计原则：零网络、零 LLM；通过 monkeypatch + tmp_path 隔离文件系统。
"""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core import auth  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ============================================================
# XJ-05: 直接导入脱敏函数。
# mitm_addon.py 在模块顶层 `from mitmproxy import tls`，若测试环境未安装
# mitmproxy，则注入最小桩模块（仅提供注解求值所需的 ClientHelloData），
# 以便导入并测试纯 Python 实现的 _redact_headers / _redact_body。
# 该桩仅在真实 mitmproxy 缺失时注入，不影响已安装 mitmproxy 的环境。
# ============================================================
try:
    from mcp_servers.mitm_addon import (  # noqa: E402
        _REDACT_PLACEHOLDER,
        _redact_body,
        _redact_headers,
    )
    _MITM_ADDON_AVAILABLE = True
except Exception:
    if "mitmproxy" not in sys.modules:
        _stub_mp = types.ModuleType("mitmproxy")
        _stub_tls = types.ModuleType("mitmproxy.tls")

        class _ClientHelloData:  # 占位类型，仅用于函数注解求值
            pass

        _stub_tls.ClientHelloData = _ClientHelloData
        _stub_mp.tls = _stub_tls
        sys.modules["mitmproxy"] = _stub_mp
        sys.modules["mitmproxy.tls"] = _stub_tls
    try:
        from mcp_servers.mitm_addon import (  # noqa: E402
            _REDACT_PLACEHOLDER,
            _redact_body,
            _redact_headers,
        )
        _MITM_ADDON_AVAILABLE = True
    except Exception:  # pragma: no cover
        _MITM_ADDON_AVAILABLE = False
        _REDACT_PLACEHOLDER = "***REDACTED***"
        _redact_headers = None  # type: ignore[assignment]
        _redact_body = None  # type: ignore[assignment]


# ============================================================
# 共享固件：把 core.auth 的数据目录重定向到临时目录
# ============================================================
@pytest.fixture
def isolated_auth(tmp_path, monkeypatch):
    """把 core.auth 的数据目录重定向到 tmp_path，并重置内存缓存。

    - _PROJECT_ROOT / _USERS_FILE / _SECRET_FILE 指向 tmp_path
    - _state.cache 置空，确保 _load() 从新位置重新加载（清空既有用户缓存）
    - _login_failures 清空，避免跨用例污染
    """
    monkeypatch.setattr(auth, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(auth, "_USERS_FILE", tmp_path / "data" / "users.json")
    monkeypatch.setattr(auth, "_SECRET_FILE", tmp_path / "data" / ".auth_secret")
    # D7 holder 化：_CACHE 已移到 _state.cache
    monkeypatch.setattr(auth._state, "cache", None)
    monkeypatch.setattr(auth, "_login_failures", {})
    return auth


# ============================================================
# XJ-01: 注册功能默认关闭
# ============================================================
class TestXJ01RegisterDefaultClosed:
    def test_register_disabled_by_default(self, isolated_auth, monkeypatch):
        """未设置 XUANJIAN_DISABLE_REGISTER 时，注册默认关闭。"""
        monkeypatch.delenv("XUANJIAN_DISABLE_REGISTER", raising=False)
        result = isolated_auth.register("newuser", "password123")
        assert result["ok"] is False
        assert "注册功能" in result["error"]

    def test_register_succeeds_when_enabled(self, isolated_auth, monkeypatch):
        """XUANJIAN_DISABLE_REGISTER=0 时注册成功。"""
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")
        result = isolated_auth.register("newuser", "password123")
        assert result["ok"] is True
        assert result["username"] == "newuser"
        assert "token" in result


# ============================================================
# XJ-02: mitmproxy 仅绑定 127.0.0.1
# ============================================================
class TestXJ02MitmBindLoopback:
    def test_all_mitm_cmd_blocks_bind_loopback(self):
        """start.py 中所有 mitm_cmd 命令构造块都包含 --listen-host 127.0.0.1。"""
        start_py = _PROJECT_ROOT / "start.py"
        source = start_py.read_text(encoding="utf-8")

        # 关键标志与回环地址必须出现在源码中
        assert '"--listen-host"' in source
        assert '"127.0.0.1"' in source

        # 提取 start_mitmproxy() 中所有 mitm_cmd = [...] 命令构造块
        blocks = re.findall(r"mitm_cmd\s*=\s*\[(.*?)\]", source, re.DOTALL)
        assert len(blocks) >= 3, f"期望至少 3 个 mitm_cmd 块，实际 {len(blocks)}"

        # 每个命令块都必须绑定到 127.0.0.1
        for idx, block in enumerate(blocks, start=1):
            assert '"--listen-host"' in block, f"第 {idx} 个 mitm_cmd 块缺少 --listen-host"
            assert '"127.0.0.1"' in block, f"第 {idx} 个 mitm_cmd 块未绑定 127.0.0.1"


# ============================================================
# XJ-03: 默认密码不再打印到控制台
# ============================================================
class TestXJ03PasswordNotPrinted:
    def test_init_default_user_does_not_print_password(
        self, isolated_auth, tmp_path, monkeypatch, capsys
    ):
        """init_default_user() 不向控制台打印明文密码，只提示查看文件。"""
        # 强制走随机生成 + 持久化路径，以便回读真实密码做断言
        monkeypatch.setattr(isolated_auth, "_DEFAULT_PASSWORD", "")
        monkeypatch.delenv("PENTEST_DEFAULT_PASSWORD", raising=False)

        isolated_auth.init_default_user()

        captured = capsys.readouterr()
        out = captured.out

        # 回读实际生成的密码
        pw_file = tmp_path / "data" / ".default_password"
        assert pw_file.exists(), "默认密码文件应被创建"
        actual_password = pw_file.read_text(encoding="utf-8").strip()
        assert actual_password, "密码不应为空"

        # 明文密码绝不能出现在控制台输出中
        assert actual_password not in out
        # 应提示用户去文件查看密码
        assert "请查看 data/.default_password 文件" in out


# ============================================================
# XJ-05: 流量脱敏
# ============================================================
@pytest.mark.skipif(not _MITM_ADDON_AVAILABLE, reason="无法导入 mitm_addon 脱敏函数")
class TestXJ05TrafficDesensitization:
    def test_redact_placeholder_value(self):
        assert _REDACT_PLACEHOLDER == "***REDACTED***"

    def test_redact_headers_authorization(self):
        result = _redact_headers(
            {"Authorization": "Bearer abc123", "Content-Type": "application/json"}
        )
        assert result == {
            "Authorization": _REDACT_PLACEHOLDER,
            "Content-Type": "application/json",
        }

    def test_redact_headers_cookie(self):
        result = _redact_headers({"Cookie": "session=xyz", "X-Custom": "val"})
        assert result == {"Cookie": _REDACT_PLACEHOLDER, "X-Custom": "val"}

    def test_redact_headers_set_cookie_and_api_key(self):
        result = _redact_headers({"Set-Cookie": "a=1; Path=/", "X-API-Key": "key123"})
        assert result == {
            "Set-Cookie": _REDACT_PLACEHOLDER,
            "X-API-Key": _REDACT_PLACEHOLDER,
        }

    def test_redact_body_json_password(self):
        body = '{"username": "admin", "password": "secret123"}'
        result = _redact_body(body)
        parsed = json.loads(result)
        assert parsed["username"] == "admin"
        assert parsed["password"] == _REDACT_PLACEHOLDER
        assert "secret123" not in result

    def test_redact_body_form_password_and_token(self):
        body = "username=admin&password=secret123&token=abc"
        result = _redact_body(body)
        assert "username=admin" in result
        assert f"password={_REDACT_PLACEHOLDER}" in result
        assert f"token={_REDACT_PLACEHOLDER}" in result
        assert "secret123" not in result
        # token 原值也应被替换
        assert "token=abc" not in result

    def test_redact_body_plain_text_unchanged(self):
        body = "plain text without secrets"
        assert _redact_body(body) == body
