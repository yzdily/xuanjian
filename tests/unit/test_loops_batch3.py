"""§2.8 批次 3 四类探针单元测试（core/loops/batch3_probes.py）。

四类：请求走私 / JNDI / 反序列化 / OAuth-OIDC。
纯内存测试，不发起真实网络请求（请求走私用 mock socket）。
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from core.loops.batch3_probes import (
    analyze_oauth_oidc,
    build_deserialization_payloads,
    build_jndi_payloads,
    detect_insecure_deserialization,
    detect_jndi_injection,
    detect_request_smuggling,
)


# ============================================================
# 1. 请求走私
# ============================================================
def test_detect_smuggling_negative_no_response():
    """无 smuggled 标记响应 → detected=False。"""
    fake_sock = MagicMock()
    fake_sock.__enter__.return_value = fake_sock

    def _recv(n):
        if not hasattr(_recv, "_called"):
            _recv._called = True
            return b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        return b""  # 连接关闭

    fake_sock.recv.side_effect = _recv
    with patch("socket.create_connection", return_value=fake_sock):
        result = detect_request_smuggling("127.0.0.1", 80)
    assert result["detected"] is False
    assert result["vuln_type"] == "请求走私"


def test_detect_smuggling_positive_smuggled_marker():
    """响应含 smuggled 标记 → detected=True。"""
    fake_sock = MagicMock()
    fake_sock.__enter__.return_value = fake_sock

    def _recv(n):
        if not hasattr(_recv, "_called"):
            _recv._called = True
            return b"HTTP/1.1 200 OK\r\n\r\nGPOST smuggled=1 response"
        return b""

    fake_sock.recv.side_effect = _recv
    with patch("socket.create_connection", return_value=fake_sock):
        result = detect_request_smuggling("127.0.0.1", 80)
    assert result["detected"] is True
    assert "CL.TE" in result["variants"] or "TE.CL" in result["variants"]
    assert result["severity"] == "high"


def test_detect_smuggling_socket_error_handled():
    """socket 错误不抛异常，返回 detected=False。"""
    with patch("socket.create_connection", side_effect=socket.error("refused")):
        result = detect_request_smuggling("127.0.0.1", 80)
    assert result["detected"] is False


# ============================================================
# 2. JNDI
# ============================================================
def test_build_jndi_payloads_contains_jndi():
    pls = build_jndi_payloads("attacker.oob.com")
    assert pls
    # 至少有一个明文 jndi payload（混淆变体不含字面 jndi 是预期的）
    assert any("jndi" in p.lower() for p in pls)
    assert all("attacker.oob.com" in p for p in pls)


def test_build_jndi_payloads_protocols():
    pls = build_jndi_payloads("oob.com")
    protocols = set()
    for p in pls:
        if "ldap" in p:
            protocols.add("ldap")
        if "rmi" in p:
            protocols.add("rmi")
        if "dns" in p:
            protocols.add("dns")
    assert {"ldap", "rmi", "dns"} <= protocols


def test_detect_jndi_injection_generates_requests():
    async def fake_req(method, url, params):
        return MagicMock()
    results = detect_jndi_injection({"id": "1"}, "oob.com", fake_req)
    assert results
    assert all(r["sent"] for r in results)
    assert all(r["verify_via"] == "DNS callback on oob.com" for r in results)
    # 每个参数 × 4 个 payload
    assert len(results) == 4


# ============================================================
# 3. 反序列化
# ============================================================
def test_build_deserialization_payloads_multi_lang():
    pls = build_deserialization_payloads("oob.com")
    assert set(pls.keys()) == {"java", "python", "php", "nodejs"}
    for lang, payloads in pls.items():
        assert payloads, f"{lang} 应有 payload"


def test_detect_insecure_deserialization_generates_payloads():
    async def fake_req(method, url, body):
        return MagicMock()
    results = detect_insecure_deserialization("{}", "oob.com", fake_req)
    assert results
    langs = {r["lang"] for r in results}
    assert {"java", "python", "php", "nodejs"} <= langs
    assert all(r["sent"] for r in results)


# ============================================================
# 4. OAuth-OIDC
# ============================================================
def test_oauth_no_state_risks_csrf():
    result = analyze_oauth_oidc({"client_id": "x", "redirect_uri": "https://app/cb"})
    assert result["checks"]["state_present"]["passed"] is False
    assert "CSRF" in result["risks"][0]
    assert result["severity"] == "high"


def test_oauth_secure_flow():
    result = analyze_oauth_oidc({
        "client_id": "x",
        "redirect_uri": "https://app/cb",
        "state": "abc123",
        "code_challenge": "xyz",
    }, token_response={"sub": "user123", "access_token": "tok"})
    for name, c in result["checks"].items():
        assert c["passed"], f"{name} 应通过: {c['detail']}"
    assert result["risks"] == []
    assert result["severity"] == "info"


def test_oauth_client_secret_leak():
    result = analyze_oauth_oidc(
        {"client_id": "x"},
        client_config={"client_secret": "supersecretkey123"},
    )
    assert result["checks"]["client_secret_protected"]["passed"] is False
    assert any("client_secret" in r for r in result["risks"])


def test_oauth_token_not_bound():
    result = analyze_oauth_oidc(
        {"state": "a"},
        token_response={"access_token": "tok"},  # 缺 sub/user_id
    )
    assert result["checks"]["token_bound_to_user"]["passed"] is False
    assert any("未绑定" in r for r in result["risks"])
