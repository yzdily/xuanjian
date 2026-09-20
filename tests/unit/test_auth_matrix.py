"""修复 1.4：三身份矩阵 / 凭据域路由 / token↔主体绑定。"""
from __future__ import annotations

import base64
import json

from core.loops.auth_matrix import (
    THREE_IDENTITIES,
    bind_token_userid,
    cred_for,
    decode_jwt_payload,
    identities_covered,
)


def _jwt(payload: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS256'})}.{b64(payload)}.signature"


_REGISTRY = {
    "credential_sets": [
        {
            "id": "CRED-001",
            "auth_type": "cookie",
            "applicable_domains": ["webapp", "data"],
        },
        {
            "id": "CRED-002",
            "auth_type": "bearer",
            "applicable_domains": ["fts", "mock"],
        },
    ]
}


def test_cred_for_matching_domain():
    cred = cred_for("webapp", _REGISTRY)
    assert cred["id"] == "CRED-001"
    assert cred_for("fts", _REGISTRY)["id"] == "CRED-002"


def test_cred_for_mismatch_returns_empty():
    assert cred_for("unknown", _REGISTRY) == {}
    assert cred_for("", _REGISTRY) == {}
    assert cred_for("webapp", None) == {}


def test_decode_jwt_payload():
    assert decode_jwt_payload(_jwt({"sub": "u1"})) == {"sub": "u1"}
    assert decode_jwt_payload("not-a-jwt") is None
    assert decode_jwt_payload("") is None


def test_bind_token_userid_bound():
    token = _jwt({"sub": "u1", "role": "admin"})
    assert bind_token_userid(token, "u1") is True


def test_bind_token_userid_mismatch_signals_unbound():
    token = _jwt({"sub": "u1"})
    # 载荷主体是 u1，却拿来操作 u2 → 未绑定（同 token 换 userid 的绕过特征）
    assert bind_token_userid(token, "u2") is False


def test_bind_token_userid_alternate_subject_keys():
    assert bind_token_userid(_jwt({"user_id": "7"}), "7") is True
    assert bind_token_userid(_jwt({"uid": "7"}), "7") is True
    assert bind_token_userid(_jwt({"account": "bob"}), "bob") is True


def test_bind_token_userid_non_jwt_returns_false():
    assert bind_token_userid("opaque-session-token", "u1") is False


def test_identities_covered():
    assert identities_covered(THREE_IDENTITIES) is True
    assert identities_covered(["noauth", "low"]) is False
    assert identities_covered(None) is False
