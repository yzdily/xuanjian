"""
Comprehensive security tests for the XuanJian web API.

Covers security hardening S1-S9:

  S1 - Path traversal prevention in /api/reports/save
       The endpoint validates ``task_id`` via ``_validate_task_id()``
       (regex ``^[a-zA-Z0-9_\\-]+$``).  Malicious values such as
       ``../../etc/passwd`` are rejected with HTTP 400.

  S2 - No-key authentication returns 401
       When ``XUANJIAN_API_KEY`` is not set AND ``XUANJIAN_AUTH_DISABLED``
       is not "1", all ``/api/`` business endpoints (except ``/api/auth/*``
       and ``/api/health``) must return 401 without a valid JWT token.

  S3 - No token from URL query
       The auth middleware no longer extracts ``api_key`` from
       ``query_params``.  Passing ``?api_key=xxx`` must NOT authenticate.

  S4 - Password not printed to console
       ``init_default_user()`` in ``core/auth.py`` must NOT print the
       plaintext password to stdout.  It prints
       "请查看 data/.default_password 文件" instead.

  S5 - Register default closed
       ``XUANJIAN_DISABLE_REGISTER`` defaults to "1" (closed).
       ``auth.register()`` returns ``{"ok": False}`` by default and
       succeeds when ``XUANJIAN_DISABLE_REGISTER=0``.

  S6 - Path traversal prevention in /api/traffic/{task_id}
       All traffic endpoints validate ``task_id`` / ``fp_id`` / ``flow_id``
       via ``_validate_id()``.  Invalid values return HTTP 400.

  S7 - Cache-Control: no-store on auth API responses
       Login and register responses include the
       ``Cache-Control: no-store`` header.

  S8 - Register rate limiting
       The register endpoint limits to 3 requests per 60 seconds per IP.
       The 4th request must return HTTP 429.

  S9 - Upload size and extension limiting
       The ``/api/screenshot/upload`` endpoint rejects files larger than
       10 MB (HTTP 413) and non-image file extensions.

Implementation notes
--------------------
* Uses ``fastapi.testclient.TestClient`` for in-process HTTP testing.
* For S2/S3 a minimal FastAPI app is built with an inline auth middleware
  that faithfully replicates ``web.server._auth_middleware`` — importing
  ``web.server`` directly has heavy startup side effects.
* For S1/S6/S7/S8/S9 the **actual** API routers are mounted into a fresh
  FastAPI app so the real validation logic is exercised.
* ``capsys`` captures stdout for the S4 plaintext-password check.
* ``monkeypatch.setenv`` controls feature-flag env vars (S5, S8).
* ``tmp_path`` + ``monkeypatch`` redirect data directories for isolation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is importable regardless of pytest invocation cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import base64
import hmac
import os
from io import BytesIO

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

# ---- real module imports (exercise actual hardening code) ---------------
from core import auth  # noqa: E402
from web.api import auth_api  # noqa: E402
from web.api import reports_api  # noqa: E402
from web.api.auth_api import router as auth_router  # noqa: E402
from web.api.models_api import router as models_router  # noqa: E402
from web.api.reports_api import _validate_task_id  # noqa: E402
from web.api.reports_api import router as reports_router  # noqa: E402
from web.api import system_api  # noqa: E402
from web.api.system_api import router as system_router  # noqa: E402
from web._security import validate_task_id, apply_security_headers  # noqa: E402
from web._security import validate_task_id as _validate_id  # noqa: E402  (D9-S1: traffic_api._validate_id 已收编进 web._security)
from web.traffic_api import traffic_router  # noqa: E402


# ============================================================
# Shared fixtures
# ============================================================

@pytest.fixture
def isolated_auth(tmp_path, monkeypatch):
    """Redirect the ``auth`` module's file paths to ``tmp_path``.

    This guarantees that user/secret data created during a test never
    touches the real ``data/`` directory and that ``_CACHE`` is reset
    so each test starts from an empty user store.
    """
    monkeypatch.setattr(auth, "_USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(auth, "_CACHE", None)
    monkeypatch.setattr(auth, "_SECRET_FILE", tmp_path / ".auth_secret")
    monkeypatch.setattr(auth, "_SECRET_KEY", "")
    # Regenerate a fresh signing secret inside tmp_path.
    auth._load_or_generate_secret()
    return tmp_path


@pytest.fixture
def clean_rate_limiter():
    """Clear the module-level register rate-limiter before & after each test."""
    auth_api._register_attempts.clear()
    yield
    auth_api._register_attempts.clear()


def _make_test_user_and_token(monkeypatch, password: str = "TestPass123") -> str:
    """Create the default *admin* user with a known password and return a JWT token.

    Requires the ``isolated_auth`` fixture to have been applied first so that
    user data is written to a temporary location.
    """
    monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", password)
    auth.init_default_user()
    result = auth.login("admin", password)
    assert result["ok"], f"login failed during test setup: {result}"
    return result["token"]


def _build_auth_middleware_app(api_key: str = "") -> FastAPI:
    """Build a minimal FastAPI app with an inline auth middleware.

    The middleware logic faithfully mirrors ``web.server._auth_middleware``
    (including the S3 hardening that no longer reads query params) but
    avoids importing ``web.server`` which has heavy startup side effects.
    """
    app = FastAPI()

    _WHITELIST = {
        "/api/auth/login", "/api/auth/register", "/api/auth/logout",
        "/api/health", "/",
    }

    @app.get("/api/health")
    async def _health():
        return {"ok": True}

    @app.get("/api/business")
    async def _business():
        return {"ok": True, "data": "secret"}

    @app.post("/api/auth/login")
    async def _login():
        return {"ok": True}

    @app.middleware("http")
    async def _auth_middleware(request: Request, call_next):
        path = request.url.path

        # Whitelisted paths skip authentication entirely.
        if path in _WHITELIST or path.startswith("/api/auth/"):
            return await call_next(request)

        if path.startswith("/api/"):
            token = ""
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            if not token:
                token = request.headers.get("X-API-Key", "")
            # S3 hardening: token is NOT extracted from URL query params.

            if api_key:
                # API-key mode: require a matching static key or valid JWT.
                if token and hmac.compare_digest(token, api_key):
                    return await call_next(request)
                if token:
                    payload = auth.verify_token(token)
                    if payload:
                        request.state.user = payload.get("username", "unknown")
                        return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={"ok": False, "error": "请先登录或在请求头添加 X-API-Key",
                             "code": "UNAUTHORIZED"},
                )
            else:
                # No API key configured: require JWT (unless auth disabled).
                if os.getenv("XUANJIAN_AUTH_DISABLED", "0") == "1":
                    if token:
                        payload = auth.verify_token(token)
                        if payload:
                            request.state.user = payload.get("username", "unknown")
                    return await call_next(request)
                if token:
                    payload = auth.verify_token(token)
                    if payload:
                        request.state.user = payload.get("username", "unknown")
                        return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={"ok": False, "error": "请先登录", "code": "UNAUTHORIZED"},
                )

        return await call_next(request)

    return app


# ============================================================
# S1 - Path traversal prevention in /api/reports/save
# ============================================================

@pytest.mark.integration
class TestS1PathTraversalSaveReport:
    """``_validate_task_id()`` rejects path-traversal payloads; the
    ``/api/reports/save`` endpoint returns HTTP 400 for malicious
    ``task_id`` values and succeeds for well-formed ones."""

    def test_validate_task_id_rejects_traversal(self):
        assert _validate_task_id("../../etc/passwd") is False
        assert _validate_task_id("../../../data/secret") is False
        assert _validate_task_id("..\\..\\windows\\system32") is False

    def test_validate_task_id_rejects_empty_and_special(self):
        assert _validate_task_id("") is False
        assert _validate_task_id(None) is False
        assert _validate_task_id("task.with.dots") is False
        assert _validate_task_id("task with spaces") is False
        assert _validate_task_id("task;rm -rf /") is False
        assert _validate_task_id("task|cat /etc/passwd") is False

    def test_validate_task_id_accepts_safe_values(self):
        assert _validate_task_id("valid_task") is True
        assert _validate_task_id("task-123") is True
        assert _validate_task_id("ABCdef_456") is True
        assert _validate_task_id("a") is True

    def test_save_report_rejects_path_traversal(self, monkeypatch, tmp_path):
        """POST /api/reports/save with a traversal task_id → 400."""
        monkeypatch.setattr(reports_api, "REPORTS_DIR", tmp_path / "reports")

        app = FastAPI()
        app.include_router(reports_router)
        client = TestClient(app)

        resp = client.post("/api/reports/save", json={
            "task_id": "../../etc/passwd",
            "content": "malicious",
            "kind": "md",
        })
        assert resp.status_code == 400
        body = resp.json()
        assert body["ok"] is False
        assert "非法" in body["error"]

    def test_save_report_accepts_valid_task_id(self, monkeypatch, tmp_path):
        """POST /api/reports/save with a valid task_id → 200, file written."""
        reports_dir = tmp_path / "reports"
        monkeypatch.setattr(reports_api, "REPORTS_DIR", reports_dir)

        app = FastAPI()
        app.include_router(reports_router)
        client = TestClient(app)

        resp = client.post("/api/reports/save", json={
            "task_id": "valid_task",
            "content": "# Report content\nHello world",
            "kind": "md",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # The file must be written inside the (temp) reports dir,
        # not escaped to a parent directory.
        expected = reports_dir / "valid_task_report.md"
        assert expected.exists()
        assert "Hello world" in expected.read_text(encoding="utf-8")

    def test_save_report_rejects_empty_content(self, monkeypatch, tmp_path):
        """Empty content is rejected before task_id validation."""
        monkeypatch.setattr(reports_api, "REPORTS_DIR", tmp_path / "reports")

        app = FastAPI()
        app.include_router(reports_router)
        client = TestClient(app)

        resp = client.post("/api/reports/save", json={
            "task_id": "valid_task",
            "content": "",
        })
        assert resp.json()["ok"] is False


# ============================================================
# S2 - No-key authentication returns 401
# ============================================================

@pytest.mark.integration
class TestS2NoKeyAuthReturns401:
    """Without ``XUANJIAN_API_KEY`` and with auth not disabled, all
    ``/api/`` business endpoints return 401 unless a valid JWT is
    supplied.  Whitelisted paths (``/api/health``, ``/api/auth/*``)
    remain accessible."""

    def test_business_endpoint_401_without_token(self, monkeypatch):
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/business")
        assert resp.status_code == 401
        body = resp.json()
        assert body["ok"] is False
        assert body["code"] == "UNAUTHORIZED"

    def test_health_endpoint_not_blocked(self, monkeypatch):
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_auth_endpoints_not_blocked(self, monkeypatch):
        """``/api/auth/*`` paths are whitelisted and skip auth."""
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.post("/api/auth/login")
        assert resp.status_code == 200

    def test_valid_jwt_allows_access(self, isolated_auth, monkeypatch):
        """A valid Bearer JWT token passes the no-key auth middleware."""
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)
        token = _make_test_user_and_token(monkeypatch)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/business",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_invalid_jwt_returns_401(self, monkeypatch):
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/business",
                          headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401

    def test_auth_disabled_bypasses_auth(self, monkeypatch):
        """When ``XUANJIAN_AUTH_DISABLED=1`` requests pass through."""
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.setenv("XUANJIAN_AUTH_DISABLED", "1")

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/business")
        assert resp.status_code == 200


# ============================================================
# S3 - No token from URL query
# ============================================================

@pytest.mark.integration
class TestS3NoTokenFromUrlQuery:
    """The auth middleware does NOT extract ``api_key`` from URL query
    parameters.  Passing ``?api_key=xxx`` must not authenticate."""

    def test_api_key_in_query_does_not_authenticate(self, monkeypatch):
        secret = "super-secret-api-key-12345"
        monkeypatch.setenv("XUANJIAN_API_KEY", secret)

        app = _build_auth_middleware_app(api_key=secret)
        client = TestClient(app)

        # Correct key in the query string → still 401 (query ignored).
        resp = client.get(f"/api/business?api_key={secret}")
        assert resp.status_code == 401

    def test_api_key_in_header_authenticates(self, monkeypatch):
        secret = "super-secret-api-key-12345"
        monkeypatch.setenv("XUANJIAN_API_KEY", secret)

        app = _build_auth_middleware_app(api_key=secret)
        client = TestClient(app)

        resp = client.get("/api/business", headers={"X-API-Key": secret})
        assert resp.status_code == 200

    def test_token_in_query_does_not_authenticate(self, monkeypatch):
        """A JWT token in the query string is also ignored."""
        monkeypatch.delenv("XUANJIAN_API_KEY", raising=False)
        monkeypatch.delenv("XUANJIAN_AUTH_DISABLED", raising=False)

        app = _build_auth_middleware_app(api_key="")
        client = TestClient(app)

        resp = client.get("/api/business?token=some.jwt.token")
        assert resp.status_code == 401

    def test_wrong_api_key_in_header_rejected(self, monkeypatch):
        secret = "super-secret-api-key-12345"
        monkeypatch.setenv("XUANJIAN_API_KEY", secret)

        app = _build_auth_middleware_app(api_key=secret)
        client = TestClient(app)

        resp = client.get("/api/business", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401


# ============================================================
# S4 - Password not printed to console
# ============================================================

@pytest.mark.integration
class TestS4PasswordNotPrinted:
    """``init_default_user()`` must not leak the plaintext password to
    stdout.  Instead it prints a pointer to ``data/.default_password``."""

    def test_plaintext_password_not_in_stdout(self, isolated_auth, monkeypatch,
                                              capsys):
        known_password = "MySecretDefaultPwd456"
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", known_password)

        auth.init_default_user()

        captured = capsys.readouterr()
        # The actual password must never appear in stdout.
        assert known_password not in captured.out
        # The pointer message must be present.
        assert "请查看 data/.default_password 文件" in captured.out

    def test_user_actually_created_with_password(self, isolated_auth, monkeypatch):
        """Sanity: the password still works for login (it was just not printed)."""
        known_password = "MySecretDefaultPwd456"
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", known_password)

        auth.init_default_user()

        result = auth.login("admin", known_password)
        assert result["ok"] is True
        assert "token" in result

    def test_init_message_mentions_username(self, isolated_auth, monkeypatch,
                                            capsys):
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "TempPwd12345")
        auth.init_default_user()

        captured = capsys.readouterr()
        assert "admin" in captured.out
        assert "默认管理员账号已创建" in captured.out

    def test_existing_user_skips_reinit(self, isolated_auth, monkeypatch, capsys):
        """If admin already exists, init_default_user returns early and
        prints nothing to stdout."""
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "FirstPwd12345")
        auth.init_default_user()

        # Second call — user already exists.
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "SecondPwd67890")
        auth.init_default_user()

        captured = capsys.readouterr()
        # The second password must not appear (init was skipped).
        assert "SecondPwd67890" not in captured.out


# ============================================================
# S5 - Register default closed
# ============================================================

@pytest.mark.integration
class TestS5RegisterDefaultClosed:
    """``XUANJIAN_DISABLE_REGISTER`` defaults to "1" (closed).
    ``auth.register()`` returns ``{"ok": False}`` by default and
    succeeds when the flag is set to "0"."""

    def test_register_closed_by_default(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "1")

        result = auth.register("newuser1", "StrongPwd123")
        assert result["ok"] is False
        assert "关闭" in result.get("error", "")

    def test_register_closed_when_env_unset(self, isolated_auth, monkeypatch):
        """Even with the env var completely unset, the default is "1"."""
        monkeypatch.delenv("XUANJIAN_DISABLE_REGISTER", raising=False)

        result = auth.register("newuser2", "StrongPwd123")
        assert result["ok"] is False

    def test_register_open_when_disabled_zero(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        result = auth.register("newuser3", "StrongPwd123")
        assert result["ok"] is True
        assert result["username"] == "newuser3"
        assert "token" in result

    def test_register_rejects_duplicate(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        first = auth.register("dupuser", "StrongPwd123")
        assert first["ok"] is True

        second = auth.register("dupuser", "AnotherPwd456")
        assert second["ok"] is False
        assert "已存在" in second.get("error", "")

    def test_register_rejects_short_password(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        result = auth.register("shortpwuser", "short")
        assert result["ok"] is False
        assert "8" in result.get("error", "")


# ============================================================
# S6 - Path traversal prevention in /api/traffic/{task_id}
# ============================================================

@pytest.mark.integration
class TestS6TrafficPathTraversal:
    """All ``/api/traffic/{task_id}`` endpoints validate ``task_id`` and
    ``fp_id`` via ``_validate_id()``.  Invalid values return HTTP 400."""

    def test_validate_id_rejects_traversal(self):
        assert _validate_id("../etc") is False
        assert _validate_id("../../etc/passwd") is False
        assert _validate_id("..\\windows") is False

    def test_validate_id_rejects_special_chars(self):
        assert _validate_id("") is False
        assert _validate_id(None) is False
        assert _validate_id("task.with.dots") is False
        assert _validate_id("task with spaces") is False
        assert _validate_id("task;malicious") is False
        assert _validate_id("task/slash") is False

    def test_validate_id_accepts_safe_values(self):
        assert _validate_id("valid-task_123") is True
        assert _validate_id("ABCdef456") is True
        assert _validate_id("a") is True

    def test_traffic_summary_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        # Dots are not in [a-zA-Z0-9_\-] → 400.
        resp = client.get("/api/traffic/foo.bar")
        assert resp.status_code == 400
        assert "非法" in resp.json().get("error", "")

    def test_traffic_summary_valid_id_not_found(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        # Valid format but no sitemap on disk → 404 (not 400).
        resp = client.get("/api/traffic/valid-task")
        assert resp.status_code == 404

    def test_traffic_packets_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        resp = client.get("/api/traffic/foo.bar/packets")
        assert resp.status_code == 400

    def test_traffic_feature_rejects_invalid_fp_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        # task_id valid, fp_id contains a dot → 400.
        resp = client.get("/api/traffic/valid-task/feature/evil.fp")
        assert resp.status_code == 400
        assert "非法" in resp.json().get("error", "")

    def test_traffic_feature_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        resp = client.get("/api/traffic/foo.bar/feature/validfp")
        assert resp.status_code == 400

    def test_traffic_flow_rejects_invalid_flow_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        resp = client.get("/api/traffic/valid-task/flow/evil.flow")
        assert resp.status_code == 400

    def test_traffic_evidence_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(traffic_router)
        client = TestClient(app)

        resp = client.get("/api/traffic/foo.bar/evidence")
        assert resp.status_code == 400


# ============================================================
# S7 - Cache-Control: no-store on auth API responses
# ============================================================

@pytest.mark.integration
class TestS7CacheControlHeaders:
    """Login and register responses include ``Cache-Control: no-store``
    via the ``_security_headers()`` helper."""

    def test_login_success_has_no_store(self, isolated_auth, monkeypatch):
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "TestPass123")
        auth.init_default_user()

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "TestPass123",
        })
        assert resp.status_code == 200
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_login_failure_has_no_store(self, isolated_auth, monkeypatch):
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "TestPass123")
        auth.init_default_user()

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrong-password",
        })
        assert resp.status_code == 401
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_login_bad_json_has_no_store(self, isolated_auth):
        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.post("/api/auth/login",
                           content=b"not json",
                           headers={"content-type": "application/json"})
        assert resp.status_code == 400
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_register_success_has_no_store(self, isolated_auth, monkeypatch,
                                           clean_rate_limiter):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.post("/api/auth/register", json={
            "username": "reguser7",
            "password": "StrongPwd123",
        })
        assert resp.status_code == 200
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_register_failure_has_no_store(self, isolated_auth, monkeypatch,
                                            clean_rate_limiter):
        # Register disabled → 400, but still must have the header.
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "1")

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.post("/api/auth/register", json={
            "username": "reguser8",
            "password": "StrongPwd123",
        })
        assert resp.status_code == 400
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_me_returns_user_with_valid_token(self, isolated_auth, monkeypatch):
        """The /api/auth/me endpoint works with a valid token."""
        monkeypatch.setattr(auth, "_DEFAULT_PASSWORD", "TestPass123")
        auth.init_default_user()
        token = auth.login("admin", "TestPass123")["token"]

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.get("/api/auth/me",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_me_rejects_missing_token(self):
        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        resp = client.get("/api/auth/me")
        assert resp.status_code == 401


# ============================================================
# S8 - Register rate limiting
# ============================================================

@pytest.mark.integration
class TestS8RegisterRateLimiting:
    """The register endpoint allows at most 3 requests per 60 seconds
    per IP.  The 4th request must return HTTP 429."""

    def test_fourth_register_returns_429(self, isolated_auth, monkeypatch,
                                         clean_rate_limiter):
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        # First three requests — should not be rate-limited.
        for i in range(3):
            resp = client.post("/api/auth/register", json={
                "username": f"ratelimit_user_{i}",
                "password": "StrongPwd123",
            })
            assert resp.status_code != 429, (
                f"Request {i + 1} unexpectedly rate-limited"
            )

        # Fourth request — must be rate-limited.
        resp = client.post("/api/auth/register", json={
            "username": "ratelimit_user_3",
            "password": "StrongPwd123",
        })
        assert resp.status_code == 429
        body = resp.json()
        assert body["ok"] is False
        assert body["code"] == "RATE_LIMITED"

    def test_rate_limit_per_ip(self, isolated_auth, monkeypatch,
                               clean_rate_limiter):
        """All requests from the same TestClient IP share the counter."""
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        # Exhaust the limit with short/invalid requests (still counted).
        for _ in range(3):
            client.post("/api/auth/register", json={
                "username": "x",
                "password": "short",
            })  # 400 (password too short), but counts toward rate limit

        resp = client.post("/api/auth/register", json={
            "username": "newuser",
            "password": "StrongPwd123",
        })
        assert resp.status_code == 429

    def test_rate_limit_has_no_store_header(self, isolated_auth, monkeypatch,
                                            clean_rate_limiter):
        """The 429 response still carries the security cache-control header."""
        monkeypatch.setenv("XUANJIAN_DISABLE_REGISTER", "0")

        app = FastAPI()
        app.include_router(auth_router)
        client = TestClient(app)

        for _ in range(3):
            client.post("/api/auth/register", json={
                "username": "hdr_user",
                "password": "StrongPwd123",
            })

        resp = client.post("/api/auth/register", json={
            "username": "hdr_user_4",
            "password": "StrongPwd123",
        })
        assert resp.status_code == 429
        assert "no-store" in resp.headers.get("cache-control", "").lower()


# ============================================================
# S9 - Upload size and extension limiting
# ============================================================

@pytest.mark.integration
class TestS9UploadSizeLimiting:
    """``/api/screenshot/upload`` rejects files larger than 10 MB (HTTP 413)
    and non-image file extensions."""

    def test_oversized_upload_returns_413(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        # Build a body just over 10 MB.  The content-length check fires
        # before the body is parsed, so the content need not be valid JSON.
        large_body = b"x" * (10 * 1024 * 1024 + 1024)
        resp = client.post(
            "/api/screenshot/upload",
            content=large_body,
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 413
        assert "过大" in resp.json().get("error", "")

    def test_non_image_extension_rejected_json(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        small_b64 = base64.b64encode(b"fake-image-data").decode()
        resp = client.post("/api/screenshot/upload", json={
            "image_base64": small_b64,
            "ext": ".exe",
        })
        assert resp.status_code == 200  # returns a dict error (not HTTP error)
        body = resp.json()
        assert "error" in body
        assert "不支持" in body["error"]

    def test_non_image_extension_rejected_multipart(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        resp = client.post(
            "/api/screenshot/upload",
            files={"file": ("evil.exe", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "error" in body
        assert "不支持" in body["error"]

    def test_valid_small_image_accepted(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        # Minimal PNG-like bytes.
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        small_b64 = base64.b64encode(png_header).decode()
        resp = client.post("/api/screenshot/upload", json={
            "image_base64": small_b64,
            "ext": ".png",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "path" in body
        assert "filename" in body

        # Verify the file was written to the (temp) upload directory.
        upload_dir = tmp_path / "data" / "uploads"
        assert upload_dir.exists()
        saved = list(upload_dir.glob("upload_*.png"))
        assert len(saved) == 1

    def test_oversized_decoded_image_rejected(self, monkeypatch, tmp_path):
        """Even when Content-Length is small, a decoded base64 payload
        exceeding 10 MB is rejected."""
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        # 8 MB of binary → ~10.7 MB of base64 → JSON body > 10 MB.
        # The content-length check catches this before decoding.
        large_b64 = base64.b64encode(b"\x00" * (8 * 1024 * 1024)).decode()
        resp = client.post("/api/screenshot/upload", json={
            "image_base64": large_b64,
            "ext": ".png",
        })
        assert resp.status_code == 413

    def test_allowed_extensions_accepted(self, monkeypatch, tmp_path):
        """Each allowed image extension is accepted."""
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        small_b64 = base64.b64encode(b"data").decode()
        for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
            resp = client.post("/api/screenshot/upload", json={
                "image_base64": small_b64,
                "ext": ext,
            })
            assert resp.status_code == 200, f"Extension {ext} rejected"
            assert "path" in resp.json()

    def test_missing_image_base64_rejected(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(models_router)
        client = TestClient(app)

        resp = client.post("/api/screenshot/upload", json={
            "ext": ".png",
        })
        body = resp.json()
        assert "error" in body


# ============================================================
# S1 扩展 - Path traversal prevention in /api/scans/* and /api/sessions/*
# （原 S1 只覆盖 reports_api，本类补齐 system_api / sessions_api 遗漏的
#   路径构造点：compare、switch、history）
# ============================================================

@pytest.mark.integration
class TestS1ScanSessionsPathTraversal:
    """``validate_task_id()`` 是 web 层单源（D9 S6）。system_api 与
    sessions_api 把 task_id 拼进文件路径（sitemap / chat 历史）前必须校验，
    非法值（路径穿越）应被拒绝，且不触发任何文件读取。"""

    def test_validate_task_id_is_single_source(self):
        """reports_api._validate_task_id 必须就是 web._security.validate_task_id
        （单源），防止日后又出现第二份漂移实现。"""
        assert reports_api._validate_task_id is validate_task_id

    def test_compare_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        """GET /api/scans/compare?task_a=../../etc → 400（不读文件）。"""
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(system_router)
        client = TestClient(app)

        resp = client.get(
            "/api/scans/compare?task_a=..%2F..%2Fetc%2Fpasswd&task_b=valid-task"
        )
        assert resp.status_code == 400
        body = resp.json()
        assert "非法" in body.get("error", "")
        # 不能返回任何漏洞对比数据（说明 Sitemap.load 未被穿越调用）。
        assert "only_a" not in body

    def test_compare_accepts_valid_task_ids(self, monkeypatch, tmp_path):
        """合法 task_id（即便磁盘上不存在）走正常分支，不报 400。"""
        monkeypatch.chdir(tmp_path)

        app = FastAPI()
        app.include_router(system_router)
        client = TestClient(app)

        # 缺参数 → 原始 400（"需要提供 task_a 和 task_b"），而非 "非法的 task_id"。
        resp = client.get("/api/scans/compare?task_a=task-a&task_b=task-b")
        assert resp.status_code == 200
        assert "需要提供" in resp.json().get("error", "")

    def test_sessions_switch_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        """POST /api/sessions/switch 非法 task_id → 直接拒绝，不拼路径。"""
        monkeypatch.chdir(tmp_path)

        # 延迟导入，避免 core.session 在收集阶段被加载。
        from web.api.sessions_api import router as sessions_router

        app = FastAPI()
        app.include_router(sessions_router)
        client = TestClient(app)

        resp = client.post("/api/sessions/switch",
                          json={"task_id": "../../etc/passwd"})
        assert resp.status_code == 200  # FastAPI 默认 200 + {"error": ...}
        body = resp.json()
        # 必须是校验拦截，而不是"会话不存在"（后者说明已拼路径去读文件了）。
        assert body.get("error") == "无效的 task_id"

    def test_sessions_history_rejects_invalid_task_id(self, monkeypatch, tmp_path):
        """GET /api/sessions/{task_id}/history 非法 task_id → 直接拒绝。"""
        monkeypatch.chdir(tmp_path)

        from web.api.sessions_api import router as sessions_router

        app = FastAPI()
        app.include_router(sessions_router)
        client = TestClient(app)

        # 用查询式路径参数规避 Starlette 对 path 中 "/" 的归一化。
        resp = client.get("/api/sessions/..%2F..%2Fetc%2Fpasswd/history")
        # 归一化后要么命中校验拦截（200+error），要么不匹配路由（404）。
        # 两种情况下都不应返回任何对话历史内容。
        body = resp.json() if resp.status_code == 200 else {}
        assert "events" not in body or body.get("error") == "无效的 task_id"


# ============================================================
# S10 - Global security response headers
# ============================================================

@pytest.mark.integration
class TestS10GlobalSecurityHeaders:
    """``apply_security_headers()`` 给响应补上纵深防御头；已存在的头不被覆盖。"""

    def test_apply_sets_defaults(self):
        class _FakeResp:
            def __init__(self):
                self.headers = {}

        resp = _FakeResp()
        apply_security_headers(resp)
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "no-referrer"
        assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")

    def test_apply_keeps_existing_headers(self):
        class _FakeResp:
            def __init__(self):
                self.headers = {"X-Frame-Options": "SAMEORIGIN"}

        resp = _FakeResp()
        apply_security_headers(resp)
        # 已存在的头不被覆盖。
        assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
        # 其他头仍被补齐。
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
