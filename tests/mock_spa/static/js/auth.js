/**
 * auth.js — 认证状态管理
 *
 * 此文件包含 js_analyzer.py 需要解析的以下模式：
 * - localStorage.getItem/setItem("token"/"auth"/...)  → _STORAGE_KEY_DIRECT_PATTERN
 * - sessionStorage.getItem/setItem("session"/...)     → _STORAGE_KEY_DIRECT_PATTERN
 * - 变量赋值形式的 storage key                        → _STORAGE_KEY_VAR_PATTERN
 */

// ===== Token 管理（匹配 _STORAGE_KEY_DIRECT_PATTERN） =====

var TOKEN_KEY = "auth_token";
var REFRESH_TOKEN_KEY = "refresh_token";
var SESSION_KEY = "session_id";

// localStorage 操作
function getToken() {
    return localStorage.getItem("auth_token");
}

function setToken(token) {
    localStorage.setItem("auth_token", token);
}

function getRefreshToken() {
    return localStorage.getItem("refresh_token");
}

function setRefreshToken(token) {
    localStorage.setItem("refresh_token", token);
}

// sessionStorage 操作
function getSessionId() {
    return sessionStorage.getItem("session_id");
}

function setSessionId(sid) {
    sessionStorage.setItem("session_id", sid);
}

// ===== 认证状态检查 =====

function isLoggedIn() {
    var token = localStorage.getItem("auth_token");
    return token !== null && token !== undefined && token !== "";
}

function getAuthState() {
    return {
        token: localStorage.getItem("auth_token"),
        refreshToken: localStorage.getItem("refresh_token"),
        sessionId: sessionStorage.getItem("session_id"),
        loginType: localStorage.getItem("login_type"),
    };
}

// ===== 登录/登出逻辑 =====

function doLogin(username, password) {
    return axios.post("/api/auth/login", {
        username: username,
        password: password,
    }).then(function(res) {
        if (res.data.code === 0) {
            var data = res.data.data;
            localStorage.setItem("auth_token", data.token);
            localStorage.setItem("login_type", "password");
            sessionStorage.setItem("session_id", data.session_id || "mock_session");
        }
        return res.data;
    });
}

function doLogout() {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("login_type");
    sessionStorage.removeItem("session_id");
    window.location.href = "/login";
}

// ===== JWT 解析（模拟） =====

function parseJwt(token) {
    try {
        var parts = token.split(".");
        if (parts.length !== 3) return null;
        var payload = atob(parts[1]);
        return JSON.parse(payload);
    } catch (e) {
        return null;
    }
}

function isTokenExpired() {
    var token = localStorage.getItem("auth_token");
    if (!token) return true;
    var payload = parseJwt(token);
    if (!payload || !payload.exp) return true;
    return Date.now() >= payload.exp * 1000;
}

// ===== 权限检查 =====

function hasPermission(perm) {
    var role = localStorage.getItem("user_role");
    if (role === "admin") return true;
    var perms = JSON.parse(localStorage.getItem("permissions") || "[]");
    return perms.indexOf(perm) !== -1;
}
