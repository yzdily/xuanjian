/**
 * api.js — Axios 配置与 API 调用定义
 *
 * 此文件包含 js_analyzer.py 需要解析的以下模式：
 * - axios.create({baseURL: "..."})  → _AXIOS_BASEURL_PATTERN
 * - const BASE_URL = "..."          → _BASEURL_ASSIGN_PATTERN
 * - fetch("/api/...")               → _PATH_PATTERNS / API call extraction
 * - axios.get("/api/...")           → API call extraction
 */

// ===== axios baseURL 配置（匹配 _AXIOS_BASEURL_PATTERN） =====
const http = axios.create({
    baseURL: "/api/v1",
    timeout: 15000,
    headers: {
        "Content-Type": "application/json",
    },
});

// 第二个 axios 实例（不同 baseURL）
const httpV2 = axios.create({
    baseURL: "/api/v2",
    timeout: 10000,
});

// ===== 通用 baseURL 赋值（匹配 _BASEURL_ASSIGN_PATTERN） =====
const BASE_URL = "/api";
window.API_BASE = "/api/v1";
config.apiUrl = "/api/v2";

// ===== Axios 请求拦截器（注入 token） =====
http.interceptors.request.use(
    function(config) {
        var token = localStorage.getItem("auth_token");
        if (token) {
            config.headers["Authorization"] = "Bearer " + token;
        }
        return config;
    },
    function(error) {
        return Promise.reject(error);
    }
);

// ===== Axios 响应拦截器（401 跳转登录） =====
http.interceptors.response.use(
    function(response) {
        return response.data;
    },
    function(error) {
        if (error.response && error.response.status === 401) {
            localStorage.removeItem("auth_token");
            window.location.href = "/login";
        }
        return Promise.reject(error);
    }
);

// ===== API 调用定义（匹配 _PATH_PATTERNS） =====

// 认证相关
function login(username, password) {
    return http.post("/auth/login", { username: username, password: password });
}

function getUserInfo() {
    return http.get("/auth/userinfo");
}

function logout() {
    return http.post("/auth/logout");
}

// 用户管理
function getUserList(params) {
    return http.get("/users/list", { params: params });
}

function getUserDetail(id) {
    return http.get("/users/detail", { params: { id: id } });
}

function createUser(data) {
    return http.post("/users/create", data);
}

function updateUser(id, data) {
    return http.put("/users/update", { id: id, ...data });
}

function deleteUser(id) {
    return http.delete("/users/delete", { params: { id: id } });
}

// V2 版本 API（使用 httpV2 实例）
function exportData() {
    return httpV2.get("/export/data");
}

function importData(file) {
    return httpV2.post("/import/data", file);
}

// 系统配置
function getSystemConfig() {
    return http.get("/system/config");
}

function updateSystemConfig(data) {
    return http.post("/system/config", data);
}

// 使用 fetch 的 API 调用（另一类模式）
function fetchDashboard() {
    return fetch("/api/v1/dashboard", {
        headers: {
            "Authorization": "Bearer " + localStorage.getItem("auth_token"),
        },
    }).then(function(res) { return res.json(); });
}

// 公开接口（不需要认证）
function checkHealth() {
    return fetch("/api/public/health").then(function(res) { return res.json(); });
}

// GraphQL 端点
function graphqlQuery(query) {
    return http.post("/graphql", { query: query });
}

// 管理后台接口
function getAdminLogs() {
    return http.get("/admin/logs");
}

// 网关代理接口
function callGateway(service, action) {
    return http.post("/gateway/" + service, { action: action });
}
