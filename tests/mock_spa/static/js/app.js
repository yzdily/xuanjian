/**
 * app.js — SPA 路由配置与应用逻辑
 *
 * 此文件包含：
 * - 前端路由表定义（Vue Router 风格）
 * - 页面渲染逻辑（模拟 SPA 客户端路由）
 * - API 调用触发（模拟真实用户操作产生的流量）
 */

// ===== 路由表定义（Vue Router 风格） =====

var routes = [
    { path: "/dashboard", name: "Dashboard", component: "DashboardPage", meta: { requiresAuth: true } },
    { path: "/users", name: "UserList", component: "UserListPage", meta: { requiresAuth: true } },
    { path: "/users/detail", name: "UserDetail", component: "UserDetailPage", meta: { requiresAuth: true } },
    { path: "/system/config", name: "SystemConfig", component: "SystemConfigPage", meta: { requiresAuth: true } },
    { path: "/export/data", name: "ExportData", component: "ExportDataPage", meta: { requiresAuth: true } },
    { path: "/login", name: "Login", component: "LoginPage", meta: { requiresAuth: false } },
];

// ===== 路由表（history 模式） =====

var router = {
    mode: "history",
    routes: routes,
    current: "/",

    push: function(path) {
        window.history.pushState({}, "", path);
        this.current = path;
        this.render(path);
    },

    render: function(path) {
        var content = document.getElementById("main-content");
        if (!content) return;

        // 检查认证
        var route = routes.find(function(r) { return r.path === path; });
        if (route && route.meta && route.meta.requiresAuth) {
            if (!isLoggedIn()) {
                this.push("/login");
                return;
            }
        }

        // 渲染对应页面
        switch (path) {
            case "/dashboard":
                content.innerHTML = renderDashboard();
                fetchDashboard().then(function(data) {
                    document.getElementById("metrics").innerHTML = JSON.stringify(data.data, null, 2);
                });
                break;
            case "/users":
                content.innerHTML = renderUserList();
                getUserList().then(function(data) {
                    renderUserTable(data.data);
                });
                break;
            case "/users/detail":
                content.innerHTML = renderUserDetail();
                getUserDetail(1).then(function(data) {
                    document.getElementById("user-detail").innerHTML = JSON.stringify(data.data, null, 2);
                });
                break;
            case "/system/config":
                content.innerHTML = renderSystemConfig();
                getSystemConfig().then(function(data) {
                    document.getElementById("config").innerHTML = JSON.stringify(data.data, null, 2);
                });
                break;
            case "/export/data":
                content.innerHTML = renderExport();
                exportData().then(function(data) {
                    document.getElementById("export-result").innerHTML = data.data.export_url;
                });
                break;
            case "/login":
                content.innerHTML = renderLogin();
                break;
            default:
                content.innerHTML = "<div>404 Not Found</div>";
        }

        // 更新侧边栏高亮
        updateSidebar(path);
    },
};

// ===== 页面渲染函数 =====

function renderSidebar() {
    return '<div class="sidebar">' +
        '<a data-route="/dashboard">Dashboard</a>' +
        '<a data-route="/users">Users</a>' +
        '<a data-route="/system/config">System Config</a>' +
        '<a data-route="/export/data">Export</a>' +
        '</div>';
}

function renderDashboard() {
    return '<div class="content">' + renderSidebar() +
        '<div style="flex:1;padding:24px;">' +
        '<div class="card"><h2>Dashboard</h2><pre id="metrics">Loading...</pre></div>' +
        '</div></div>';
}

function renderUserList() {
    return '<div class="content">' + renderSidebar() +
        '<div style="flex:1;padding:24px;">' +
        '<div class="card"><h2>User List</h2>' +
        '<table id="user-table"><thead><tr><th>ID</th><th>Name</th><th>Role</th><th>Email</th></tr></thead>' +
        '<tbody id="user-tbody"></tbody></table></div>' +
        '</div></div>';
}

function renderUserDetail() {
    return '<div class="content">' + renderSidebar() +
        '<div style="flex:1;padding:24px;">' +
        '<div class="card"><h2>User Detail</h2><pre id="user-detail">Loading...</pre></div>' +
        '</div></div>';
}

function renderSystemConfig() {
    return '<div class="content">' + renderSidebar() +
        '<div style="flex:1;padding:24px;">' +
        '<div class="card"><h2>System Config</h2><pre id="config">Loading...</pre></div>' +
        '</div></div>';
}

function renderExport() {
    return '<div class="content">' + renderSidebar() +
        '<div style="flex:1;padding:24px;">' +
        '<div class="card"><h2>Export Data</h2>' +
        '<p>Export URL: <span id="export-result">Loading...</span></p>' +
        '</div></div>';
}

function renderLogin() {
    return '<div class="login-form">' +
        '<h2>Login</h2>' +
        '<input type="text" id="username" placeholder="Username" value="admin">' +
        '<input type="password" id="password" placeholder="Password" value="admin123">' +
        '<button onclick="handleLogin()">Login</button>' +
        '</div>';
}

function renderUserTable(users) {
    var tbody = document.getElementById("user-tbody");
    if (!tbody) return;
    tbody.innerHTML = users.map(function(u) {
        return '<tr><td>' + u.id + '</td><td>' + u.name + '</td>' +
            '<td><span class="badge">' + u.role + '</span></td>' +
            '<td>' + u.email + '</td></tr>';
    }).join("");
}

function updateSidebar(path) {
    var links = document.querySelectorAll(".sidebar a");
    links.forEach(function(a) {
        a.classList.toggle("active", a.dataset.route === path);
    });
}

// ===== 登录处理 =====

function handleLogin() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    doLogin(username, password).then(function(res) {
        if (res.code === 0) {
            router.push("/dashboard");
        } else {
            alert("Login failed: " + res.message);
        }
    });
}

// ===== 初始化 =====

window.addEventListener("popstate", function() {
    router.render(window.location.pathname);
});

// 侧边栏点击事件
document.addEventListener("click", function(e) {
    if (e.target.dataset && e.target.dataset.route) {
        router.push(e.target.dataset.route);
    }
});

// 初始路由
window.addEventListener("DOMContentLoaded", function() {
    var path = window.location.pathname;
    if (path === "/" || path === "") {
        if (isLoggedIn()) {
            router.push("/dashboard");
        } else {
            router.push("/login");
        }
    } else {
        router.render(path);
    }
});
