/**
 * realtime.js — 实时通信端点定义
 *
 * 此文件包含 js_analyzer.py 需要解析的以下模式：
 * - new WebSocket("ws://...")  → _WEBSOCKET_PATTERN
 * - new WebSocket("wss://...") → _WEBSOCKET_PATTERN
 * - new EventSource("/api/...") → _SSE_PATTERN
 * - new EventSource("https://...") → _SSE_PATTERN
 */

// ===== WebSocket 端点 =====

// 主聊天 WebSocket
var chatWs = new WebSocket("ws://127.0.0.1:9876/ws/chat");

// 安全 WebSocket（wss）
var notifyWs = new WebSocket("wss://127.0.0.1:9876/ws/notifications");

// 相对路径 WebSocket（需要 baseURL 拼接）
var statusWs = new WebSocket("/ws/status");

// ===== WebSocket 事件处理 =====

chatWs.onopen = function(event) {
    console.log("Chat WebSocket connected");
    var token = localStorage.getItem("auth_token");
    chatWs.send(JSON.stringify({ type: "auth", token: token }));
};

chatWs.onmessage = function(event) {
    var msg = JSON.parse(event.data);
    console.log("Received:", msg);
    // 更新 UI
    var chatBox = document.getElementById("chat-box");
    if (chatBox) {
        chatBox.innerHTML += "<div>" + msg.text + "</div>";
    }
};

chatWs.onclose = function(event) {
    console.log("Chat WebSocket closed, reconnecting in 3s...");
    setTimeout(function() {
        chatWs = new WebSocket("ws://127.0.0.1:9876/ws/chat");
    }, 3000);
};

// ===== SSE (Server-Sent Events) 端点 =====

// 通知 SSE
var notifySource = new EventSource("/api/sse/notifications");

notifySource.onmessage = function(event) {
    var data = JSON.parse(event.data);
    console.log("SSE notification:", data);
};

notifySource.onerror = function(event) {
    console.log("SSE connection error, closing...");
    notifySource.close();
};

// 仪表盘实时数据 SSE
var dashboardSource = new EventSource("/api/v1/dashboard/stream");

dashboardSource.addEventListener("metrics", function(event) {
    var metrics = JSON.parse(event.data);
    updateDashboard(metrics);
});

// 完整 URL 的 SSE
var extSource = new EventSource("https://127.0.0.1:9876/api/v2/export/stream");

// ===== 辅助函数 =====

function updateDashboard(metrics) {
    var el = document.getElementById("dashboard-metrics");
    if (el) {
        el.innerHTML = JSON.stringify(metrics, null, 2);
    }
}

// WebSocket 重连管理器
function ReconnectManager(url, onMessage) {
    var ws = null;
    var reconnectDelay = 1000;

    function connect() {
        ws = new WebSocket(url);
        ws.onmessage = function(event) {
            reconnectDelay = 1000;
            onMessage(event.data);
        };
        ws.onclose = function() {
            setTimeout(connect, reconnectDelay);
            reconnectDelay = Math.min(reconnectDelay * 2, 30000);
        };
    }

    connect();
    return {
        send: function(data) { if (ws) ws.send(data); },
        close: function() { if (ws) ws.close(); },
    };
}
