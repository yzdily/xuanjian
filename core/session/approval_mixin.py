"""
手动审批机制 — 敏感操作前请求用户确认

借鉴 Venom 的手动审批设计，避免自动化流程越权推进。
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from core.log import get_logger

log = get_logger("approval")


class ApprovalAction(str, Enum):
    """需要审批的操作类型"""
    SEND_REQUEST = "send_request"
    EXECUTE_COMMAND = "execute_command"
    WRITE_FILE = "write_file"
    DELETE_DATA = "delete_data"
    SQL_INJECTION = "sql_injection"
    XSS_PAYLOAD = "xss_payload"


@dataclass
class ApprovalRequest:
    """审批请求"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action: ApprovalAction = ApprovalAction.SEND_REQUEST
    context: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    timeout_seconds: int = 300  # 5 minutes
    created_at: float = field(default_factory=lambda: __import__("time").time())


@dataclass
class ApprovalResponse:
    """审批响应"""
    request_id: str
    approved: bool
    reason: str = ""
    responded_at: float = field(default_factory=lambda: __import__("time").time())


class ApprovalMixin:
    """手动审批 Mixin — 供 AgentSession 继承"""

    _approval_callbacks: dict[str, asyncio.Future[ApprovalResponse]] = {}

    def __init__(self, *args, **kwargs):
        self._approval_callbacks: dict[str, asyncio.Future[ApprovalResponse]] = {}
        super().__init__(*args, **kwargs)  # 透传给后续 Mixin

    async def request_approval(
        self,
        action: ApprovalAction | str,
        context: dict[str, Any],
        description: str = "",
        timeout_seconds: int = 300,
    ) -> bool:
        """请求用户审批敏感操作

        Args:
            action: 操作类型
            context: 操作上下文（如 {url, method, body}）
            description: 操作描述
            timeout_seconds: 超时时间（秒）

        Returns:
            True = 用户批准, False = 用户拒绝或超时
        """
        if isinstance(action, str):
            action = ApprovalAction(action)

        request = ApprovalRequest(
            action=action,
            context=context,
            description=description or f"请求执行 {action.value} 操作",
            timeout_seconds=timeout_seconds,
        )

        log.info("请求审批: %s (%s)", request.id, action.value)

        # 创建等待 Future
        loop = asyncio.get_running_loop()
        future: asyncio.Future[ApprovalResponse] = loop.create_future()
        self._approval_callbacks[request.id] = future

        try:
            # 推送审批请求到前端（通过 SSE）
            await self._emit_approval_request(request)

            # 等待用户响应
            response = await asyncio.wait_for(
                future,
                timeout=timeout_seconds,
            )

            if response.approved:
                log.info("审批通过: %s", request.id)
                return True
            else:
                log.warning("审批拒绝: %s - %s", request.id, response.reason)
                return False

        except asyncio.TimeoutError:
            log.warning("审批超时: %s (等待 %ds)", request.id, timeout_seconds)
            return False
        except Exception as e:
            log.error("审批异常: %s - %s", request.id, e)
            return False
        finally:
            self._approval_callbacks.pop(request.id, None)

    def submit_approval_response(self, response: ApprovalResponse) -> bool:
        """提交审批响应（由前端调用）

        Args:
            response: 审批响应

        Returns:
            True = 成功提交, False = request_id 不存在
        """
        future = self._approval_callbacks.get(response.request_id)
        if future is None:
            log.warning("未知的审批请求 ID: %s", response.request_id)
            return False

        if not future.done():
            future.set_result(response)
            return True
        else:
            log.warning("审批请求已完成: %s", response.request_id)
            return False

    async def _emit_approval_request(self, request: ApprovalRequest) -> None:
        """推送审批请求到前端（通过 SSE）

        子类需要实现具体的 SSE 推送逻辑。
        """
        # 默认实现：记录日志，等待子类覆盖
        log.debug("推送审批请求: %s -> SSE", request.id)

        # 如果有 emit 方法（如 AgentSession），使用它
        if hasattr(self, "emit"):
            await self.emit("approval_request", {
                "id": request.id,
                "action": request.action.value,
                "context": request.context,
                "description": request.description,
                "timeout": request.timeout_seconds,
            })


# 全局审批管理器（用于跨会话审批）
class ApprovalManager:
    """全局审批管理器"""

    _instance = None
    _callbacks: dict[str, Callable[[ApprovalResponse], None]] = {}

    @classmethod
    def get_instance(cls) -> "ApprovalManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._callbacks: dict[str, Callable[[ApprovalResponse], None]] = {}

    def register(self, request_id: str, callback: Callable[[ApprovalResponse], None]) -> None:
        """注册审批回调"""
        self._callbacks[request_id] = callback

    def submit(self, response: ApprovalResponse) -> bool:
        """提交审批响应"""
        callback = self._callbacks.pop(response.request_id, None)
        if callback:
            callback(response)
            return True
        return False


# 便捷函数
def request_approval_for_request(url: str, method: str, body: str = "") -> ApprovalRequest:
    """为 HTTP 请求创建审批请求"""
    return ApprovalRequest(
        action=ApprovalAction.SEND_REQUEST,
        context={"url": url, "method": method, "body": body[:500]},
        description=f"请求发送 {method} 请求到 {url}",
    )


def request_approval_for_command(command: str) -> ApprovalRequest:
    """为命令执行创建审批请求"""
    return ApprovalRequest(
        action=ApprovalAction.EXECUTE_COMMAND,
        context={"command": command},
        description=f"请求执行命令: {command[:100]}",
    )