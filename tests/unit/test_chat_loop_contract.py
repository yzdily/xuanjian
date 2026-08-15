"""A5 / D6 契约冻结测试：core.session.chat_loop 公开面。

依据 D6_split_contract_draft.md §1.2 + §3.3：拆分 chat_loop（ChatLoopMixin.chat
按 phase 抽函数到 core/session/_chat_phases/）时，以下公开名与签名必须保持原样：

冻结公开面：
- ChatLoopMixin（class，core.session.__init__:17 从 chat_loop 导入）
- ChatLoopMixin.chat（async generator，event-dict 流式产出格式冻结）

零网络、零 LLM；在完整 venv（含 dotenv/httpx）下运行。
"""
from __future__ import annotations

import asyncio
import inspect


def test_chatloopmixin_importable_and_class():
    from core.session.chat_loop import ChatLoopMixin

    assert inspect.isclass(ChatLoopMixin)


def test_chat_method_frozen_signature():
    """chat() 是 ChatLoopMixin 的核心公开方法，签名冻结。"""
    from core.session.chat_loop import ChatLoopMixin

    assert hasattr(ChatLoopMixin, "chat"), "ChatLoopMixin.chat 必须存在（冻结公开方法）"
    chat = ChatLoopMixin.chat
    assert inspect.iscoroutinefunction(chat) or inspect.isasyncgenfunction(chat), (
        "chat() 必须是 async / async generator"
    )
    params = list(inspect.signature(chat).parameters)
    assert params and params[0] == "self", f"chat() 首参必须是 self：{params}"
