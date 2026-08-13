"""WorkerAgent 包 — Phase 2 并行测试子 Agent。

本包由原 core/worker_agent.py 拆分而来（Mixin 模式），对外接口不变：
    from core.worker_agent import WorkerAgent 仍然可用。

子模块：
    _helpers — _WorkerAgentHelpers Mixin（辅助方法）
    _agent   — WorkerAgent 主类（继承 _WorkerAgentHelpers）
"""

from core.worker_agent._agent import (
    WorkerAgent,
    WORKER_COMPRESS_THRESHOLD,
    WORKER_SKIP_CIRCUIT_BREAKER_RATIO,
    WORKER_SKIP_CIRCUIT_BREAKER_MIN_ROUNDS,
    log,
)

__all__ = [
    "WorkerAgent",
    "WORKER_COMPRESS_THRESHOLD",
    "WORKER_SKIP_CIRCUIT_BREAKER_RATIO",
    "WORKER_SKIP_CIRCUIT_BREAKER_MIN_ROUNDS",
    "log",
]
