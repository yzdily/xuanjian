"""
Fuzz Registry — Fuzzer 注册与路由

根据漏洞类型自动选择最合适的 Fuzzer 执行 fuzz。
"""

from __future__ import annotations

from core.log import get_logger
from core.fuzz.base import BaseFuzzer, FuzzTask, FuzzEvidence, FuzzResult
from core.di import register_resetter

log = get_logger("fuzz.registry")

_router: "FuzzRouter | None" = None


class FuzzRouter:
    """Fuzzer 路由器 — 根据 vuln_type 自动路由到最合适的 Fuzzer。

    使用方式：
        router = get_fuzz_router()
        evidence = await router.fuzz(task)
    """

    def __init__(self, proxy_url: str = ""):
        self._fuzzers: list[BaseFuzzer] = []
        self.proxy_url = proxy_url
        self._register_builtins()

    def _register_builtins(self):
        """注册内置 Fuzzer（按优先级排序）。"""
        from core.fuzz.sqli import SQLiFuzzer
        from core.fuzz.race_condition import RaceConditionFuzzer
        from core.fuzz.waf_bypass import WAFBypassFuzzer

        self._fuzzers = [
            SQLiFuzzer(proxy_url=self.proxy_url),
            RaceConditionFuzzer(proxy_url=self.proxy_url),
            WAFBypassFuzzer(proxy_url=self.proxy_url),
        ]
        # 按优先级降序排列
        self._fuzzers.sort(key=lambda f: f.PRIORITY, reverse=True)

    def register(self, fuzzer: BaseFuzzer) -> None:
        """动态注册一个 Fuzzer。"""
        self._fuzzers.append(fuzzer)
        self._fuzzers.sort(key=lambda f: f.PRIORITY, reverse=True)

    def route(self, task: FuzzTask) -> BaseFuzzer | None:
        """根据 vuln_type 找到最合适的 Fuzzer。

        返回 None 表示没有合适的 Fuzzer（不再有兜底 Fuzzer）。
        """
        for f in self._fuzzers:
            if f.can_handle(task.vuln_type):
                return f
        return None

    async def fuzz(self, task: FuzzTask) -> FuzzEvidence:
        """一键 fuzz：自动路由 + 执行。

        这是外部调用的主入口。
        """
        fuzzer = self.route(task)
        if fuzzer is None:
            log.warning("没有 Fuzzer 能处理 vuln_type=%s", task.vuln_type)
            return FuzzEvidence(
                result=FuzzResult.INCONCLUSIVE,
                confidence=0.0,
                summary=f"没有适合 {task.vuln_type} 的 Fuzzer，建议 LLM 使用 proxy_send_request 手动验证",
                fuzzer_name="none",
                stop_reason="no_fuzzer_available",
            )

        log.info(
            "Fuzz 路由: vuln_type=%s → %s (url=%s, param=%s)",
            task.vuln_type, fuzzer.NAME, task.target_url[:80], task.param_name,
        )

        try:
            evidence = await fuzzer.fuzz(task)
            log.info(
                "Fuzz 完成: %s → %s (confidence=%.0f%%, requests=%d, %.1fs, stop=%s)",
                fuzzer.NAME, evidence.result.value,
                evidence.confidence * 100, evidence.requests_sent,
                evidence.elapsed_seconds, evidence.stop_reason,
            )
            return evidence
        except Exception as e:
            log.error("Fuzzer 异常: %s — %s", fuzzer.NAME, e, exc_info=True)
            return FuzzEvidence(
                result=FuzzResult.ERROR,
                confidence=0.0,
                summary=f"Fuzzer {fuzzer.NAME} 执行异常: {e}",
                fuzzer_name=fuzzer.NAME,
                error_message=str(e),
            )

    @property
    def fuzzer_names(self) -> list[str]:
        """列出所有已注册的 Fuzzer 名称。"""
        return [f.NAME for f in self._fuzzers]

    @property
    def count(self) -> int:
        return len(self._fuzzers)


def get_fuzz_router(proxy_url: str = "") -> FuzzRouter:
    """获取全局 FuzzRouter 单例（懒加载）。"""
    global _router
    if _router is None:
        _router = FuzzRouter(proxy_url=proxy_url)
    return _router


def reset_fuzz_router() -> None:
    """重置全局路由器（测试用）。"""
    global _router
    _router = None


# ---- 注册到 core.di 统一单例重置注册表（测试隔离用）----
register_resetter("fuzz_router", reset_fuzz_router)
