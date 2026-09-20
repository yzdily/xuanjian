"""testflow 编排壳 — PHASE_ORDER 调度 + 三执行者 + decide_mode（v3 §三）。

不变性质：任何模式下矩阵格都 100% 有结论（R3 全量原则）。
FAST 大量为 needs_follow_up(llm 步骤未跑) —— 显式未闭环，不静默缩水。

P4 顺序 bug 修复：OPT2 定档从 chat_loop.py:1555（XSS 启动后）迁到此处
census 完成后，事件序固定为 普查完成 → 归属修正 → 定档 → 相位执行。

事件协议：async generator yield str（chat_loop 直接透传到终端事件流）。
"""
from __future__ import annotations

import asyncio
import importlib
from typing import Any, AsyncGenerator, Callable, Iterable

from core.testflow.attribution_rules import PHASE_ORDER, group_by_risk_domain
from core.testflow.gates import gate_pre, run_triage_gate

__all__ = ["TestflowEngine", "decide_mode", "MODE_WORKER_LIMIT", "TOOL_REGISTRY"]

# 模式 → llm worker 上限（worker 2→3 顺带解决 cap2 触顶）
MODE_WORKER_LIMIT: dict[str, int] = {"FAST": 0, "STANDARD": 3, "DEEP": 5, "SMART": 3}

# 工具执行者注册表：域 → (loops 模块, 函数名)（懒加载，零接线模块不改实现）
TOOL_REGISTRY: dict[str, tuple[str, str]] = {
    "authz": ("core.loops.idor_probe", "idor_probe"),
    "authz_write": ("core.loops.write_risk_probe", "evaluate_write_risk"),
    "upload": ("core.loops.upload_exploit", "main"),
    "upload_chain": ("core.loops.chain_search", "verify_stored_xss"),
    "config": ("core.loops.config_switch_probe", "main"),
    "config_deep": ("core.loops.deep_dive", "main"),
    "chain": ("core.loops.chain_search", "chain_enumerate"),
    "injection": ("core.loops.injection_tamper", "main"),
    "bypass": ("core.loops.bypass_coverage", "main"),
    "waf": ("core.loops.identify_waf", "main"),
}


def decide_mode(session: Any, census_summary: dict[str, Any]) -> str:
    """OPT2 定档（census 完成后调用，修 P4）。

    三源信号合并（v2 §7.7.1）：
      A = L1 未授权数据端点数（census 业务码分层）
      B = 写端点数（含 dry-run 待授权的）
      C = 敏感字段命中数
    """
    l1 = int(census_summary.get("l1_unauthorized", 0) or 0)
    writes = int(census_summary.get("write_endpoints", 0) or 0)
    sensitive = int(census_summary.get("sensitive_fields", 0) or 0)
    user_mode = str(getattr(session, "scan_mode", "") or "").upper()

    if user_mode in MODE_WORKER_LIMIT and user_mode != "SMART":
        return user_mode  # 用户显式选档 → 不自动升级（SMART 才自动定）
    if l1 >= 3 or (writes >= 3 and sensitive >= 1) or sensitive >= 5:
        return "DEEP"
    if l1 >= 1 or writes >= 2 or sensitive >= 1:
        return "STANDARD"
    return "FAST"


class TestflowEngine:
    """Stage 3 域内测试编排壳。

    用法（chat_loop / census 完成后）:
        engine = TestflowEngine(session, sitemap)
        async for event in engine.run(feature_points, census_summary):
            emit(event)   # 终端事件流
    """

    def __init__(self, session: Any = None, sitemap: Any = None,
                 local_runner: Callable[..., Any] | None = None,
                 llm_dispatcher: Callable[..., Any] | None = None,
                 mode: str = "SMART"):
        self.session = session
        self.sitemap = sitemap
        self.mode = mode
        # local 执行者注入点：fast_scanner scan_target（rules 子集）
        self.local_runner = local_runner
        # llm 执行者注入点：worker_agent 按 (fp, domain) 派单
        self.llm_dispatcher = llm_dispatcher
        self.mode_workers = MODE_WORKER_LIMIT.get(mode, 3)
        self.worker_slots = self.mode_workers

    # ---- 深挖队列 ----
    def build_deep_dive_queue(self, feature_points: Iterable) -> list[tuple[Any, str]]:
        """归属命中对 (fp, domain) 按 PHASE_ORDER 排序。"""
        groups = group_by_risk_domain(feature_points)
        queue: list[tuple[Any, str]] = []
        for domain in PHASE_ORDER:
            if domain in ("precheck", "recon"):
                continue  # Stage 0/1 已完成
            for fp in groups.get(domain, []):
                if getattr(fp, "origin", "") == "validated" or getattr(fp, "risk_domains", None):
                    queue.append((fp, domain))
        return queue

    # ---- 主循环 ----
    async def run(self, feature_points: Iterable,
                  census_summary: dict[str, Any] | None = None) -> AsyncGenerator[str, None]:
        if census_summary is not None and self.mode == "SMART":
            self.mode = decide_mode(self.session, census_summary)
            yield f"🎚️ 定档: {self.mode}（L1 {census_summary.get('l1_unauthorized', 0)}"
            f" / 写 {census_summary.get('write_endpoints', 0)}"
            f" / 敏感 {census_summary.get('sensitive_fields', 0)}）"
            self.mode_workers = MODE_WORKER_LIMIT.get(self.mode, 3)

        queue = self.build_deep_dive_queue(feature_points)
        if not queue:
            yield "🧩 域归属: 0 端点归属命中，跳过 Stage 3"
            return
        yield f"📌 深挖队列: {len(queue)} 个 (功能点,域) 对进入 Stage 3"

        by_domain: dict[str, list] = {}
        for fp, dom in queue:
            by_domain.setdefault(dom, []).append(fp)

        for domain in PHASE_ORDER:
            if domain in ("precheck", "recon"):
                continue
            fps = by_domain.get(domain, [])
            if not fps:
                yield f"— {domain}: 0 端点归属，跳过"
                continue
            playbook = self._load_playbook(domain)
            if playbook is None:
                # R3 全量原则：无 playbook 不静默缺位
                for fp in fps:
                    fp.domain_status[domain] = "needs_follow_up"
                yield f"⚠ {domain}: playbook 未落地，{len(fps)} 格标 needs_follow_up（显式未闭环）"
                continue
            yield f"✅ {domain} 相位: {len(fps)} 功能点命中，执行 playbook"
            verified = await self._run_phase(domain, fps, playbook)
            yield f"✅ {domain} 相位完成: {verified} 个 verified"

    # ---- 相位执行 ----
    async def _run_phase(self, domain: str, fps: list, playbook: dict) -> int:
        verified = 0
        for fp in fps:
            for step in playbook.get("steps", []):
                ok, reason = gate_pre(step)
                if not ok:
                    fp.domain_status[domain] = "needs_follow_up"
                    continue
                try:
                    executor = step["executor"]
                    if executor == "local":
                        await self._exec_local(step, fp)
                    elif executor == "llm":
                        await self._exec_llm(step, fp, domain)
                    elif executor == "tool":
                        await self._exec_tool(step, fp)
                except NotImplementedError:
                    fp.domain_status[domain] = "needs_follow_up"
                    continue
                except Exception as exc:  # tool/接线缺失 → 显式未闭环
                    fp.domain_status.setdefault(domain, "needs_follow_up")
                    if getattr(fp, "_testflow_errors", None) is None:
                        fp._testflow_errors = []
                    fp._testflow_errors.append(f"{step['id']}: {exc}")
                    continue
            if fp.domain_status.get(domain) == "reported":
                verified += 1
        return verified

    # ---- 三执行者 ----
    async def _exec_local(self, step: dict, fp: Any) -> None:
        """local = FastScanner 按域裁剪（scan_target rules 子集）。"""
        if self.local_runner is None:
            raise NotImplementedError("local_runner 未注入（批次 2 接 fast_scanner）")
        rules = step.get("rules")
        if asyncio.iscoroutinefunction(self.local_runner):
            await self.local_runner(fp=fp, rules=rules, step=step)
        else:
            await asyncio.to_thread(self.local_runner, fp=fp, rules=rules, step=step)

    async def _exec_llm(self, step: dict, fp: Any, domain: str) -> None:
        """llm = worker 按 (fp, domain) 派单，SKILL 决策树。

        FAST 模式（worker 0）→ 步骤显式标 needs_follow_up，不静默。
        """
        if self.worker_slots <= 0:
            fp.domain_status[domain] = "needs_follow_up"
            return
        if self.llm_dispatcher is None:
            fp.domain_status[domain] = "needs_follow_up"
            return
        self.worker_slots -= 1
        try:
            if asyncio.iscoroutinefunction(self.llm_dispatcher):
                await self.llm_dispatcher(step=step, fp=fp, domain=domain)
            else:
                await asyncio.to_thread(self.llm_dispatcher, step=step, fp=fp, domain=domain)
        finally:
            self.worker_slots += 1

    async def _exec_tool(self, step: dict, fp: Any) -> None:
        """tool = 存量 loops 模块（零接线，不改实现，懒加载）。"""
        ref = step.get("tool") or ""
        mod_name, func_name = TOOL_REGISTRY.get(ref, (None, None))
        if mod_name is None:
            if "." in ref:
                mod_name, func_name = ref.rsplit(".", 1)
            else:
                raise NotImplementedError(f"tool 未注册: {ref}")
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name, None)
        if func is None:
            raise NotImplementedError(f"{mod_name}.{func_name} 不存在")
        if asyncio.iscoroutinefunction(func):
            await func(fp)
        else:
            await asyncio.to_thread(func, fp)

    # ---- playbook 加载 ----
    def _load_playbook(self, domain: str) -> dict | None:
        import logging
        from pathlib import Path
        path = Path(__file__).parent / "playbooks" / f"{domain}.yaml"
        if not path.exists():
            return None
        try:
            import yaml
            with path.open(encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            logging.getLogger(__name__).warning("PyYAML 未安装，playbook 不可用: %s", path)
            return None

    # ---- Stage 4.1 覆盖盲区（G5 前置）----
    @staticmethod
    def detect_gaps(feature_points: Iterable) -> list[dict[str, str]]:
        """扫"端点有归属但矩阵格无结论"的盲区 + silent 执行者。"""
        gaps: list[dict[str, str]] = []
        for fp in feature_points:
            for dom in (getattr(fp, "risk_domains", None) or []):
                status = (getattr(fp, "domain_status", None) or {}).get(dom)
                if status is None:
                    gaps.append({"fp": getattr(fp, "id", "?"), "domain": dom,
                                 "reason": "矩阵格无结论（silent）"})
                elif status == "needs_follow_up":
                    reason = "; ".join(getattr(fp, "_testflow_errors", [])[:3]) or "llm 步骤未跑"
                    gaps.append({"fp": getattr(fp, "id", "?"), "domain": dom, "reason": reason})
        return gaps

    # ---- Stage 5 前置：GATE-TRI ----
    def finish(self, findings: list[dict[str, Any]],
               baseline: dict[str, Any] | None = None) -> tuple[list, list]:
        return run_triage_gate(findings, baseline=baseline)
