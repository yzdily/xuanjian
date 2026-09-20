"""testflow llm 执行者 — (fp, domain) 任务单元派单桥（v3 §四/§五 Stage 3 R4）。

三件事：
  1. WORKER_SYSTEM_PROMPT 全局铁律编译（§4.1 五条，复盘方法论沉淀）
  2. (fp, domain) → WorkerAgent 域内派单（worker_agent.check_matches_domain 过滤）
  3. 域内结论写回矩阵格（reported / no_issue / needs_follow_up）

engine 注入方式::

    from core.testflow.llm_dispatcher import make_llm_dispatcher
    engine = TestflowEngine(session, sitemap,
                            llm_dispatcher=make_llm_dispatcher(session, session_info))
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from core.sitemap import CheckResult
from core.sitemap.models import MatrixOutcome
from core.worker_agent import WorkerAgent, check_matches_domain

__all__ = ["FIVE_IRON_RULES", "make_llm_dispatcher"]

log = logging.getLogger("testflow.llm_dispatcher")

# ── §4.1 全局铁律（编译进每个 testflow worker 上下文，~40 行）──
# 来源：SKILL.md 复盘沉淀章节（hexiao §2 / huaxiang §15.3 §15.1 / 0901 §11.2 / CORS §13.3）
FIVE_IRON_RULES = """
## ⛔ 全局铁律（违反任何一条 = 误报，GATE-TRI 会拦下你的结论）

1. **未授权三重判定**（禁止只看 HTTP 状态码）：
   HTTP 200 不等于未授权漏洞。必须依次排除：
   ① 业务层拒绝（code:xxx 用户未登录/权限不足）→ 已鉴权，非漏洞；
   ② 空数据（data:null/[]）→ 无泄露，非漏洞；
   ③ 公开数据（公告/商品列表/SPA 壳/静态资源）→ 非漏洞。
   只有「200 + 非公开业务数据」才可能是未授权访问。

2. **无效令牌矩阵**：返回 500 = 拒绝通过，**不标洞**；
   200 + 业务码正常返回 = 绕过实锤。Token 无效时服务端崩溃不是鉴权缺陷的证据。

3. **XSS 假阳性排除**：500 错误回显中的 payload 不算 XSS；
   存储型 XSS 必须**新会话（无认证）读回**注入内容并确认浏览器执行才算。

4. **CORS 复核四条件**：ACAO 回显 Origin + ACAC:true + 敏感数据 + 非公开接口，
   四条全中才算；黑名单（反射任意 origin 的公开接口）直接排除。

5. **根因三分类**（整站/批量未授权必做）：先归因——配置开关 /
   网关缺失 / 代码遗漏，写入 detail 的 root_cause 字段，不要逐条平铺报洞。

证据要求：每条结论必须带 evidence_request + evidence_response（原始请求/响应摘录），
没有证据的发现会被 GATE-TRI 六项准入降级为 Info 留人工复核。
"""


def make_llm_dispatcher(
    session: Any,
    session_info: dict | None = None,
    on_event: Callable[[dict], None] | None = None,
) -> Callable[..., Any]:
    """构造 engine.llm_dispatcher 注入件。

    Args:
        session: AgentSession（用 llm / sitemap / task_id）
        session_info: 认证信息 {"headers": {...}}（FastScanner/worker 共用）
        on_event: worker 事件回调（orchestrator 侧把 worker 事件接进事件流）

    Returns:
        async callable(step=, fp=, domain=)
    """
    worker_seq = {"n": 0}

    async def _dispatch(step: dict, fp: Any, domain: str) -> None:
        if session.llm is None:
            raise NotImplementedError("LLM 未配置，llm 执行者不可用")

        worker_seq["n"] += 1
        worker = WorkerAgent(
            worker_id=f"tf-{domain}-{worker_seq['n']:02d}",
            llm=session.llm,
            sitemap=session.sitemap,
            session_info=session_info or {},
            features=[fp],
            group_name=f"{domain}|{getattr(fp, 'name', fp.id)}",
            domain=domain,
        )
        # 全局铁律编译（§4.1）：紧跟 SKILL 注入之后，防止 LLM 用推理覆盖判定
        worker.context.add_system(FIVE_IRON_RULES)

        vulns = 0
        try:
            async for evt in worker.run():
                if on_event is not None:
                    try:
                        on_event(evt)
                    except Exception:
                        pass
                if evt.get("type") == "worker_done":
                    vulns = int(evt.get("vulns", 0) or 0)
        except Exception as exc:
            log.warning("testflow worker %s 异常: %s", worker.worker_id, exc)
            raise

        # ---- 域内结论写回矩阵格 ----
        domain_checks = [c for c in fp.checklist
                         if check_matches_domain(c.vuln_type, domain)]
        done = [c for c in domain_checks
                if c.result not in (CheckResult.PENDING,) and not c.needs_browser]
        has_vuln = any(c.result in (CheckResult.VULNERABLE,) for c in domain_checks)
        if has_vuln:
            fp.domain_status[domain] = MatrixOutcome.REPORTED.value
        elif len(done) >= len([c for c in domain_checks if not c.needs_browser]) and done:
            fp.domain_status[domain] = MatrixOutcome.NO_ISSUE.value
        else:
            fp.domain_status[domain] = MatrixOutcome.NEEDS_FOLLOW_UP.value

    return _dispatch
