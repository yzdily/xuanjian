"""tests/integration/test_dag_workflow.py — 长期 L2 验收。

按 XUANJIAN_ROADMAP_LONG_TERM §3.3 3+ 断言：
1. DAG 拓扑序（A < B < C）
2. 环检测抛 ValueError
3. Agent pub/sub 链
4. 5 Agent 串联跑通（stub 降级路径）
"""
from __future__ import annotations

import time

import pytest

from core.os.event_bus import OSEventBus
from core.workflow import (
    Agent,
    AuthzAgent,
    DAG,
    FuzzAgent,
    Node,
    ReconAgent,
    ReportAgent,
    VerifyAgent,
)
from core.workflow.dag import DAG as _DAG  # noqa: F401


def test_dag_topo_order():
    dag = DAG()
    dag.add(Node("a", lambda c: c))
    dag.add(Node("b", lambda c: c, deps=["a"]))
    dag.add(Node("c", lambda c: c, deps=["a", "b"]))
    order = dag.topo_order()
    assert order.index("a") < order.index("b") < order.index("c")


def test_dag_cycle_detection():
    dag = DAG()
    dag.add(Node("x", lambda c: c, deps=["y"]))
    dag.add(Node("y", lambda c: c, deps=["x"]))
    with pytest.raises(ValueError):
        dag.topo_order()
    assert dag.has_cycle() is True


def test_dag_unknown_dep_raises():
    dag = DAG()
    dag.add(Node("a", lambda c: c, deps=["missing"]))
    with pytest.raises(ValueError):
        dag.topo_order()


def test_dag_no_cycle():
    dag = DAG()
    dag.add(Node("a", lambda c: c))
    dag.add(Node("b", lambda c: c, deps=["a"]))
    assert dag.has_cycle() is False


def test_agent_pubsub_chain():
    """单 Agent 订阅 start → run → publish done。"""
    bus = OSEventBus(dispatch_timeout=2.0)
    seen: list[dict] = []

    class A(Agent):
        def __init__(self):
            super().__init__("a", ["start"], bus)

        def run(self, ctx):
            seen.append(ctx)
            bus.publish("a.done", {"from": "a", "ctx": ctx})
            return {}

    A()
    bus.publish("start", {"x": 1})
    time.sleep(0.2)
    assert seen == [{"x": 1}]


def test_five_agents_pipeline_runs():
    """5 Agent 串联：scan.start → recon.done → authz.done → fuzz.done → verify.done → report.done。"""
    bus = OSEventBus(dispatch_timeout=2.0)
    dones: list[str] = []

    def make_done_listener(name: str):
        def listen(p):
            dones.append(name)
        return listen

    # 订阅 done 事件记录
    for n in ("recon.done", "authz.done", "fuzz.done", "verify.done", "report.done"):
        bus.subscribe(n, make_done_listener(n))

    # 启动 5 Agent
    ReconAgent(bus)
    AuthzAgent(bus)
    FuzzAgent(bus)
    VerifyAgent(bus)
    ReportAgent(bus)

    bus.publish("scan.start", {"url": "http://example.com", "tenant": "default"})
    # 等整条链跑完
    deadline = time.time() + 3
    while time.time() < deadline and len(dones) < 5:
        time.sleep(0.05)
    # 5 个 done 应都收到（顺序可不同，但都到）
    for n in ("recon.done", "authz.done", "fuzz.done", "verify.done", "report.done"):
        assert n in dones, f"missing {n}; got {dones}"


def test_agent_disabled(monkeypatch):
    """XUANJIAN_AGENT_DISABLED=1 → Agent 不执行 run。"""
    monkeypatch.setenv("XUANJIAN_AGENT_DISABLED", "1")
    bus = OSEventBus(dispatch_timeout=1.0)
    seen: list[dict] = []

    class A(Agent):
        def __init__(self):
            super().__init__("a", ["start"], bus)

        def run(self, ctx):
            seen.append(ctx)
            return {}

    A()
    bus.publish("start", {"x": 1})
    time.sleep(0.2)
    assert seen == []  # 被 _disabled 拦截
