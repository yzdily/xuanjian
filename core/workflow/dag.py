"""core.workflow.dag — DAG 描述 + 拓扑排序（含环检测）（长期 L2）。

按 XUANJIAN_ROADMAP_LONG_TERM §3.3 落地。
零外部依赖。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Node:
    """DAG 节点：id + fn(ctx) + deps + retry + on_fail 策略。"""

    id: str
    fn: Callable[[dict], dict]
    deps: list[str] = field(default_factory=list)
    retry: int = 0
    on_fail: str = "skip"  # skip|halt|fallback:{node_id}


@dataclass
class DAG:
    """有向无环图，节点字典 + 拓扑排序 + 环检测。"""

    nodes: dict[str, Node] = field(default_factory=dict)

    def add(self, node: Node) -> "DAG":
        self.nodes[node.id] = node
        return self

    def topo_order(self) -> list[str]:
        """DFS 拓扑排序；环检测抛 ValueError。"""
        visited: set[str] = set()
        on_stack: set[str] = set()
        order: list[str] = []

        def dfs(nid: str, path: list[str]) -> None:
            if nid in on_stack:
                cycle = " -> ".join(path + [nid])
                raise ValueError(f"DAG 含环: {cycle}")
            if nid in visited:
                return
            if nid not in self.nodes:
                raise ValueError(f"未知节点: {nid}")
            on_stack.add(nid)
            for d in self.nodes[nid].deps:
                dfs(d, path + [nid])
            on_stack.discard(nid)
            visited.add(nid)
            order.append(nid)

        for n in list(self.nodes):
            dfs(n, [])
        return order

    def has_cycle(self) -> bool:
        try:
            self.topo_order()
            return False
        except ValueError:
            return True


__all__ = ["DAG", "Node"]
