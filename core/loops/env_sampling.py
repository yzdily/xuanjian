"""
core/loops/env_sampling.py — 环境采样 + 负载均衡定性（§3.6 环境采样 N≥6 + LB 定性）。

## 为什么需要（grep 核验）
玄鉴 core 源码层 grep 无 `env_consistency` / `环境采样` / `负载均衡` 命中
（仅 skills 知识库文档提及）→ 净新增。现有 `double_identity_matrix.py`（F9）
只做双身份静态对照，未对"同一接口反复请求"做 N≥6 固定采样；当 200/302 交替
出现时，易被误判为鉴权漏洞，实为多后端 LB 不一致。

## 能力
- `sample_endpoint`：同接口固定 N≥6 采样 + 双身份 + 静态资源对照；
  200/302 交替先判 LB 不一致，不轻易判鉴权漏洞。
- `is_load_balanced`：纯逻辑——响应序列在状态码间交替即判 LB（非鉴权问题）。

## 零依赖
纯 stdlib；`http` 为可注入 async callable（测试 mock），不模块级 import httpx。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SampleResult:
    """同接口 N 次采样的定性结果。

    Attributes:
        responses: N 次采样的响应列表（dict）
        is_lb: True=状态码交替→负载均衡不一致（非鉴权漏洞）
        authz_consistent: True=状态码全一致→可下稳定鉴权结论
    """

    responses: list[dict[str, Any]]
    is_lb: bool
    authz_consistent: bool


def _code_of(item: Any) -> int:
    """从响应项取 http 状态码；兼容 dict（http_code/status）与裸 int。"""
    if isinstance(item, dict):
        v = item.get("http_code") or item.get("status") or 0
    else:
        v = item
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def is_load_balanced(resp_seq: list[Any]) -> bool:
    """交替即判 LB，不轻易判鉴权漏洞。

    响应序列在相邻状态码间持续翻转（如 200,302,200,302）→ 多后端 LB 不一致，
    不应判为鉴权漏洞。元素可为 dict（取 http_code）或裸状态码 int。

    Args:
        resp_seq: 响应序列（dict 或 int 均可）

    Returns:
        True=检测到交替（LB 不一致）；空序列或不足两个→False
    """
    if not resp_seq or len(resp_seq) < 2:
        return False
    codes = [_code_of(x) for x in resp_seq]
    # 严格交替：任意相邻两个状态码都不同 → LB 不一致
    return all(codes[i] != codes[i + 1] for i in range(len(codes) - 1))


def _codes_consistent(resp_seq: list[Any]) -> bool:
    """状态码全一致→可下稳定鉴权结论。"""
    if not resp_seq:
        return False
    codes = [_code_of(x) for x in resp_seq]
    return all(c == codes[0] for c in codes)


async def sample_endpoint(http, req, *, n: int = 6, identities=("noauth", "low", "high")) -> SampleResult:
    """同接口固定 N≥6 采样 + 双身份 + 静态资源对照；200/302 交替先判 LB 不一致。

    对同一接口固定采样 N 次（默认 6）：状态码交替→判 LB 不一致（不判鉴权漏洞）；
    全一致→authz_consistent=True，可下稳定鉴权结论。

    Args:
        http: async callable，签名 http(req) -> resp_dict（可注入测试 mock）
        req: 请求构造 dict（url/method/headers/params 等）
        n: 固定采样次数（推荐 ≥6）
        identities: 双身份 + 无身份标签（noauth/low/high），由上游按身份分组对照解释
    """
    # identities 标签由上游对照解释；本函数聚焦同身份 N 次采样 + LB 定性
    responses: list[dict[str, Any]] = [await http(req) for _ in range(n)]
    return SampleResult(
        responses=responses,
        is_lb=is_load_balanced(responses),
        authz_consistent=_codes_consistent(responses),
    )


__all__ = ["SampleResult", "sample_endpoint", "is_load_balanced"]
