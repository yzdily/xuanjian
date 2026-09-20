"""F4 补强 — LOOP step 适配层（E3-1：actuator 链；E3-2：shiro 链 + C 类人工确认）。

背景：`loop_matrix.yaml` 声明了 11 条 trigger / 34 个 step，但 `LoopController.execute()`
需要一个 `step_handler` 才能真正执行；此前只有测试注入过 handler，生产链路从未接通。
本模块提供**矩阵驱动**的 step → 已实现能力 的适配层。

设计约定（详见 .workbuddy/artifacts/E3-1_step_handlers骨架设计_0919.md）：
1. termination 键（如 heapdump_unreachable / cipherKey_failed / key_unobtainable）
   **由 handler 负责写入 ctx**，否则 `LoopController._is_terminated()` 永远为假、链条会空跑到底。
2. 产物通过 `Finding.extracted_artifacts` 传递（`loop_controller.py` 会合并进 ctx）。
3. 矩阵驱动：端点、目标字段、体积上限、密钥来源顺序都从 `step` dict 读取，不硬编码业务细节。
4. 未注册的 step **必须显式记录**（`ctx["_loop_missing_handlers"]`），不允许静默跳过 ——
   "什么都不做还不吭声"正是当前引擎的病根。
5. 凭据策略（0919 用户确认）：**报告/detail 默认写明文**（报告是证据，脱敏成指纹反而添乱）；
   仅当环境变量 `XJ_EVIDENCE_REDACT=1` 时才输出脱敏证明。明文同时写入内存 ctx 供后续步骤使用。
6. **C 类（利用）步骤绝不自动执行**（E3-2）：矩阵标 `auto: false` 的步骤由 controller
   拦在 handler 之前；handler 自身再过一道硬开关 `XJ_LOOP_AUTO_EXPLOIT`（默认 false），
   即使矩阵漏标也不会自动打 —— 只产出 `awaiting_manual` 三问节点。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

from core.framework_scan.framework_scan import FrameworkScanner
from core.framework_scan.heapdump_analyzer import download_and_analyze_heapdump
from core.framework_scan.shiro_detect import DEFAULT_SHIRO_KEYS, detect_shiro_rememberme
from core.loops.loop_controller import (
    Finding,
    auto_exploit_enabled,
    record_awaiting_manual,
)

DEFAULT_TIMEOUT = 30.0
HEAPDUMP_TIMEOUT = 300.0
MAX_TEXT = 200_000

StepHandler = Callable[[dict, dict], Awaitable[Finding | None]]
STEP_HANDLERS: dict[str, StepHandler] = {}


def register(step_name: str):
    """把 handler 注册到 step 名上（矩阵里的 step 名即键）。"""

    def deco(fn: StepHandler) -> StepHandler:
        STEP_HANDLERS[step_name] = fn
        return fn

    return deco


def get_handler(step_name: str) -> StepHandler | None:
    return STEP_HANDLERS.get(step_name)


# ================================================================
# HTTP 适配（坑：复用点的 async / sync 约定不一致）
#   - FrameworkScanner.request_fn  -> 需 await（framework_scan.py:88）
#   - detect_shiro_rememberme.request_fn -> 同步调用（shiro_detect.py:41）
#   - download_and_analyze_heapdump.download_fn -> 同步调用（heapdump_analyzer.py:43）
#
# ★ E3-2 真实网络踩坑：`dict(r.headers)` 会把头名**全部小写**
#   （httpx.Headers 迭代即小写），于是 shiro 检测里的 `headers.get("Set-Cookie")`
#   在假响应单测里能过、一打真实服务就永远取不到 deleteMe（表现为"目标不活跃"）。
#   修法：Resp.headers 直接存 `httpx.Headers`（大小写不敏感）。
#   另：httpx 0.28 起 per-request `cookies=` 已废弃，改设在 Client 上。
# ================================================================
@dataclass
class Resp:
    """统一响应壳：满足 .status（FrameworkScanner）与 .headers（shiro 检测，大小写不敏感）。"""

    status: int
    headers: Any = field(default_factory=dict)
    text: str = ""


def _client_kwargs() -> dict:
    # 测试目标常为自签证书 / 非标准端口；与既有扫描行为保持一致
    return {"follow_redirects": False, "verify": False}


def srequest(method: str, url: str, timeout: float = DEFAULT_TIMEOUT, **kw) -> Resp | None:
    """同步请求（供 sync 复用点使用）。失败返回 None，由调用方决定如何降级。"""
    cookies = kw.pop("cookies", None)
    try:
        with httpx.Client(timeout=timeout, cookies=cookies, **_client_kwargs()) as client:
            r = client.request(method, url, **kw)
            return Resp(r.status_code, httpx.Headers(r.headers), r.text[:MAX_TEXT])
    except Exception:
        return None


async def arequest(method: str, url: str, timeout: float = DEFAULT_TIMEOUT, **kw) -> Resp:
    """异步请求（供 FrameworkScanner 使用）。失败返回 status=-1，不抛异常。"""
    cookies = kw.pop("cookies", None)
    try:
        async with httpx.AsyncClient(timeout=timeout, cookies=cookies, **_client_kwargs()) as client:
            r = await client.request(method, url, **kw)
            return Resp(r.status_code, httpx.Headers(r.headers), r.text[:MAX_TEXT])
    except Exception as exc:  # 网络错误不阻断链条，交给 termination 判断
        return Resp(-1, {"x-error": str(exc)[:200]}, "")


# ================================================================
# 凭据呈现策略：默认明文（报告是证据），仅环境开关可切脱敏
# ================================================================
def present_secret(value: str) -> str:
    if os.getenv("XJ_EVIDENCE_REDACT", "0") == "1":
        return mask_secret(value)
    return value


def mask_secret(value: str) -> str:
    """脱敏证明：掩码 + 长度 + 指纹（仅 XJ_EVIDENCE_REDACT=1 时使用）。"""
    if not value:
        return ""
    fp = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{value[:3]}***（{len(value)} 位，sha256:{fp}）"


def _findings_payload(found: dict[str, str]) -> dict[str, str]:
    return {k: present_secret(v) for k, v in found.items()}


def _actuator_url(ctx: dict) -> str:
    """取 actuator 根地址。

    优先用上一步写进 ctx 的 `actuator_url`；缺失时从 `base_url` 兜底推导 ——
    这样单条 step 可以被**单独重跑**（调试 / 复测 / 补测），不必强制走完整链。
    """
    url = ctx.get("actuator_url")
    if url:
        return str(url)
    base = ctx.get("base_url") or ctx.get("target_url")
    return base.rstrip("/") + "/actuator" if base else ""


# ================================================================
# step 1 — 枚举 actuator 端点
# ================================================================
@register("scan_all_actuator_endpoints")
async def scan_all_actuator_endpoints(step: dict, ctx: dict) -> Finding | None:
    base = ctx.get("base_url") or ctx.get("target_url")
    if not base:
        ctx["heapdump_unreachable"] = True
        return None

    framework = step.get("framework", "spring_boot_actuator")
    scanner = FrameworkScanner(request_fn=arequest, concurrency=1, interval_ms=0)
    hits = await scanner.scan(base, [framework])
    exposed = [h for h in hits if h.get("exposed")]

    # 矩阵驱动：若 step 声明了 endpoints，则只保留声明内的
    declared = step.get("endpoints")
    if declared:
        allowed = {f"/actuator/{name}" for name in declared}
        exposed = [h for h in exposed if h.get("endpoint") in allowed]

    if not exposed:  # 没暴露 → 命中终止条件，链条停在这里
        ctx["heapdump_unreachable"] = True
        return None

    actuator_url = base.rstrip("/") + "/actuator"
    ctx["actuator_url"] = actuator_url
    ctx["actuator_exposed"] = [h["endpoint"] for h in exposed]
    return Finding(
        id=f"loop_actuator_{abs(hash(base)) % 10**6}",
        vuln_type="actuator_exposure",
        severity="Critical",
        url=base,
        detail={"framework": framework, "endpoints": ctx["actuator_exposed"]},
        extracted_artifacts={"actuator_url": actuator_url},
    )


# ================================================================
# step 2 — 从 /actuator/env 提取凭据（JSON 优先，正则兜底）
# ================================================================
_SECRET_RE = re.compile(
    r'(?i)(password|passwd|jdbc[.\w]*|datasource[.\w]*|secret|access[_-]?key)'
    r'\s*[":=\s]+\s*([^\s",}]{4,120})'
)
_DRILL_CONTAINERS = ("activeProfiles", "propertySources", "properties")


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """摊平 actuator/env 的嵌套 JSON → {叶子键: 值}。"""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _DRILL_CONTAINERS:
                out.update(_flatten(v, prefix))
            else:
                out.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}{i}."))
    else:
        out[prefix.rstrip(".")] = obj
    return out


def _collect_from_json(text: str, keys: list[str]) -> dict[str, str]:
    try:
        flat = _flatten(json.loads(text))
    except Exception:
        return {}
    found: dict[str, str] = {}
    for k, v in flat.items():
        if isinstance(v, str) and v and any(t in k.lower() for t in keys):
            found.setdefault(k, v)
    return found


def _collect_from_regex(text: str, keys: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for m in _SECRET_RE.finditer(text):
        key, value = m.group(1).lower(), m.group(2)
        if any(t in key for t in keys):
            found.setdefault(key, value)
    return found


@register("extract_creds_from_env")
async def extract_creds_from_env(step: dict, ctx: dict) -> Finding | None:
    actuator_url = _actuator_url(ctx)
    if not actuator_url:
        return None

    path = step.get("endpoint_path", "/env")
    url = actuator_url.rstrip("/") + path
    resp = await arequest("GET", url)
    if resp.status != 200 or not resp.text:
        return None

    keys = [t.lower() for t in step.get("targets", ["password", "jdbc", "datasource", "secret", "key"])]
    found = _collect_from_json(resp.text, keys)          # ① JSON 优先
    source = "json"
    if not found:                                        # ② 正则兜底
        found = _collect_from_regex(resp.text, keys)
        source = "regex"
    if not found:
        return None

    ctx.update(found)                                    # 明文进内存，供后续利用步使用
    ctx["env_leaked_keys"] = list(found)
    return Finding(
        id=f"loop_env_{abs(hash(url)) % 10**6}",
        vuln_type="actuator_env_leak",
        severity="Critical",
        url=url,
        # 报告要明文（XJ_EVIDENCE_REDACT=1 时才脱敏）
        detail={"source": source, "keys": list(found), "evidence": _findings_payload(found)},
        extracted_artifacts=found,
    )


# ================================================================
# step 3 — 下载并分析 heapdump
# ================================================================
def _download_bytes(url: str) -> bytes | None:
    resp = srequest("GET", url, timeout=HEAPDUMP_TIMEOUT)
    if resp is None or resp.status != 200:
        return None
    return resp.text.encode("utf-8", "ignore")


@register("heapdump_download_extract")
async def heapdump_download_extract(step: dict, ctx: dict) -> Finding | None:
    actuator_url = _actuator_url(ctx)
    if not actuator_url:
        return None

    max_mb = int(step.get("max_size_mb", 100))
    # ★ 同步重活丢线程：download_and_analyze_heapdump 是同步函数，
    #   直接调用会阻塞事件循环（100MB 下载会拖垮并行会话）
    result = await asyncio.to_thread(
        download_and_analyze_heapdump, actuator_url, max_mb, _download_bytes
    )

    status = result.get("status")
    if status in ("download_failed", "empty"):
        ctx["heapdump_unreachable"] = True
        return None

    secrets = result.get("secrets") or []
    if not secrets:                    # 下载成功但没挖到密钥 → cipherKey 失败
        ctx["cipherKey_failed"] = True
        return None

    extracted: dict[str, str] = {}
    for item in secrets:
        kind, value = item.get("type", ""), item.get("value", "")
        if not value:
            continue
        if kind == "shiro_key":
            ctx["shiro_key"] = value
            extracted.setdefault("shiro_key", value)
        elif kind == "password":
            ctx.setdefault("db_password", value)
            extracted.setdefault("db_password", value)
        else:
            extracted.setdefault(kind, value)

    return Finding(
        id=f"loop_heapdump_{abs(hash(actuator_url)) % 10**6}",
        vuln_type="heapdump_leak",
        severity="Critical",
        url=str(result.get("url") or actuator_url),
        detail={
            "size_mb": result.get("size_mb"),
            "secret_types": sorted({i.get("type", "") for i in secrets}),
            "evidence": _findings_payload(extracted),
        },
        extracted_artifacts=extracted,
    )


# ================================================================
# shiro_remmeberme_active 链（E3-2）
#   step 1/2 = A 类（检测/取密钥，可自动）
#   step 3/4 = C 类（利用，矩阵 auto: false，绝不自动执行）
# ================================================================
def _shiro_target(ctx: dict) -> str:
    """Shiro 检测打站点根（rememberMe 是全局 Cookie，不走具体接口路径）。"""
    return str(ctx.get("base_url") or ctx.get("target_url") or "").rstrip("/")


@register("detect_rememberme_active")
async def detect_rememberme_active(step: dict, ctx: dict) -> Finding | None:
    """复用 `core.framework_scan.shiro_detect.detect_shiro_rememberme`。

    两个坑（读源码才发现）：
    1. 它的 `request_fn` 是**同步调用**（`shiro_detect.py:41`）→ 传本模块的 `srequest`；
    2. 它期望响应对象带 `.headers`（`resp.headers.get("Set-Cookie")`）—— `Resp` 已满足；
       但网络等待不能阻塞事件循环 → 整个同步函数丢 `asyncio.to_thread`，
       否则一个慢目标会把并行的其它会话一起拖死。
    """
    target = _shiro_target(ctx)
    if not target:
        ctx["key_unobtainable"] = True
        return None

    result = await asyncio.to_thread(detect_shiro_rememberme, target, srequest)
    status = str(result.get("status") or "")

    if status == "inactive":                 # 无 rememberMe 特征 → 无密钥链路可言
        ctx["rememberme_inactive"] = True
        return None

    ctx["rememberme_active"] = True
    ctx["shiro_detect_status"] = status
    if result.get("key"):                    # weak_key 分支（当前实现为占位，恒不命中）
        ctx["shiro_key"] = result["key"]
        ctx["shiro_key_source"] = "detect"

    severity = str(result.get("severity") or "High")
    return Finding(
        id=f"loop_shiro_rm_{abs(hash(target)) % 10**6}",
        vuln_type="shiro_remmeberme_active",
        severity=severity,
        url=target,
        detail={
            # ⚠️ 键名不能叫 "status"：controller 会把 detail 合并进 chain 步骤，
            #    而 "status" 是链状态的协议字段（finding / ok / awaiting_manual…），
            #    这里若叫 status 会把「有产出」的步骤标成 "active_no_key"（前端状态错乱）。
            "detect_status": status,
            "note": result.get("note", ""),
            "evidence": {"Set-Cookie": "rememberMe=deleteMe"},
        },
        extracted_artifacts={
            "rememberme_active": True,
            **({"shiro_key": result["key"]} if result.get("key") else {}),
        },
    )


def _canonical_default_key(candidate: str) -> str:
    """把矩阵声明的默认 key 归一到 `DEFAULT_SHIRO_KEYS` 的规范写法。

    踩坑：矩阵原本写成 `default_kph+...`（小写 k），而 `shiro_detect` 的规范 key 是
    `kPH+...`（大写）—— 大小写不一致会让"默认 key 来源"与常见 key 列表对不上。
    矩阵已修正；这里再做一层大小写归一，防止日后又写错。
    """
    lowered = {k.lower(): k for k in DEFAULT_SHIRO_KEYS}
    return lowered.get(candidate.lower(), candidate)


def _find_key_in_ctx_env(ctx: dict) -> str:
    """从 ctx 里找 actuator/env 泄漏的 Shiro key（键名含 cipherKey/shiro/rememberMe）。

    跳过引擎自己的内部键（`_loop_*`）与 `shiro_key` 本身 —— 否则会把"已解析结果"
    当成"env 泄漏来源"，来源标注失真。
    """
    for k, v in ctx.items():
        name = str(k).lower()
        if name.startswith("_") or name in ("shiro_key", "shiro_key_source"):
            continue
        if isinstance(v, str) and v and any(
            t in name for t in ("cipherkey", "shiro", "rememberme")
        ):
            return v
    return ""


def _resolve_cipher_key(step: dict, ctx: dict) -> tuple[str, str]:
    """按矩阵 `sources` 声明的**顺序**尝试取 key，返回 (key, source)。

    sources 语法（矩阵驱动）：
      - `default_<key>` / `default` → 指定默认 key（缺省时遍历常见 key 列表）
      - `heapdump`                  → 前面 actuator 链 heapdump 挖出的 `ctx["shiro_key"]`
      - `env`                       → `/actuator/env` 泄漏值里形如 Shiro key 的字段
    """
    sources = step.get("sources") or ["default", "heapdump", "env"]
    for raw in sources:
        src = str(raw)
        if src.startswith("default"):
            candidate = src[len("default"):].lstrip("_")
            if candidate:
                return _canonical_default_key(candidate), "default"
            if DEFAULT_SHIRO_KEYS:
                return DEFAULT_SHIRO_KEYS[0], "default"
        elif src == "heapdump":
            key = ctx.get("shiro_key") or ctx.get("heapdump_shiro_key")
            if key:
                return str(key), "heapdump"
        elif src == "env":
            key = _find_key_in_ctx_env(ctx)
            if key:
                return key, "env"
    return "", ""


@register("extract_cipher_key")
async def extract_cipher_key(step: dict, ctx: dict) -> Finding | None:
    """按矩阵 sources 顺序取 Shiro cipherKey；全部拿不到 → `key_unobtainable` 终止。

    诚实标注：`shiro_detect._try_decrypt_with_key` 目前是**占位实现**（恒 False），
    因此默认 key 只是"候选"而非已解密验证的密钥 —— detail 里 `verified=False` 明示，
    避免把"候选"吹成"已确认可利用"。
    """
    if not ctx.get("rememberme_active"):
        # 前提不成立（rememberMe 不活跃/未检测到）→ 密钥无从取得
        ctx["key_unobtainable"] = True
        return None

    key, source = _resolve_cipher_key(step, ctx)
    if not key:
        ctx["key_unobtainable"] = True
        return None

    verified = source == "detect"
    ctx["shiro_key"] = key
    ctx["shiro_key_source"] = source
    return Finding(
        id=f"loop_shiro_key_{abs(hash(key)) % 10**6}",
        vuln_type="shiro_cipherKey_leak",
        severity="Critical" if verified else "High",
        url=_shiro_target(ctx),
        detail={
            "source": source,
            "cipherKey": present_secret(key),
            "verified": verified,
            "note": "" if verified else "候选密钥（未通过解密验证）",
        },
        extracted_artifacts={"shiro_key": key},
    )


@register("construct_deserialization_payload")
async def construct_deserialization_payload(step: dict, ctx: dict) -> Finding | None:
    """C 类利用步骤：**绝不自动执行**，只产出人工确认节点。

    双保险：controller 已用矩阵 `auto: false` 拦在 handler 之前；这里再过一道硬开关
    `XJ_LOOP_AUTO_EXPLOIT`（默认 false），即使矩阵漏标也不会自动打。
    本阶段也**不实现**真实载荷构造 —— 不发起任何请求。
    """
    if not auto_exploit_enabled():
        record_awaiting_manual(ctx, step)
        return None
    ctx["_loop_auto_exploit_unlocked"] = True
    record_awaiting_manual(ctx, step, unlocked=True)
    return None


@register("validate_rce")
async def validate_rce(step: dict, ctx: dict) -> Finding | None:
    """C 类利用步骤：**绝不自动执行 RCE 验证**（同上，双保险 + 零请求）。"""
    if not auto_exploit_enabled():
        record_awaiting_manual(ctx, step)
        return None
    ctx["_loop_auto_exploit_unlocked"] = True
    record_awaiting_manual(ctx, step, unlocked=True)
    return None


# ================================================================
# dispatch — 注入给 LoopController.execute(step_handler=...)
# ================================================================
async def dispatch(step: dict, ctx: dict) -> Finding | None:
    """按 step 名分发；未注册的步骤显式记录，绝不静默。"""
    name = step.get("step", "")
    handler = get_handler(name)
    if handler is None:
        ctx.setdefault("_loop_missing_handlers", []).append(name)
        return None
    return await handler(step, ctx)


__all__ = [
    "STEP_HANDLERS",
    "Resp",
    "arequest",
    "srequest",
    "dispatch",
    "get_handler",
    "mask_secret",
    "present_secret",
    "register",
    "detect_rememberme_active",
    "extract_cipher_key",
    "construct_deserialization_payload",
    "validate_rce",
]
