"""AuthorizedScope — 单一权威作用域契约（924 复盘 §4.2 后续重构项）。

背景（task_1790219173_3617ab 跨资产污染）：
  scope 概念此前散落在 crawler（ScopeMixin）、sitemap（_host_in_scope）、
  report（零过滤）三处，且"自动膨胀"与"严格隔离"互相矛盾。
  924 当日以 ``Sitemap._host_in_scope`` 单一实现止血；本模块把契约正式固化：

  - ``AuthorizedScope{target, extra_scope[], mode}`` —— 唯一权威定义；
  - ``mode ∈ {strict, extended}`` —— 默认 strict：绝不允许自动把陌生域
    晋升进作用域；extended 才允许 infer（逃生门 ``XUANJIAN_SCOPE_AUTO_PROMOTE=1``，
    需用户显式开启并在报告中注明）；
  - ``scope_fingerprint`` —— target + 显式 extra_scope + mode 的稳定哈希，
    报告 / sitemap / CI 闸门产物 / 流量证据统一打标，便于审计与串扰回溯
    （"这份产物是在哪个作用域状态下生成的"一眼可查）。

接入约定：
  - ``Sitemap`` 持有 ``self.scope``（extra_scope 集合**共享同一对象引用**，
    运行期 ``sitemap.extra_scope.update(...)`` 自动反映到契约）；
  - ``ScopeMixin`` 的逃生门判定统一走 ``current_mode()``；
  - 所有新代码优先使用本契约，不要另行实现 host 判定。
"""
# noqa: giant

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---- 模式常量 ----
SCOPE_MODE_STRICT = "strict"
SCOPE_MODE_EXTENDED = "extended"

# 逃生门环境变量：显式设 1 才恢复"高频域自动晋升"旧行为（924 泄漏①收紧）
_SCOPE_AUTO_PROMOTE_ENV = "XUANJIAN_SCOPE_AUTO_PROMOTE"


def current_mode() -> str:
    """读取当前作用域模式：默认 strict；XUANJIAN_SCOPE_AUTO_PROMOTE=1 → extended。"""
    return (
        SCOPE_MODE_EXTENDED
        if os.environ.get(_SCOPE_AUTO_PROMOTE_ENV) == "1"
        else SCOPE_MODE_STRICT
    )


def is_extended_mode() -> bool:
    """当前是否处于 extended（允许自动晋升关联域）模式。"""
    return current_mode() == SCOPE_MODE_EXTENDED


@dataclass
class AuthorizedScope:
    """授权作用域契约（单一权威实现）。

    Attributes:
        target: 扫描目标（URL 或裸域，允许带端口）。
        extra_scope: 显式授权的关联域集合。**与 Sitemap.extra_scope 共享同一
            set 对象引用**，运行期增删自动生效（契约不做拷贝）。
        mode: ``strict``（默认，禁止自动晋升）或 ``extended``（逃生门开启）。
    """

    target: str = ""
    extra_scope: set[str] = field(default_factory=set)
    mode: str = SCOPE_MODE_STRICT

    # ---- 构造 ----

    @classmethod
    def from_parts(
        cls,
        target: str = "",
        extra_scope: set[str] | list[str] | None = None,
        mode: str | None = None,
    ) -> "AuthorizedScope":
        """从散件构造契约。

        - ``extra_scope`` 传 set 时**共享引用**（Sitemap 运行期可变）；
          传 list 时转为内部 set（调用方不再持有引用）。
        - ``mode`` 缺省读环境（XUANJIAN_SCOPE_AUTO_PROMOTE）。
        """
        if extra_scope is None:
            extra_scope = set()
        elif isinstance(extra_scope, set):
            pass  # 共享引用 —— Sitemap 持有同一集合
        else:
            extra_scope = {str(s).strip().lower() for s in extra_scope if str(s).strip()}
        return cls(
            target=(target or "").strip(),
            extra_scope=extra_scope,  # type: ignore[arg-type]
            mode=mode if mode in (SCOPE_MODE_STRICT, SCOPE_MODE_EXTENDED) else current_mode(),
        )

    # ---- 判定（权威实现；Sitemap._host_in_scope / _authorized_hosts 委托至此）----

    def hosts(self) -> set[str]:
        """计算授权 host 集合：target 主域及其子域 + 显式 extra_scope。

        - target 带端口时同时收录 hostname 与 netloc（同主机不同端口视为同一服务）。
        - extra_scope 中的条目支持裸域或带 scheme 的 URL，统一归一化为 hostname。
        """
        hosts: set[str] = set()
        target = (self.target or "").strip()
        if target:
            t = target if "://" in target else f"https://{target}"
            parsed = urlparse(t)
            netloc = (parsed.netloc or "").lower()
            hostname = (parsed.hostname or "").lower()
            if netloc:
                hosts.add(netloc)
            if hostname:
                hosts.add(hostname)
                # 主域本身（子域以 .hostname 结尾判定覆盖，无需额外展开）
        for item in (self.extra_scope or set()):
            s = str(item).strip().lower()
            if not s:
                continue
            if "://" in s:
                p = urlparse(s)
                if p.hostname:
                    hosts.add(p.hostname)
                    if p.netloc:
                        hosts.add(p.netloc)
            else:
                hosts.add(s.lstrip("."))
        return hosts

    def contains(self, url: str) -> bool:
        """判断 URL 的 host 是否在授权作用域内。

        无 host 的相对路径/空 URL 一律视为在范围内（不阻断目标内功能点）；
        无 target 信息时不做判定（防御式，避免全量误杀）。
        """
        url = (url or "").strip()
        if not url:
            return True
        if "://" not in url:
            return True  # 相对路径 / 仅路径 → 无法判断 host，放行
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            return True
        if not host:
            return True
        authorized = self.hosts()
        if not authorized:
            return True
        if host in authorized:
            return True
        # 子域：host 以任一授权 hostname + "." 开头（或反向包含，覆盖根域授权场景）
        for h in authorized:
            if not h:
                continue
            if host == h or host.endswith("." + h) or h.endswith("." + host):
                return True
        return False

    # ---- 指纹 ----

    def fingerprint(self) -> str:
        """作用域指纹：target + 显式 extra_scope + mode 的稳定短哈希。

        - 相同作用域状态 → 相同指纹（跨进程稳定，sha256 不受 PYTHONHASHSEED 影响）；
        - 任一要素变化（新增授权域 / 切换模式）→ 指纹变化，
          报告与 sitemap 落盘时各打一份，事后可核对"两份产物是否同一作用域产物"。
        """
        canonical = json.dumps(
            {
                "target": (self.target or "").strip().lower(),
                "extra_scope": sorted(
                    str(s).strip().lower() for s in (self.extra_scope or set()) if str(s).strip()
                ),
                "mode": self.mode or SCOPE_MODE_STRICT,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

    # ---- 展示 ----

    def describe(self) -> str:
        """人类可读的授权资产清单（供报告 §1.1 渲染）。"""
        parts: list[str] = []
        target = (self.target or "").strip()
        if target:
            t = target if "://" in target else f"https://{target}"
            host = (urlparse(t).netloc or t).lower()
            parts.append(host)
        for s in sorted(str(x).strip().lower() for x in (self.extra_scope or set())):
            if s and s not in parts:
                parts.append(s)
        text = "、".join(parts) if parts else "（未声明）"
        mode_label = "extended（允许自动发现关联域）" if self.mode == SCOPE_MODE_EXTENDED else "strict（严格隔离）"
        return f"{text}（模式: {mode_label}）"
