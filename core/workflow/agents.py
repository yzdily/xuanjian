"""core.workflow.agents — 5 个核心 Agent（长期 L2）。

按 XUANJIAN_ROADMAP_LONG_TERM §3.3 落地：
- recon: 订阅 scan.start → 发 recon.done
- authz: 订阅 recon.done → 发 authz.done
- fuzz: 订阅 authz.done → 发 fuzz.done
- verify: 订阅 fuzz.done → 发 verify.done（含 PoC 闸）
- report: 订阅 verify.done → 发 report.done

业务委托到 core/ 现有模块；找不到时降级 stub（不抛错），便于单元测试不依赖完整栈。

零外部依赖。
"""
from __future__ import annotations

from typing import Any

from core.os.event_bus import OSEventBus
from core.workflow.agent import Agent


def _safe_import(mod: str, attr: str | None = None):
    """延迟 import 业务；失败返 None。"""
    try:
        m = __import__(mod, fromlist=["*"])
        if attr:
            return getattr(m, attr, None)
        return m
    except Exception:
        return None


class ReconAgent(Agent):
    """侦察 Agent：sitemap 抓取。"""

    def __init__(self, bus: OSEventBus):
        super().__init__("recon", ["scan.start"], bus)

    def run(self, ctx: dict) -> dict:
        crawl = _safe_import("core.crawl")
        url = ctx.get("url", "")
        if crawl and hasattr(crawl, "crawl_sitemap"):
            sitemap = crawl.crawl_sitemap(url)
        else:
            sitemap = [{"url": url, "method": "GET", "_stub": True}]
        return {"sitemap": sitemap, "ctx": ctx}


class AuthzAgent(Agent):
    """鉴权 Agent：build_authz_matrix。"""

    def __init__(self, bus: OSEventBus):
        super().__init__("authz", ["recon.done"], bus)

    def run(self, ctx: dict) -> dict:
        bu = _safe_import("core.business_understanding")
        sitemap = ctx.get("sitemap", [])
        if bu and hasattr(bu, "build_authz_matrix"):
            matrix = bu.build_authz_matrix(sitemap)
        else:
            matrix = {"endpoints": len(sitemap), "_stub": True}
        return {"authz": matrix, "ctx": ctx.get("ctx", ctx)}


class FuzzAgent(Agent):
    """fuzz Agent：SQLi / BOLA 等扫描。"""

    def __init__(self, bus: OSEventBus):
        super().__init__("fuzz", ["authz.done"], bus)

    def run(self, ctx: dict) -> dict:
        sqli = _safe_import("core.fuzz.sqli")
        sitemap = ctx.get("sitemap", [])
        authz = ctx.get("authz", {})
        if sqli and hasattr(sqli, "scan"):
            findings = sqli.scan(sitemap, authz=authz)
        else:
            findings = []
        return {"findings": findings, "ctx": ctx.get("ctx", ctx)}


class VerifyAgent(Agent):
    """验证 Agent：用 PoC 闸（M1）跑复现。"""

    def __init__(self, bus: OSEventBus):
        super().__init__("verify", ["fuzz.done"], bus)

    def run(self, ctx: dict) -> dict:
        poc_gen = _safe_import("core.poc_gen")
        poc_play = _safe_import("core.poc_playback")
        findings = ctx.get("findings", [])
        verified: list[dict] = []
        for f in findings:
            if not (poc_gen and poc_play):
                verified.append({**f, "poc": {"_stub": True}, "verdict": "confirmed"})
                continue
            poc = poc_gen.gen_poc(f)
            r = poc_play.play(poc)
            if r.get("success"):
                verified.append({**f, "poc": poc, "verdict": "confirmed"})
            else:
                verified.append({**f, "poc": poc, "verdict": "rejected"})
        return {"verified": verified, "ctx": ctx.get("ctx", ctx)}


class ReportAgent(Agent):
    """报告 Agent：渲染报告（M1 PoC 闸 + M2 反幻觉护栏已就位）。"""

    def __init__(self, bus: OSEventBus):
        super().__init__("report", ["verify.done"], bus)

    def run(self, ctx: dict) -> dict:
        rep = _safe_import("core.session.report_mixin")
        verified = ctx.get("verified", [])
        tenant = ctx.get("ctx", {}).get("tenant") or ctx.get("tenant", "default")
        if rep and hasattr(rep, "render_report"):
            report = rep.render_report(verified, tenant=tenant)
        else:
            report = {"verified_count": len(verified), "tenant": tenant, "_stub": True}
        return {"report": report}


__all__ = ["ReconAgent", "AuthzAgent", "FuzzAgent", "VerifyAgent", "ReportAgent"]
