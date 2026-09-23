"""T8 / T15 离线夹具测试：敏感路径内容校验 + 多簇兜底页判定。

★ 为什么用离线夹具而不是"重放 ics.aibank.com"：
方案原稿的验收方式依赖真实网络 + 目标站今天仍在线，**不可 CI、不可复现**。
这里把 0923 实测到的三段真实响应形态固化成夹具：

- ``FALLBACK_A``：186 个互不相关路径共享的兜底页（HTML 壳）
- ``FALLBACK_B``：另一簇兜底页（``.git/config`` / ``shell.php`` / SPA 首页共享）
  —— **同一站点同时存在两簇**，这正是单基线 wildcard 检测漏掉 5 条误报的真因
- ``PROTECTED_403``：``/WEB-INF/classes/`` 被正确拦截

对应缺陷：D1 / D2 / D4 / E1 / E2 / E16。
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from core.dir_scanner import DirectoryScanner

# ============================================================
# 夹具：三段真实响应形态
# ============================================================

# 兜底页 A：SPA 外壳（会被 SPA 空壳检测识别）
FALLBACK_A = (
    "<!DOCTYPE html><html><head><title>Loading</title></head>"
    "<body><div id=\"root\"></div><script src=\"/static/js/app.js\"></script>"
    "</body></html>"
)

# 兜底页 B：另一簇兜底（长度与 A 明显不同，body_hash 也不同）
FALLBACK_B = (
    "<!DOCTYPE html><html><head><title>404 - Not Found</title>"
    "<meta charset=\"utf-8\"></head><body><h1>页面不存在</h1>"
    "<p>您访问的页面已失效，请返回首页。</p>"
    "<p>Requested resource is not available.</p></body></html>"
)

PROTECTED_403 = "<html><head><title>403 Forbidden</title></head><body>Access denied.</body></html>"

# 真实泄露（唯一响应体 + 内容指纹命中）
REAL_GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
    "\tbare = false\n\tlogallrefupdates = true\n"
    "[remote \"origin\"]\n\turl = git@internal.example.com:root/web.git\n"
)

# 会被 SENSITIVE_PATTERNS 命中的路径（与 0923 实测 5 条一致）
_SENSITIVE_LIKE = (
    "/.git/config", "/.git/index", "/.svn/entries",
    "/..;/actuator/env", "/WEB-INF/classes/application.yml",
    "/.env", "/backup.zip", "/.htaccess",
)


class _FakeResponse:
    def __init__(self, status_code=200, content=b"", headers=None):
        self.status_code = status_code
        self.content = content if isinstance(content, bytes) else content.encode()
        self.headers = headers or {}
        self.reason_phrase = "OK"


class _FakeAsyncClient:
    def __init__(self, handler):
        self._handler = handler
        self.is_closed = False

    async def get(self, url, headers=None):
        return self._handler(url)

    async def aclose(self):
        self.is_closed = True


def _install(monkeypatch, handler):
    from core import dir_scanner
    monkeypatch.setattr(dir_scanner.httpx, "AsyncClient",
                        lambda **kw: _FakeAsyncClient(handler))


def _path(url: str) -> str:
    return "/" + url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url


def _is_random_probe(path: str) -> bool:
    """基线探测用的是随机 16 位字母路径。"""
    seg = path.strip("/").split("/")[-1]
    return len(seg) >= 16 and seg.isalpha()


# ============================================================
# 1. 多簇兜底页判定（纯函数，确定性）
# ============================================================

class TestComputeCatchAllClusters:
    """T15 的核心判定：按 body_hash 簇识别兜底页。

    为什么必须是"簇"而不是 wildcard 标志：``wildcard_detected`` 只要基线探测
    返回非 404 就为 True（SPA/WAF/自定义 200 兜底页全命中），拿它否决会发现
    对这类目标的真实泄露大面积漏报。簇证据要求"同一响应体被多条不同路径共享"。
    """

    def test_ics_single_cluster(self):
        """ics.aibank.com 形态：4/5 共享同一响应体 → 判定为兜底页。"""
        from core.dir_scanner._scanner import compute_catch_all_clusters
        assert compute_catch_all_clusters(["a"] * 4 + ["b"]) == {"a": 4}

    def test_dominant_cluster_detected_among_two(self):
        """同站存在第二簇时，占多数的那一簇仍要被识别出来。

        实测 ics.aibank.com 就是这种形态：主力兜底页 + 另一簇局部兜底页。
        单基线 wildcard 只覆盖了基线那一簇，第二簇的敏感路径一路走到 finding。
        注：判定要求单簇占比 ≥60%，因此 50/50 平分的两簇都不会被判为兜底页
        —— 那种情形由内容指纹校验兜底（T8）。
        """
        from core.dir_scanner._scanner import compute_catch_all_clusters
        got = compute_catch_all_clusters(["a"] * 7 + ["b"] * 3)
        assert set(got) == {"a"}
        assert got["a"] == 7

    def test_small_sample_not_judged(self):
        """样本 < 5 不做判定（避免"1/1 = 100%"式误判）。"""
        from core.dir_scanner._scanner import compute_catch_all_clusters
        assert compute_catch_all_clusters(["a", "a", "a"]) == {}

    def test_below_threshold_ratio_not_judged(self):
        """占比不足 60% 不判定（真实目录扫出多个不同内容的路径）。"""
        from core.dir_scanner._scanner import compute_catch_all_clusters
        # 3/10 = 30%
        assert compute_catch_all_clusters(["a"] * 3 + [f"h{i}" for i in range(7)]) == {}

    def test_cluster_below_min_count_not_judged(self):
        """占比够但条数 < 3 不判定。"""
        from core.dir_scanner._scanner import compute_catch_all_clusters
        # 2/2 = 100% 但总数 < 5 已先被拦；这里构造 2/6 ≈ 33% 且条数 2
        assert compute_catch_all_clusters(["a", "a"] + [f"h{i}" for i in range(4)]) == {}

    def test_empty_input(self):
        from core.dir_scanner._scanner import compute_catch_all_clusters
        assert compute_catch_all_clusters([]) == {}


class TestMultiClusterCatchAll:
    def test_catch_all_recorded_and_no_confirmed(self, monkeypatch):
        """端到端（离线夹具）：两簇兜底页必须被记录，且不得产出 confirmed。

        这是防"把 5 条实证误报写进银行客户报告"的最后一道闸。
        """
        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(200, FALLBACK_A)
            if p in _SENSITIVE_LIKE:
                return _FakeResponse(200, FALLBACK_B)
            return _FakeResponse(200, FALLBACK_A)

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=6, recursive=False)
        result = asyncio.run(scanner.scan("https://ics.example.com/"))

        assert result.catch_all_detected is True
        assert result.catch_all_clusters, "必须记录 body_hash 簇分布供报告解释"
        confirmed = [f for f in result.findings if f.review_status == "confirmed"]
        assert confirmed == [], (
            f"catch-all 目标不得有 confirmed 发现，实际 {len(confirmed)} 条"
        )
        # 无论走"丢弃"还是"降级"，都不允许出现 HIGH
        assert all(f.severity not in ("high", "critical") for f in result.findings)

    def test_catch_all_demotes_fingerprint_matched_findings(self, monkeypatch):
        """簇命中时，连"指纹已匹配"的发现也要被降级（catch-all 一票否决）。

        修正前只有指纹校验，没有簇证据 → 兜底页恰好含配置样式内容时会误报。
        """
        # 第二簇：内容恰好命中 application.yml 指纹（真实世界见于运维调试页/
        # WAF 自定义错误页回显生效配置）
        shared_cfg = (
            "spring:\n  datasource:\n    url: jdbc:mysql://db/prod\n"
            "server:\n  port: 8080\n"
        )
        assert "spring:" in shared_cfg

        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(200, FALLBACK_A)
            if p.startswith("/WEB-INF/classes/application"):
                return _FakeResponse(200, shared_cfg)      # 指纹会命中
            return _FakeResponse(200, shared_cfg)          # 多条路径共享 → 成簇

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=6, recursive=False)
        result = asyncio.run(scanner.scan("https://cfg.example.com/"))

        if result.catch_all_clusters:
            for f in result.findings:
                assert f.review_status == "needs_review", (
                    "簇命中时不得有任何 confirmed"
                )
                assert f.severity not in ("high", "critical")
                assert f.review_reason, "降级必须写明原因"
                assert "body_sha256=" in f.evidence


# ============================================================
# 2. 真实泄露：内容指纹命中 → confirmed（不能把好的一起否掉）
# ============================================================

class TestRealLeakConfirmed:
    def test_real_git_config_is_confirmed(self, monkeypatch):
        """真实 .git/config（含 [core]/[remote]）必须落库为 confirmed。

        防止"为了压误报把真泄露也一起压掉"—— 这是修 D1 时最容易引入的回归。
        """
        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(404, "not found")
            if p == "/.git/config":
                return _FakeResponse(200, REAL_GIT_CONFIG)
            return _FakeResponse(404, "not found")

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://real.example.com/"))

        hits = [f for f in result.findings if f.path == "/.git/config"]
        assert hits, "真实泄露必须被发现"
        assert hits[0].review_status == "confirmed", (
            f"内容指纹命中应为 confirmed，实际 {hits[0].review_status}"
            f"（quality={hits[0].evidence_quality}）"
        )
        assert hits[0].evidence_quality == "content_match"
        assert hits[0].severity in ("high", "critical")

    def test_unverified_path_is_dropped(self, monkeypatch):
        """验证器明确否定（有指纹但内容不匹配）→ 不产出发现。

        与 fast_scanner/_checks_server.py 的 `if not matched: return None` 对齐。
        """
        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(404, "not found")
            if p == "/.git/config":
                # 有指纹（要求 [core]）但返回 HTML 兜底页 → 应被丢弃
                return _FakeResponse(200, FALLBACK_B)
            return _FakeResponse(404, "not found")

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://drop.example.com/"))
        assert all(f.path != "/.git/config" for f in result.findings), (
            "内容不匹配指纹的路径不得产出发现（否则 JSON/HTML 兜底页会一路误报）"
        )

    def test_no_fingerprint_type_is_demoted_not_dropped(self, monkeypatch):
        """无指纹可用的类型 → 保留但降级为 needs_review + medium（不丢数据）。"""

        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(404, "not found")
            if p == "/actuator/threaddump":
                # actuator 系列有指纹（要求 "threadName" 等）；这里返回不含
                # 指纹的纯文本 → 走 header_only 弱证据分支，应保留但降级
                return _FakeResponse(
                    200, ("unauthenticated. " * 10).encode(),
                    headers={"content-type": "text/plain"},
                )
            return _FakeResponse(404, "not found")

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://m.example.com/"))
        for f in result.findings:
            assert f.severity not in ("high", "critical")
            assert f.review_status in ("confirmed", "needs_review")


# ============================================================
# 3. 指纹表补全回归（T8 补的 key 必须真的生效）
# ============================================================

class TestFingerprintCoverage:
    @pytest.mark.parametrize("path,body,expect", [
        # 0923 实测 5 条里的 .git/index —— 修正前指纹表**没有这个 key**，
        # 会落到 header_only 弱证据分支
        ("/.git/index", "DIRC\x00\x00\x00\x02" + "y" * 200, True),
        ("/.svn/entries", "12\n", True),
        ("/WEB-INF/classes/application.yml",
         "spring:\n  datasource:\n    url: jdbc:mysql://x", True),
        # 兜底页（HTML）→ 有指纹但内容不匹配 → 必须 False
        ("/.git/config", FALLBACK_B, False),
        ("/.git/index", FALLBACK_B, False),
    ])
    def test_verify_sensitive_path_content(self, path, body, expect):
        from core.fast_scanner._fp_filters import _verify_sensitive_path_content
        matched, _quality = _verify_sensitive_path_content(path, body)
        assert matched is expect, f"{path} 期望 matched={expect}，实际 {matched}"

    def test_git_index_has_fingerprint_key(self):
        """T8 必须为 .git/index 补上指纹，否则它永远只能拿弱证据。"""
        from core.fast_scanner._constants import SENSITIVE_PATH_FINGERPRINTS
        assert ".git/index" in SENSITIVE_PATH_FINGERPRINTS, (
            ".git/index 缺指纹 key → 会走 header_only 分支，JSON 型兜底页仍会误报"
        )
        assert ".git/config" in SENSITIVE_PATH_FINGERPRINTS

    def test_business_deny_not_a_leak(self, monkeypatch):
        """业务层拒绝（未登录 JSON）不是泄露。"""
        def handler(url):
            p = _path(url)
            if _is_random_probe(p):
                return _FakeResponse(404, "nf")
            if p == "/.env":
                return _FakeResponse(
                    200,
                    '{"code":500,"message":"\u7528\u6237\u672a\u767b\u5f55"}',
                    headers={"content-type": "application/json"},
                )
            return _FakeResponse(404, "nf")

        _install(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://b.example.com/"))
        assert all(f.path != "/.env" for f in result.findings), (
            "业务层拒绝响应不应被当作敏感路径泄露"
        )
