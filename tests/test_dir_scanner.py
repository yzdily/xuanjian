"""
目录扫描器 + 目标不可达路径修复的回归测试。

覆盖：
1. DirectoryScanner 主机不可达预检（ConnectError → 立即中止，不发字典请求）
2. DirectoryScanner 软 404 / 通配符假阳性过滤（dirsearch 同款基线对比）
3. DirectoryScanner 状态码白名单 + 敏感路径分类
4. DirectoryScanner 受限递归
5. ScanStrategyConfig.crawl_timeout 透传修复（Bug 2 回归）
6. _advance_phase 必须传 summary + 无裸调用残留（Bug 1 回归）
"""

import asyncio
import inspect
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

from core.dir_scanner import (
    DEFAULT_WORDLIST,
    DirectoryScanner,
    DirScanResult,
    RECURSE_CANDIDATES,
    SENSITIVE_PATTERNS,
    scan_directories,
    build_tech_aware_wordlist,
    UNIVERSAL_PATHS,
    STATIC_RESOURCE_PATHS,
    API_PRIORITY_KEYWORDS,
)


# ============================================================
# 测试桩：FakeResponse / FakeAsyncClient
# ============================================================

class FakeResponse:
    def __init__(self, status_code=200, content=b"", headers=None):
        self.status_code = status_code
        self.content = content if isinstance(content, bytes) else content.encode()
        self.headers = headers or {}
        self.reason_phrase = "OK"


class FakeAsyncClient:
    """根据 handler(url) -> FakeResponse 的假客户端。"""

    def __init__(self, handler):
        self._handler = handler
        self.is_closed = False
        self.calls = 0

    async def get(self, url, headers=None):
        self.calls += 1
        return self._handler(url)

    async def aclose(self):
        self.is_closed = True


def _install_fake_client(monkeypatch, handler):
    """把 dir_scanner 内的 httpx.AsyncClient 替换为返回 FakeAsyncClient 的工厂。"""
    from core import dir_scanner

    def _factory(**kwargs):
        return FakeAsyncClient(handler)

    monkeypatch.setattr(dir_scanner.httpx, "AsyncClient", _factory)
    return _factory


# ============================================================
# 1. 主机不可达预检
# ============================================================

class TestHostUnreachable:
    def test_connect_error_triggers_critical_path_fallback(self, monkeypatch):
        """基线连接失败 → host_unreachable=True + 关键路径兜底（best-effort）。"""
        call_log = []

        def handler(url):
            call_log.append(url)
            raise httpx.ConnectError("connection refused")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://dead.example.com/"))

        assert result.host_unreachable is True
        assert result.critical_path_fallback is True
        assert result.discovered_count == 0  # 全部 ConnectError，无存活
        assert result.sensitive_count == 0
        # ★ 关键路径兜底应发了请求（全部 ConnectError，total_requests=0
        #   但 connect_errors 应 > 0）
        assert result.connect_errors > 0
        # 基线（2 随机路径 × 2 重试）+ 关键路径子集 都尝试过
        assert len(call_log) >= 4  # 至少 4 次基线 + N 次关键路径

    def test_critical_path_fallback_finds_surviving_path(self, monkeypatch):
        """基线失败但关键路径中有存活端点 → 应被发现。"""
        def handler(url):
            # 基线随机路径（16 位字母）→ ConnectError
            path = url.rsplit("/", 1)[-1]
            if len(path) >= 16 and path.isalpha():
                raise httpx.ConnectError("refused")
            # /actuator/env 在关键路径里，返回 200
            if url.endswith("/actuator/env"):
                return FakeResponse(
                    200, b'{"propertySources":[]}',
                    headers={"content-type": "application/json"},
                )
            # 其余关键路径 → ConnectError
            raise httpx.ConnectError("refused")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://partial.example.com/"))

        assert result.host_unreachable is True
        assert result.critical_path_fallback is True
        assert result.discovered_count == 1
        paths = {e.path for e in result.entries}
        assert "/actuator/env" in paths
        # 敏感分类仍然生效
        assert result.sensitive_count >= 1

    def test_timeout_triggers_fallback(self, monkeypatch):
        """基线超时 → host_unreachable=True + 关键路径兜底。"""
        def handler(url):
            raise httpx.ReadTimeout("read timeout")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(max_workers=4, recursive=False)
        result = asyncio.run(scanner.scan("https://slow.example.com/"))

        assert result.host_unreachable is True
        assert result.critical_path_fallback is True
        assert result.timeout_errors > 0


# ============================================================
# 2. 软 404 / 通配符过滤
# ============================================================

class TestWildcardFiltering:
    def test_soft_404_filtered(self, monkeypatch):
        """随机路径返回 200（软 404）→ 同样响应的字典项被过滤。"""
        soft_404_body = b"<html><body>not found page</body></html>"

        def handler(url):
            # /admin 返回真实内容
            if url.endswith("/admin"):
                return FakeResponse(200, b"<html><title>Admin Console</title></html>")
            # /backup.zip 返回 404
            if url.endswith("/backup.zip"):
                return FakeResponse(404, b"")
            # 其余（含基线随机路径 + /login）返回软 404 200
            return FakeResponse(200, soft_404_body)

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            wordlist=["admin", "login", "backup.zip"],
        )
        result = asyncio.run(scanner.scan("https://target.example.com/"))

        paths = {e.path for e in result.entries}
        assert "/admin" in paths, "真实路径应被发现"
        assert "/login" not in paths, "软 404 响应应被过滤"
        assert "/backup.zip" not in paths, "404 应被状态码白名单排除"
        assert result.wildcard_detected is True


# ============================================================
# 3. 状态码白名单 + 敏感路径分类
# ============================================================

class TestStatusAndSensitive:
    def test_status_filter_and_sensitive_findings(self, monkeypatch):
        def handler(url):
            if url.endswith("/actuator/env"):
                return FakeResponse(
                    200, b'{"propertySources":[{"name":"systemEnvironment"}]}',
                    headers={"content-type": "application/json"},
                )
            if url.endswith("/.env"):
                return FakeResponse(200, b"DB_PASSWORD=s3cret\n")
            if url.endswith("/api"):
                return FakeResponse(301, b"", headers={"location": "/api/"})
            return FakeResponse(404, b"")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            wordlist=["actuator/env", ".env", "api", "missing"],
        )
        result = asyncio.run(scanner.scan("https://target.example.com/"))

        paths = {e.path for e in result.entries}
        assert "/actuator/env" in paths
        assert "/.env" in paths
        assert "/api" in paths  # 301 在白名单内
        assert "/missing" not in paths  # 404 排除

        # 敏感分类
        vuln_types = {f.vuln_type for f in result.findings}
        assert any("Actuator" in v for v in vuln_types)
        assert any(".env" in v or "环境配置" in v for v in vuln_types)
        # actuator/env 与 .env 都应判 high
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) >= 2
        assert result.wildcard_detected is False  # 基线 404

    def test_403_and_405_kept(self, monkeypatch):
        def handler(url):
            if url.endswith("/forbidden"):
                return FakeResponse(403, b"")
            if url.endswith("/no-method"):
                return FakeResponse(405, b"")
            return FakeResponse(404, b"")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            wordlist=["forbidden", "no-method"],
        )
        result = asyncio.run(scanner.scan("https://target.example.com/"))
        paths = {e.path for e in result.entries}
        assert "/forbidden" in paths
        assert "/no-method" in paths


# ============================================================
# 4. 受限递归
# ============================================================

class TestRecursion:
    def test_recurses_into_candidate_dirs(self, monkeypatch):
        def handler(url):
            if url.endswith("/api"):
                return FakeResponse(301, b"", headers={"location": "/api/"})
            if url.endswith("/api/users"):
                return FakeResponse(200, b'{"users":[]}',
                                    headers={"content-type": "application/json"})
            return FakeResponse(404, b"")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=True, max_depth=2,
            wordlist=["api", "users"],
        )
        result = asyncio.run(scanner.scan("https://target.example.com/"))

        paths = {e.path for e in result.entries}
        assert "/api" in paths
        assert "/api/users" in paths, "递归应发现 /api/users"
        assert result.recursed_dirs >= 1
        assert "api" in RECURSE_CANDIDATES


# ============================================================
# 5. Bug 2 回归：ScanStrategyConfig.crawl_timeout
# ============================================================

class TestScanStrategyConfigCrawlTimeout:
    def test_crawl_timeout_present_for_all_modes(self):
        from core.scan_strategies import (
            ScanConfig, ScanMode, ScanStrategyConfig, get_scan_strategy,
        )

        for mode in ("fast", "standard", "deep", "smart"):
            cfg = get_scan_strategy(mode)
            assert isinstance(cfg, ScanStrategyConfig)
            assert hasattr(cfg, "crawl_timeout"), f"{mode} 缺少 crawl_timeout"
            assert isinstance(cfg.crawl_timeout, int)
            assert cfg.crawl_timeout > 0

    def test_fast_mode_crawl_timeout_matches_scan_config(self):
        from core.scan_strategies import ScanConfig, ScanMode, get_scan_strategy

        fast_cfg = ScanConfig.from_mode(ScanMode.FAST)
        strategy = get_scan_strategy("fast")
        # FAST crawl_timeout=180（与 tests/unit/test_scan_strategies.py 一致；本断言校验透传一致性）
        assert strategy.crawl_timeout == fast_cfg.crawl_timeout == 180
        assert strategy.fast_scan_timeout == fast_cfg.fast_scan_timeout

    def test_crawl_timeout_is_real_attribute_not_missing(self):
        """直接复现原报错：访问 .crawl_timeout 不再抛 AttributeError。"""
        from core.scan_strategies import get_scan_strategy
        cfg = get_scan_strategy("fast")
        _ = cfg.crawl_timeout  # 不应抛异常
        _ = cfg.fast_scan_timeout


# ============================================================
# 6. Bug 1 回归：_advance_phase 必须传 summary
# ============================================================

class TestAdvancePhaseSummary:
    def test_advance_phase_signature_requires_summary(self):
        from core.session.advance_mixin import AdvancePhaseMixin

        sig = inspect.signature(AdvancePhaseMixin._advance_phase)
        assert "summary" in sig.parameters
        param = sig.parameters["summary"]
        # summary 无默认值（必填位置参数）
        assert param.default is inspect.Parameter.empty

    def test_no_bare_advance_phase_calls_in_session_sources(self):
        """全代码库不应残留 self._advance_phase() 空参调用。"""
        session_dir = Path(__file__).parent.parent / "core" / "session"
        pattern = re.compile(r"self\._advance_phase\s*\(\s*\)")
        offenders = []
        for py_file in session_dir.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for m in pattern.finditer(text):
                offenders.append(f"{py_file.name}: {m.group().strip()}")
        assert not offenders, f"残留空参 _advance_phase() 调用: {offenders}"

    def test_advance_phase_without_summary_raises_typeerror(self):
        """直接调用不带 summary 必须报 TypeError（锁定方法契约）。"""
        from core.session.advance_mixin import AdvancePhaseMixin

        class _Dummy(AdvancePhaseMixin):
            pass

        with pytest.raises(TypeError):
            # 不传 summary → 缺必填参数
            asyncio.run(_Dummy()._advance_phase())  # type: ignore[arg-type]


# ============================================================
# 7. 数据模型 / 字典健全性
# ============================================================

class TestWordlistIntegrity:
    def test_default_wordlist_non_empty(self):
        assert len(DEFAULT_WORDLIST) >= 100
        # 无前导斜杠
        assert all(not w.startswith("/") for w in DEFAULT_WORDLIST)

    def test_scanner_dedupes_wordlist(self):
        """构造器必须去重保序（原始人工字典可能含重复条目）。"""
        scanner = DirectoryScanner(
            wordlist=DEFAULT_WORDLIST + ["admin", "admin", "login"],
        )
        assert len(scanner.wordlist) == len(set(scanner.wordlist))
        assert "admin" in scanner.wordlist
        assert "login" in scanner.wordlist

    def test_sensitive_patterns_cover_actuator_and_env(self):
        joined = " ".join(k for k, _, _ in SENSITIVE_PATTERNS)
        assert "actuator/env" in joined
        assert "actuator/heapdump" in joined
        assert ".env" in joined
        assert ".git" in joined

    def test_to_dict_serializable(self):
        r = DirScanResult(target="https://x/")
        d = r.to_dict()
        assert d["target"] == "https://x/"
        assert d["discovered_count"] == 0
        assert d["entries"] == []


# ============================================================
# 8. 便捷入口 scan_directories
# ============================================================

class TestScanDirectoriesHelper:
    def test_helper_returns_result(self, monkeypatch):
        def handler(url):
            return FakeResponse(404, b"")

        _install_fake_client(monkeypatch, handler)
        result = asyncio.run(scan_directories(
            "https://x.example.com/", recursive=False,
        ))
        assert isinstance(result, DirScanResult)
        # 基线随机路径返回 404 → 主机可达（host_unreachable=False），无软 404
        assert result.host_unreachable is False
        assert result.wildcard_detected is False
        assert result.discovered_count == 0  # 全部 404，无命中


# ============================================================
# 9. SPA catch-all 路由误报率测试
# ============================================================

# SPA 空壳页面模板（模拟 React/Vue 的 index.html）
_SPA_INDEX_HTML = b"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SPA App</title>
  <script defer src="/static/js/main.a1b2c3d4.js"></script>
</head>
<body>
  <div id="root"></div>
</body>
</html>"""

# 带动态内容的 SPA 空壳（模拟嵌入请求路径 hash 的 catch-all 响应）
def _make_spa_shell_with_path(path: str) -> bytes:
    """生成包含请求路径的 SPA 壳页面（body_hash 不同但内容高度相似）。"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SPA App</title>
  <meta name="x-request-path" content="{path}">
  <script defer src="/static/js/main.a1b2c3d4.js"></script>
</head>
<body>
  <div id="root"></div>
</body>
</html>""".encode()


class TestSPACatchAllFalsePositive:
    """SPA 站点 catch-all 路由误报率专项测试。

    测试矩阵：
    A. 真 catch-all（基线返回 SPA HTML）→ 通配符过滤全部命中，0 误报
    B. 动态内容 catch-all（body_hash 不同但相似）→ Jaccard 相似度过滤
    C. 模式 catch-all（基线 404，字典路径返回相同 body）→ catch-all 检测 + 早期中止
    D. 混合场景（真实 API + catch-all）→ 真实端点存活，catch-all 被过滤
    E. 非 SPA 站点 → 不误判 catch-all
    F. 工具函数单元测试（_normalize_body / _bodies_similar）
    G. 字典构建（静态排除 / API 优先 / 大小合理性）
    """

    # ---- A. 真 catch-all（基线返回 SPA HTML）→ 通配符过滤 ----

    def test_true_catch_all_zero_false_positives(self, monkeypatch):
        """所有路径（含基线随机路径）返回相同 SPA HTML → 通配符过滤全部命中，0 误报。"""
        _install_fake_client(monkeypatch, lambda url: FakeResponse(200, _SPA_INDEX_HTML))

        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React, Node.js",
            is_spa=True,
            wordlist=[
                "api", "api/v1", "swagger-ui.html", "actuator/env",
                "graphql", "openapi.json", ".env", ".git/config",
                "health", "metrics",
                "admin", "login", "dashboard", "docs",
                "upload", "backup", "test",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa.example.com/"))

        # 通配符检测应触发（基线随机路径返回非 404）
        assert result.wildcard_detected is True, \
            "基线随机路径返回 SPA HTML 应触发通配符检测"

        # 所有 SPA 响应应被通配符过滤 → 0 个假阳性 entries
        assert result.discovered_count == 0, \
            f"纯 catch-all 站点不应有任何 entries（全被通配符过滤），" \
            f"实际 {result.discovered_count} 个"

        # SPA 标志应被检测
        assert result.is_spa_detected is True

    def test_true_catch_all_no_spa_entries_leak(self, monkeypatch):
        """纯 catch-all 站点 entries 中不应有 SPA 壳响应泄漏。"""
        _install_fake_client(monkeypatch, lambda url: FakeResponse(200, _SPA_INDEX_HTML))

        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React",
            is_spa=True,
            wordlist=["api", "swagger", "admin", "login", "docs", "test"],
        )
        result = asyncio.run(scanner.scan("https://spa-leak.example.com/"))

        # 检查 entries 中没有 SPA 壳响应
        spa_entries = [
            e for e in result.entries
            if e.body_text and '<div id="root">' in e.body_text
        ]
        assert len(spa_entries) == 0, \
            f"entries 中不应有 SPA 壳响应泄漏，实际 {len(spa_entries)} 个"

    # ---- B. 动态内容 catch-all → Jaccard 相似度过滤 ----

    def test_dynamic_content_catch_all_filtered_by_similarity(self, monkeypatch):
        """catch-all 响应体含动态内容（请求路径）→ Jaccard 相似度过滤。

        基线随机路径也返回动态 SPA 壳 → 通配符基线存储 body_text →
        后续字典路径的 SPA 壳通过相似度对比被过滤。
        """
        def handler(url):
            path = urlparse(url).path
            # 真实 API → 返回 JSON（与 SPA 壳完全不同）
            if path == "/api/v1/users":
                return FakeResponse(
                    200, b'{"users":[{"id":1,"name":"alice"}]}',
                    headers={"content-type": "application/json"},
                )
            # 其余路径（含基线随机路径）→ 返回包含路径的 SPA 壳
            return FakeResponse(200, _make_spa_shell_with_path(path))

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="Vue, Node.js",
            is_spa=True,
            wordlist=[
                "api/v1/users", "swagger", "actuator/env",
                "health", "metrics", ".env",
                "admin", "login", "dashboard", "docs",
                "upload", "backup", "test", "console",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa-dynamic.example.com/"))

        # 通配符检测应触发
        assert result.wildcard_detected is True, \
            "基线随机路径返回 SPA 壳应触发通配符检测"

        # 真实 API 端点应被发现（与 SPA 壳不相似，不被过滤）
        paths = {e.path for e in result.entries}
        assert "/api/v1/users" in paths, \
            "真实 API 端点不应被相似度过滤误杀"

        # SPA 壳响应应被相似度过滤（不残留在 entries 中）
        spa_entries = [
            e for e in result.entries
            if e.body_text and '<div id="root">' in e.body_text
        ]
        assert len(spa_entries) == 0, \
            f"动态内容 SPA 壳应被 Jaccard 相似度过滤，" \
            f"实际残留 {len(spa_entries)} 个"

    # ---- C. 模式 catch-all（基线 404 → catch-all 检测 + 早期中止）----

    def test_pattern_catch_all_detected_with_404_baseline(self, monkeypatch):
        """基线返回 404，但字典路径全部返回相同 SPA HTML → catch-all 检测 + 早期中止。

        场景：后端配置了 catch-all 路由（匹配已知路径前缀），
        但随机路径不匹配 → 返回 404。此时通配符基线不触发，
        但 catch-all 检测应通过 body_hash 统计发现。
        """
        def handler(url):
            path = urlparse(url).path
            # 基线随机路径（16 位字母）→ 404
            last_segment = path.rsplit("/", 1)[-1]
            if len(last_segment) >= 16 and last_segment.isalpha():
                return FakeResponse(404, b"")
            # 字典路径 → 返回相同 SPA HTML
            return FakeResponse(200, _SPA_INDEX_HTML)

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React",
            is_spa=True,
            wordlist=[
                "api", "api/v1", "swagger", "actuator/env",
                "graphql", "openapi.json", ".env", "health",
                "admin", "login", "dashboard", "docs",
                "upload", "backup", "test", "console",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa-pattern.example.com/"))

        # catch-all 应被检测（>=5 entries 且 >50% 相同 body_hash）
        assert result.catch_all_detected is True, \
            "模式 catch-all（基线 404 + 字典路径返回相同 body）应被检测"

        # 早期中止应跳过部分非 API 路径
        assert result.early_abort_count > 0, \
            f"应触发早期中止，实际 early_abort_count={result.early_abort_count}"

        # catch-all 诊断字段应填充
        assert result.catch_all_rate > 50.0
        assert result.catch_all_hash != ""

    # ---- D. 混合场景（真实 API + catch-all）----

    def test_real_api_survives_catch_all_filtering(self, monkeypatch):
        """真实 API 端点 + SPA catch-all 混合 → 真实端点存活，catch-all 被过滤。"""
        real_api_responses = {
            "/api/v1/users": (
                200,
                b'{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}',
                {"content-type": "application/json"},
            ),
            "/actuator/env": (
                200,
                b'{"propertySources":[{"name":"systemEnvironment"}]}',
                {"content-type": "application/json"},
            ),
            "/swagger-ui.html": (
                200,
                b'<html><title>Swagger UI</title><script>SwaggerUIBundle({})</script></html>',
                {"content-type": "text/html"},
            ),
        }

        def handler(url):
            path = urlparse(url).path
            if path in real_api_responses:
                status, content, headers = real_api_responses[path]
                return FakeResponse(status, content, headers=headers)
            return FakeResponse(200, _SPA_INDEX_HTML)

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React, Node.js",
            is_spa=True,
            wordlist=[
                "api/v1/users", "actuator/env", "swagger-ui.html",
                "openapi.json", "graphql", ".env", "health", "metrics",
                "admin", "login", "dashboard", "docs",
                "upload", "backup", "test", "console",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa-mixed.example.com/"))

        # 真实 API 端点应被发现
        paths = {e.path for e in result.entries}
        assert "/api/v1/users" in paths, "真实 API 端点应被发现"
        assert "/actuator/env" in paths, "Actuator 端点应被发现"
        assert "/swagger-ui.html" in paths, "Swagger UI 应被发现"

        # SPA 壳响应应被过滤
        spa_entries = [
            e for e in result.entries
            if e.body_text and '<div id="root">' in e.body_text
        ]
        assert len(spa_entries) == 0, \
            f"SPA 壳响应不应残留在 entries 中，实际 {len(spa_entries)} 个"

        # 敏感路径分类仍生效
        vuln_types = {f.vuln_type for f in result.findings}
        assert any("Actuator" in v for v in vuln_types), \
            "Actuator 环境信息泄露应被分类"

    # ---- D.2 误报率量化 ----

    def test_false_positive_rate_below_threshold(self, monkeypatch):
        """SPA catch-all 站点的误报率（假阳性 entries 占比）应为 0%。"""
        real_endpoints = {
            "/api/v1/users": b'{"users":[]}',
            "/api/v1/products": b'{"products":[]}',
            "/actuator/health": b'{"status":"UP"}',
        }

        def handler(url):
            path = urlparse(url).path
            if path in real_endpoints:
                return FakeResponse(
                    200, real_endpoints[path],
                    headers={"content-type": "application/json"},
                )
            return FakeResponse(200, _SPA_INDEX_HTML)

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React, Node.js",
            is_spa=True,
            wordlist=[
                "api/v1/users", "api/v1/products", "actuator/health",
                "swagger", "openapi.json", "graphql", ".env",
                "health", "metrics", "api/v2", "api/v3",
                "admin", "login", "dashboard", "docs", "upload",
                "backup", "test", "console", "panel", "config",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa-fp.example.com/"))

        # 误报率计算：entries 中返回 SPA 壳内容的比例
        total_entries = len(result.entries)
        assert total_entries > 0, "应至少发现真实端点"

        false_positives = [
            e for e in result.entries
            if e.body_text and '<div id="root">' in e.body_text
        ]
        fp_rate = len(false_positives) / total_entries if total_entries else 1.0

        assert fp_rate == 0.0, \
            f"误报率应为 0%（通配符+相似度过滤），" \
            f"实际 {fp_rate*100:.1f}% ({len(false_positives)}/{total_entries})"

    # ---- E. 非 SPA 站点不触发误报 ----

    def test_non_spa_site_no_false_catch_all(self, monkeypatch):
        """非 SPA 站点（各路径返回不同内容）不应误判 catch-all。"""
        def handler(url):
            path = urlparse(url).path
            if path == "/admin":
                return FakeResponse(200, b"<html><title>Admin Panel</title><h1>Welcome Admin</h1></html>")
            if path == "/login":
                return FakeResponse(200, b"<html><title>Login</title><form>username/password</form></html>")
            if path == "/api/v1/users":
                return FakeResponse(200, b'{"users":[]}', headers={"content-type": "application/json"})
            if path == "/docs":
                return FakeResponse(200, b"<html><title>Documentation</title><p>API docs here</p></html>")
            return FakeResponse(404, b"")

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            wordlist=["admin", "login", "api/v1/users", "docs"],
        )
        result = asyncio.run(scanner.scan("https://normal.example.com/"))

        # 不应误判 catch-all
        assert result.catch_all_detected is False, \
            "各路径返回不同内容的非 SPA 站点不应被判为 catch-all"
        assert result.early_abort_count == 0, \
            "非 catch-all 站点不应触发早期中止"

        # 所有真实路径都应被发现
        paths = {e.path for e in result.entries}
        assert "/admin" in paths
        assert "/login" in paths
        assert "/api/v1/users" in paths
        assert "/docs" in paths

    # ---- E.2 SPA 空壳基线检测（运行时动态 is_spa）----

    def test_spa_shell_detected_from_baseline(self, monkeypatch):
        """未传入 is_spa 但基线响应匹配 SPA 空壳 → 动态启用 SPA 模式。"""
        def handler(url):
            path = urlparse(url).path
            # 真实 API
            if path == "/api/v1/status":
                return FakeResponse(
                    200, b'{"status":"ok"}',
                    headers={"content-type": "application/json"},
                )
            # 所有其他路径（含基线随机路径）返回 SPA 壳
            return FakeResponse(200, _SPA_INDEX_HTML)

        _install_fake_client(monkeypatch, handler)
        # ★ 不传入 is_spa=True，让基线检测自动识别
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="",
            wordlist=[
                "api/v1/status", "swagger", "actuator/env",
                "health", "admin", "login", "docs",
            ],
        )
        result = asyncio.run(scanner.scan("https://spa-baseline.example.com/"))

        # 基线检测应识别 SPA
        assert result.is_spa_detected is True, \
            "基线响应匹配 SPA 空壳特征时应动态启用 SPA 模式"

        # 通配符检测应触发
        assert result.wildcard_detected is True

        # 真实 API 端点应被发现
        paths = {e.path for e in result.entries}
        assert "/api/v1/status" in paths, "真实 API 端点应被发现"

        # SPA 壳响应应被过滤
        spa_entries = [
            e for e in result.entries
            if e.body_text and '<div id="root">' in e.body_text
        ]
        assert len(spa_entries) == 0

    # ---- F. 相似度过滤工具单元测试 ----

    def test_bodies_similar_exact_match(self):
        """_bodies_similar 对相同内容返回 True。"""
        scanner = DirectoryScanner(max_workers=1, recursive=False)
        body = "<html><body>Hello World This is a test page with enough content</body></html>"
        assert scanner._bodies_similar(body, body) is True

    def test_bodies_similar_with_dynamic_content(self):
        """_bodies_similar 对仅动态内容不同的响应返回 True。"""
        scanner = DirectoryScanner(max_workers=1, recursive=False)
        # 使用 16+ 字符的 token（匹配正则 [a-zA-Z0-9_\-]{16,}）
        body1 = '<html><body>Token: abc123def456ghi789 Timestamp: 1700000000 Page content here</body></html>'
        body2 = '<html><body>Token: xyz789ghi012jkl345 Timestamp: 1700000099 Page content here</body></html>'
        assert scanner._bodies_similar(body1, body2) is True, \
            "仅动态内容（token/时间戳）不同的响应应判为相似"

    def test_bodies_similar_different_content(self):
        """_bodies_similar 对完全不同的内容返回 False。"""
        scanner = DirectoryScanner(max_workers=1, recursive=False)
        body1 = '{"users": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]}'
        body2 = '<html><body><div id="root"></div><script src="/main.js"></script></body></html>'
        assert scanner._bodies_similar(body1, body2) is False

    def test_bodies_similar_spa_shells_with_different_paths(self):
        """_bodies_similar 对仅路径不同的 SPA 壳返回 True。"""
        scanner = DirectoryScanner(max_workers=1, recursive=False)
        body1 = _make_spa_shell_with_path("/admin").decode()
        body2 = _make_spa_shell_with_path("/login").decode()
        assert scanner._bodies_similar(body1, body2) is True, \
            "仅请求路径不同的 SPA 壳应判为相似"

    def test_normalize_body_strips_dynamic_content(self):
        """_normalize_body 应剥离时间戳/token/hash 等动态内容。"""
        scanner = DirectoryScanner(max_workers=1, recursive=False)
        raw = 'Token: csrf_abc123def456ghi789 Time: 1700000000 Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
        normalized = scanner._normalize_body(raw)
        assert "1700000000" not in normalized, "时间戳应被剥离"
        assert "csrf_abc123def456" not in normalized, "CSRF token 应被剥离"
        assert "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" not in normalized, "hash 应被剥离"

    # ---- G. 字典构建测试 ----

    def test_static_resources_excluded_in_spa_wordlist(self):
        """build_tech_aware_wordlist(is_spa=True) 应排除静态资源路径。"""
        wl = build_tech_aware_wordlist("React, Node.js", is_spa=True)

        # 静态资源应被排除
        excluded = {"static", "assets", "images", "css", "js", "dist", "build"}
        for s in excluded:
            assert s not in wl, f"SPA 模式应排除静态资源 '{s}'"

        # 通用 API 路径应保留
        assert "api" in wl
        assert "swagger-ui.html" in wl
        assert "graphql" in wl
        assert ".env" in wl

    def test_static_resources_excluded_in_build_candidates(self):
        """_build_candidates 在 is_spa=True 时应排除静态资源。"""
        scanner = DirectoryScanner(
            wordlist=["api", "static", "assets", "admin", "swagger"],
            is_spa=True,
        )
        candidates = scanner._build_candidates()
        assert "static" not in candidates
        assert "assets" not in candidates
        assert "api" in candidates
        assert "swagger" in candidates

    def test_api_priority_paths_ordered_first(self):
        """build_tech_aware_wordlist 应将 API 优先路径排在前面。"""
        wl = build_tech_aware_wordlist("Java/Spring", is_spa=False)
        from core.dir_scanner import _is_api_priority
        first_non_api_idx = None
        for i, w in enumerate(wl):
            if not _is_api_priority(w):
                first_non_api_idx = i
                break
        assert first_non_api_idx is not None, "应存在非 API 路径"

        # 第一个非 API 路径之前的所有路径都应是 API 优先
        for w in wl[:first_non_api_idx]:
            assert _is_api_priority(w), \
                f"路径 '{w}' 不在 API 优先组但排在前面"

    def test_tech_aware_wordlist_sizes_are_reasonable(self):
        """不同技术栈的字典大小应合理（定向 < 全量）。"""
        default_wl = build_tech_aware_wordlist("", is_spa=False)
        java_wl = build_tech_aware_wordlist("Java/Spring", is_spa=False)
        php_wl = build_tech_aware_wordlist("PHP, WordPress", is_spa=False)
        spa_wl = build_tech_aware_wordlist("React, Node.js", is_spa=True)

        # 定向字典应小于全量
        assert len(java_wl) < len(default_wl), \
            "Java 定向字典应小于全量默认字典"
        assert len(php_wl) < len(default_wl), \
            "PHP 定向字典应小于全量默认字典"

        # SPA 字典应最小（排除了静态资源）
        assert len(spa_wl) < len(java_wl), \
            "SPA 字典（排除静态资源）应小于非 SPA 定向字典"

        # 全量字典至少 100 条
        assert len(default_wl) >= 100

    # ---- H. catch-all 诊断字段完整性（使用模式 catch-all 场景）----

    def test_catch_all_diagnostic_fields_populated(self, monkeypatch):
        """模式 catch-all 场景下诊断字段应完整填充。"""
        def handler(url):
            path = urlparse(url).path
            last_segment = path.rsplit("/", 1)[-1]
            # 基线随机路径 → 404
            if len(last_segment) >= 16 and last_segment.isalpha():
                return FakeResponse(404, b"")
            # 字典路径 → 返回相同 SPA HTML
            return FakeResponse(200, _SPA_INDEX_HTML)

        _install_fake_client(monkeypatch, handler)
        scanner = DirectoryScanner(
            max_workers=4, recursive=False,
            tech_stack="React",
            is_spa=True,
            wordlist=["api", "swagger", "actuator/env", "health",
                      "admin", "login", "docs", "test",
                      "metrics", "graphql"],
        )
        result = asyncio.run(scanner.scan("https://spa-diag.example.com/"))

        assert result.catch_all_detected is True, \
            f"模式 catch-all 应被检测（entries={len(result.entries)}）"
        assert result.catch_all_rate > 0, "catch_all_rate 应被填充"
        assert result.catch_all_hash != "", "catch_all_hash 应被填充"
        assert len(result.catch_all_body) > 0, "catch_all_body 应被填充"
        assert result.is_spa_detected is True
        assert result.tech_stack_detected == "React"
        assert result.wordlist_size > 0
        assert result.early_abort_count > 0, "early_abort_count 应被填充"

        # to_dict 序列化应包含新字段
        d = result.to_dict()
        assert "early_abort_count" in d
        assert "tech_stack_detected" in d
        assert "is_spa_detected" in d
        assert "wordlist_size" in d
