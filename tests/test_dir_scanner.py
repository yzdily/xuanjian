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

import httpx
import pytest

from core.dir_scanner import (
    DEFAULT_WORDLIST,
    DirectoryScanner,
    DirScanResult,
    RECURSE_CANDIDATES,
    SENSITIVE_PATTERNS,
    scan_directories,
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
        assert strategy.crawl_timeout == fast_cfg.crawl_timeout == 60
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
