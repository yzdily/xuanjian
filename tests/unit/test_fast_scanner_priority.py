"""Fix4 回归测试：优先级感知调度。

覆盖三点：
1. ScanTarget.priority 字段默认值与自定义；
2. scan_targets 按优先级降序排序（critical→high→medium→low），高价值目标先扫；
3. WAF/超时封禁后不盲目跳过全部，仅跳过 medium/low，继续尝试 critical/high。

所有测试均通过 monkeypatch scan_target 实现，不发起真实网络请求。
"""

import asyncio

import pytest

from core.fast_scanner import FastScanner, ScanTarget, ScanResult


def _target(url: str, priority: str = "medium") -> ScanTarget:
    return ScanTarget(url=url, priority=priority)


@pytest.mark.asyncio
async def test_scantarget_priority_default_and_custom():
    assert _target("http://x/a").priority == "medium"
    assert _target("http://x/b", "critical").priority == "critical"
    assert _target("http://x/c", "high").priority == "high"


@pytest.mark.asyncio
async def test_scan_targets_orders_by_priority_desc():
    scanner = FastScanner(max_workers=1)
    targets = [
        _target("http://x/low", "low"),
        _target("http://x/critical", "critical"),
        _target("http://x/medium", "medium"),
        _target("http://x/high", "high"),
    ]
    attempted: list[str] = []

    async def fake_scan(target, enabled_rules=None):
        attempted.append(target.priority)
        return ScanResult(target_url=target.url, elapsed=0, total_requests=0, rules_run=0)

    scanner.scan_target = fake_scan
    await scanner.scan_targets(targets)
    # 必须严格按 critical → high → medium → low 顺序
    assert attempted == ["critical", "high", "medium", "low"]


@pytest.mark.asyncio
async def test_scan_targets_waf_continues_critical_high_only():
    scanner = FastScanner(max_workers=1)
    targets = [
        _target("http://x/critical", "critical"),
        _target("http://x/high", "high"),
        _target("http://x/medium", "medium"),
        _target("http://x/low", "low"),
    ]
    attempted: list[str] = []

    async def fake_scan(target, enabled_rules=None):
        attempted.append(target.url)
        # 第一个目标扫描即触发 WAF 全局封禁（模拟真实打挂）
        scanner._waf_blocked = True
        return ScanResult(target_url=target.url, elapsed=0, total_requests=0, rules_run=0)

    scanner.scan_target = fake_scan
    results = await scanner.scan_targets(targets)

    # 封禁后仅 critical/high 被继续尝试，medium/low 被跳过
    assert attempted == ["http://x/critical", "http://x/high"]
    assert len(results) == 2


@pytest.mark.asyncio
async def test_scan_targets_timeout_continues_critical_high_only():
    scanner = FastScanner(max_workers=1)
    targets = [
        _target("http://x/low", "low"),
        _target("http://x/high", "high"),
        _target("http://x/critical", "critical"),
    ]
    attempted: list[str] = []

    async def fake_scan(target, enabled_rules=None):
        attempted.append(target.url)
        scanner._timeout_blocked = True
        return ScanResult(target_url=target.url, elapsed=0, total_requests=0, rules_run=0)

    scanner.scan_target = fake_scan
    results = await scanner.scan_targets(targets)

    # 排序后 critical 先于 high，故超时触发后实际尝试顺序为 [critical, high]
    assert attempted == ["http://x/critical", "http://x/high"]
    assert len(results) == 2
