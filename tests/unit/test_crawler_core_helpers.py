# -*- coding: utf-8 -*-
"""D6 阶段 0：crawler_core 模块级纯函数 / 监听器行为回归测试。

这些函数从 AutoCrawler 方法内嵌套 def 提升而来，闭包捕获的变量改为显式参数。
本测试锁定它们的运行时行为，确保提升（move + 参数化）未引入回归。
零网络、零 LLM、零 Playwright（用极简桩对象替代 request/response/self/noise）。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.crawler import crawler_core as cc  # noqa: E402


# ---------- 极简桩对象 ----------

class FakeRequest:
    def __init__(self, url, resource_type="xhr", method="GET", headers=None,
                 post_data=None, post_data_buffer=None):
        self.url = url
        self.resource_type = resource_type
        self.method = method
        self.headers = headers or {}
        self.post_data = post_data
        self.post_data_buffer = post_data_buffer


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body="", resource_type="fetch"):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self._body = body
        self.resource_type = resource_type

    async def text(self):
        return self._body


class FakeSelf:
    def __init__(self, in_scope=True):
        self._in_scope = in_scope

    def _is_in_scope(self, url: str) -> bool:
        return self._in_scope


class FakeNoise:
    def __init__(self):
        self.calls = []

    def record(self, url, resource_type):
        self.calls.append((url, resource_type))


# ---------- _collect_paths_from_menu_node ----------

def test_collect_paths_basic():
    out = set()
    node = {
        "path": "/admin/user",
        "children": [
            {"url": "/admin/role"},
            {"path": "/admin/log"},
        ],
    }
    cc._collect_paths_from_menu_node(node, out)
    assert "/admin/user" in out
    assert "/admin/role" in out
    assert "/admin/log" in out


def test_collect_paths_filters_non_path():
    out = set()
    node = {
        "path": "https://evil.com/x",     # 跨域 http → 过滤
        "url": "javascript:void(0)",       # javascript: → 过滤
        "menuUrl": "#/home",               # fragment-only → 过滤
        "router": "/real/path",            # 保留
    }
    cc._collect_paths_from_menu_node(node, out)
    assert "/real/path" in out
    assert "https://evil.com/x" not in out
    assert len(out) == 1


def test_collect_paths_list_input():
    # 列表只递归 dict/list 元素；裸字符串项会被忽略（与原始嵌套函数一致）
    out = set()
    cc._collect_paths_from_menu_node(["/a", {"path": "/b"}, {"url": "/c"}], out)
    assert "/b" in out and "/c" in out
    assert "/a" not in out  # 裸字符串不入集


# ---------- _is_menu_tree_structure ----------

def test_is_menu_tree_true():
    data = [
        {"name": "用户", "path": "/u", "children": [{"name": "x"}]},
        {"title": "角色", "path": "/r", "children": [{"name": "y"}]},
        {"label": "日志", "path": "/l", "children": [{"name": "z"}]},
    ]
    assert cc._is_menu_tree_structure(data) is True


def test_is_menu_tree_false_flat():
    data = [{"foo": 1}, {"bar": 2}, {"baz": 3}]
    assert cc._is_menu_tree_structure(data) is False


def test_is_menu_tree_false_short():
    assert cc._is_menu_tree_structure([{"name": "a", "path": "/a"}]) is False


# ---------- _menu_fingerprint ----------

def test_menu_fingerprint_with_href():
    fp = cc._menu_fingerprint({"text": "用户管理", "href": "https://x.com/admin/user?utm=1"}, "https://x.com/home")
    assert fp == ("用户管理", "x.com/admin/user")


def test_menu_fingerprint_without_href():
    fp = cc._menu_fingerprint({"text": "提交", "href": ""}, "https://x.com")
    assert fp == ("提交", "@btn")


def test_menu_fingerprint_empty_text():
    assert cc._menu_fingerprint({"text": "  ", "href": "/a"}, "x") is None


# ---------- _collect_ids_from_url ----------

def test_collect_ids_query():
    id_pool = {}
    cc._collect_ids_from_url("https://x.com/api/user?id=123&role_id=9", id_pool)
    assert "123" in id_pool.get("/api/user", set())
    assert "9" in id_pool.get("/api/user", set())


def test_collect_ids_path_segment():
    id_pool = {}
    cc._collect_ids_from_url("https://x.com/api/users/456/profile", id_pool)
    assert "456" in id_pool.get("/api/users", set())


def test_collect_ids_uuid_segment():
    uuid = "a" * 12  # 长度>=8 且全 hex
    id_pool = {}
    cc._collect_ids_from_url(f"https://x.com/api/order/{uuid}", id_pool)
    assert uuid in id_pool.get("/api/order", set())


# ---------- _get_wait_params ----------

def test_get_wait_params_returns_dict():
    # 不依赖 score_menu 具体分值，只保证返回可解包的 dict（契约稳定）
    assert isinstance(cc._get_wait_params({"text": "x"}, "business"), dict)


# ---------- _cdp_on_request / _cdp_on_response ----------

def test_cdp_on_request_filters_resource_type():
    captured = []
    cc._cdp_on_request(FakeRequest("https://x.com/a", resource_type="document"), captured)
    assert captured == []  # document 不收录
    cc._cdp_on_request(FakeRequest("https://x.com/api", resource_type="xhr"), captured)
    assert len(captured) == 1
    assert captured[0]["url"] == "https://x.com/api"
    assert "timestamp" in captured[0]


def test_cdp_on_response_backfills():
    captured = [{"url": "https://x.com/api"}]
    resp = FakeResponse("https://x.com/api", status=200, headers={"X": "1"}, body="<html>")
    asyncio.run(cc._cdp_on_response(resp, captured))
    item = captured[0]
    assert item["status"] == 200
    assert item["response_headers"] == {"X": "1"}
    assert item["response_body"] == "<html>"


# ---------- _noise_listener ----------

def test_noise_listener_records():
    noise = FakeNoise()
    cc._noise_listener(FakeRequest("https://x.com/a", resource_type="xhr"), noise)
    assert noise.calls == [("https://x.com/a", "xhr")]


# ---------- _smart_wait_business_xhr ----------

def test_smart_wait_no_business_returns_zero():
    # in-scope 恒为 False → 第一阶段静默期后判定无业务 → 返回 0
    import time as _t
    captured = []
    start = _t.monotonic()
    res = asyncio.run(cc._smart_wait_business_xhr(captured, 0, FakeSelf(in_scope=False),
                                                  initial_quiet_s=0.05, settle_quiet_s=0.05, max_wait_s=1.0))
    assert res == 0
    assert _t.monotonic() - start < 1.0  # 不应等到 max_wait_s


def test_smart_wait_detects_business():
    captured = [{"resource_type": "xhr", "url": "https://x.com/api"}]
    res = asyncio.run(cc._smart_wait_business_xhr(captured, 0, FakeSelf(in_scope=True),
                                                  initial_quiet_s=0.05, settle_quiet_s=0.05, max_wait_s=1.0))
    assert res >= 1
