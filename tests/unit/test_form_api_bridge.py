"""form_api_bridge 单元测试（确定性，零网络 / 零文件副作用）

验证点：
- ``_is_testable_action``：空 / # / javascript: / mailto: / tel: / data: / blob: / 正常 URL 的边界
- ``register_form_apis``：完整流程
    * 正常表单注册（add_api + add_api_sample 被调用）
    * 已提交表单跳过（submitted=True / requests_triggered>0）
    * 非业务 action 过滤
    * 相对 URL 解析（urljoin）
    * 非 http(s) scheme 过滤
    * 去重（existing_apis / sitemap.apis）
    * max_forms 限制
    * sitemap=None 时只计算不写 side-effect
    * method 缺省 POST / 大写归一
    * fields 过滤与 post_data 拼接
    * add_api_sample 抛异常被吞掉不影响 add_api

设计：用 FakeSitemap（无需真实 Sitemap 类）验证调用契约。
"""

from __future__ import annotations

from typing import Any

import pytest

from core.form_api_bridge import _is_testable_action, register_form_apis


# ============================================================
# 测试替身：Fake sitemap
# ============================================================
class _FakeApiEndpoint:
    """模拟 APIEndpoint：只需要 .method / .url / .discovered_by 属性。"""

    def __init__(self, method: str, url: str, discovered_by: str = ""):
        self.method = method
        self.url = url
        self.discovered_by = discovered_by


class FakeSitemap:
    """极简 sitemap 替身：记录 add_api / add_api_sample 调用，维护 apis 字典用于去重。"""

    def __init__(self, apis: dict | None = None,
                 add_api_sample_side_effect: Exception | None = None):
        self.apis: dict[str, _FakeApiEndpoint] = apis or {}
        self.add_api_calls: list[dict[str, Any]] = []
        self.add_api_sample_calls: list[dict[str, Any]] = []
        self._sample_side_effect = add_api_sample_side_effect

    def add_api(self, method: str, url: str, discovered_by: str = "", **kwargs) -> Any:
        self.add_api_calls.append(
            {"method": method, "url": url, "discovered_by": discovered_by, "kwargs": kwargs}
        )
        key = f"{method} {url}"
        ep = _FakeApiEndpoint(method, url, discovered_by)
        self.apis[key] = ep
        return ep

    def add_api_sample(self, method: str, url: str, headers: dict | None = None,
                       body: str = "", status_code: int = 0,
                       discovered_by: str = "", response_body: str = "",
                       response_headers: dict | None = None,
                       content_type: str = "", js_context: str = "",
                       flow_id: str = "", trigger_context: dict | None = None,
                       **kwargs) -> None:
        if self._sample_side_effect is not None:
            raise self._sample_side_effect
        self.add_api_sample_calls.append({
            "method": method, "url": url, "headers": headers, "body": body,
            "status_code": status_code, "discovered_by": discovered_by,
            "response_body": response_body, "response_headers": response_headers,
            "content_type": content_type, "js_context": js_context,
            "flow_id": flow_id, "trigger_context": trigger_context,
        })


# ---- 工厂函数：构造 crawl_result ----
def _form(action: str = "", method: str = "POST", fields: list | None = None,
          page: str = "", submitted: bool = False, requests_triggered: int = 0) -> dict:
    return {
        "action": action,
        "method": method,
        "fields": fields if fields is not None else ["username", "password"],
        "page": page,
        "submitted": submitted,
        "requests_triggered": requests_triggered,
    }


def _crawl_result(forms: list, api_endpoints: list | None = None) -> dict:
    return {"forms": forms, "api_endpoints": api_endpoints or []}


# ============================================================
# _is_testable_action
# ============================================================
class TestIsTestableAction:
    def test_empty_string(self):
        assert _is_testable_action("") is False

    def test_none(self):
        assert _is_testable_action(None) is False  # type: ignore[arg-type]

    def test_hash(self):
        assert _is_testable_action("#") is False

    def test_javascript_bare(self):
        assert _is_testable_action("javascript:") is False

    def test_javascript_void(self):
        assert _is_testable_action("javascript:void(0)") is False

    def test_void_bare(self):
        assert _is_testable_action("void(0)") is False

    def test_mailto(self):
        assert _is_testable_action("mailto:a@b.com") is False

    def test_tel(self):
        assert _is_testable_action("tel:+8613800138000") is False

    def test_data(self):
        assert _is_testable_action("data:text/html,<h1>x</h1>") is False

    def test_blob(self):
        assert _is_testable_action("blob:https://example.com/uuid") is False

    def test_normal_absolute_url(self):
        assert _is_testable_action("https://example.com/login") is True

    def test_relative_url(self):
        assert _is_testable_action("/login") is True

    def test_whitespace_stripped(self):
        # 带前后空白的合法 action 应被 strip 后判为可测
        assert _is_testable_action("  /login  ") is True

    def test_whitespace_only(self):
        assert _is_testable_action("   ") is False

    def test_uppercase_javascript_prefix(self):
        # 前缀匹配是大小写不敏感的（.lower() 后比较）
        assert _is_testable_action("JavaScript:void(0)") is False
        assert _is_testable_action("MAILTO:a@b.com") is False


# ============================================================
# register_form_apis — 正常流程
# ============================================================
class TestRegisterNormal:
    def test_single_form_registered(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", method="POST",
                                  fields=["user", "pass"], page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")

        assert added == ["POST https://example.com/login"]
        assert len(sm.add_api_calls) == 1
        assert sm.add_api_calls[0]["method"] == "POST"
        assert sm.add_api_calls[0]["url"] == "https://example.com/login"
        assert sm.add_api_calls[0]["discovered_by"] == "form_inference"
        # add_api_sample 也被调用
        assert len(sm.add_api_sample_calls) == 1
        sample = sm.add_api_sample_calls[0]
        assert sample["method"] == "POST"
        assert sample["url"] == "https://example.com/login"
        assert sample["content_type"] == "application/x-www-form-urlencoded"
        assert sample["discovered_by"] == "form_inference"

    def test_post_data_built_from_fields(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", fields=["user", "pass"],
                                  page="https://example.com/login")])
        register_form_apis(sm, cr, target_url="https://example.com/")
        sample = sm.add_api_sample_calls[0]
        # post_data = "user=&pass="
        assert sample["body"] == "user=&pass="

    def test_trigger_context_captures_form_action_and_page(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", fields=["u"],
                                  page="https://example.com/login")])
        register_form_apis(sm, cr, target_url="https://example.com/")
        ctx = sm.add_api_sample_calls[0]["trigger_context"]
        assert ctx == {"form_action": "/login", "form_page": "https://example.com/login"}

    def test_multiple_forms_all_registered(self):
        sm = FakeSitemap()
        cr = _crawl_result([
            _form(action="/login", fields=["u"], page="https://example.com/login"),
            _form(action="/register", method="POST", fields=["email"],
                  page="https://example.com/register"),
        ])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert len(added) == 2
        assert "POST https://example.com/login" in added
        assert "POST https://example.com/register" in added
        assert len(sm.add_api_calls) == 2


# ============================================================
# register_form_apis — 跳过逻辑
# ============================================================
class TestRegisterSkip:
    def test_skip_submitted_form(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", submitted=True,
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_skip_requests_triggered_form(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", requests_triggered=3,
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_skip_non_business_action_javascript(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="javascript:void(0)",
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_skip_non_business_action_hash(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="#", page="https://example.com/")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []

    def test_skip_empty_action(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="", page="https://example.com/")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []


# ============================================================
# register_form_apis — 相对 URL 解析 & scheme 过滤
# ============================================================
class TestUrlResolution:
    def test_relative_action_resolved_via_urljoin(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="auth/signin", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        # urljoin("https://example.com/login", "auth/signin") → .../auth/signin
        assert added == ["POST https://example.com/auth/signin"]

    def test_relative_action_uses_target_url_when_no_page(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/api/login", fields=["u"], page="")])
        added = register_form_apis(sm, cr, target_url="https://example.com/portal")
        assert added == ["POST https://example.com/api/login"]

    def test_non_http_scheme_filtered(self):
        """action 解析后非 http(s) 的应被跳过（如 file://）。"""
        sm = FakeSitemap()
        # target_url 是 http，但 action 是 file: → _is_testable_action 放过 file?
        # 注意 _is_testable_action 不过滤 file:，但 urljoin 后 scheme 不是 http/https → 跳过
        cr = _crawl_result([_form(action="file:///etc/passwd", fields=["u"],
                                  page="https://example.com/")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []


# ============================================================
# register_form_apis — 去重逻辑
# ============================================================
class TestDedup:
    def test_dedup_against_existing_apis(self):
        sm = FakeSitemap()
        cr = _crawl_result(
            [_form(action="/login", fields=["u"], page="https://example.com/login")],
            api_endpoints=[{"method": "POST", "url": "https://example.com/login"}],
        )
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_dedup_against_sitemap_apis(self):
        existing = {"POST https://example.com/login":
                    _FakeApiEndpoint("POST", "https://example.com/login")}
        sm = FakeSitemap(apis=existing)
        cr = _crawl_result([_form(action="/login", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_dedup_different_method_kept(self):
        """同 URL 不同 method 不算重复。"""
        sm = FakeSitemap()
        cr = _crawl_result(
            [_form(action="/login", method="GET", fields=["u"],
                   page="https://example.com/login")],
            api_endpoints=[{"method": "POST", "url": "https://example.com/login"}],
        )
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == ["GET https://example.com/login"]


# ============================================================
# register_form_apis — max_forms 限制
# ============================================================
class TestMaxForms:
    def test_max_forms_limits_count(self):
        sm = FakeSitemap()
        forms = [
            _form(action=f"/api/{i}", fields=["u"], page="https://example.com/")
            for i in range(10)
        ]
        cr = _crawl_result(forms)
        added = register_form_apis(sm, cr, target_url="https://example.com/", max_forms=3)
        assert len(added) == 3
        assert len(sm.add_api_calls) == 3

    def test_max_forms_zero(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", fields=["u"],
                                  page="https://example.com/")])
        added = register_form_apis(sm, cr, target_url="https://example.com/", max_forms=0)
        # max_forms=0 → 第一条加入后 len(added)=1 >= 0 → break
        assert len(added) == 1


# ============================================================
# register_form_apis — sitemap=None（只计算不写 side-effect）
# ============================================================
class TestSitemapNone:
    def test_none_sitemap_no_side_effect(self):
        cr = _crawl_result([_form(action="/login", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(None, cr, target_url="https://example.com/")
        # 仍返回计算结果
        assert added == ["POST https://example.com/login"]
        # 无 sitemap 对象，不会有任何写入

    def test_none_sitemap_still_dedup_against_existing_apis(self):
        cr = _crawl_result(
            [_form(action="/login", fields=["u"], page="https://example.com/login")],
            api_endpoints=[{"method": "POST", "url": "https://example.com/login"}],
        )
        added = register_form_apis(None, cr, target_url="https://example.com/")
        assert added == []


# ============================================================
# register_form_apis — method / fields 边界
# ============================================================
class TestMethodAndFields:
    def test_method_defaults_to_post(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", method="", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == ["POST https://example.com/login"]

    def test_method_uppercased(self):
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", method="post", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == ["POST https://example.com/login"]

    def test_empty_fields_no_sample_but_api_added(self):
        """fields 为空时 add_api_sample 不调用，但 add_api 仍调用。"""
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", fields=[], page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == ["POST https://example.com/login"]
        assert len(sm.add_api_calls) == 1
        assert sm.add_api_sample_calls == []

    def test_falsy_fields_filtered(self):
        """fields 中含 None / 空字符串等 falsy 值应被过滤。"""
        sm = FakeSitemap()
        cr = _crawl_result([_form(action="/login", fields=["user", "", None, "pass"],
                                  page="https://example.com/login")])
        register_form_apis(sm, cr, target_url="https://example.com/")
        sample = sm.add_api_sample_calls[0]
        # 只有 user / pass 两个有效字段
        assert sample["body"] == "user=&pass="

    def test_none_fields_treated_as_empty(self):
        sm = FakeSitemap()
        # 直接构造 form dict，确保 fields=None 传入（不走 _form 工厂的默认值）
        cr = _crawl_result([{
            "action": "/login", "method": "POST", "fields": None,
            "page": "https://example.com/login",
            "submitted": False, "requests_triggered": 0,
        }])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == ["POST https://example.com/login"]
        assert sm.add_api_sample_calls == []


# ============================================================
# register_form_apis — 容错
# ============================================================
class TestRobustness:
    def test_empty_forms_list(self):
        sm = FakeSitemap()
        cr = _crawl_result([])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []
        assert sm.add_api_calls == []

    def test_missing_forms_key(self):
        sm = FakeSitemap()
        cr = {}  # 无 forms 键
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert added == []

    def test_add_api_sample_exception_swallowed(self):
        """add_api_sample 抛异常不应影响 add_api 与返回值。"""
        sm = FakeSitemap(add_api_sample_side_effect=RuntimeError("boom"))
        cr = _crawl_result([_form(action="/login", fields=["u"],
                                  page="https://example.com/login")])
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        # add_api 仍被调用且返回正常
        assert added == ["POST https://example.com/login"]
        assert len(sm.add_api_calls) == 1

    def test_default_max_forms_is_50(self):
        """不传 max_forms 时使用默认值 50。"""
        sm = FakeSitemap()
        forms = [
            _form(action=f"/api/{i}", fields=["u"], page="https://example.com/")
            for i in range(60)
        ]
        cr = _crawl_result(forms)
        added = register_form_apis(sm, cr, target_url="https://example.com/")
        assert len(added) == 50
