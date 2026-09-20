from core.crawler.login_mixin import LoginMixin
from core.intent import jwt_headers_to_local_storage
from core.js_analyzer import (
    JSAnalysisResult,
    JSApiCall,
    JSRoute,
    _extract_storage_keys,
    _looks_like_auth_state_key,
    _looks_like_auth_storage_key,
    js_result_to_crawl_data,
)


def test_authenticated_api_success_with_custom_token_header():
    captured = [
        {
            "resource_type": "fetch",
            "url": "https://wpsisv-portalui.showcon.cn/org/api/v1/tenant-enterprise/major",
            "headers": {"Sc-Id-Token": "eyJ.valid.jwt", "Sc-I18n": "zh_CN"},
            "status_code": 200,
            "response_body": '{"code":"000000","message":"success","data":{"id":575}}',
        }
    ]

    assert LoginMixin._has_authenticated_api_success(captured) is True


def test_authenticated_api_success_rejects_invalid_uri_root():
    captured = [
        {
            "resource_type": "fetch",
            "url": "https://wpsisv-portalui.showcon.cn/config/users",
            "headers": {"Sc-Id-Token": "eyJ.valid.jwt"},
            "status_code": 200,
            "response_body": '{"code":"000001","message":"invalid uri root","data":null}',
        }
    ]

    assert LoginMixin._has_authenticated_api_success(captured) is False


def test_sc_id_token_maps_to_showcon_storage_key():
    token = "eyJ.valid.jwt.payload.signature"

    items = jwt_headers_to_local_storage({"Sc-Id-Token": token})

    assert items["Sc-Id-Token"] == token
    assert items["token"] == token
    assert items["showcon_token_mpv1.0"] == token
    assert items["showcon_login_type"] == "tenant_user_pass"


def test_sc_id_token_injects_login_type_for_router_guard():
    """路由守卫在读取 token 之前先检查 login_type，缺失→直接跳 /error。"""
    token = "eyJ.valid.jwt.payload.signature"

    items = jwt_headers_to_local_storage({"Sc-Id-Token": token})

    assert "showcon_login_type" in items
    assert items["showcon_login_type"] in ("tenant_user_pass", "user_sso")


def test_js_extracts_login_type_auth_state_keys():
    js_text = """
    var r="showcon_login_type", l="showncon_loginPageKey";
    function h(){ return localStorage.getItem(r) }
    localStorage.setItem("custom_login_method", "enterprise");
    """

    keys = _extract_storage_keys(js_text)

    assert "showcon_login_type" in keys
    assert "custom_login_method" in keys


def test_looks_like_auth_state_key():
    assert _looks_like_auth_state_key("showcon_login_type") is True
    assert _looks_like_auth_state_key("loginType") is True
    assert _looks_like_auth_state_key("custom_login_method") is True
    assert _looks_like_auth_state_key("showcon_token_mpv1.0") is False
    assert _looks_like_auth_state_key("token") is False


def test_jwt_maps_to_js_discovered_custom_storage_keys():
    token = "eyJ.valid.jwt.payload.signature"

    items = jwt_headers_to_local_storage(
        {"X-Auth-Token": token},
        storage_keys=["tenant_auth_token_v2", "refresh_token", "csrf_token"],
    )

    assert items["tenant_auth_token_v2"] == token
    assert "refresh_token" not in items
    assert "csrf_token" not in items


def test_js_extracts_custom_storage_keys_from_direct_and_variable_usage():
    js_text = """
    var i="showcon_token_mpv1.0", o="showcon_refresh_token_mpv1.0";
    function p(){ return localStorage.getItem(i) }
    localStorage.setItem("tenant_auth_token_v2", token);
    sessionStorage.getItem("jwt_session_key");
    """

    keys = _extract_storage_keys(js_text)

    assert "showcon_token_mpv1.0" in keys
    assert "tenant_auth_token_v2" in keys
    assert "jwt_session_key" in keys


def test_js_hash_routes_keep_app_base_from_source_file():
    result = JSAnalysisResult(
        routes=[
            JSRoute(
                path="/manage/businessConfig",
                source_file="https://wpsisv-portalui.showcon.cn/view/static/js/app.592edd5b.js",
            )
        ],
        router_mode="hash",
    )

    data = js_result_to_crawl_data(result, "https://wpsisv-portalui.showcon.cn")

    assert data["js_routes"][0]["url"] == "https://wpsisv-portalui.showcon.cn/view/#/manage/businessConfig"


def test_js_api_paths_still_use_origin_base_not_app_base():
    result = JSAnalysisResult(
        api_calls=[
            JSApiCall(
                method="GET",
                path="/org/api/v1/tenant-enterprise/major",
                source_file="https://wpsisv-portalui.showcon.cn/view/static/js/app.592edd5b.js",
            )
        ]
    )

    data = js_result_to_crawl_data(result, "https://wpsisv-portalui.showcon.cn")

    assert data["js_api_calls"][0]["url"] == "https://wpsisv-portalui.showcon.cn/org/api/v1/tenant-enterprise/major"
