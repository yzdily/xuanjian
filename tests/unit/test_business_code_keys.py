"""§4 Phase 2 item 7：业务码可配置（BUSINESS_CODE_DOMAINS）单元测试。

验证：
1. 默认域 profile_a 精确复现 _constants.BUSINESS_DENY_PATTERNS 的检测行为
2. 域B profile_b 可识别 ret/errno 风格业务拒绝
3. 未知域回退到默认域
4. build_business_deny_patterns 返回 6 条正则，与 _is_business_deny 迭代形态兼容
"""

import re

from core.config import (
    BUSINESS_CODE_DOMAINS,
    DEFAULT_BUSINESS_DOMAIN,
    build_business_deny_patterns,
)
from core.fast_scanner._constants import BUSINESS_DENY_PATTERNS


def _matches(text: str, patterns: list[str]) -> bool:
    """复用 _is_business_deny 的逐条 re.search 形态。"""
    if not text or len(text) < 5:
        return False
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


# 域A 标准业务拒绝样本（应被 profile_a 命中）
_A_POSITIVE = [
    '{"code":401,"msg":"未登录"}',
    '{"errorCode":403,"message":"权限不足"}',
    '{"status_code":500,"error_msg":"身份验证失败"}',
    '{"msg":"token已过期"}',
    '{"success":false,"data":null}',
    '{"status":"false"}',
    'code:401, msg: unauthorized',
]
# 域A 正常业务样本（不应被命中）
_A_NEGATIVE = [
    '{"code":0,"data":[{"name":"admin"}]}',
    '{"success":true,"data":[1,2,3]}',
    '{"code":200,"msg":"ok"}',
    '{"result":"ok"}',
]


def test_default_domain_is_profile_a():
    assert DEFAULT_BUSINESS_DOMAIN == "profile_a"
    assert "profile_a" in BUSINESS_CODE_DOMAINS and "profile_b" in BUSINESS_CODE_DOMAINS


def test_build_returns_six_patterns():
    pats = build_business_deny_patterns()
    assert isinstance(pats, list)
    assert len(pats) == 6, "应产出 6 条正则（与 BUSINESS_DENY_PATTERNS 形态对齐）"
    # 每条都是合法可编译正则
    for p in pats:
        assert isinstance(p, str)
        re.compile(p)


def test_profile_a_reproduces_current_behavior_positive():
    """profile_a materialize 后应命中所有当前 BUSINESS_DENY_PATTERNS 能命中的样本。"""
    built = build_business_deny_patterns("profile_a")
    for sample in _A_POSITIVE:
        assert _matches(sample, built), f"profile_a 应命中: {sample}"
        # 行为对齐：原硬编码同样命中
        assert _matches(sample, BUSINESS_DENY_PATTERNS), f"原 PATTERN 应命中: {sample}"


def test_profile_a_reproduces_current_behavior_negative():
    built = build_business_deny_patterns("profile_a")
    for sample in _A_NEGATIVE:
        assert not _matches(sample, built), f"profile_a 不应命中: {sample}"
        assert not _matches(sample, BUSINESS_DENY_PATTERNS), f"原 PATTERN 不应命中: {sample}"


def test_profile_a_built_equals_hardcoded_semantically():
    """profile_a 与硬编码在正负样本集上判定完全一致（行为零回归）。"""
    built = build_business_deny_patterns("profile_a")
    for sample in _A_POSITIVE + _A_NEGATIVE:
        assert _matches(sample, built) == _matches(sample, BUSINESS_DENY_PATTERNS), sample


def test_profile_b_detects_ret_errno_style():
    """域B（ret/errno/errmsg 风格）能识别域A 不覆盖的拒绝样本。"""
    built_b = build_business_deny_patterns("profile_b")
    # ret:-1 风格（域B 才覆盖 -1/-2 长码）
    assert _matches('{"ret":-1,"errmsg":"未登录"}', built_b)
    assert _matches('{"errno":403,"errMsg":"无权访问"}', built_b)
    assert _matches('{"ret":401,"errmsg":"鉴权失败"}', built_b)
    # ok:false 风格（域B flag 含 ok）
    assert _matches('{"ok":false}', built_b)
    # 正常样本不命中
    assert not _matches('{"ret":0,"data":"ok"}', built_b)


def test_unknown_domain_falls_back_to_default():
    """未知域应回退到默认域（profile_a），不抛错。"""
    unknown = build_business_deny_patterns("nonexistent_domain")
    default = build_business_deny_patterns(None)
    assert unknown == default
