"""regression 测试包共享配置。

注册 ``regression`` 标记，使项目 ``--strict-markers`` 配置下
``@pytest.mark.regression`` 可用（pyproject 已启用 strict markers，
未注册的标记会导致收集期 ERROR）。
"""

from __future__ import annotations

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "regression: regression pin — 锁定此前已修复缺陷的正确行为，防止回退",
    )
