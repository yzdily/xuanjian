"""Sitemap 包 — 站点地图 + 功能点清单 + 测试覆盖矩阵。

Phase 0 探索时构建页面和 API 列表
Phase 1 分析时识别功能点，为每个功能点生成测试 checklist
Phase 2 逐项测试，每测完一项打勾标记结论
Phase 3 输出覆盖矩阵：功能 × 漏洞类型 × 结论

【模块结构】
- 数据模型（TestStatus / CheckResult / Priority / PageInfo / APIEndpoint
            / CheckItem / FeaturePoint）→ core/sitemap/models.py
- 模块常量 → constants.py
- Sitemap 主类 → sitemap.py（核心 CRUD + 序列化）
- API 样本管理 → api_samples.py（ApiSamplesMixin）
- 功能点生成 → feature_gen.py（FeatureGenMixin）
- 覆盖率统计 → coverage.py（CoverageMixin）
- 报告渲染 → report.py（ReportMixin）

所有原 `from core.sitemap import X` 仍然可用，向后兼容。
"""

# ★ 从 sitemap.models 重新导出所有数据模型，保持向后兼容
from core.sitemap.models import (
    TestStatus,
    CheckResult,
    Priority,
    PageInfo,
    APIEndpoint,
    CheckItem,
    FeaturePoint,
)

# ★ 从 constants 重新导出，供外部直接引用
from core.sitemap.constants import (
    GENERIC_NAMES as _GENERIC_NAMES,  # noqa: F401（内部常量，保留旧名兼容）
    STATIC_EXTS as _STATIC_EXTS,      # noqa: F401
    STATIC_PATH_SEGS as _STATIC_PATH_SEGS,  # noqa: F401
    SEVERITY_LABEL as _SEVERITY_LABEL,      # noqa: F401
    CHECK_RESULT_ICON as _CHECK_RESULT_ICON,  # noqa: F401
    CHECK_RESULT_ICON_WITH_TEXT as _CHECK_RESULT_ICON_WITH_TEXT,  # noqa: F401
    TEST_STATUS_ICON_WITH_TEXT as _TEST_STATUS_ICON_WITH_TEXT,  # noqa: F401
)

# ★ 导出主类
from core.sitemap.sitemap import Sitemap

__all__ = [
    "Sitemap",
    "TestStatus", "CheckResult", "Priority",
    "PageInfo", "APIEndpoint", "CheckItem", "FeaturePoint",
]
