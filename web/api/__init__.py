"""
web/api — 新特性的 API 路由（独立蓝图，避免污染 server.py）

每个特性一个文件：
- diff_api.py    — 候选2：sitemap diff + 增量回归
- replay_api.py  — 候选1：剧场（后续追加）
- crypto_api.py  — 候选3：加密接口（后续追加）

在 server.py 启动时统一 include_router。
"""
