"""core.testflow — 测试流重新编排（0920 v3 · bug-legacy 复用版）。

组织单位 = (功能点, 漏洞域) 稀疏矩阵，替代"漏洞项/规则"横向全局：
- attribution_rules / attribution : 域归属引擎（R1，纯分析 0 请求）
- coverage_derive                 : per-endpoint 应测类型推导（bug-legacy §7.2）
- gates                           : GATE-PRE/GATE-PAIR/GATE-TRI（G3/G4）
- engine                          : 编排壳（PHASE_ORDER + 三执行者 + decide_mode）
- validate_workflow               : L6-L10 覆盖闸门（G5/G6 前置校验）

灰度 flag：XUANJIAN_TESTFLOW_V2 ∈ {census, playbook, full}。
未设置 → 全部组件不接线，存量行为不变（53 回归钉不动）。
"""
