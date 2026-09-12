"""
PentestAgent Core — 自动化渗透测试 Agent 框架

模块结构：
  config.py       — 配置常量（映射表、关键词集合）
  tools.py        — 统一工具定义（OpenAI function calling 格式）
  session.py      — AgentSession 核心（分阶段状态机）
  intent.py       — LLM 意图解析
  tool_executor.py — 工具执行路由
  parallel.py     — Phase 2 并行调度
  worker_agent.py — 并行子 Agent
  sitemap.py      — 站点地图 + 功能点 + Checklist + 覆盖矩阵
  context.py      — 上下文管理与压缩
  llm.py          — LLM 客户端封装
  state.py        — Idea/Memory 状态管理
  tool_router.py  — MCP Server 函数路由
  auto_crawler.py — 自动爬虫
  prompts/        — 提示词
    solver.md     — 基础 Solver 提示词
    phases.py     — 各阶段提示词
"""
