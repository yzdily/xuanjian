"""Golden 录制→回放闸门 — D6 怪物方法 decompose 的行为测试安全网。

依据 ``hollowing-optimization-plan/plan/D6_architect_review.md`` §6.2 / §6.4.3 / P1-2：
  - 沙箱无浏览器/LLM，无法产 golden 样本 → 本包只提供「录制→回放」机制；
    样本在完整 venv（fastapi + playwright + LLM）下由 ``scripts/record_golden.py``
    录制落 ``tests/golden/<method>/*.json``。
  - 回放测试在样本缺失时 **skip**（不 fail），保证沙箱 pytest 全绿；
    样本一旦落盘，回放测试自动激活 → 行为等价即解锁 decompose（D6 Stage 2–4）。

三个怪物方法（签名不变、内部逻辑错时契约测试全绿，故须行为兜底）：
  - ``crawler_core.AutoCrawler._crawl_round``      (≈911 行)
  - ``crawler_core.AutoCrawler._crawl_page_inner`` (≈1779 行)
  - ``chat_loop.ChatLoopMixin.chat``               (≈1912 行)

模块：
  - serializer : dataclass/事件 → 规范化 JSON；易变字段（时间戳/UUID/token）占位化
  - diff       : 语义等价 diff（顺序 + type + 关键 payload）
  - recorder   : 非侵入式包装（零改动怪物方法）+ GoldenSample 落盘/加载
"""
