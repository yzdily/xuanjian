"""
业务理解 + 对账完整链路端到端测试。

测试覆盖:
1. 提示词文件存在 + 内容非空
2. context 拼装产物合理(不超长、覆盖关键信息)
3. JSON 解析能识别多种格式(```json``` / 裸 JSON / 嵌套)
4. analyze_business 流程能在 LLM 失败时降级
5. render_to_markdown 对完整/缺字段/空 result 都不崩
6. reconcile_loop 在无 execute_new_tasks 时也能跑
7. reconcile_loop 最大 2 轮硬上限生效
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_prompts_exist():
    from core.business_understanding import PROMPT_PATH as BU_PROMPT
    from core.reconcile import PROMPT_PATH as REC_PROMPT
    assert BU_PROMPT.exists(), f"业务理解提示词缺失: {BU_PROMPT}"
    assert REC_PROMPT.exists(), f"对账提示词缺失: {REC_PROMPT}"
    bu_text = BU_PROMPT.read_text(encoding="utf-8")
    assert "产品经理" in bu_text
    assert "JSON" in bu_text
    assert "domain" in bu_text
    rec_text = REC_PROMPT.read_text(encoding="utf-8")
    assert "渗透总监" in rec_text or "对账" in rec_text
    assert "new_tasks" in rec_text


def test_context_build():
    from core.business_understanding import build_context_for_llm
    sm = MagicMock()
    sm.target = "http://example.com"
    sm.business_type = {"description": "电商"}
    sm.tech_stack = ["React", "Node.js"]
    sm.pages = {
        "http://example.com/login": {"title": "登录"},
        "http://example.com/cart": {"title": "购物车"},
    }
    sm.apis = {
        "POST http://example.com/api/login": {"method": "POST", "url": "http://example.com/api/login"},
        "POST http://example.com/api/order": {"method": "POST", "url": "http://example.com/api/order"},
    }
    sm.api_samples = {
        "k1": {
            "url": "http://example.com/api/order",
            "method": "POST",
            "request_body": '{"item_id": "x", "amount": 100, "user_id": 1}',
            "response_body": '{"order_id": "abc"}',
        }
    }
    sm.js_routes = [{"path": "/profile", "name": "profile"}]
    crawl = {
        "rounds_data": [
            {"role": "user", "login_success": True, "api_endpoints": {"a": {}, "b": {}}},
            {"role": "admin", "login_success": True, "api_endpoints": {"c": {}}},
        ]
    }
    ctx = build_context_for_llm(sm, crawl_result=crawl)
    assert "http://example.com" in ctx
    assert "电商" in ctx
    assert "React" in ctx
    assert "admin" in ctx
    assert "user" in ctx
    assert "POST" in ctx
    assert "/api/order" in ctx
    assert "amount" in ctx  # 字段名清单


def test_json_parsing():
    from core.business_understanding import _parse_response
    # 1. 标准 ```json ``` 块
    raw1 = '前置文本\n```json\n{"domain":{"label":"电商"},"roles":[]}\n```\n\n**中文总结：**\n这是一个电商系统。'
    u1, s1 = _parse_response(raw1)
    assert u1 and u1.get("domain", {}).get("label") == "电商", f"解析失败: {u1}"
    assert "电商系统" in s1
    # 2. 裸 JSON
    raw2 = '{"domain": {"label": "SaaS"}, "roles": [{"name": "tenant_admin"}]}'
    u2, _ = _parse_response(raw2)
    assert u2 and u2["domain"]["label"] == "SaaS"
    # 3. JSON 中含嵌套 {}
    raw3 = '```json\n{"domain":{"label":"x","evidence":["api {a}","b"]}}\n```'
    u3, _ = _parse_response(raw3)
    assert u3 and "label" in u3["domain"]
    # 4. 空字符串
    u4, s4 = _parse_response("")
    assert u4 is None


def test_render_to_markdown():
    from core.business_understanding import render_to_markdown
    # 完整 result
    full_result = {
        "status": "ok",
        "summary": "这是一个加密货币交易平台。",
        "understanding": {
            "domain": {"label": "数字货币交易所", "sub_type": "CEX", "confidence": 0.95,
                       "evidence": ["/api/spot/order", "字段 fiat_currency"]},
            "roles": [
                {"name": "普通用户", "capabilities": ["现货交易", "查看自己资产"],
                 "cannot": ["查看他人资产"], "auth_method": "JWT"},
                {"name": "管理员", "capabilities": ["冻结账户"], "auth_method": "TOTP"},
            ],
            "data_landscape": [
                {"name": "用户订单", "from": "POST /api/order", "storage": "MySQL",
                 "attack_surface": ["IDOR", "金额篡改"], "owner": "下单用户"}
            ],
            "critical_flows": [
                {"name": "下单支付", "steps": ["加购", "确认", "支付"],
                 "state_machine": "pending → paid → filled", "involved_apis": ["POST /api/order"]}
            ],
            "promises": [
                {"id": "P-001", "priority": "P0", "statement": "用户只能查看自己订单",
                 "mechanism_guess": "session 过滤"},
                {"id": "P-002", "priority": "P1", "statement": "提现金额不能超过余额"}
            ],
            "attack_hypotheses": [
                {"role": "user", "test_endpoint": "GET /api/order/{id}",
                 "param_to_modify": "id", "vulnerability_type": "IDOR",
                 "test_method": "改 id 为他人订单", "why_value": "P-001 是 P0 承诺"}
            ],
            "top_3_directions": [
                {"direction": "金额篡改", "reason": "下单流程关键"},
                "跨用户越权",
                "提现风控绕过",
            ],
            "unknowns": ["未发现管理员后台"],
        },
    }
    md = render_to_markdown(full_result)
    assert "1.2.1 系统定位" in md
    assert "电商" not in md  # 不应套用通用模板
    assert "数字货币交易所" in md
    assert "P-001" in md
    assert "IDOR" in md
    assert "金额篡改" in md

    # 失败 result
    err_md = render_to_markdown({"status": "error", "error": "LLM 超时"})
    assert "未完成" in err_md
    # None
    none_md = render_to_markdown(None)
    assert "未完成" in none_md


def test_analyze_business_fallback():
    """LLM 返回非 JSON 时,正确降级为 degraded（规则推导兜底）。

    ★ #8 修复后：JSON 解析失败不再直接返回 error，而是先尝试规则推导：
    - 规则推导成功 → status='degraded'，下游 Phase 可继续
    - 规则推导也失败 → status='error'
    """
    from core.business_understanding import analyze_business
    sm = MagicMock()
    sm.target = "http://x"
    sm.pages = {"http://x/login": {"title": "登录"}, "http://x/cart": {"title": "购物车"}}
    sm.apis = {
        "POST http://x/api/login": {"method": "POST", "url": "http://x/api/login"},
        "GET http://x/api/users": {"method": "GET", "url": "http://x/api/users"},
    }
    sm.api_samples = {}
    sm.business_type = None
    sm.tech_stack = None
    sm.js_routes = []

    llm = MagicMock()
    llm.chat = MagicMock(return_value=MagicMock(content="无法解析的文本"))

    result = asyncio.run(analyze_business(sm, llm, timeout=10.0))
    # 提供了足够多的 sitemap 信息后，规则推导应成功 → degraded
    assert result["status"] == "degraded", f"expected degraded, got {result['status']}"
    assert result.get("understanding") is not None
    assert "error" in result


def test_analyze_business_timeout():
    """LLM 超时时降级为 timeout。"""
    from core.business_understanding import analyze_business
    sm = MagicMock()
    sm.target = "http://x"
    sm.pages = {}
    sm.apis = {}
    sm.api_samples = {}
    sm.business_type = None
    sm.tech_stack = None
    sm.js_routes = []

    llm = MagicMock()
    # 模拟 chat 调用挂起直到超时（用同步阻塞，因 analyze_business 用 to_thread 调用）
    import time as _time
    def _hang(*args, **kwargs):
        _time.sleep(2)
        return MagicMock(content='{"domain":{"label":"x"}}')
    llm.chat = _hang

    result = asyncio.run(analyze_business(sm, llm, timeout=0.1))
    assert result["status"] == "timeout"


def test_reconcile_context_build():
    from core.reconcile import build_reconcile_context
    # 模拟 sitemap
    sm = MagicMock()
    sm.xss_findings = []
    fp = MagicMock()
    fp.name = "下单"
    fp.module = "订单/创建"
    check_item = MagicMock()
    check_item.result = MagicMock(value="not_vuln")
    check_item.item = "测试 IDOR"
    check_item.vuln_type = "IDOR"
    fp.checklist = [check_item]
    sm.features = {"f1": fp}
    bu = {
        "status": "ok",
        "understanding": {
            "domain": {"label": "电商"},
            "promises": [{"id": "P-001", "statement": "x", "priority": "P0"}],
            "attack_hypotheses": [{"test_endpoint": "/x", "param_to_modify": "y",
                                   "vulnerability_type": "IDOR"}],
            "top_3_directions": [{"direction": "金额篡改"}],
        }
    }
    ctx = build_reconcile_context(sm, bu)
    assert "P-001" in ctx
    assert "IDOR" in ctx
    assert "订单" in ctx  # module 分组按 fp.module = 订单/创建
    assert "金额篡改" in ctx


def test_reconcile_loop_max_2_rounds():
    """验证 2 轮硬上限。即使 LLM 每轮都给新任务,最多跑 2 轮。"""
    from core.reconcile import reconcile_loop

    sm = MagicMock()
    sm.xss_findings = []
    sm.features = {}

    bu = {
        "status": "ok",
        "understanding": {
            "domain": {"label": "x"},
            "promises": [],
            "attack_hypotheses": [],
            "top_3_directions": [],
        }
    }

    # 模拟 LLM: 每轮都返回 3 个 new_tasks(unique id)
    counter = {"n": 0}

    def fake_chat(messages, **kwargs):
        counter["n"] += 1
        n = counter["n"]
        return MagicMock(content=f'''```json
{{
  "coverage_summary": {{"verdict": "has_critical_gaps", "promises_total":5}},
  "promise_coverage": [],
  "gap_findings": [],
  "new_tasks": [
    {{"id":"GAP-R{n}-01","title":"任务{n}-1","role":"user","target_url":"/x","param_to_modify":"id","vulnerability_type":"IDOR","test_method":"x","expected_if_safe":"403","expected_if_vuln":"data","why_top":"r{n}"}}
  ]
}}
```''')

    llm = MagicMock()
    llm.chat = fake_chat

    events = []
    exec_calls = {"count": 0}

    async def fake_exec(tasks):
        exec_calls["count"] += 1
        return [{"status": "已执行", "summary": f"call {exec_calls['count']}"} for _ in tasks]

    result = asyncio.run(reconcile_loop(
        sitemap=sm, bu_result=bu, llm=llm,
        execute_new_tasks=fake_exec,
        max_rounds=2,
        on_event=lambda m: events.append(m),
        timeout_per_round=10.0,
    ))
    assert result["status"] == "ok"
    assert result["rounds"] == 2, f"应跑满 2 轮: {result['rounds']}"
    # exec 也只被调 2 次
    assert exec_calls["count"] == 2, f"补齐执行也应只 2 次: {exec_calls}"
    # final new_tasks 合并了 2 轮的(各 1 个 = 2 个)
    new_tasks = result["reconcile_data"].get("new_tasks", [])
    assert len(new_tasks) == 2


def test_reconcile_loop_covered_well_stops_early():
    """如果第 1 轮 verdict=covered_well,应该停止不进第 2 轮。"""
    from core.reconcile import reconcile_loop

    sm = MagicMock()
    sm.xss_findings = []
    sm.features = {}

    bu = {"status": "ok", "understanding": {"promises": [], "domain": {}}}

    call_count = {"n": 0}

    def fake_chat(*a, **k):
        call_count["n"] += 1
        return MagicMock(content='''```json
{"coverage_summary":{"verdict":"covered_well","promises_total":5,"promises_covered":5},
 "promise_coverage":[],"gap_findings":[],"new_tasks":[]}
```''')

    llm = MagicMock(chat=fake_chat)
    result = asyncio.run(reconcile_loop(sm, bu, llm, max_rounds=2, timeout_per_round=10.0))
    assert result["rounds"] == 1, "covered_well 应提前停止"
    assert call_count["n"] == 1
