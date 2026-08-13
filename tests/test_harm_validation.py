"""
漏洞危害验证模块端到端测试。

覆盖:
1. 提示词文件存在 + 内容含关键标准词
2. collect_vulnerabilities 正确收集 checklist + XSS 漏洞
3. context 拼装包含业务理解 promises + 漏洞详情
4. JSON 数组解析 (含审核员总评)
5. validate_harm 失败/超时降级
6. 无漏洞时 status=no_vulns
7. render_to_markdown 渲染完整报告章节(accepted/borderline/rejected)
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_prompt_exists():
    from core.harm_validation import PROMPT_PATH
    assert PROMPT_PATH.exists()
    text = PROMPT_PATH.read_text(encoding="utf-8")
    assert "SRC" in text or "赏金" in text
    assert "accepted" in text and "rejected" in text and "borderline" in text
    assert "形式漏洞" in text or "防御纵深" in text or "拒收" in text
    assert "harm_story" in text


def test_collect_vulnerabilities():
    from core.harm_validation import collect_vulnerabilities

    sm = MagicMock()
    # checklist 漏洞
    fp = MagicMock()
    fp.name = "用户登录"
    fp.module = "认证/登录"
    fp.page_url = "http://x/login"
    c1 = MagicMock()
    c1.result = MagicMock(value="vulnerable")
    c1.id = "c1"
    c1.item = "SQL 注入"
    c1.vuln_type = "SQL Injection"
    c1.severity = MagicMock(value="high")
    c1.detail = "username 参数可注入"
    c1.evidence_request = "POST /api/login\nuser=admin' OR '1'='1"
    c1.evidence_response = "登录成功"
    c1.reproduce_steps = "1. 输入 payload..."
    c1.fix_suggestion = "用 prepare statement"
    c2 = MagicMock()
    c2.result = MagicMock(value="not_vuln")
    fp.checklist = [c1, c2]
    sm.features = {"f1": fp}

    # XSS findings
    sm.xss_findings = [
        {
            "id": "xss_1", "status": "confirmed", "title": "Reflected XSS - /search",
            "xss_type": "reflected", "url": "http://x/search?q=", "severity": "medium",
            "description": "搜索框反射型 XSS", "browser_triggered": True,
            "browser_evidence": "alert popped", "echo_contexts": ["html_text"],
            "payload": "<svg onload=alert(1)>",
            "reproduce_steps": "访问 URL...",
            "fix_suggestion": "对输出做编码",
        },
        {"id": "xss_2", "status": "false_positive"},  # 应被过滤
    ]

    vulns = collect_vulnerabilities(sm)
    assert len(vulns) == 2, f"应收集 2 个漏洞: {len(vulns)}"
    # checklist 漏洞
    sql_vuln = next((v for v in vulns if v["source"] == "checklist"), None)
    assert sql_vuln is not None
    assert sql_vuln["vuln_type"] == "SQL Injection"
    assert "登录" in sql_vuln["feature"]
    # XSS 漏洞
    xss_vuln = next((v for v in vulns if v["source"] == "xss_module"), None)
    assert xss_vuln is not None
    assert xss_vuln["browser_triggered"] is True


def test_build_context():
    from core.harm_validation import build_context_for_llm

    sm = MagicMock()
    sm.business_understanding = {
        "status": "ok",
        "understanding": {
            "domain": {"label": "电商"},
            "promises": [
                {"id": "P-001", "priority": "P0", "statement": "用户只能看自己订单"},
                {"id": "P-002", "priority": "P1", "statement": "提现金额必须 > 0"},
            ],
            "data_landscape": [
                {"name": "订单数据", "owner": "下单用户"},
            ],
        }
    }
    vulns = [
        {
            "vuln_id": "V-001", "source": "checklist", "title": "IDOR 越权",
            "vuln_type": "IDOR", "url": "http://x/order/123",
            "module": "订单", "feature": "订单详情", "severity_original": "high",
            "detail": "可读他人订单",
            "evidence_request": "GET /order/9999",
            "evidence_response": "{order_id:9999}",
            "reproduce_steps": "1. 改 ID",
        },
        {
            "vuln_id": "V-002", "source": "xss_module", "title": "Reflected XSS",
            "vuln_type": "XSS-reflected", "url": "http://x/search",
            "severity_original": "medium",
            "browser_triggered": False,
            "echo_contexts": ["html_text"],
            "payload": "<svg/onload=alert(1)>",
        },
    ]
    ctx = build_context_for_llm(sm, vulns)
    # 业务理解
    assert "P-001" in ctx
    assert "电商" in ctx
    assert "订单数据" in ctx
    # 漏洞
    assert "V-001" in ctx
    assert "V-002" in ctx
    assert "IDOR" in ctx
    assert "GET /order/9999" in ctx
    assert "<svg/onload=alert(1)>" in ctx


def test_parse_response():
    from core.harm_validation import _parse_response

    raw = '''```json
[
  {
    "vuln_id": "V-001",
    "verdict": "accepted",
    "platform_level": "high",
    "harm_story": "登录用户改 URL 中 order_id 即可读他人订单",
    "evidence_strength": "strong",
    "broken_promises": ["P-001"],
    "would_be_accepted_by": ["腾讯SRC", "HackerOne"],
    "reject_reason": "",
    "fix_priority": "立即"
  },
  {
    "vuln_id": "V-002",
    "verdict": "rejected",
    "platform_level": "no_value",
    "harm_story": "",
    "evidence_strength": "weak",
    "broken_promises": [],
    "would_be_accepted_by": [],
    "reject_reason": "Cookie 缺 HttpOnly 但全站无 XSS",
    "fix_priority": "加固建议"
  }
]
```

**审核员总评：**
本次发现的 1 个 IDOR 是真实危害,建议立即修复。其余 1 个为形式合规问题。
'''
    verdicts, summary = _parse_response(raw)
    assert verdicts is not None
    assert len(verdicts) == 2
    assert verdicts[0]["verdict"] == "accepted"
    assert verdicts[0]["broken_promises"] == ["P-001"]
    assert verdicts[1]["verdict"] == "rejected"
    assert "形式合规" in summary


def test_parse_response_fallback():
    from core.harm_validation import _parse_response
    # 裸 JSON 数组
    raw2 = '[{"vuln_id":"V","verdict":"accepted"}]'
    v, _ = _parse_response(raw2)
    assert v is not None and len(v) == 1
    # 空文本
    v2, s2 = _parse_response("")
    assert v2 is None


def test_validate_harm_no_vulns():
    """空 sitemap 应返回 status=no_vulns。"""
    from core.harm_validation import validate_harm
    sm = MagicMock()
    sm.features = {}
    sm.xss_findings = []
    sm.business_understanding = {}
    llm = MagicMock()
    result = asyncio.run(validate_harm(sm, llm))
    assert result["status"] == "no_vulns"


def test_validate_harm_llm_fallback():
    """LLM 返回非 JSON 时降级。"""
    from core.harm_validation import validate_harm
    sm = MagicMock()
    fp = MagicMock()
    fp.name = "x"; fp.module = "y"; fp.page_url = "z"
    c = MagicMock()
    c.result = MagicMock(value="vulnerable")
    c.id = "c1"; c.item = "test"; c.vuln_type = "T"
    c.severity = MagicMock(value="high")
    c.detail = ""; c.evidence_request = ""; c.evidence_response = ""
    c.reproduce_steps = ""; c.fix_suggestion = ""
    fp.checklist = [c]
    sm.features = {"f1": fp}
    sm.xss_findings = []
    sm.business_understanding = {}

    llm = MagicMock()
    llm.chat = MagicMock(return_value=MagicMock(content="无法解析"))
    result = asyncio.run(validate_harm(sm, llm, timeout=10.0))
    assert result["status"] == "error"
    assert "JSON" in result["error"] or "解析" in result["error"]


def test_render_full_report():
    from core.harm_validation import render_to_markdown

    hv_result = {
        "status": "ok",
        "verdicts": [
            {
                "vuln_id": "V-001", "verdict": "accepted",
                "platform_level": "critical",
                "harm_story": "登录用户改 URL 即可读他人订单,涉及全用户数据",
                "evidence_strength": "strong",
                "broken_promises": ["P-001"],
                "would_be_accepted_by": ["腾讯SRC", "HackerOne"],
                "reject_reason": "",
                "fix_priority": "立即",
                "_original": {
                    "title": "IDOR 越权读他人订单",
                    "vuln_type": "IDOR",
                    "url": "http://x/order/123",
                    "evidence_request": "GET /order/9999",
                    "evidence_response": '{"order_id":"9999","amount":1000}',
                    "reproduce_steps": "1. 登录\n2. 改 URL 中 ID",
                }
            },
            {
                "vuln_id": "V-002", "verdict": "borderline",
                "platform_level": "low",
                "harm_story": "反射型 XSS 但 cookie 已 HttpOnly,无法窃取 token",
                "evidence_strength": "medium",
                "broken_promises": [],
                "would_be_accepted_by": [],
                "reject_reason": "危害链有一环靠假设撑着",
                "fix_priority": "上线前",
                "_original": {
                    "title": "Reflected XSS in /search",
                    "vuln_type": "XSS-reflected",
                    "url": "http://x/search",
                }
            },
            {
                "vuln_id": "V-003", "verdict": "rejected",
                "platform_level": "no_value",
                "harm_story": "",
                "reject_reason": "Cookie 缺 HttpOnly 但全站无 XSS",
                "fix_priority": "加固建议",
                "_original": {
                    "title": "bt_rtoken 缺 HttpOnly",
                    "vuln_type": "Cookie 安全",
                }
            },
        ],
        "summary": "真正值得修的是 IDOR 越权,这类一个 HTTP 请求即可批量读他人数据,影响全用户。"
                   "其余多为形式合规问题,建议加固时一并处理。预算应集中在订单/资金相关接口的鉴权审计。",
        "stats": {"accepted": 1, "borderline": 1, "rejected": 1},
        "total_vulns": 3,
    }
    md = render_to_markdown(hv_result)
    assert "5. 漏洞危害验证" in md
    assert "5.1 裁决总览" in md
    assert "5.2" in md and "接受的漏洞" in md
    assert "5.3" in md and "边缘漏洞" in md
    assert "5.4" in md and "拒收" in md
    assert "5.5" in md and "总评" in md
    assert "IDOR 越权" in md
    assert "立即修复" in md
    assert "🔴" in md  # critical 标识
    assert "GET /order/9999" in md  # 证据保留
    assert "P-001" in md
    assert "腾讯SRC" in md
    assert "Cookie 缺 HttpOnly 但全站无 XSS" in md  # 拒收理由
    assert "形式合规问题" in md  # 总评


def test_render_no_vulns():
    """无漏洞时返回空字符串(不渲染章节)。"""
    from core.harm_validation import render_to_markdown
    md = render_to_markdown({"status": "no_vulns"})
    assert md == ""


def test_render_error():
    from core.harm_validation import render_to_markdown
    md = render_to_markdown({"status": "timeout", "error": "LLM 超时"})
    assert "5. 漏洞危害验证" in md
    assert "未完成" in md or "超时" in md
