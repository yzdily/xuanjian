"""优化模块测试：CWE 映射 / 四维定级 / 误报率闭环（优化.md 建议2/5/9）。"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cwe_mapping import lookup_cwe, normalize_vuln_type, enrich_finding_with_cwe
from core.severity_rules import score_severity, score_severity_explicit, apply_severity
from core import fp_rate_tracker
from core.harm_validation.tools import generate_placeholder_verdicts
from core.harm_validation.parser import parse_response


# ---------- CWE 映射 ----------

def test_cwe_exact_match():
    info = lookup_cwe("SQL注入")
    assert info["cwe_id"] == "CWE-89"
    assert "89" in info["cwe_url"]


def test_cwe_alias_match():
    assert normalize_vuln_type("SQL Injection") == "SQL注入"
    assert normalize_vuln_type("sqli") == "SQL注入"
    assert normalize_vuln_type("跨站脚本攻击") == "XSS"
    assert lookup_cwe("idor")["cwe_id"] == "CWE-639"


def test_cwe_no_match_does_not_invent_cwe200():
    info = lookup_cwe("完全不存在的漏洞类型xyz")
    assert info["cwe_id"] == ""  # 不乱用 CWE-200


def test_enrich_finding_idempotent():
    f = {"vuln_type": "XSS"}
    enrich_finding_with_cwe(f)
    assert f["cwe_id"] == "CWE-79"
    f["cwe_id"] = "CWE-999"  # 已有不覆盖
    enrich_finding_with_cwe(f)
    assert f["cwe_id"] == "CWE-999"


# ---------- 四维定级 ----------

def test_severity_explicit_thresholds():
    assert score_severity_explicit(3, 3, 3, 3)[0] == "critical"  # 30
    assert score_severity_explicit(0, 0, 0, 0)[0] == "info"       # 0
    assert score_severity_explicit(2, 2, 2, 2)[0] == "high"       # 16
    assert score_severity_explicit(0, 1, 1, 1)[0] == "low"        # 7


def test_severity_from_finding_body_confirmed_upgrades():
    f = {"vuln_type": "未授权访问", "evidence_quality": "body_confirmed",
         "detail": "实测拿到 password 和手机号"}
    sev, score, rationale = score_severity(f)
    assert sev == "critical"  # body_confirmed + 密钥 → 数据敏感度3 + 可利用性满
    assert "四维定级" in rationale


def test_severity_header_only_downgrades():
    f = {"vuln_type": "信息泄露", "evidence_quality": "header_only", "detail": ""}
    sev, score, _ = score_severity(f)
    # 信息泄露基线1/1/3/1=10 -> header_only 修正 -1/-1 -> 0/0/3/1=5 -> low
    assert sev == "low"


def test_apply_severity_idempotent():
    f = {"vuln_type": "SQL注入", "evidence_quality": "body_confirmed",
         "detail": "已复现 命令执行"}
    apply_severity(f)
    assert f["severity"] in ("critical", "high")
    assert "severity_score" in f
    first_score = f["severity_score"]
    f["severity"] = "low"  # 人工改了
    apply_severity(f)  # 幂等，不覆盖
    assert f["severity"] == "low"
    assert f["severity_score"] == first_score


# ---------- 误报率闭环 ----------

def test_fp_rate_record_and_stats(tmp_path):
    p = tmp_path / "fp.json"
    fp_rate_tracker.record_scan(
        40, {"accepted": 5, "borderline": 10, "rejected": 25},
        vuln_type_breakdown={"未授权访问": {"initial": 20, "accepted": 2, "borderline": 5, "rejected": 13}},
        phase="authz", scan_id="t1", path=p,
    )
    fp_rate_tracker.record_scan(
        10, {"accepted": 1, "borderline": 2, "rejected": 7},
        phase="authz", scan_id="t2", path=p,
    )
    s = fp_rate_tracker.get_stats(path=p)
    assert s["summary"]["scans"] == 2
    assert s["summary"]["total_initial"] == 50
    assert s["summary"]["total_verified"] == 6
    assert s["summary"]["total_rejected"] == 32
    # 漏洞类型聚合
    vt = {v["vuln_type"]: v for v in s["by_vuln_type"]}
    assert vt["未授权访问"]["initial"] == 20
    assert vt["未授权访问"]["rejected"] == 13
    # 阶段聚合
    assert s["by_phase"]["authz"]["initial"] == 50


def test_fp_rate_zero_initial(tmp_path):
    p = tmp_path / "fp2.json"
    rec = fp_rate_tracker.record_scan(0, {"accepted": 0, "borderline": 0, "rejected": 0}, path=p)
    assert rec["fp_rate"] == 0.0


def test_fp_rate_format_text(tmp_path):
    p = tmp_path / "fp3.json"
    fp_rate_tracker.record_scan(10, {"accepted": 1, "borderline": 0, "rejected": 9},
                                vuln_type_breakdown={"XSS": {"initial": 10, "accepted": 1, "borderline": 0, "rejected": 9}},
                                path=p)
    txt = fp_rate_tracker.format_stats_text(path=p)
    assert "误报率统计反馈闭环" in txt
    assert "XSS" in txt


# ---------- LLM 失败确定性降级（P0-3）----------

def test_placeholder_strong_evidence_kept_as_borderline():
    """LLM 故障时，响应体级强证据漏洞应保留为 borderline，而非一刀切 rejected。"""
    vulns = [
        {"vuln_id": "V-1", "vuln_type": "未授权访问", "evidence_quality": "body_confirmed",
         "evidence": "无认证响应: {\"users\":[...]}"},
        {"vuln_id": "V-2", "vuln_type": "信息泄露", "evidence_quality": "header_only"},
        {"vuln_id": "V-3", "vuln_type": "信息泄露", "evidence_quality": "content_match"},
    ]
    raw = generate_placeholder_verdicts(vulns)
    verdicts, _ = parse_response(raw)
    by_id = {v["vuln_id"]: v for v in verdicts}
    # 强证据 → borderline（保留待人工复核）
    assert by_id["V-1"]["verdict"] == "borderline"
    assert by_id["V-3"]["verdict"] == "borderline"
    # 弱证据 → rejected
    assert by_id["V-2"]["verdict"] == "rejected"
    assert by_id["V-1"]["poc_response"] != "未生成"  # 强证据保留原响应
