"""0923 端到端离线验收（三条核心验收钉，可 CI，不依赖网络 / 真实 LLM / 浏览器）。

★ 为什么需要这一层：
0923 的 bug 全部"单点已修、链路未验"——单测证明"函数逻辑对"，
不证明"接进真实链路后对"。本文件按 `0923_技术方案.md §15 验收钉总表`
把**跨模块**的链路钉死，用**离线夹具**替代真实站点重放（原方案 V15 不可 CI）。

覆盖的验收钉：
- 钉 1：单个子 Agent 熔断**不得**炸掉整个任务 → 终态 `partial`（T2 + T3 + T9 + T13）
- 钉 2：catch-all 误报**不得**进"已确认漏洞"（两个消费点都要过滤，T8 + T8b + T15）
- 钉 3：「继续」**不得**重头重爬（T5 + T6 + T7，含前后端口径一致）
- 钉 4：运行中余额耗尽 → `partial` 而非 `failed`（P13）
- 钉 5：前端五态映射**唯一**（P14）

说明：钉 1 中 `BrowseWorker.run()` 的真实触发需要两轮 LLM 交互（第一轮 `round_num > 1`
门槛不满足），无法在不拖入真实 LLM/浏览器的前提下稳定复现，
故改用 **AST 契约守护**精确锁定"raise 必须在 try 内"这一**根因**——
这比脆弱的集成重放更能防止回归（该断言会随代码结构变化立即失败）。
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
import sqlite3
from pathlib import Path

import pytest

import core.scan_store as ss
from core.session.base import AgentSessionBase

ROOT = Path(__file__).resolve().parents[2]
WORKER_PY = ROOT / "core" / "browse_worker" / "_worker.py"
CHAT_LOOP_PY = ROOT / "core" / "session" / "chat_loop.py"
INDEX_HTML = ROOT / "web" / "index.html"
SESSIONS_API = ROOT / "web" / "api" / "sessions_api.py"


# ============================================================
# 公共夹具
# ============================================================

def _bare_session(task_id: str = "task_e2e"):
    """最小会话（绕过 __init__，避免拉起 LLM / 浏览器 / 恢复逻辑）。"""
    s = AgentSessionBase.__new__(AgentSessionBase)
    s.task_id = task_id
    s.phase = "test"
    return s


def _drain(agen):
    async def _run():
        return [x async for x in agen]
    return asyncio.run(_run())


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """临时 scan_store（隔离真实 data/scan_store.db）。"""
    monkeypatch.setattr(ss, "_DB_PATH", tmp_path / "e2e_store.db")
    monkeypatch.setattr(ss._state, "conn", None)
    ss._ensure_conn()
    yield ss
    try:
        if ss._state.conn is not None:
            ss._state.conn.close()
    except Exception:
        pass
    monkeypatch.setattr(ss._state, "conn", None)


@pytest.fixture()
def isolated_cwd(tmp_path, monkeypatch):
    """cwd 隔离：会话 `_event()` / 镜像走相对路径，避免污染真实 data/。"""
    monkeypatch.chdir(tmp_path)
    yield tmp_path


# ============================================================
# 钉 1：单组子 Agent 熔断不得炸掉整个任务
# ============================================================

def _is_browse_stuck_raise(node: ast.AST) -> bool:
    """是否 `raise BrowseStuckError(...)`。"""
    if not isinstance(node, ast.Raise) or node.exc is None:
        return False
    func = getattr(node.exc, "func", None)
    return isinstance(func, ast.Name) and func.id == "BrowseStuckError"


def _scan_raises(node: ast.AST, in_try: bool,
                 inside: list, outside: list) -> None:
    """递归收集 `raise BrowseStuckError`，区分是否位于 try body 内。

    跳过嵌套函数/类定义 —— 否则 helper 里的 raise 会被误算进本函数。
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    if isinstance(node, ast.Try):
        for st in node.body:
            _scan_raises(st, True, inside, outside)
        for st in node.handlers + node.orelse + node.finalbody:
            _scan_raises(st, in_try, inside, outside)
        return
    if _is_browse_stuck_raise(node):
        (inside if in_try else outside).append(node)
        return
    for child in ast.iter_child_nodes(node):
        _scan_raises(child, in_try, inside, outside)


def _worker_run_node() -> ast.AsyncFunctionDef:
    tree = ast.parse(WORKER_PY.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.AsyncFunctionDef) and n.name == "run")


def _collect_stuck_raises() -> tuple[list, list]:
    """返回 run() 中 `(try 内, try 外)` 两组 `raise BrowseStuckError`。

    注意要从 run().body 的**每个直接语句**开始扫描：`_scan_raises` 会跳过
    嵌套函数定义，若直接把 run() 节点传进去，根节点本身会被跳过。
    """
    inside: list = []
    outside: list = []
    for stmt in _worker_run_node().body:
        _scan_raises(stmt, False, inside, outside)
    return inside, outside


class TestP3CircuitBreakerDoesNotKillTask:
    """T2 / B1：P3 熔断必须"优雅收尾"，而不是把异常穿透成任务崩溃。"""

    def test_raise_browse_stuck_is_inside_try(self):
        """★ 核心回归钉：`raise BrowseStuckError` 必须落在 try body 内。

        0923 实测崩溃根因（`d.citicaibank.cn` 15:50）：
        raise 在 while 顶部、**try 之外** → 穿透 `chat_loop` 的 `async for`
        → `web/server.py` 记 `task_failed(uncaught_exception)`，
        单组子 Agent 卡死 = 整个任务的所有成果丢失。
        """
        inside, outside = _collect_stuck_raises()
        assert inside, (
            "run() 中必须存在位于 try 内的 `raise BrowseStuckError`"
            "（否则熔断异常会穿透整个任务）"
        )

    def test_no_bare_raise_at_loop_top_level(self):
        """反证：try 之外的裸 raise 必须已清除。"""
        inside, outside = _collect_stuck_raises()
        assert not outside, (
            f"发现 {len(outside)} 处位于 try 之外的 `raise BrowseStuckError`"
            f"（行 {[n.lineno for n in outside]}）—— 会直接炸掉任务"
        )

    def test_stuck_event_emitted_from_except_branch(self):
        """`except BrowseStuckError` 分支必须 yield `browse_worker_stuck`。

        修正前消费端没有这个 case → 事件被静默丢弃：用户既看不到熔断，
        也不知道有多少组没跑完。
        """
        tree = ast.parse(WORKER_PY.read_text(encoding="utf-8"))
        found = False
        for h in ast.walk(tree):
            if not isinstance(h, ast.ExceptHandler) or h.type is None:
                continue
            if getattr(h.type, "id", None) != "BrowseStuckError":
                continue
            for sub in ast.walk(h):
                if isinstance(sub, ast.Dict):
                    keys = [k.value for k in sub.keys
                            if isinstance(k, ast.Constant)]
                    if "type" in keys:
                        vals = [v.value for v in sub.values
                                if isinstance(v, ast.Constant)]
                        if "browse_worker_stuck" in vals:
                            found = True
        assert found, "except BrowseStuckError 必须产出 browse_worker_stuck 事件"

    def test_chat_loop_consumes_stuck_event_into_terminal_judgement(self):
        """消费端：chat_loop 必须处理该事件并写入 `_browse_stuck_groups`（T3/T9）。"""
        src = CHAT_LOOP_PY.read_text(encoding="utf-8")
        assert 'evt_type == "browse_worker_stuck"' in src, "缺少消费分支"
        assert "_stuck_groups.append(" in src, "熔断的组未被记录"
        assert "_browse_stuck_groups = list(_stuck_groups)" in src, \
            "熔断组未传递给终态判定 → partial 永不触发"

    # ---- 真实行为：终态语义 ----

    def test_stuck_group_makes_terminal_state_partial(self):
        s = _bare_session()
        s._browse_stuck_groups = ["首页"]
        assert s._normalize_terminal_event("done") == "task_partial"

    def test_unreachable_wins_over_partial(self):
        """目标不可达优先于 partial —— "没测到"比"没测完"更严重。"""
        s = _bare_session()
        s._target_unreachable = True
        s._browse_stuck_groups = ["首页"]
        assert s._normalize_terminal_event("done") == "task_unreachable"

    def test_clean_run_stays_done(self):
        s = _bare_session()
        assert s._normalize_terminal_event("done") == "done"

    @pytest.mark.parametrize("etype", ["task_failed", "task_aborted", "task_partial",
                                       "system", "vuln", "error"])
    def test_non_done_events_pass_through(self, etype):
        """只允许改写 `done`，不得误伤其它终态/普通事件。"""
        s = _bare_session()
        s._target_unreachable = True          # 即使不可达也不该改写这些
        assert s._normalize_terminal_event(etype) == etype

    def test_terminal_map_covers_five_states(self):
        assert set(AgentSessionBase.TERMINAL_EVENT_MAP) == {
            "done", "task_partial", "task_unreachable", "task_failed", "task_aborted",
        }

    def test_terminal_state_is_persisted(self, store, isolated_cwd):
        """T13：终态必须落库（修正前失败任务永久停在 `running`，实测 31 条残留）。"""
        from core.session.chat_loop import _write_terminal_state

        store.upsert_scan("task_e2e_1", target="https://t.example", status="running")
        assert _write_terminal_state(
            "task_e2e_1", status="partial", phase="test",
            reason="browse_stuck", resumable=True,
        ) is True
        row = store.get_scan("task_e2e_1")
        assert row["status"] == "partial"
        assert row["resumable"] == 1
        assert row["resume_phase"] == "test"

    def test_terminal_write_never_raises(self, isolated_cwd):
        """终态写入失败不得反过来炸掉正在收尾的任务。"""
        from core.session.chat_loop import _write_terminal_state
        assert _write_terminal_state("", status="failed") is False
        assert _write_terminal_state("no_such_task", status="failed") is False


# ============================================================
# 钉 2：catch-all 误报不得进"已确认漏洞"
# ============================================================

def _dir_row(url: str, review_status: str | None = "needs_review",
             vuln_type: str = "源码泄露(.git)", severity: str = "high") -> dict:
    row = {
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "detail": f"{url} 命中路径关键字",
        "evidence": "",
    }
    if review_status is not None:
        row["review_status"] = review_status
    return row


def _sitemap_with_ledger(rows: list[dict]):
    from core.sitemap import Sitemap
    sm = Sitemap(target="https://bank.example", task_id="task_e2e_fp")
    sm._dirscan_sensitive_vulns = rows
    return sm


class TestFalsePositivesNeverReachReport:
    """T8 / T8b / T15：0923 实测三个银行目标各报 5 条**一字不差**的 HIGH，
    实为 SPA/兜底页误报。若交付给银行客户就是"报假漏洞"（合规事故）。"""

    def test_needs_review_not_counted_as_confirmed(self):
        sm = _sitemap_with_ledger([
            _dir_row("/.git/config", "needs_review"),
            _dir_row("/.git/index", "confirmed"),
        ])
        cov = sm.get_coverage()
        assert cov["dirscan_confirmed"] == 1
        assert cov["dirscan_needs_review"] == 1
        urls = [v["url"] for v in cov["vuln_list"] if v.get("source") == "dirscan"]
        assert urls == ["/.git/index"], f"误报进了已确认漏洞：{urls}"

    def test_missing_review_status_is_fail_safe(self):
        """★ fail-open 回归钉：无 `review_status` 时必须视为**未确认**。

        反过来的默认值（`confirmed`）正是把无证据误报写进银行报告的原因。
        """
        sm = _sitemap_with_ledger([_dir_row("/.git/config", None)])
        cov = sm.get_coverage()
        assert cov["dirscan_confirmed"] == 0
        assert cov["dirscan_needs_review"] == 1
        assert not [v for v in cov["vuln_list"] if v.get("source") == "dirscan"]

    def test_matrix_second_consumer_also_filters(self):
        """★ 第二消费点回归钉：`get_coverage_matrix()` 零过滤曾让误报从矩阵视图漏出。"""
        sm = _sitemap_with_ledger([
            _dir_row("/.git/config", "needs_review"),
            _dir_row("/WEB-INF/classes/application.yml", "confirmed"),
        ])
        md = sm.get_coverage_matrix()
        assert "/WEB-INF/classes/application.yml" in md, "已确认项应正常展示"
        assert "/.git/config" not in md, "未验证发现不得渲染进矩阵表格"
        assert "1" in md and "待复核" in md, "必须声明还有多少条待复核（不丢数据）"

    def test_matrix_declares_nothing_when_all_confirmed(self):
        sm = _sitemap_with_ledger([_dir_row("/.git/config", "confirmed")])
        md = sm.get_coverage_matrix()
        assert "/.git/config" in md
        assert "未通过内容校验" not in md

    def test_zero_feature_target_still_reports_confirmed_findings(self):
        """total==0 分支（目标不可达 / 纯被动侦察）也必须上报已确认发现，
        否则目录类发现会被整体吞掉（实测 119.253.84.35 场景）。"""
        sm = _sitemap_with_ledger([_dir_row("/actuator/env", "confirmed")])
        cov = sm.get_coverage()
        assert cov["total"] == 0
        assert cov["vulns"] == 1
        assert cov["vuln_list"][0]["url"] == "/actuator/env"


# ============================================================
# 钉 3：「继续」不得重头重爬
# ============================================================

class TestResumeDoesNotRestart:
    """T5 / T6 / T7：用户主诉原话「输入继续提示，我让继续你又扫其他目标的重头开始扫描」。"""

    @staticmethod
    def _sm_with(apis: int = 0, features: int = 0, tested_features: int = 0):
        """构造 sitemap。

        注意 `_infer_resume_stage` 是**按功能点粒度**判定的
        （每个功能点只要有任一 checklist 有结果就算"测过"），
        所以"部分完成"要靠 `tested_features < features` 表达，
        而不是"每个功能点里一半 check 有结果"。
        """
        from core.sitemap import Sitemap
        from core.sitemap.models import (CheckItem, CheckResult, FeaturePoint,
                                         Priority, TestStatus)
        sm = Sitemap(target="https://t.example", task_id="task_e2e_resume")
        for i in range(apis):
            sm.apis[f"GET /api/{i}"] = object()
        for i in range(features):
            fp = FeaturePoint(id=f"fp{i}", name=f"功能{i}", priority=Priority.HIGH)
            if i < tested_features:
                fp.checklist.append(CheckItem(vuln_type="XSS",
                                              result=CheckResult.NOT_VULN))
                fp.test_status = TestStatus.TESTED
            else:
                fp.checklist.append(CheckItem(vuln_type="XSS",
                                              result=CheckResult.PENDING))
            sm.features[fp.id] = fp
        return sm

    def test_no_produce_goes_explore(self):
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with()
        assert _infer_resume_stage(s) == "explore"

    def test_apis_without_features_goes_analyze(self):
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with(apis=94)
        assert _infer_resume_stage(s) == "analyze"

    def test_untested_features_goes_analyze(self):
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with(apis=94, features=493, tested_features=0)
        assert _infer_resume_stage(s) == "analyze"

    def test_partially_tested_goes_test(self):
        """★ 用户主诉 2 的核心：已抓 94 API / 493 功能点、只测了一部分，
        必须**原地**从 test 续，而不是回到 Phase 0 重爬（否则这些成果全丢）。"""
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with(apis=94, features=493, tested_features=100)
        assert _infer_resume_stage(s) == "test"

    def test_fully_tested_goes_report(self):
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with(apis=94, features=10, tested_features=10)
        assert _infer_resume_stage(s) == "report"

    def test_explicit_stop_forbids_reusing_breakpoint(self):
        """「彻底停止」（非暂停）后再点「继续」必须回到 explore（语义 = 重开）。"""
        from core.session.chat_loop import _infer_resume_stage
        s = _bare_session()
        s.sitemap = self._sm_with(apis=94, features=493, tested_features=100)
        s._resume_blocked = True
        assert _infer_resume_stage(s) == "explore"

    def test_infer_never_raises_on_broken_session(self):
        from core.session.chat_loop import _infer_resume_stage

        class _Boom:
            @property
            def sitemap(self):
                raise RuntimeError("懒加载失败")
        assert _infer_resume_stage(_Boom()) == "explore"

    # ---- 关键词归一（前后端必须同一套规则）----

    @pytest.mark.parametrize("msg", [
        "继续", "继续吧", "继续测试", "继续测试跑完这个流程",
        "请继续", "麻烦帮我继续", "接着刚才那个", "恢复",
        "resume", "Continue", "go on", "/继续", "。继续",
        "task_1790130538_0bc917 继续",
    ])
    def test_match_resume_prefix_hits(self, msg):
        from core.session.chat_loop import _match_resume
        assert _match_resume(msg) is True, f"{msg!r} 应命中 resume"

    @pytest.mark.parametrize("msg", ["", "   ", "开始吧", "你好", "扫描 example.com", "扫描任务"])
    def test_match_resume_rejects_others(self, msg):
        from core.session.chat_loop import _match_resume
        assert _match_resume(msg) is False, f"{msg!r} 不应命中 resume"

    def test_frontend_uses_same_keyword_tables(self):
        """★ R5 守护：前端命令表必须与后端同一套前缀规则（否则「继续xx」单端不认）。"""
        from core.session import chat_loop as cl
        src = INDEX_HTML.read_text(encoding="utf-8")

        def _js_list(name: str) -> list[str]:
            m = re.search(rf"const {name}\s*=\s*\[(.*?)\]", src, re.S)
            assert m, f"index.html 缺少 {name}"
            return re.findall(r"'([^']*)'", m.group(1))

        assert _js_list("RESUME_PREFIXES") == list(cl._RESUME_PREFIXES)
        assert _js_list("RESUME_POLITE_PREFIXES") == list(cl._RESUME_POLITE_PREFIXES)

    def test_enter_phase_explore_is_idempotent(self, isolated_cwd):
        """T6：断点进入必须**原地**（`_advance_phase` 的语义是"推进到下一阶段"，
        拿它来恢复会直接跳过目标阶段）。"""
        from core.session import AgentSession
        s = AgentSession.__new__(AgentSession)
        s.task_id = "task_e2e_enter"
        s.phase = "report"

        _drain(s._enter_phase("explore"))
        assert s.phase == "explore"

    def test_resume_uses_enter_phase_not_advance_phase(self):
        """契约守护：idle 分支的 resume 必须调 `_enter_phase`。"""
        src = CHAT_LOOP_PY.read_text(encoding="utf-8")
        assert "_enter_phase(_resume_stage)" in src, "resume 未走幂等的 _enter_phase"

    # ---- T7：resume 裁决接口 ----

    def test_resume_route_exists_and_only_adjudicates(self):
        """T7：`/api/tasks/{id}/resume` 必须存在，且**只裁决不执行**（避免第三套实现）。"""
        src = SESSIONS_API.read_text(encoding="utf-8")
        assert '@router.post("/api/tasks/{task_id}/resume")' in src
        for reason in ("invalid_id", "running", "stopped", "not_loaded", "ok"):
            assert f'"{reason}"' in src, f"缺少裁决分支 {reason}"

    def test_status_route_exposes_five_state_fields(self):
        """status 接口必须给出 `status` / `resumable` / `resume_phase`（前端靠它判断）。"""
        src = SESSIONS_API.read_text(encoding="utf-8")
        for field in ('"status"', '"resumable"', '"resume_phase"', '"running"'):
            assert field in src


# ============================================================
# 钉 4：P13 —— 运行中余额耗尽 → partial（不是 failed）
# ============================================================

class TestRuntimeBalanceGuard:
    """P13：preflight 只管开跑前；余额在**扫描途中**耗尽时，
    把已抓成果全部作废（failed）是错的 —— 用户要的是"已完成多少 + 怎么接着跑"。
    实测依据：当日 `insufficient balance` 39 次 > `429` 6 次。"""

    @pytest.mark.parametrize("err", [
        "Error code: 402 - insufficient balance",
        "insufficient_quota: you exceeded your current quota",
        "exceeded_current_quota_error",
        "Your account is suspended due to billing",
    ])
    def test_balance_errors_classify_as_account(self, err):
        from core.llm._failure import classify_llm_failure, is_blocking_failure
        kind, _msg = classify_llm_failure(err)
        assert kind == "llm_account"
        assert is_blocking_failure(err) is True

    def test_rate_limit_is_not_account(self):
        from core.llm._failure import classify_llm_failure
        assert classify_llm_failure("429 too many requests")[0] == "llm_rate_limit"

    def test_progress_note_mentions_resume(self):
        from core.session.chat_loop import build_partial_progress_note
        from core.sitemap import Sitemap
        sm = Sitemap(target="https://t.example", task_id="t")
        sm.apis["GET /a"] = object()
        note = build_partial_progress_note("test", sm)
        assert "API 1" in note and "停" in note
        assert "继续" in note, "必须给出续跑指引，否则用户只能重跑"
        assert "不会重爬" in note

    def test_progress_note_never_raises(self):
        from core.session.chat_loop import build_partial_progress_note

        class _Boom:
            @property
            def apis(self):
                raise RuntimeError("boom")
        assert isinstance(build_partial_progress_note("test", _Boom()), str)

    def test_account_failure_routes_to_partial_not_failed(self):
        """★ 契约守护：`llm_account` 分支必须推 `task_partial` 且落库 `partial`。"""
        src = CHAT_LOOP_PY.read_text(encoding="utf-8")
        m = re.search(r'if _reason_kind == "llm_account":(.*?)\n                    yield self\._event\("system", f"LLM 调用出错',
                      src, re.S)
        assert m, "未找到 llm_account 的独立分支（余额错误会退回 failed 分支）"
        block = m.group(1)
        assert '"task_partial"' in block
        assert 'status="partial"' in block
        assert "resumable=True" in block
        assert 'status="failed"' not in block


# ============================================================
# 钉 5：前端五态映射唯一 + T12 preflight 已接线（P14 / T12）
# ============================================================

class TestFrontendTerminalMapping:
    def test_single_mapping_table_covers_five_states(self):
        """P14：五态与前端映射"有且仅有一个映射表"。"""
        src = INDEX_HTML.read_text(encoding="utf-8")
        m = re.search(r"const TERMINAL_STATE_UI = \{(.*?)\n\};", src, re.S)
        assert m, "缺少 TERMINAL_STATE_UI 唯一映射表"
        table = m.group(1)
        for key in ("done", "task_partial", "task_unreachable",
                    "task_failed", "task_aborted"):
            assert f"'{key}'" in table, f"映射表缺少 {key}"

    def test_no_legacy_hardcoded_terminal_branches(self):
        """反证：不得残留旧的逐个 `type === 'task_xxx'` 硬编码展示分支。"""
        src = INDEX_HTML.read_text(encoding="utf-8")
        for legacy in ("else if (type === 'task_failed')",
                       "else if (type === 'task_aborted')"):
            assert legacy not in src, f"仍有硬编码分支：{legacy}"

    def test_partial_shows_resume_hint(self):
        src = INDEX_HTML.read_text(encoding="utf-8")
        assert "可点「继续」从断点续跑" in src or "从断点续跑" in src

    def test_preflight_is_wired_into_scan_entry(self):
        """★ T12 回归钉：此前 `/api/models/preflight` 是**死接口**（前端 0 处调用）。"""
        src = INDEX_HTML.read_text(encoding="utf-8")
        assert "async function preflightModelHealth()" in src, "缺少 preflight 封装"
        assert "await preflightModelHealth()" in src, "preflight 未被调用（仍是死接口）"
        # 必须位于扫描入口 startScanForTarget 内、且在改状态之前
        m = re.search(r"async function startScanForTarget\(target\) \{(.*?)\n  target\.status = 'running';",
                      src, re.S)
        assert m, "未找到 startScanForTarget 的 preflight 前置段"
        assert "_pf.blocking" in m.group(1), "阻断型问题未拦截"
        assert "return" in m.group(1), "阻断后未提前返回"

    def test_preflight_degradation_never_blocks(self):
        """健康检查接口自身失败时必须降级放行（不能因为检查挡住用户）。"""
        src = INDEX_HTML.read_text(encoding="utf-8")
        m = re.search(r"async function preflightModelHealth\(\) \{(.*?)\n\}", src, re.S)
        assert m
        body = m.group(1)
        assert body.count("skipped: true") >= 2, "接口异常/网络异常都应降级放行"
        assert "blocking: false" in body

    def test_resume_uses_authoritative_route(self):
        """T7：前端续跑应先向后端要权威裁决，而不是自己猜。"""
        src = INDEX_HTML.read_text(encoding="utf-8")
        assert "/resume`" in src or "/resume'" in src, "前端未调用 resume 裁决接口"


# ============================================================
# 总览：本次修复引入的资产仍在位（防止被误删/回退）
# ============================================================

def test_0923_assets_in_place():
    checks = {
        "T1 台账写入侧": ROOT / "core" / "session" / "dir_finding_store.py",
        "T1/T8b 判定谓词": ROOT / "core" / "sitemap" / "dir_findings.py",
        "T8 发现策略": ROOT / "core" / "dir_scanner" / "_finding_policy.py",
        "T4/B5 分型": ROOT / "core" / "llm" / "_failure.py",
        "T12 preflight": ROOT / "core" / "llm" / "_preflight.py",
        "T14 镜像（base 内实现）": ROOT / "core" / "session" / "base.py",
        "去标识化": ROOT / "core" / "redaction.py",
    }
    missing = [name for name, p in checks.items() if not p.exists()]
    assert not missing, f"0923 修复资产缺失：{missing}"


def test_redaction_runs_on_this_python():
    """★ 兼容性回归钉：`Path.read_text(newline=)` 是 Python 3.13+ 的参数，
    本仓 `requires-python = ">=3.10"`。用了它 → 异常被 except 吞掉 →
    **去标识化静默失效**（合规红线失守且不报错）。"""
    import sys
    import tempfile
    from core.redaction import redact_file as _redact_file

    if sys.version_info >= (3, 13):        # pragma: no cover
        pytest.skip("3.13+ 原生支持 read_text(newline=)")

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "n.json"
        p.write_text('{"v": "中信百信银行", "n": 1}\n', encoding="utf-8", newline="")
        changed, msg = _redact_file(p)
        assert changed is True, f"脱敏未生效：{msg}"
        with open(p, "r", encoding="utf-8", newline="") as f:
            after = f.read()
        assert "中信百信银行" not in after
