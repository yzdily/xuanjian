"""
ScanStore — SQLite 扫描结果索引层。

保留 JSONL 作为原始数据源，SQLite 只存索引/摘要/指标，
用于多会话查询、历史对比、商业 API 等场景。

表结构：
- scans: 扫描任务元数据（task_id / target / status / metrics / created_at）
  ★ 0923 v2（T16）追加 4 列：phase_status / fail_reason / resumable / resume_phase
- vulns: 漏洞摘要（task_id / feature_id / vuln_type / severity / status / url）
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from core.di import register_resetter

# ★ 安全加固：使用基于项目根目录的绝对路径，避免工作目录依赖
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _PROJECT_ROOT / "data" / "scan_store.db"

# ★ 并发写入保护：全局锁，序列化所有写操作
_write_lock = threading.Lock()

# ================================================================
# ★ T16 (0923 v2)：终态语义常量
# ================================================================
# 产品方案 §2.2 的五态终态；'finished' 为历史遗留值，读取端仍需兼容。
TERMINAL_STATUSES: tuple[str, ...] = (
    "completed",    # 完整走完 Phase 0→3
    "partial",      # 走完了但有组未执行/未覆盖
    "unreachable",  # 目标不可达，仅被动侦察
    "failed",       # 环境/配置类硬失败，可重试
    "aborted",      # 用户主动停止
)
LEGACY_FINISHED = "finished"

# 可由 set_terminal_state 写入的可选列（白名单 —— upsert_scan 会把这些 kwargs
# 直接当列名拼进 SQL，所以列必须先在 _migrate_columns 里建好）
_SCAN_OPTIONAL_COLUMNS: tuple[tuple[str, str], ...] = (
    ("phase_status", "TEXT DEFAULT ''"),
    ("fail_reason", "TEXT DEFAULT ''"),
    ("resumable", "INTEGER DEFAULT 0"),
    ("resume_phase", "TEXT DEFAULT ''"),
)


def _get_conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


# 模块级单例（延迟创建）
@dataclass
class _ScanStoreState:
    conn: Optional[sqlite3.Connection] = None


_state = _ScanStoreState()


def _ensure_conn() -> sqlite3.Connection:
    if _state.conn is None:
        _state.conn = _get_conn()
        _init_db(_state.conn)
    return _state.conn


def _ensure_column(conn: sqlite3.Connection, table: str, col: str, decl: str) -> bool:
    """幂等加列（T16）。

    为什么需要它：``upsert_scan`` 的 UPDATE 分支把 kwargs **直接当列名**拼 SQL
    （见下方 ``sets.append(f"{k} = ?")``），所以任何新字段都必须先在物理表里存在，
    否则写终态时会抛 ``sqlite3.OperationalError: no such column``。

    Returns:
        True 表示本次真的新建了列；False 表示列已存在（无需变更）。
    """
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    if col in cols:
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    conn.commit()
    return True


def _migrate_columns(conn: sqlite3.Connection) -> int:
    """对已存在的库补齐终态元数据列（幂等，可重复调用）。

    Returns:
        本次新增的列数（0 = 已是最新 schema）。
    """
    added = 0
    for col, decl in _SCAN_OPTIONAL_COLUMNS:
        if _ensure_column(conn, "scans", col, decl):
            added += 1
    return added


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            task_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            scan_mode TEXT DEFAULT 'batch',
            model TEXT DEFAULT '',
            metrics_json TEXT DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            finished_at REAL,
            -- ★ 0923 v2（T16）终态元数据；老库由 _migrate_columns 补齐
            phase_status TEXT DEFAULT '',
            fail_reason TEXT DEFAULT '',
            resumable INTEGER DEFAULT 0,
            resume_phase TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            feature_id TEXT NOT NULL,
            feature_name TEXT DEFAULT '',
            vuln_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'confirmed',
            url TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY (task_id) REFERENCES scans(task_id)
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_task ON vulns(task_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity);
        CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulns(vuln_type);
    """)
    conn.commit()
    # ★ T16：老库补列（CREATE TABLE IF NOT EXISTS 不会改已存在的表结构）
    _migrate_columns(conn)


# ================================================================
# Public API
# ================================================================

def upsert_scan(task_id: str, target: str, **kwargs) -> None:
    """插入或更新扫描记录。"""
    conn = _ensure_conn()
    now = time.time()
    with _write_lock:
        existing = conn.execute("SELECT 1 FROM scans WHERE task_id = ?", (task_id,)).fetchone()
        if existing:
            sets = ["updated_at = ?"]
            vals = [now]
            for k, v in kwargs.items():
                if k == "metrics":
                    sets.append("metrics_json = ?")
                    vals.append(json.dumps(v, ensure_ascii=False))
                else:
                    # ★ T16：白名单过滤 —— 本分支把 key 直接当列名拼 SQL，
                    #   未登记的 key 会抛 no such column。静默跳过并告警，
                    #   避免一个笔误打死整条终态写入链路。
                    _known = {"status", "scan_mode", "model", "target", "finished_at"}
                    _known |= {c for c, _ in _SCAN_OPTIONAL_COLUMNS}
                    if k not in _known:
                        try:
                            from core.log import get_logger
                            get_logger(__name__).warning(
                                "[scan_store] upsert_scan 忽略未知列: %s", k)
                        except Exception:
                            pass
                        continue
                    sets.append(f"{k} = ?")
                    vals.append(v)
            vals.append(task_id)
            conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE task_id = ?", vals)
        else:
            metrics_json = json.dumps(kwargs.pop("metrics", {}), ensure_ascii=False)
            conn.execute(
                """INSERT INTO scans (task_id, target, status, scan_mode, model, metrics_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (task_id, target, kwargs.get("status", "running"), kwargs.get("scan_mode", "batch"),
                 kwargs.get("model", ""), metrics_json, now, now),
            )
        conn.commit()


def finish_scan(task_id: str, metrics: dict | None = None) -> None:
    """标记扫描完成。"""
    conn = _ensure_conn()
    now = time.time()
    with _write_lock:
        if metrics:
            conn.execute(
                "UPDATE scans SET status = 'finished', finished_at = ?, metrics_json = ?, updated_at = ? WHERE task_id = ?",
                (now, json.dumps(metrics, ensure_ascii=False), now, task_id),
            )
        else:
            conn.execute(
                "UPDATE scans SET status = 'finished', finished_at = ?, updated_at = ? WHERE task_id = ?",
                (now, now, task_id),
            )
        conn.commit()


# ================================================================
# ★ T16 (0923 v2)：真实终态写入
# ================================================================

def set_terminal_state(
    task_id: str,
    *,
    status: str,
    phase: str = "",
    reason: str = "",
    resumable: bool = False,
    metrics: dict | None = None,
) -> int:
    """写入任务真实终态（修 D5：失败/中断任务不再永久停在 ``running``）。

    ★ 为什么不扩 ``finish_scan``：``finish_scan(task_id, metrics)`` 已被
    ``core/parallel/_orch_phases/_report_phase.py`` 与 ``core/task_queue.py`` 调用，
    且硬编码 ``status='finished'``。改签名会静默破坏这两处；因此新增独立函数，
    ``finish_scan`` 保持原样。

    Args:
        task_id: 任务 ID。必须已由 ``upsert_scan`` 建行（本函数只 UPDATE，不 INSERT，
            避免生成 target 为空的幽灵记录）。
        status: 五态之一（``TERMINAL_STATUSES``）或历史值 ``'finished'``。
        phase: 终态时的阶段名（explore / analyze / test / report）。
        reason: 失败/中断原因（截断 300 字符）。
        resumable: 是否可从 ``resume_phase`` 续跑。
        metrics: 可选指标快照，写入 ``metrics_json``。

    Returns:
        受影响行数（0 = 无该 task_id 记录，已记 warning）。

    Raises:
        ValueError: status 不在允许集合内（防止拼写错误写入不可读状态）。
    """
    if status not in TERMINAL_STATUSES and status != LEGACY_FINISHED:
        raise ValueError(
            f"非法终态 {status!r}，允许: {TERMINAL_STATUSES} / {LEGACY_FINISHED!r}"
        )
    conn = _ensure_conn()
    now = time.time()
    sets = [
        "status = ?", "updated_at = ?", "finished_at = ?",
        "phase_status = ?", "fail_reason = ?", "resumable = ?", "resume_phase = ?",
    ]
    vals: list = [
        status, now, now, phase or "", str(reason)[:300],
        1 if resumable else 0, phase if resumable else "",
    ]
    if metrics is not None:
        sets.append("metrics_json = ?")
        vals.append(json.dumps(metrics, ensure_ascii=False))
    vals.append(task_id)
    with _write_lock:
        cur = conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE task_id = ?", vals)
        conn.commit()
        rowcount = cur.rowcount
    if rowcount == 0:
        try:
            from core.log import get_logger
            get_logger(__name__).warning(
                "[scan_store] 终态写入未命中记录（task_id 未 upsert 过）: %s status=%s",
                task_id, status,
            )
        except Exception:
            pass
    return rowcount


def mark_stale_running(max_age_hours: float = 6.0) -> int:
    """把"卡死在过去"的 ``running`` 任务回填为 ``failed``（T16，修 D5 存量）。

    ★ 为什么必须有：实测 ``data/scan_store.db`` 中 ``running = 31`` / ``finished = 32``，
    最早残留 2026-07-31 —— 只修"新路径写终态"永远清不掉存量，且这些残留会让
    仪表盘统计、删除护栏、「继续」候选判定全部失去依据。

    进程启动时调用一次即可（幂等）。

    Args:
        max_age_hours: ``updated_at`` 早于该小时数仍为 running 的，判为残留。

    Returns:
        被回填的行数（0 = 没有残留）。
    """
    conn = _ensure_conn()
    now = time.time()
    cutoff = now - max(0.0, max_age_hours) * 3600.0
    with _write_lock:
        cur = conn.execute(
            "UPDATE scans SET status = 'failed', resumable = 0, "
            "fail_reason = 'stale_running_backfilled', updated_at = ? "
            "WHERE status = 'running' AND updated_at < ?",
            (now, cutoff),
        )
        conn.commit()
        return cur.rowcount


def upsert_vuln(task_id: str, feature_id: str, vuln_type: str, **kwargs) -> None:
    """插入漏洞记录（自动去重：同 task_id + feature_id + vuln_type 只保留一条）。"""
    conn = _ensure_conn()
    now = time.time()
    with _write_lock:
        existing = conn.execute(
            "SELECT id FROM vulns WHERE task_id = ? AND feature_id = ? AND vuln_type = ?",
            (task_id, feature_id, vuln_type),
        ).fetchone()

        if existing:
            sets = []
            vals = []
            for k, v in kwargs.items():
                sets.append(f"{k} = ?")
                vals.append(v)
            if sets:
                vals.append(existing["id"])
                conn.execute(f"UPDATE vulns SET {', '.join(sets)} WHERE id = ?", vals)
        else:
            conn.execute(
                """INSERT INTO vulns (task_id, feature_id, feature_name, vuln_type, severity, status, url, detail, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (task_id, feature_id, kwargs.get("feature_name", ""), vuln_type,
                 kwargs.get("severity", "medium"), kwargs.get("status", "confirmed"),
                 kwargs.get("url", ""), kwargs.get("detail", ""), now),
            )
        conn.commit()


def mark_scan_deleted(task_id: str) -> int:
    """★ 软删扫描记录（C1 四件套第 4 项）。

    只把 ``scans.status`` 置为 ``'deleted'``，不物理删除行 —— 零 schema 变更、
    可撤销，且让 ``list_scans()`` 默认不再返回它（CI 门禁 ``_latest_task_id()``
    因此自动顺延到上一条真实存在的扫描，不再拿到磁盘上已不存在的 task_id）。

    Returns:
        受影响行数（0 表示该 task_id 无记录）。
    """
    conn = _ensure_conn()
    now = time.time()
    with _write_lock:
        cur = conn.execute(
            "UPDATE scans SET status = 'deleted', updated_at = ? WHERE task_id = ?",
            (now, task_id),
        )
        conn.commit()
        return cur.rowcount


def mark_vulns_deleted(task_id: str) -> int:
    """★ 软删该 task_id 的漏洞摘要行（与 ``mark_scan_deleted`` 同批调用）。

    ``vulns.status`` 字段已存在（默认 ``'confirmed'``），直接复用，零 schema 变更。

    Returns:
        受影响行数。
    """
    conn = _ensure_conn()
    with _write_lock:
        cur = conn.execute(
            "UPDATE vulns SET status = 'deleted' WHERE task_id = ?",
            (task_id,),
        )
        conn.commit()
        return cur.rowcount


def list_scans(limit: int = 50, status: str | None = None,
               include_deleted: bool = False) -> list[dict]:
    """列出扫描记录。

    Args:
        limit: 最多返回条数。
        status: 显式按状态过滤（如 ``'finished'``）。传入时以它为准，
            ``include_deleted`` 不再叠加过滤 —— 传 ``status='deleted'`` 即可
            单独排查已软删记录。
        include_deleted: 未显式指定 ``status`` 时是否一并返回软删记录
            （默认 False，排查历史用 True）。
    """
    conn = _ensure_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM scans WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    elif include_deleted:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans WHERE status != 'deleted' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(task_id: str) -> dict | None:
    """获取单条扫描记录。"""
    conn = _ensure_conn()
    row = conn.execute("SELECT * FROM scans WHERE task_id = ?", (task_id,)).fetchone()
    return dict(row) if row else None


def get_vulns(task_id: str, severity: str | None = None) -> list[dict]:
    """获取扫描的漏洞列表。"""
    conn = _ensure_conn()
    if severity:
        rows = conn.execute(
            "SELECT * FROM vulns WHERE task_id = ? AND severity = ? ORDER BY created_at",
            (task_id, severity),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM vulns WHERE task_id = ? ORDER BY created_at",
            (task_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_all_vulns(limit: int = 200, severity: str | None = None) -> list[dict]:
    """★ 获取所有扫描的漏洞列表（聚合，按时间倒序）。

    供前端漏洞页面加载历史漏洞使用。关联 scans 表获取 target。

    数据来源：
    1. scan_store.vulns 表（扫描正常完成时 upsert_vuln 同步）
    2. ★ sitemap.json 的 checklist（兜底：扫描未正常 finish 或未同步时）
       避免 task_1784962790_39f96a 这种有 54 个 checklist 漏洞但没同步到 DB 的情况
    """
    conn = _ensure_conn()
    # ★ C1：软删（status='deleted'）的漏洞行不再出现在聚合列表里
    _alive = "(v.status IS NULL OR v.status != 'deleted')"
    if severity:
        rows = conn.execute(
            "SELECT v.*, s.target as target FROM vulns v "
            "LEFT JOIN scans s ON v.task_id = s.task_id "
            f"WHERE v.severity = ? AND {_alive} ORDER BY v.created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT v.*, s.target as target FROM vulns v "
            "LEFT JOIN scans s ON v.task_id = s.task_id "
            f"WHERE {_alive} ORDER BY v.created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    db_vulns = [dict(r) for r in rows]

    # ★ 兜底：从 sitemap.json 补充未同步到 DB 的漏洞
    try:
        import json as _json
        from pathlib import Path as _Path
        from time import time as _time
        tasks_dir = _Path("data/tasks")
        if tasks_dir.exists():
            # 收集 DB 中已有的 (task_id, feature_id, vuln_type) 去重键
            db_keys = set()
            for v in db_vulns:
                key = (v.get("task_id", ""), v.get("feature_id", ""), v.get("vuln_type", ""))
                db_keys.add(key)

            sitemap_vulns = []
            for sitemap_file in tasks_dir.glob("*-sitemap.json"):
                try:
                    data = _json.loads(sitemap_file.read_text(encoding="utf-8"))
                except Exception:
                    continue
                task_id = data.get("task_id", "") or sitemap_file.stem.replace("-sitemap", "")
                target = data.get("target", "") or ""
                features = data.get("features", {}) or {}
                for fp_id, fp in features.items():
                    if not isinstance(fp, dict):
                        continue
                    fp_name = fp.get("name", fp_id) or fp_id
                    fp_url = fp.get("page_url", "") or ""
                    for c in (fp.get("checklist", []) or []):
                        if not isinstance(c, dict):
                            continue
                        if c.get("result") != "vulnerable":
                            continue
                        vt = c.get("vuln_type", "") or "未知"
                        sev = (c.get("severity", "medium") or "medium").lower()
                        # severity 过滤
                        if severity and sev != severity.lower():
                            continue
                        # 去重：DB 已有的跳过
                        key = (task_id, fp_id, vt)
                        if key in db_keys:
                            continue
                        sitemap_vulns.append({
                            "id": None,
                            "task_id": task_id,
                            "feature_id": fp_id,
                            "feature_name": fp_name,
                            "vuln_type": vt,
                            "severity": sev,
                            "status": "confirmed",
                            "url": c.get("evidence_request", "") or fp_url,
                            "detail": (c.get("detail", "") or "")[:500],
                            "created_at": sitemap_file.stat().st_mtime,
                            "target": target,
                            "_source": "sitemap",
                        })
            # 合并：DB 漏洞 + sitemap 补充漏洞
            db_vulns.extend(sitemap_vulns)
            # 重新按 created_at 倒序
            db_vulns.sort(key=lambda v: v.get("created_at", 0) or 0, reverse=True)
            # 重新截断 limit
            if len(db_vulns) > limit:
                db_vulns = db_vulns[:limit]
    except Exception:
        pass

    return db_vulns


def get_stats() -> dict:
    """获取全局统计。"""
    conn = _ensure_conn()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_vulns = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    by_severity = {}
    for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM vulns GROUP BY severity"):
        by_severity[row["severity"]] = row["cnt"]
    return {
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "by_severity": by_severity,
    }


# ★ DI 收敛（D7/A4）：注册单例重置钩子，供 reset_singletons() 在测试间统一重置
def _reset_core_scan_store__conn() -> None:
    _state.conn = None

register_resetter("core_scan_store__conn", _reset_core_scan_store__conn)
