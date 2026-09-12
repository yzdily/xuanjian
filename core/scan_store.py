"""
ScanStore — SQLite 扫描结果索引层。

保留 JSONL 作为原始数据源，SQLite 只存索引/摘要/指标，
用于多会话查询、历史对比、商业 API 等场景。

表结构：
- scans: 扫描任务元数据（task_id / target / status / metrics / created_at）
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
            finished_at REAL
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


def list_scans(limit: int = 50, status: str | None = None) -> list[dict]:
    """列出扫描记录。"""
    conn = _ensure_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM scans WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
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
    if severity:
        rows = conn.execute(
            "SELECT v.*, s.target as target FROM vulns v "
            "LEFT JOIN scans s ON v.task_id = s.task_id "
            "WHERE v.severity = ? ORDER BY v.created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT v.*, s.target as target FROM vulns v "
            "LEFT JOIN scans s ON v.task_id = s.task_id "
            "ORDER BY v.created_at DESC LIMIT ?",
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
