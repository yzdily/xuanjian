"""
Web 层共享状态中心。

承载所有需要跨 router 模块访问的全局状态：
- LLM 连接池（_pool）
- 多会话表（_sessions / _current_session_id）
- LLM 日志文件缓存
- session 工具函数：get_session / _list_saved_sessions / _resolve_sitemap

所有 API 子模块通过 `from web._state import ...` 引用，避免循环依赖。

★ 设计要点：
- 可变标量（current_session_id）放在 STATE 字典里，因为 dict 是引用类型，
  跨模块共享时永远是同一个对象；如果用 module-level 变量 + global，
  其它模块 import 后修改的是各自模块名空间里的副本，会出现状态不同步。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.llm import LLMPool
from core.session import AgentSession
from core.log import get_logger

log = get_logger("web.state")

# ---- LLM 连接池（全局唯一） ----
_pool = LLMPool()


# ---- 多会话表 ----
_sessions: dict[str, AgentSession] = {}

# 可变标量打包到 dict 里，确保跨模块引用一致
STATE: dict = {
    "current_session_id": None,  # type: str | None
}


def get_current_session_id() -> str | None:
    return STATE["current_session_id"]


def set_current_session_id(sid: str | None) -> None:
    STATE["current_session_id"] = sid


# ---- LLM 日志文件缓存 ----
_llm_cache = {"mtime": 0, "size": 0, "records": []}


def _get_cached_llm_records(log_file: Path) -> list:
    """读取 LLM 日志文件，带缓存（文件没变就不重新读）。"""
    if not log_file.exists():
        return []
    try:
        stat = log_file.stat()
        if stat.st_mtime == _llm_cache["mtime"] and stat.st_size == _llm_cache["size"]:
            return _llm_cache["records"]
        records = []
        for line in log_file.read_text(encoding="utf-8").strip().splitlines():
            try:
                records.append(json.loads(line))
            except Exception:
                pass
        _llm_cache["mtime"] = stat.st_mtime
        _llm_cache["size"] = stat.st_size
        _llm_cache["records"] = records
        return records
    except Exception:
        return []


# ---- Session 工具函数 ----

def get_session() -> AgentSession:
    """获取当前会话，没有则自动创建。"""
    cur = STATE["current_session_id"]
    if cur and cur in _sessions:
        return _sessions[cur]
    session = AgentSession(llm=_pool.primary)
    _sessions[session.task_id] = session
    STATE["current_session_id"] = session.task_id
    from core.log import bind_context
    bind_context(session_id=session.task_id, phase=session.phase)
    log.info("新建会话: %s", session.task_id)
    return session


def _list_saved_sessions() -> list[dict]:
    """扫描 data/tasks/ 目录，列出所有历史会话。"""
    tasks_dir = Path("data/tasks")
    if not tasks_dir.exists():
        return []

    task_ids: set[str] = set()
    for f in tasks_dir.glob("task_*-sitemap.json"):
        tid = f.name.replace("-sitemap.json", "")
        task_ids.add(tid)
    for f in tasks_dir.glob("task_*-chat.jsonl"):
        tid = f.name.replace("-chat.jsonl", "")
        task_ids.add(tid)

    cur = STATE["current_session_id"]
    result = []
    for task_id in task_ids:
        sitemap_file = tasks_dir / f"{task_id}-sitemap.json"
        chat_file = tasks_dir / f"{task_id}-chat.jsonl"

        target = ""
        total_features = 0
        vuln_count = 0
        mtime = 0

        if sitemap_file.exists():
            try:
                data = json.loads(sitemap_file.read_text(encoding="utf-8"))
                target = data.get("target", "")
                features = data.get("features", {})
                total_features = len(features)
                vuln_count = sum(1 for fp in features.values()
                                for c in fp.get("checklist", []) if c.get("result") == "vulnerable")
                mtime = sitemap_file.stat().st_mtime
            except Exception:
                pass

        if not target and chat_file.exists():
            try:
                mtime = chat_file.stat().st_mtime
                for line in chat_file.read_text(encoding="utf-8").strip().splitlines()[:20]:
                    evt = json.loads(line)
                    if evt.get("type") == "system" and "目标确认:" in evt.get("data", ""):
                        target = evt["data"].split("目标确认:")[1].strip()
                        break
                    if evt.get("type") == "user" and not target:
                        import re
                        url_match = re.search(r'https?://[^\s,，]+', evt.get("data", ""))
                        if url_match:
                            target = url_match.group(0).rstrip('.,;')
            except Exception:
                pass

        if not mtime:
            mtime = time.time()

        result.append({
            "task_id": task_id,
            "target": target or "新会话",
            "features": total_features,
            "vulns": vuln_count,
            "time": mtime,
            "active": task_id == cur,
        })

    result.sort(key=lambda x: x["time"], reverse=True)
    return result


def _restore_session(task_id: str = "") -> AgentSession | None:
    """从磁盘恢复会话（sitemap + chat 历史）。重启后自动加载最近的会话。"""
    tasks_dir = Path("data/tasks")
    if not tasks_dir.exists():
        return None

    if not task_id:
        chats = sorted(tasks_dir.glob("task_*-chat.jsonl"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not chats:
            return None
        task_id = chats[0].name.replace("-chat.jsonl", "")

    sitemap_file = tasks_dir / f"{task_id}-sitemap.json"
    if not sitemap_file.exists():
        return None

    try:
        data = json.loads(sitemap_file.read_text(encoding="utf-8"))
        from core.sitemap import Sitemap
        sitemap = Sitemap(target=data.get("target", ""), task_id=task_id)
        if not sitemap.load():
            return None
        from core.session import AgentSession
        session = AgentSession(llm=_pool.primary, skip_recover=True)
        session.task_id = task_id
        session.sitemap = sitemap
        session._phase = data.get("phase", "idle")
        session.started = True
        _sessions[task_id] = session
        STATE["current_session_id"] = task_id
        from core.log import bind_context
        bind_context(session_id=task_id, phase=session._phase)
        log.info("已恢复会话: task_id=%s, target=%s, phase=%s, features=%d",
                 task_id, sitemap.target, session._phase, len(sitemap.features))
        return session
    except Exception as e:
        log.warning("恢复会话失败: %s", e)
        return None


def _resolve_sitemap(task_id: str = ""):
    """根据 task_id 获取对应的 sitemap，不传则取当前会话。"""
    if task_id:
        if task_id in _sessions and _sessions[task_id].sitemap:
            return _sessions[task_id].sitemap
        from core.sitemap import Sitemap
        sitemap = Sitemap(target="", task_id=task_id)
        if sitemap.load():
            return sitemap
        return None
    session = get_session()
    return session.sitemap
