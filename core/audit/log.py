"""core.audit.log — append-only 审计日志 + 报表（长期 L3）。

按 XUANJIAN_ROADMAP_LONG_TERM §4.3 落地：
- record(who, role, action, target, result, extra) 追加一行
- report(since=, who=) 过滤生成报表

零外部依赖。
回滚：XUANJIAN_AUDIT_DISABLED=1 → record no-op，return False
"""
from __future__ import annotations

import json
import os
import pathlib
import threading
from datetime import datetime, timezone


class AuditLog:
    """append-only JSON Lines 审计日志。"""

    def __init__(self, path: str = "data/audit/audit.log"):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._disabled = os.environ.get("XUANJIAN_AUDIT_DISABLED") == "1"

    def record(
        self,
        *,
        who: str,
        role: str,
        action: str,
        target: str,
        result: str,
        extra: dict | None = None,
    ) -> bool:
        """记录一条审计。返回是否真的写入（关闭时 False）。"""
        if self._disabled:
            return False
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "who": who,
            "role": role,
            "action": action,
            "target": target,
            "result": result,
        }
        if extra:
            entry["extra"] = extra
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True

    def report(
        self,
        *,
        since: str | None = None,
        who: str | None = None,
    ) -> list[dict]:
        """生成审计报表（按时间/用户过滤）。"""
        if not self.path.exists():
            return []
        out: list[dict] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since and e.get("ts", "") < since:
                continue
            if who and e.get("who") != who:
                continue
            out.append(e)
        return out

    def clear(self) -> None:
        """清空（仅测试用）。"""
        with self._lock:
            if self.path.exists():
                self.path.unlink()


__all__ = ["AuditLog"]
