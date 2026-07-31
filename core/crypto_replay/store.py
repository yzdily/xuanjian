"""
core/crypto_replay/store.py — 加密模板持久化

格式：data/crypto_templates/<host>.json
（用 JSON 而不是 YAML，避免引入 pyyaml 依赖；现有项目已有 pyyaml 但还是 JSON 更稳）
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any

from core.log import get_logger
from core.crypto_replay.models import CryptoTemplate

log = get_logger("crypto_replay.store")

TEMPLATE_ROOT = Path("data/crypto_templates")
_LOCK = Lock()


def _safe_host(host: str) -> str:
    if not host:
        return "unknown"
    bad = '/\\:*?"<>|'
    return "".join(c for c in host if c not in bad).lower() or "unknown"


def _path_of(host: str) -> Path:
    return TEMPLATE_ROOT / f"{_safe_host(host)}.json"


def save_template(template: CryptoTemplate) -> bool:
    """保存或覆盖一个 host 的模板。"""
    if not template.host:
        log.warning("CryptoTemplate 缺少 host，跳过")
        return False
    try:
        TEMPLATE_ROOT.mkdir(parents=True, exist_ok=True)
        path = _path_of(template.host)
        with _LOCK:
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(template.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp.replace(path)
        log.info("保存加密模板 host=%s fields=%d", template.host, len(template.fields))
        return True
    except Exception as e:
        log.warning("保存模板失败: %s", e)
        return False


def load_template(host: str) -> CryptoTemplate | None:
    """加载某 host 的模板。"""
    if not host:
        return None
    path = _path_of(host)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return CryptoTemplate.from_dict(data)
    except Exception as e:
        log.warning("加载模板失败 %s: %s", path, e)
        return None


def list_templates() -> list[dict[str, Any]]:
    """列出所有模板的元信息。"""
    if not TEMPLATE_ROOT.exists():
        return []
    out = []
    for p in TEMPLATE_ROOT.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "host": data.get("host", p.stem),
                "fields_count": len(data.get("fields", []) or []),
                "learned_at": data.get("learned_at", 0),
                "learned_at_human": data.get("learned_at_human", ""),
                "sample_url": data.get("sample_url", ""),
            })
        except Exception as e:
            log.warning("读取模板失败 %s: %s", p, e)
    out.sort(key=lambda x: x.get("learned_at", 0), reverse=True)
    return out


def delete_template(host: str) -> bool:
    path = _path_of(host)
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except Exception as e:
        log.warning("删除模板失败: %s", e)
        return False


__all__ = ["save_template", "load_template", "list_templates", "delete_template",
           "TEMPLATE_ROOT"]
