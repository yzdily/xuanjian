"""
core/crypto_replay/learner.py — 从捕获的加密流量学习模板

输入约定（payload of `crypto.captured` 事件）：
{
  "host": "example.com",            # 必需
  "url": "https://...",             # 学习时的样本 URL（可选）
  "field": "password",              # 加密字段名
  "algorithm": "sm4",               # aes / sm4 / sm2
  "mode": "CBC",                    # 可选
  "key": "<base64 or hex>",         # 可选（hook 拦截到的 key）
  "iv": "<base64 or hex>",          # 可选
  "encoding": "base64",             # 输出编码
  "location": "body",               # body / header / query
  "sample_plaintext": "...",        # 可选，明文样本
  "sample_ciphertext": "...",       # 可选，密文样本
}

学习策略：
- 同一 host 同一字段 → upsert 覆盖（最新一次为准）
- 不同字段 → 累加
"""

from __future__ import annotations

from typing import Any

from core.log import get_logger
from core.crypto_replay.models import AlgorithmType, CryptoTemplate, EncryptedField
from core.crypto_replay.store import load_template, save_template

log = get_logger("crypto_replay.learner")


def _safe_algo(value: str) -> AlgorithmType:
    if not value:
        return AlgorithmType.UNKNOWN
    try:
        return AlgorithmType(str(value).lower())
    except Exception:
        return AlgorithmType.UNKNOWN


def learn_from_capture(payload: dict[str, Any]) -> bool:
    """从一次捕获记录中学习（或更新）模板。返回是否更新成功。"""
    host = (payload.get("host") or "").strip().lower()
    field_name = (payload.get("field") or "").strip()
    if not host or not field_name:
        log.debug("crypto.captured 缺少 host/field，跳过 payload=%s",
                  {k: v for k, v in payload.items() if k not in ("sample_ciphertext",)})
        return False

    ef = EncryptedField(
        name=field_name,
        algorithm=_safe_algo(payload.get("algorithm", "")),
        mode=str(payload.get("mode", "CBC")),
        key=str(payload.get("key", "")),
        iv=str(payload.get("iv", "")),
        encoding=str(payload.get("encoding", "base64")),
        location=str(payload.get("location", "body")),
        sample_plaintext=str(payload.get("sample_plaintext", ""))[:200],
        sample_ciphertext=str(payload.get("sample_ciphertext", ""))[:200],
    )

    tpl = load_template(host) or CryptoTemplate(host=host)
    tpl.upsert_field(ef)
    if not tpl.sample_url and payload.get("url"):
        tpl.sample_url = str(payload.get("url", ""))

    return save_template(tpl)


__all__ = ["learn_from_capture"]
