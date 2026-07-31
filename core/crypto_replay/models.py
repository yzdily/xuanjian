"""
core/crypto_replay/models.py — 加密模板数据模型

## 核心概念
- CryptoTemplate：一个 host 上的加密接口学习成果（可包含多种算法 / 多个字段）
- EncryptedField：模板中一个字段的加密规则
- AlgorithmType：算法枚举，与 core.crypto_engine 对齐
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class AlgorithmType(str, Enum):
    AES = "aes"
    SM4 = "sm4"
    SM2 = "sm2"
    RSA = "rsa"
    DES = "des"
    UNKNOWN = "unknown"


@dataclass
class EncryptedField:
    """一个加密字段的规则。

    描述："对 host=X 的请求，请求体的 `password` 字段需要用 SM4 加密"
    """
    name: str                      # 字段名，如 "password" / "data" / "params"
    algorithm: AlgorithmType = AlgorithmType.UNKNOWN
    mode: str = "CBC"              # CBC / ECB / CTR / GCM
    key: str = ""                  # base64/hex 编码的密钥
    iv: str = ""                   # base64/hex 编码的 IV
    encoding: str = "base64"       # 输出编码：base64 / hex
    location: str = "body"         # body / header / query
    sample_plaintext: str = ""     # 学习时的明文样本（截断 200 字）
    sample_ciphertext: str = ""    # 学习时的密文样本（截断 200 字）

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if hasattr(self.algorithm, "value"):
            d["algorithm"] = self.algorithm.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EncryptedField":
        algo = d.get("algorithm", AlgorithmType.UNKNOWN.value)
        if isinstance(algo, str):
            try:
                algo = AlgorithmType(algo)
            except Exception:
                algo = AlgorithmType.UNKNOWN
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in d.items() if k in known}
        clean["algorithm"] = algo
        return cls(**clean)


@dataclass
class CryptoTemplate:
    """一个 host 的加密接口模板。"""
    host: str
    fields: list[EncryptedField] = field(default_factory=list)
    learned_at: float = 0
    sample_url: str = ""           # 学习时的样本接口 URL
    note: str = ""

    def __post_init__(self) -> None:
        if not self.learned_at:
            self.learned_at = time.time()

    def has_field(self, field_name: str) -> bool:
        return any(f.name == field_name for f in self.fields)

    def get_field(self, field_name: str) -> EncryptedField | None:
        for f in self.fields:
            if f.name == field_name:
                return f
        return None

    def upsert_field(self, ef: EncryptedField) -> None:
        for i, existing in enumerate(self.fields):
            if existing.name == ef.name:
                self.fields[i] = ef
                return
        self.fields.append(ef)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "fields": [f.to_dict() for f in self.fields],
            "learned_at": self.learned_at,
            "learned_at_human": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(self.learned_at)
            ),
            "sample_url": self.sample_url,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CryptoTemplate":
        fields_data = d.get("fields", []) or []
        ts = cls(
            host=d.get("host", ""),
            fields=[EncryptedField.from_dict(x) for x in fields_data if isinstance(x, dict)],
            learned_at=d.get("learned_at", 0),
            sample_url=d.get("sample_url", ""),
            note=d.get("note", ""),
        )
        return ts


__all__ = ["AlgorithmType", "EncryptedField", "CryptoTemplate"]
