"""
core/crypto_replay/applier.py — 把模板应用到明文，输出密文

供主流程在注入 payload 时调用：
    from core.crypto_replay import has_template, encrypt_field
    if has_template(host):
        payload = encrypt_field(host, "password", payload)

如果模板缺失或算法不支持，会安全降级（返回原明文 + 记录警告），不影响主流程。
"""

from __future__ import annotations

from typing import Any

from core.log import get_logger
from core.crypto_replay.models import AlgorithmType, CryptoTemplate, EncryptedField
from core.crypto_replay.store import load_template

log = get_logger("crypto_replay.applier")


def has_template(host: str) -> bool:
    return load_template(host) is not None


def _decode_key_or_iv(value: str, encoding_hint: str = "") -> bytes:
    """智能解码 key/iv：先尝试 base64，失败则 hex，再失败按 utf-8 字面值。"""
    import base64
    if not value:
        return b""
    if encoding_hint == "hex":
        try:
            return bytes.fromhex(value)
        except Exception:
            pass
    # base64 first
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        pass
    try:
        return bytes.fromhex(value)
    except Exception:
        pass
    return value.encode("utf-8")


def _encrypt_with_engine(plaintext: str, ef: EncryptedField) -> str | None:
    """调用 core.crypto_engine 加密。失败返回 None。

    本函数对 crypto_engine 接口做了适配性容错：先尝试 .encrypt(...) 方法，
    若签名不匹配则降级返回 None。
    """
    try:
        from core import crypto_engine as ce
    except Exception as e:
        log.warning("crypto_engine 不可用: %s", e)
        return None

    algo = ef.algorithm
    key = _decode_key_or_iv(ef.key)
    iv = _decode_key_or_iv(ef.iv) if ef.iv else b""

    # 尝试常见的 API 形态（兼容不同版本的 crypto_engine 实现）
    candidates: list[tuple[str, dict[str, Any]]] = []
    if algo == AlgorithmType.AES:
        candidates += [
            ("encrypt_aes", {"plaintext": plaintext, "key": key, "iv": iv, "mode": ef.mode}),
            ("aes_encrypt", {"plaintext": plaintext, "key": key, "iv": iv, "mode": ef.mode}),
        ]
    elif algo == AlgorithmType.SM4:
        candidates += [
            ("encrypt_sm4", {"plaintext": plaintext, "key": key, "iv": iv, "mode": ef.mode}),
            ("sm4_encrypt", {"plaintext": plaintext, "key": key, "iv": iv, "mode": ef.mode}),
        ]
    elif algo == AlgorithmType.SM2:
        candidates += [
            ("encrypt_sm2", {"plaintext": plaintext, "public_key": ef.key}),
            ("sm2_encrypt", {"plaintext": plaintext, "public_key": ef.key}),
        ]

    for fn_name, kwargs in candidates:
        fn = getattr(ce, fn_name, None)
        if not callable(fn):
            continue
        try:
            return fn(**kwargs)
        except TypeError:
            # 签名不匹配，跳过
            continue
        except Exception as e:
            log.warning("crypto_engine.%s 失败: %s", fn_name, e)
            return None

    log.warning("crypto_engine 未找到 algo=%s 的可用入口", algo)
    return None


def encrypt_field(host: str, field_name: str, plaintext: str) -> str:
    """对一个字段加密。如果模板/算法缺失则安全降级返回原文。"""
    tpl = load_template(host)
    if tpl is None:
        return plaintext
    ef = tpl.get_field(field_name)
    if ef is None or ef.algorithm == AlgorithmType.UNKNOWN:
        return plaintext
    cipher = _encrypt_with_engine(plaintext, ef)
    return cipher if cipher is not None else plaintext


def apply_template(host: str, payload_dict: dict[str, Any]) -> dict[str, Any]:
    """对 dict 形态的 payload 批量应用模板。

    只加密 dict 顶层中"模板里有规则的"字段，其他字段原样保留。
    返回**新 dict**，不修改入参。
    """
    tpl = load_template(host)
    if tpl is None or not tpl.fields:
        return dict(payload_dict)

    out = dict(payload_dict)
    for ef in tpl.fields:
        if ef.name in out and isinstance(out[ef.name], (str, bytes)):
            plaintext = out[ef.name] if isinstance(out[ef.name], str) else out[ef.name].decode("utf-8", "ignore")
            cipher = _encrypt_with_engine(plaintext, ef)
            if cipher is not None:
                out[ef.name] = cipher
    return out


__all__ = ["has_template", "encrypt_field", "apply_template"]
