"""API Key 加密存储（AES-256-GCM 优先，HMAC-SHA256 keystream+XOR 兜底）。

从 core.llm 拆分而来；_get_encryption_key 保持对 core.auth 的惰性导入。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from core.log import get_logger

log = get_logger("llm")

# ============================================================
# ★ #15 API Key 加密存储
# ============================================================
# data/llm_configs.json 里的 api_key 之前是明文存储，一旦文件泄露会
# 直接暴露用户密钥。这里用 AES-256-GCM（优先 cryptography 库）或
# stdlib HMAC-SHA256 keystream + XOR 兜底，对 api_key 做对称加密。
# 密钥从 core.auth 的 _SECRET_KEY 派生，避免引入新秘密。
# 存储格式: "enc$v1$<base64(nonce + ciphertext)>"
# 兼容：未加密的明文 key 仍能读取（首次加载后 save 时自动加密落盘）。

_ENC_PREFIX = "enc$v1$"
_ENC_KEY_INFO = b"xuanjian-llm-apikey-encryption-v1"


def _get_encryption_key() -> bytes:
    """从 auth secret 派生 32 字节加密密钥（PBKDF2-SHA256）。"""
    try:
        # 复用 core/auth.py 持久化在 data/.auth_secret 的密钥
        from core import auth as _auth
        secret = _auth._SECRET_KEY or ""
        if not secret:
            # 极端情况：auth 尚未初始化（不应发生，但兜底）
            secret = _auth._load_or_generate_secret()
    except Exception:
        secret = ""
    if not secret:
        # 最终兜底：用进程内固定盐 + 环境变量（安全性弱于持久化密钥，但优于明文）
        secret = os.getenv("AUTH_SECRET_KEY", "xuanjian-default-llm-secret")
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"),
                                _ENC_KEY_INFO, 100000)[:32]


def _encrypt_api_key(plaintext: str) -> str:
    """加密 api_key。已经是加密格式或为空则原样返回。"""
    if not plaintext:
        return plaintext
    if plaintext.startswith(_ENC_PREFIX):
        return plaintext
    try:
        # 优先使用 cryptography 库的 AES-256-GCM（mitmproxy 已传递依赖）
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = _get_encryption_key()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return _ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")
    except ImportError:
        # 兜底：HMAC-SHA256 keystream + XOR（stdlib only）
        # 注意：不带认证标签，理论上可被篡改；但好过明文存储
        key = _get_encryption_key()
        nonce = os.urandom(16)
        ct = _xor_stream(plaintext.encode("utf-8"), key, nonce)
        return _ENC_PREFIX + "xor$" + base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_api_key(stored: str) -> str:
    """解密 api_key。非加密格式（明文）原样返回，保证向后兼容。"""
    if not stored or not stored.startswith(_ENC_PREFIX):
        return stored
    payload = stored[len(_ENC_PREFIX):]
    try:
        # AES-GCM 路径
        if not payload.startswith("xor$"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = _get_encryption_key()
            raw = base64.b64decode(payload)
            nonce, ct = raw[:12], raw[12:]
            return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
        # XOR 兜底路径
        raw = base64.b64decode(payload[4:])
        nonce, ct = raw[:16], raw[16:]
        return _xor_stream(ct, _get_encryption_key(), nonce).decode("utf-8")
    except Exception as e:
        log.warning("API Key 解密失败，按明文返回: %s", e)
        return stored


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """HMAC-SHA256 keystream 生成 + XOR（stdlib 加密兜底）。"""
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"),
                         hashlib.sha256).digest()
        chunk = data[len(out):len(out) + 32]
        out.extend(b ^ k for b, k in zip(chunk, block))
        counter += 1
    return bytes(out)
