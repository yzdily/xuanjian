"""
用户认证模块 — 轻量级登录/注册/Token 校验。

设计要点：
- 用户数据持久化在 data/users.json（单文件 JSON，启动时全量加载到内存）
- 密码使用 hashlib.pbkdf2_hmac + per-user salt 存储（不依赖 PyJWT / passlib 等第三方库）
- Token 采用 JWT-like 三段式结构：header.payload.signature，全程 base64url 编码
  - header  = base64({"alg":"HS256","typ":"JWT"})
  - payload = base64({"username":"admin","exp":1735689600})
  - signature = sha256(header + "." + payload + secret) 的十六进制摘要
- Token 有效期 24 小时
- 启动时调用 init_default_user() 自动创建默认 admin/admin 账号
- ★ 登录失败限速：同一用户名 5 次失败后锁定 5 分钟

线程安全：所有读写操作都通过 _LOCK 串行化。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from threading import Lock

from core.log import get_logger

log = get_logger("auth")

# ============================================================
# 路径与常量
# ============================================================

_USERS_FILE = Path("data/users.json")
_LOCK = Lock()
_CACHE: dict[str, dict] | None = None  # username -> user dict

# Token 有效期：24 小时（秒）
TOKEN_TTL = 24 * 60 * 60

# ★ Token 签名密钥：优先从环境变量读取，否则启动时生成随机密钥并持久化
_SECRET_FILE = Path("data/.auth_secret")
_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "")


def _load_or_generate_secret() -> str:
    """加载或生成签名密钥，持久化到 data/.auth_secret。"""
    global _SECRET_KEY
    if _SECRET_KEY:
        return _SECRET_KEY
    if _SECRET_FILE.exists():
        try:
            _SECRET_KEY = _SECRET_FILE.read_text(encoding="utf-8").strip()
            if _SECRET_KEY:
                return _SECRET_KEY
        except Exception:
            pass
    # 生成 32 字节随机密钥
    _SECRET_KEY = secrets.token_hex(32)
    try:
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_FILE.write_text(_SECRET_KEY, encoding="utf-8")
        # 设置文件权限仅当前用户可读（Unix）
        if os.name != "nt":
            os.chmod(_SECRET_FILE, 0o600)
    except Exception as e:
        log.warning("持久化 auth secret 失败: %s", e)
    return _SECRET_KEY


_SECRET_KEY = _load_or_generate_secret()

# ★ 登录失败限速配置
_LOGIN_FAIL_LIMIT = 5        # 最大失败次数
_LOGIN_LOCK_DURATION = 300   # 锁定时长（秒）
_login_failures: dict[str, list[float]] = {}  # username -> [timestamps]

# 默认管理员账号
# ★ #16: 不再使用弱口令 admin/admin，改为启动时随机生成（或读环境变量）
_DEFAULT_USERNAME = os.getenv("PENTEST_DEFAULT_USERNAME", "admin")
# 优先级：环境变量 PENTEST_DEFAULT_PASSWORD > 持久化到 data/.default_password >
# 启动时随机生成（同时持久化，确保下次启动可用同一密码）
# 空字符串表示"启动时生成"
_DEFAULT_PASSWORD = os.getenv("PENTEST_DEFAULT_PASSWORD", "")


# ============================================================
# 内部工具：base64url 编解码
# ============================================================

def _b64url_encode(data: bytes) -> str:
    """base64url 编码（去掉末尾 = 填充）。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    """base64url 解码（自动补齐 = 填充）。"""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _hash_password(password: str, salt: str = "") -> str:
    """PBKDF2-HMAC-SHA256 加盐哈希密码。

    使用 per-user salt（如果提供），否则用全局 fallback。
    返回格式: "pbkdf2$<iterations>$<salt>$<hash>"
    兼容旧的 sha256 格式（不带前缀的纯 hex）。
    """
    if not salt:
        salt = secrets.token_hex(16)
    iterations = 100000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt.encode("utf-8"), iterations)
    return f"pbkdf2${iterations}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """校验明文密码与存储的哈希是否匹配。

    兼容旧的 sha256 格式（"scare-ai-sec::salt::password" 的 sha256 hex）
    和新的 pbkdf2 格式。
    """
    if not stored:
        return False
    # 新格式: pbkdf2$<iterations>$<salt>$<hash>
    if stored.startswith("pbkdf2$"):
        try:
            parts = stored.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            expected_hash = parts[3]
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                      salt.encode("utf-8"), iterations)
            return hmac.compare_digest(dk.hex(), expected_hash)
        except (ValueError, IndexError):
            return False
    # 旧格式兼容: sha256("scare-ai-sec::salt::password")
    old_raw = f"scare-ai-sec::salt::{password}".encode("utf-8")
    old_hash = hashlib.sha256(old_raw).hexdigest()
    return hmac.compare_digest(old_hash, stored)


def _now() -> int:
    """当前 Unix 时间戳（秒）。"""
    return int(time.time())


# ============================================================
# 加载 / 持久化
# ============================================================

def _ensure_dir() -> None:
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load() -> dict[str, dict]:
    """加载用户表到内存缓存。文件不存在则返回空字典。"""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    _ensure_dir()
    users: dict[str, dict] = {}
    if _USERS_FILE.exists():
        try:
            data = json.loads(_USERS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                users = data
        except Exception as e:
            log.error("读取 users.json 失败: %s", e)
    _CACHE = users
    return _CACHE


def _flush() -> None:
    """把内存中的用户表覆盖写回文件。"""
    users = _load()
    _ensure_dir()
    tmp = _USERS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _USERS_FILE)


# ============================================================
# Token 生成与校验
# ============================================================

def _create_token(username: str) -> str:
    """为指定用户生成 24 小时有效的 JWT-like token。"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "username": username,
        "iat": _now(),
        "exp": _now() + TOKEN_TTL,
        "jti": uuid.uuid4().hex,  # token 唯一标识，便于后续黑名单扩展
    }
    header_b64 = _b64url_encode(json.dumps(header, ensure_ascii=False).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(_SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{signing_input}.{sig}"


def verify_token(token: str) -> dict | None:
    """校验 token：合法且未过期则返回 payload，否则返回 None。

    返回的 payload 形如 {"username": "admin", "iat": ..., "exp": ..., "jti": ...}
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig = parts
    # 重新计算签名做常量时间比较，防止伪造
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        _SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        log.warning("token 签名校验失败")
        return None
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as e:
        log.warning("token payload 解析失败: %s", e)
        return None
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or _now() >= int(exp):
        log.info("token 已过期: username=%s", payload.get("username"))
        return None
    # 校验用户是否仍存在
    users = _load()
    username = payload.get("username", "")
    if username not in users:
        log.info("token 对应用户不存在: %s", username)
        return None
    return payload


# ============================================================
# 对外 API：register / login / init_default_user
# ============================================================

def register(username: str, password: str) -> dict:
    """注册新用户。

    成功返回 {"ok": True, "username": ..., "token": ...}
    失败返回 {"ok": False, "error": ...}
    """
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return {"ok": False, "error": "用户名和密码不能为空"}
    if len(username) < 2:
        return {"ok": False, "error": "用户名至少 2 个字符"}
    if len(password) < 3:
        return {"ok": False, "error": "密码至少 3 个字符"}
    with _LOCK:
        users = _load()
        if username in users:
            return {"ok": False, "error": f"用户名已存在: {username}"}
        users[username] = {
            "username": username,
            "password": _hash_password(password),
            "created_at": _now(),
            "role": "user",
        }
        _flush()
        log.info("新用户注册成功: %s", username)
        return {
            "ok": True,
            "username": username,
            "token": _create_token(username),
            "message": "注册成功",
        }


def login(username: str, password: str) -> dict:
    """登录校验，成功返回 token。

    ★ 登录失败限速：同一用户名连续失败 5 次后锁定 5 分钟。
    """
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return {"ok": False, "error": "用户名和密码不能为空"}

    # ★ 登录限速检查
    now = _now()
    with _LOCK:
        recent_fails = [t for t in _login_failures.get(username, [])
                        if now - t < _LOGIN_LOCK_DURATION]
        _login_failures[username] = recent_fails
        if len(recent_fails) >= _LOGIN_FAIL_LIMIT:
            remaining = int(_LOGIN_LOCK_DURATION - (now - recent_fails[0]))
            return {"ok": False, "error": f"登录失败次数过多，请 {remaining} 秒后重试"}

    with _LOCK:
        users = _load()
        user = users.get(username)
        if not user:
            _record_login_failure(username)
            return {"ok": False, "error": "用户名或密码错误"}
        if not _verify_password(password, user.get("password", "")):
            _record_login_failure(username)
            return {"ok": False, "error": "用户名或密码错误"}
        # ★ 登录成功，清除失败记录
        _login_failures.pop(username, None)
        log.info("用户登录成功: %s", username)
        return {
            "ok": True,
            "username": username,
            "role": user.get("role", "user"),
            "token": _create_token(username),
            "message": "登录成功",
        }


def _record_login_failure(username: str) -> None:
    """记录登录失败时间戳。"""
    now = _now()
    fails = _login_failures.get(username, [])
    fails.append(now)
    # 只保留最近 LOCK_DURATION 内的记录
    fails = [t for t in fails if now - t < _LOGIN_LOCK_DURATION]
    _login_failures[username] = fails
    log.warning("登录失败: %s (第 %d 次)", username, len(fails))


def get_user(username: str) -> dict | None:
    """获取用户信息（脱敏，不含密码）。"""
    if not username:
        return None
    with _LOCK:
        users = _load()
        user = users.get(username)
        if not user:
            return None
        return {
            "username": user.get("username"),
            "role": user.get("role", "user"),
            "created_at": user.get("created_at"),
        }


def _resolve_default_password() -> str:
    """★ #16: 解析默认密码。
    优先级：
      1) 环境变量 PENTEST_DEFAULT_PASSWORD（已加载到 _DEFAULT_PASSWORD）
      2) 持久化文件 data/.default_password（首次生成后保存，下次复用）
      3) 启动时随机生成 12 位字母数字，并持久化
    """
    # 1) 环境变量优先
    if _DEFAULT_PASSWORD:
        return _DEFAULT_PASSWORD
    # 2) 持久化文件
    pw_file = Path("data/.default_password")
    if pw_file.exists():
        try:
            pw = pw_file.read_text(encoding="utf-8").strip()
            if pw:
                return pw
        except Exception:
            pass
    # 3) 随机生成 + 持久化
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    pw = "".join(secrets.choice(alphabet) for _ in range(12))
    try:
        pw_file.parent.mkdir(parents=True, exist_ok=True)
        pw_file.write_text(pw, encoding="utf-8")
        if os.name != "nt":
            os.chmod(pw_file, 0o600)
    except Exception as e:
        log.warning("持久化默认密码失败: %s", e)
    return pw


def init_default_user() -> None:
    """启动时调用：若无任何用户则创建默认管理员账号。

    ★ #16: 默认密码不再硬编码 "admin"，而是：
      - 环境变量 PENTEST_DEFAULT_PASSWORD 指定时使用之
      - 否则首次启动随机生成 12 位强密码并持久化到 data/.default_password
      - 同一台机器下次启动仍使用同一密码，避免每次启动都换密码
    若已存在 admin 账号则不做任何操作（保留用户已修改的密码）。
    """
    with _LOCK:
        users = _load()
        if _DEFAULT_USERNAME in users:
            log.debug("默认用户已存在，跳过初始化: %s", _DEFAULT_USERNAME)
            return
        password = _resolve_default_password()
        users[_DEFAULT_USERNAME] = {
            "username": _DEFAULT_USERNAME,
            "password": _hash_password(password),
            "created_at": _now(),
            "role": "admin",
        }
        _flush()
        # 用醒目方式打印到控制台和日志，方便用户首次登录拿到密码
        banner = (
            "=" * 60 + "\n"
            f"  默认管理员账号已创建\n"
            f"  用户名: {_DEFAULT_USERNAME}\n"
            f"  密码  : {password}\n"
            f"  请尽快登录后修改密码！\n"
            f"  （密码已持久化到 data/.default_password，下次启动沿用）\n"
            + "=" * 60
        )
        print(banner)
        log.warning("默认用户已创建: %s — 请尽快登录后修改密码", _DEFAULT_USERNAME)
