"""
CryptoEngine — 前端加密检测 + 加解密能力

集成 CryptoHook 浏览器插件（游刃AISec密钥获取工具），
实现目标网站加密参数的自动加解密，让子 Agent 能测试加密接口。

流程：
1. Phase 1: crypto_detect() 通过 browser_evaluate 读取插件 hook 到的密钥
2. 加密配置存入 sitemap.crypto_configs，flush 到 sample 文件
3. Phase 2: 子 Agent 调用 crypto_encrypt/decrypt，用 Python 本地加解密
"""

from __future__ import annotations

import base64
import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

from core.log import get_logger

log = get_logger("crypto")


@dataclass
class CryptoConfig:
    """一个加密配置（对应一种加密方式）。"""
    algorithm: str = ""       # AES-CBC, AES-ECB, DES-CBC, RSA, SM4, SM2 ...
    key_hex: str = ""         # 密钥（hex 格式）
    iv_hex: str = ""          # IV（hex 格式，ECB 模式无 IV）
    mode: str = ""            # CBC, ECB, CFB, OFB, CTR
    padding: str = ""         # Pkcs7, ZeroPadding, NoPadding
    key_ascii: str = ""       # 密钥（ASCII 明文，如果有）
    iv_ascii: str = ""        # IV（ASCII 明文）
    rsa_public_key: str = ""  # RSA 公钥（PEM）
    rsa_private_key: str = "" # RSA 私钥（PEM）
    sm2_public_key: str = ""  # SM2 公钥
    sm2_private_key: str = "" # SM2 私钥
    source: str = ""          # 来源说明
    encrypt_fields: list[str] = field(default_factory=list)  # 哪些字段需要加密


# 全局加密配置存储
_crypto_configs: list[CryptoConfig] = []


def get_configs() -> list[CryptoConfig]:
    return _crypto_configs


def clear_configs():
    _crypto_configs.clear()


async def detect_from_browser() -> dict:
    """检测目标网站是否有前端加密，按需注入 CryptoHook 并读取密钥。

    流程：
    1. 先检查页面流量中是否有加密迹象（非 JSON/表单的 POST body）
    2. 如果有加密迹象 → 注入 CryptoHook inject.js 到页面
    3. 刷新页面，让 hook 拦截加密操作
    4. 等待几秒后读取 hook 到的密钥
    """
    try:
        from core.mcp_bridge import _ensure_browser
        actual = getattr(_ensure_browser, "fn", _ensure_browser)
        page = await actual()

        # Step 1: 先检查插件是否已存在（用户可能手动装了）
        already_hooked = await page.evaluate("""() => {
            return typeof window.__cryptoHook__ !== 'undefined' || typeof window.getKeys === 'function';
        }""")

        if already_hooked:
            log.info("CryptoHook 已存在（用户手动安装或之前已注入）")
        else:
            # Step 2: 检测是否有加密迹象
            has_encryption = await _detect_encryption_signs(page)

            if not has_encryption:
                return {"found": False,
                        "message": "未检测到前端加密迹象（请求均为明文 JSON/表单格式）",
                        "configs": []}

            # Step 3: 注入 CryptoHook
            log.info("检测到加密迹象，注入 CryptoHook...")
            injected = await _inject_crypto_hook(page)
            if not injected:
                return {"found": False,
                        "message": "检测到加密但 CryptoHook inject.js 未找到，无法 hook 密钥。"
                                   "请将 CryptoHook/inject.js 放到项目 crypto_hook/ 目录下，"
                                   "或设置环境变量 CRYPTO_HOOK_PATH",
                        "configs": []}

            # Step 4: 刷新页面让 hook 生效（需要重新触发加密操作）
            import asyncio
            current_url = page.url
            log.info("刷新页面让 hook 生效: %s", current_url[:60])
            await page.reload(wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(3)  # 等待页面 JS 执行加密操作

            # 如果是登录页，可能需要重新触发登录操作才能 hook 到密钥
            # 提示用户或等待 Agent 后续操作

        # Step 5: 读取 hook 到的数据
        hook_data = await page.evaluate("""() => {
            if (typeof window.__cryptoHook__ !== 'undefined') {
                return window.__cryptoHook__.export();
            }
            if (typeof window.getKeys === 'function') {
                return {
                    keys: window.getKeys() || [],
                    ivs: (typeof window.getIVs === 'function') ? window.getIVs() : [],
                    secrets: (typeof window.getSecrets === 'function') ? window.getSecrets() : [],
                    cryptoRecords: (typeof window.getCryptoRecords === 'function') ? window.getCryptoRecords() : [],
                };
            }
            return null;
        }""")

        if not hook_data or (not hook_data.get("keys") and not hook_data.get("secrets")):
            return {"found": False,
                    "message": "CryptoHook 已注入但尚未 hook 到密钥。"
                               "可能需要在页面上执行一次加密操作（如登录、提交表单）后再调用 crypto_detect。",
                    "configs": []}

        # 解析插件数据，转为 CryptoConfig
        configs = _parse_hook_data(hook_data)
        _crypto_configs.clear()
        _crypto_configs.extend(configs)

        log.info("CryptoHook 检测到 %d 个加密配置", len(configs))
        for i, c in enumerate(configs):
            log.info("  [%d] %s key=%s... iv=%s...", i, c.algorithm,
                     c.key_hex[:16] if c.key_hex else "无",
                     c.iv_hex[:16] if c.iv_hex else "无")

        return {
            "found": True,
            "configs": [asdict(c) for c in configs],
            "summary": _build_summary(configs),
            "keys_count": len(hook_data.get("keys", [])),
            "ivs_count": len(hook_data.get("ivs", [])),
            "secrets_count": len(hook_data.get("secrets", [])),
            "records_count": len(hook_data.get("cryptoRecords", [])),
        }

    except Exception as e:
        err_msg = str(e)
        # ★ 区分浏览器缺失和其他异常，给更明确的安装指引
        if "Executable doesn't exist" in err_msg or "browserType" in err_msg.lower():
            install_hint = (
                "Playwright Chromium 未安装。请执行以下命令安装：\n"
                "  python -m playwright install chromium\n"
                "或设置 PLAYWRIGHT_BROWSERS_PATH 环境变量指向已有的 ms-playwright 目录。"
            )
            log.error("CryptoHook 检测失败: 浏览器未安装\n%s", install_hint)
            return {
                "found": False,
                "message": f"浏览器未安装，CryptoHook 检测跳过。{install_hint}",
                "configs": [],
                "error_type": "browser_missing",
            }
        log.warning("CryptoHook 检测失败: %s", e)
        return {"found": False, "message": f"检测失败: {e}", "configs": []}


async def _detect_encryption_signs(page) -> bool:
    """检查页面流量中是否有前端加密的迹象。"""
    try:
        # 方法 1: 检查页面中是否引用了加密库
        has_crypto_lib = await page.evaluate("""() => {
            // 检查常见加密库
            if (typeof CryptoJS !== 'undefined') return 'CryptoJS';
            if (typeof JSEncrypt !== 'undefined') return 'JSEncrypt';
            if (typeof sm2 !== 'undefined' || typeof sm4 !== 'undefined') return 'SM-Crypto';
            if (typeof forge !== 'undefined') return 'Forge';
            if (typeof sjcl !== 'undefined') return 'SJCL';
            
            // 检查全局 window 上的加密相关函数
            const cryptoNames = Object.getOwnPropertyNames(window).filter(n => 
                /encrypt|decrypt|cipher|aes|des|rsa|sm[24]/i.test(n) && typeof window[n] === 'function'
            );
            if (cryptoNames.length > 0) return 'custom:' + cryptoNames.slice(0, 3).join(',');
            
            return null;
        }""")

        if has_crypto_lib:
            log.info("检测到加密库: %s", has_crypto_lib)
            return True

        # 方法 2: 检查最近的 XHR/Fetch 请求中是否有非明文 body
        # （通过 mitmproxy 流量检查）
        try:
            from core.mcp_bridge import _store, _load_new_flows
            _load_new_flows()
            for flow_id in list(_store._order)[-20:]:
                flow = _store.get(flow_id)
                if not flow or flow.method == "GET":
                    continue
                body = flow.request_body or ""
                if body and len(body) > 10:
                    # 非 JSON、非表单 = 可能是加密
                    is_json = body.strip().startswith(("{", "["))
                    is_form = "=" in body and "&" in body
                    if not is_json and not is_form:
                        log.info("检测到疑似加密请求 body: %s %s → body=%s...",
                                 flow.method, flow.url[:50], body[:30])
                        return True
        except Exception:
            pass

        return False
    except Exception:
        return False


async def _inject_crypto_hook(page) -> bool:
    """将 CryptoHook 的 inject.js 注入到当前页面。"""
    import os
    from pathlib import Path

    hook_paths = [
        Path(__file__).parent.parent / "crypto_hook" / "inject.js",  # 项目内
        Path(os.getenv("CRYPTO_HOOK_PATH", "")) / "inject.js",       # 环境变量自定义
    ]

    for hook_path in hook_paths:
        if hook_path.exists():
            try:
                hook_js = hook_path.read_text(encoding="utf-8")
                # 注入到当前页面（立即执行）
                await page.evaluate(hook_js)
                # 同时注册为 init_script（后续页面刷新/跳转也会自动注入）
                await page.context.add_init_script(hook_js)
                log.info("CryptoHook 已注入: %s (%d bytes)", hook_path, len(hook_js))
                return True
            except Exception as e:
                log.warning("CryptoHook 注入失败 (%s): %s", hook_path, e)

    return False


def _parse_hook_data(data: dict) -> list[CryptoConfig]:
    """解析 CryptoHook 插件输出的数据，转为 CryptoConfig 列表。"""
    configs: list[CryptoConfig] = []
    seen: set[str] = set()

    # 从 keys + ivs 组合
    keys = data.get("keys", [])
    ivs = data.get("ivs", [])
    secrets = data.get("secrets", [])

    for key_info in keys:
        key_hex = key_info.get("hex", "") or key_info.get("value", "")
        key_ascii = key_info.get("ascii", "") or key_info.get("text", "")
        algorithm = key_info.get("algorithm", "").upper()
        mode = key_info.get("mode", "").upper()
        padding = key_info.get("padding", "")

        if not key_hex and not key_ascii:
            continue

        # 推断算法
        if not algorithm:
            key_len = len(key_hex) // 2 if key_hex else len(key_ascii)
            if key_len == 16:
                algorithm = "AES"
            elif key_len == 8:
                algorithm = "DES"
            elif key_len == 24:
                algorithm = "AES"  # AES-192 或 3DES
            elif key_len == 32:
                algorithm = "AES"  # AES-256
            else:
                algorithm = "AES"  # 默认

        if not mode:
            mode = "CBC"

        # 匹配 IV
        iv_hex = ""
        iv_ascii = ""
        if ivs:
            iv_info = ivs[0]  # 取第一个 IV（通常一个页面只有一种加密配置）
            iv_hex = iv_info.get("hex", "") or iv_info.get("value", "")
            iv_ascii = iv_info.get("ascii", "") or iv_info.get("text", "")

        dedup_key = f"{algorithm}-{mode}-{key_hex[:16]}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        configs.append(CryptoConfig(
            algorithm=f"{algorithm}-{mode}" if mode else algorithm,
            key_hex=key_hex,
            iv_hex=iv_hex,
            mode=mode,
            padding=padding or "Pkcs7",
            key_ascii=key_ascii,
            iv_ascii=iv_ascii,
            source="CryptoHook",
        ))

    # RSA / SM2 密钥
    for secret in secrets:
        stype = (secret.get("type", "") or "").lower()
        value = secret.get("value", "") or secret.get("key", "")
        if not value:
            continue

        if "rsa" in stype or "public" in stype or "private" in stype:
            config = CryptoConfig(algorithm="RSA", source="CryptoHook")
            if "public" in stype:
                config.rsa_public_key = value
            elif "private" in stype:
                config.rsa_private_key = value
            configs.append(config)

        elif "sm2" in stype:
            config = CryptoConfig(algorithm="SM2", source="CryptoHook")
            if "public" in stype:
                config.sm2_public_key = value
            else:
                config.sm2_private_key = value
            configs.append(config)

        elif "sm4" in stype:
            configs.append(CryptoConfig(
                algorithm="SM4",
                key_hex=value,
                source="CryptoHook",
            ))

    return configs


def _build_summary(configs: list[CryptoConfig]) -> str:
    lines = [f"检测到 {len(configs)} 种加密配置："]
    for i, c in enumerate(configs):
        if "RSA" in c.algorithm:
            has_pub = "✅" if c.rsa_public_key else "❌"
            has_priv = "✅" if c.rsa_private_key else "❌"
            lines.append(f"  [{i}] RSA — 公钥{has_pub} 私钥{has_priv}")
        elif "SM2" in c.algorithm:
            lines.append(f"  [{i}] SM2 — 公钥{'✅' if c.sm2_public_key else '❌'}")
        else:
            key_preview = c.key_hex[:16] + "..." if len(c.key_hex) > 16 else c.key_hex
            iv_preview = c.iv_hex[:16] + "..." if c.iv_hex else "无"
            lines.append(f"  [{i}] {c.algorithm} — Key: {key_preview}, IV: {iv_preview}, Padding: {c.padding}")
    lines.append("\n子 Agent 可调用 crypto_encrypt / crypto_decrypt 对 payload 加解密。")
    return "\n".join(lines)


def encrypt(plaintext: str, config_index: int = 0) -> dict:
    """用指定加密配置加密明文。返回 {"success": bool, "ciphertext": str, "format": "base64/hex"}。"""
    if not _crypto_configs:
        return {"success": False, "error": "未检测到加密配置，请先调用 crypto_detect"}
    if config_index >= len(_crypto_configs):
        return {"success": False, "error": f"配置索引 {config_index} 不存在，共 {len(_crypto_configs)} 个配置"}

    config = _crypto_configs[config_index]
    try:
        algo = config.algorithm.upper()

        if "AES" in algo:
            return _aes_encrypt(plaintext, config)
        elif "DES" in algo:
            return _des_encrypt(plaintext, config)
        elif "SM4" in algo:
            return _sm4_encrypt(plaintext, config)
        elif "RSA" in algo:
            return _rsa_encrypt(plaintext, config)
        else:
            return {"success": False, "error": f"不支持的算法: {algo}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def decrypt(ciphertext: str, config_index: int = 0) -> dict:
    """用指定加密配置解密密文。返回 {"success": bool, "plaintext": str}。"""
    if not _crypto_configs:
        return {"success": False, "error": "未检测到加密配置，请先调用 crypto_detect"}
    if config_index >= len(_crypto_configs):
        return {"success": False, "error": f"配置索引 {config_index} 不存在"}

    config = _crypto_configs[config_index]
    try:
        algo = config.algorithm.upper()

        if "AES" in algo:
            return _aes_decrypt(ciphertext, config)
        elif "DES" in algo:
            return _des_decrypt(ciphertext, config)
        elif "SM4" in algo:
            return _sm4_decrypt(ciphertext, config)
        elif "RSA" in algo:
            return _rsa_decrypt(ciphertext, config)
        else:
            return {"success": False, "error": f"不支持的算法: {algo}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---- AES ----

def _get_key_iv_bytes(config: CryptoConfig) -> tuple[bytes, bytes | None]:
    """从 hex 或 ascii 获取 key/iv 的 bytes。"""
    if config.key_hex:
        key = bytes.fromhex(config.key_hex)
    elif config.key_ascii:
        key = config.key_ascii.encode("utf-8")
    else:
        raise ValueError("无密钥")

    iv = None
    if "ECB" not in config.mode.upper():
        if config.iv_hex:
            iv = bytes.fromhex(config.iv_hex)
        elif config.iv_ascii:
            iv = config.iv_ascii.encode("utf-8")

    return key, iv


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len > len(data) or pad_len == 0:
        return data
    if all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len]
    return data


def _aes_encrypt(plaintext: str, config: CryptoConfig) -> dict:
    from Crypto.Cipher import AES
    key, iv = _get_key_iv_bytes(config)
    mode_str = config.mode.upper() if config.mode else "CBC"

    mode_map = {"CBC": AES.MODE_CBC, "ECB": AES.MODE_ECB,
                "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB, "CTR": AES.MODE_CTR}
    aes_mode = mode_map.get(mode_str, AES.MODE_CBC)

    data = _pkcs7_pad(plaintext.encode("utf-8"), AES.block_size)

    if aes_mode == AES.MODE_ECB:
        cipher = AES.new(key, aes_mode)
    elif aes_mode == AES.MODE_CTR:
        cipher = AES.new(key, aes_mode, nonce=iv[:8] if iv else b'\x00' * 8)
        data = plaintext.encode("utf-8")  # CTR 不需要 padding
    else:
        cipher = AES.new(key, aes_mode, iv=iv)

    encrypted = cipher.encrypt(data)
    return {"success": True, "ciphertext": base64.b64encode(encrypted).decode(),
            "ciphertext_hex": encrypted.hex(), "format": "base64"}


def _aes_decrypt(ciphertext: str, config: CryptoConfig) -> dict:
    from Crypto.Cipher import AES
    key, iv = _get_key_iv_bytes(config)
    mode_str = config.mode.upper() if config.mode else "CBC"

    mode_map = {"CBC": AES.MODE_CBC, "ECB": AES.MODE_ECB,
                "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB, "CTR": AES.MODE_CTR}
    aes_mode = mode_map.get(mode_str, AES.MODE_CBC)

    # 尝试 base64 解码，失败则尝试 hex
    try:
        data = base64.b64decode(ciphertext)
    except Exception:
        data = bytes.fromhex(ciphertext)

    if aes_mode == AES.MODE_ECB:
        cipher = AES.new(key, aes_mode)
    elif aes_mode == AES.MODE_CTR:
        cipher = AES.new(key, aes_mode, nonce=iv[:8] if iv else b'\x00' * 8)
    else:
        cipher = AES.new(key, aes_mode, iv=iv)

    decrypted = cipher.decrypt(data)
    if aes_mode != AES.MODE_CTR:
        decrypted = _pkcs7_unpad(decrypted)

    return {"success": True, "plaintext": decrypted.decode("utf-8", errors="replace")}


# ---- DES ----

def _des_encrypt(plaintext: str, config: CryptoConfig) -> dict:
    from Crypto.Cipher import DES
    key, iv = _get_key_iv_bytes(config)
    data = _pkcs7_pad(plaintext.encode("utf-8"), DES.block_size)
    if "ECB" in config.mode.upper():
        cipher = DES.new(key[:8], DES.MODE_ECB)
    else:
        cipher = DES.new(key[:8], DES.MODE_CBC, iv=iv[:8] if iv else b'\x00' * 8)
    encrypted = cipher.encrypt(data)
    return {"success": True, "ciphertext": base64.b64encode(encrypted).decode(), "format": "base64"}


def _des_decrypt(ciphertext: str, config: CryptoConfig) -> dict:
    from Crypto.Cipher import DES
    key, iv = _get_key_iv_bytes(config)
    try:
        data = base64.b64decode(ciphertext)
    except Exception:
        data = bytes.fromhex(ciphertext)
    if "ECB" in config.mode.upper():
        cipher = DES.new(key[:8], DES.MODE_ECB)
    else:
        cipher = DES.new(key[:8], DES.MODE_CBC, iv=iv[:8] if iv else b'\x00' * 8)
    decrypted = _pkcs7_unpad(cipher.decrypt(data))
    return {"success": True, "plaintext": decrypted.decode("utf-8", errors="replace")}


# ---- SM4（国密）----

def _sm4_encrypt(plaintext: str, config: CryptoConfig) -> dict:
    try:
        from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    except ImportError:
        return {"success": False, "error": "需要安装 gmssl: pip install gmssl"}
    key, iv = _get_key_iv_bytes(config)
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_ENCRYPT)
    data = _pkcs7_pad(plaintext.encode("utf-8"), 16)
    encrypted = sm4.crypt_ecb(data) if "ECB" in config.mode.upper() else sm4.crypt_cbc(iv or b'\x00' * 16, data)
    return {"success": True, "ciphertext": base64.b64encode(encrypted).decode(), "format": "base64"}


def _sm4_decrypt(ciphertext: str, config: CryptoConfig) -> dict:
    try:
        from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    except ImportError:
        return {"success": False, "error": "需要安装 gmssl"}
    key, iv = _get_key_iv_bytes(config)
    try:
        data = base64.b64decode(ciphertext)
    except Exception:
        data = bytes.fromhex(ciphertext)
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_DECRYPT)
    decrypted = sm4.crypt_ecb(data) if "ECB" in config.mode.upper() else sm4.crypt_cbc(iv or b'\x00' * 16, data)
    return {"success": True, "plaintext": _pkcs7_unpad(decrypted).decode("utf-8", errors="replace")}


# ---- RSA ----

def _rsa_encrypt(plaintext: str, config: CryptoConfig) -> dict:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    if not config.rsa_public_key:
        return {"success": False, "error": "无 RSA 公钥"}
    key = RSA.import_key(config.rsa_public_key)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(plaintext.encode("utf-8"))
    return {"success": True, "ciphertext": base64.b64encode(encrypted).decode(), "format": "base64"}


def _rsa_decrypt(ciphertext: str, config: CryptoConfig) -> dict:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    if not config.rsa_private_key:
        return {"success": False, "error": "无 RSA 私钥（需要私钥才能解密）"}
    key = RSA.import_key(config.rsa_private_key)
    cipher = PKCS1_v1_5.new(key)
    try:
        data = base64.b64decode(ciphertext)
    except Exception:
        data = bytes.fromhex(ciphertext)
    decrypted = cipher.decrypt(data, sentinel=b"DECRYPTION_FAILED")
    if decrypted == b"DECRYPTION_FAILED":
        return {"success": False, "error": "RSA 解密失败"}
    return {"success": True, "plaintext": decrypted.decode("utf-8", errors="replace")}
