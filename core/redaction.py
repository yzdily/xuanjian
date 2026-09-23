"""去标识化（脱敏）工具 —— 交付物与知识库回流前的最后一道闸。

★ 项目铁律：报告 / 日志 / 笔记 / 知识库回流**不得**出现真实客户名、
内网 IP、账号口令。0923 实测违规一次：``data/notes/task_1790149459_b5c238-info.md``
含真实客户名「中信百信银行」。

设计取舍：
- 只做**确定性命中**（别名表 + 正则），不引入 LLM 调用 —— 否则又添一个 429 面，
  且脱敏本身不能"猜"。
- 大小写/空白容错，避免 ``中信百信银行`` 与 ``中信百信 银行`` 漏网。
- 幂等：重复调用不会把 ``<客户机构>`` 再替换一层。
"""

from __future__ import annotations

import re

# ============================================================
# 1. 机构别名表（真实名称 → 占位符）
# ============================================================
# 说明：这里登记的是"已确认出现在项目产物里的真实机构名"。
# 新增时按 `真实名: 占位符` 追加即可，无需改逻辑。
ORG_ALIASES: dict[str, str] = {
    "中信百信银行": "客户机构",
    "百信银行": "客户机构",
    "中信银行": "客户机构",
}

# 占位符（统一措辞，便于检索）
PH_ORG = "<客户机构>"
PH_INTERNAL_IP = "<内网IP>"
PH_SECRET = "<REDACTED>"
PH_EMAIL = "<邮箱>"
PH_PHONE = "<手机号>"

# ============================================================
# 2. 正则规则
# ============================================================
# 私有网段（RFC1918 + 常见容器网段）
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.0\.0\.1)\b"
)

# 凭据类：`key: value` / `key=value` 形式
#
# ★ 值部分**必须排除引号与反斜杠**（`[^\s,;|"']` / 不含 `\`）。
#   0923 教训：第一版写成 `[^\s,;|]{8,}`，会把 JSON 字符串的收尾引号
#   （甚至 `\"` 转义、后续 `},` 结构）一起吞掉，直接破坏
#   `data/tasks/*-sitemap.json` 的 JSON 结构（14 个文件因此无法解析）。
#   脱敏工具绝不能吃掉结构字符 —— 这是硬约束。
_SECRET_VALUE_CLS = r"[^\s,;|\"'\\]{8,}"
_SECRET_KV_RE = re.compile(
    r"(?i)\b("
    r"authorization|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"secret|password|passwd|pwd|cookie|set-cookie|session[_-]?id|jwt"
    r")\b(\s*[:=]\s*)("
    r"\"[^\"\\\n]{6,}\""          # 双引号包裹（不允许内含未转义引号/换行）
    r"|'[^'\\\n]{6,}'"            # 单引号包裹
    rf"|{_SECRET_VALUE_CLS}"      # 裸值
    r")"
)

# Bearer / Basic 令牌
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{16,}")

# JWT（三段式）
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")

# 邮箱 / 手机号
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


def _sub_org(text: str) -> str:
    """替换机构别名（去空白容错 + 幂等）。"""
    out = text
    for real, _ph in ORG_ALIASES.items():
        if not real:
            continue
        # 允许字间出现空白：中信百信银行 / 中信百信 银行
        _pat = r"\s*".join(re.escape(ch) for ch in real)
        out = re.sub(_pat, PH_ORG, out)
    return out


def redact_text(text: str, *, extra_aliases: dict[str, str] | None = None) -> str:
    """对任意文本做去标识化。

    Args:
        text: 待脱敏文本；``None``/空串原样返回。
        extra_aliases: 调用方补充的 ``真实名 -> 占位符``（如本次任务的客户名）。

    Returns:
        脱敏后的文本。保证**幂等**：对已脱敏文本再次调用不产生变化。

    Examples:
        >>> redact_text("目标为「中信百信银行企业网银系统」")
        '目标为「<客户机构>企业网银系统」'
        >>> redact_text("db=10.0.0.5 authorization: Bearer abcdefghijklmnopqrst")
        'db=<内网IP> authorization: <REDACTED>'
    """
    if not text:
        return text
    out = str(text)

    # 1) 机构名（先做，避免其内部含数字被后续规则误伤）
    out = _sub_org(out)
    for real, ph in (extra_aliases or {}).items():
        if real:
            _pat = r"\s*".join(re.escape(ch) for ch in real)
            out = re.sub(_pat, ph or PH_ORG, out)

    # 2) 内网 IP（占位符本身不含数字，天然幂等）
    out = _INTERNAL_IP_RE.sub(PH_INTERNAL_IP, out)

    # 3) 凭据
    out = _JWT_RE.sub(PH_SECRET, out)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} {PH_SECRET}", out)
    out = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{PH_SECRET}", out)
    out = _EMAIL_RE.sub(PH_EMAIL, out)
    out = _PHONE_RE.sub(PH_PHONE, out)

    return out


def redact_file(path, *, extra_aliases: dict[str, str] | None = None,
                dry_run: bool = False, json_safe: bool = False) -> tuple[bool, str]:
    """对单个文本文件就地脱敏。

    Args:
        path: 文件路径（``str`` / ``Path``）。
        extra_aliases: 同 :func:`redact_text`。
        dry_run: True 时只计算不写盘。
        json_safe: True 时要求替换后仍是合法 JSON；若脱敏会导致解析失败则
            **放弃写入**并返回 ``changed=False``。处理 ``*.json`` 必须开启。

    Returns:
        ``(changed, message)``。``changed=False`` 表示无需改动或安全校验未通过。
    """
    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        return False, f"文件不存在: {p}"
    try:
        # ★ newline="" 关闭换行翻译：避免读写往返把裸 CR 变成 CRLF，
        #   进而破坏 JSON 字符串内的控制字符语义。
        # ★ 兼容性（0923 补）：``Path.read_text(newline=...)`` 是 Python 3.13+
        #   才有的参数，而本仓 ``requires-python = ">=3.10"``（本机 venv 为 3.11）
        #   → 直接用 read_text 会 TypeError，被下面 except 吞成"读取失败"，
        #   导致脱敏静默失效。必须走 open()。
        with open(p, "r", encoding="utf-8", newline="") as _f:
            original = _f.read()
    except Exception as e:
        return False, f"读取失败: {p}: {e}"
    redacted = redact_text(original, extra_aliases=extra_aliases)
    if redacted == original:
        return False, f"无需改动: {p}"

    if json_safe or p.suffix.lower() == ".json":
        import json as _json
        try:
            _json.loads(original)
        except Exception:
            return False, f"跳过（原文件已不是合法 JSON，避免二次破坏）: {p}"
        try:
            _json.loads(redacted)
        except Exception as e:
            return False, f"跳过（脱敏会破坏 JSON 结构: {e}）: {p}"

    if dry_run:
        return True, f"（dry-run）将修改: {p}"
    try:
        p.write_text(redacted, encoding="utf-8", newline="")
    except Exception as e:
        return False, f"写入失败: {p}: {e}"
    return True, f"已脱敏: {p}"
