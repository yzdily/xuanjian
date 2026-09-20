"""附件文本抽取（零外部依赖，仅 stdlib）。

用途
----
用户在终端「＋ → 上传文件」上传的文档（word / xlsx / json / txt / html / burp），
需要转成文本喂给 LLM 作为任务上下文。本模块只做**抽取**，不做请求、不碰 LLM。

设计约束（沿用项目红线）
------------------------
1. **零外部依赖**：docx / xlsx 本质是 zip + XML，用 `zipfile` + 正则剥离标签即可，
   不引入 python-docx / openpyxl。
2. **预算保护**：抽取结果有单文件与总量上限（默认 2MB / 20k 字符），
   超出截断并显式标注 —— 因为下游 `core/context.py` 有 token 预算硬拦截（D14），
   附件文本必须受限，否则会挤掉扫描样本。
3. **路径白名单**：只允许读取 `data/uploads/` 目录内的文件（防路径穿越）——
   路径由前端传入，属于不可信输入。
4. **失败可解释**：抽不出来时返回原因（旧版 .doc/.xls 是二进制格式，无法可靠抽取），
   绝不静默产出空上下文。
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from core.log import get_logger
from web._security import PROJECT_ROOT

log = get_logger("core.attachments")

UPLOAD_DIR = PROJECT_ROOT / "data" / "uploads"

MAX_FILE_BYTES = 2 * 1024 * 1024       # 单文件读取上限 2MB（上传端点侧另有 10MB 硬限）
MAX_TOTAL_CHARS = 20_000               # 拼进上下文的总字符上限
MAX_PER_FILE_CHARS = 12_000            # 单文件字符上限

# ★ 与上传端点白名单保持一致（用户 0919 指定：json/txt/word/html/burp/xlsx/excel + 图片）
TEXT_EXT = {".txt", ".json", ".burp", ".log", ".md", ".csv"}
HTML_EXT = {".html", ".htm"}
DOCX_EXT = {".docx"}
XLSX_EXT = {".xlsx"}
LEGACY_OFFICE_EXT = {".doc", ".xls"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

ALL_ALLOWED_EXT = TEXT_EXT | HTML_EXT | DOCX_EXT | XLSX_EXT | LEGACY_OFFICE_EXT | IMAGE_EXT

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_WS_RE = re.compile(r"[ \t\u00a0]+")


# ================================================================
# 安全：路径必须落在 data/uploads/ 内
# ================================================================
def resolve_upload_path(raw: str) -> tuple[Path | None, str]:
    """把前端传来的路径解析为**白名单目录内**的真实路径。

    返回 `(path, error)`；path 为 None 时 error 说明原因。

    防线（三层）：
    1. 去掉 URL 编码与首尾空白（`%2e%2e%2f` 这类绕过）；
    2. `resolve()` 后再比对是否在 `data/uploads/` 之内（防 `../` 与符号链接）；
    3. 只接受已存在的**文件**（不是目录、不是设备节点）。
    """
    if not raw or not isinstance(raw, str):
        return None, "路径为空"
    candidate = unquote(raw.strip()).replace("\\", "/")

    # 允许前端传绝对路径或相对路径（相对按项目根解析）
    p = Path(candidate)
    if not p.is_absolute():
        p = PROJECT_ROOT / candidate
    try:
        resolved = p.resolve()
    except Exception as exc:                       # 非法路径（如 Windows 保留名）
        return None, f"路径非法: {exc}"

    root = UPLOAD_DIR.resolve()
    if resolved != root and root not in resolved.parents:
        return None, "路径不在允许的上传目录内（data/uploads/）"
    if not resolved.is_file():
        return None, "文件不存在"
    return resolved, ""


# ================================================================
# 各类型抽取
# ================================================================
def _read_text_file(path: Path) -> str:
    raw = path.read_bytes()[:MAX_FILE_BYTES]
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", "replace")
    if path.suffix.lower() == ".json":
        try:                                       # JSON 格式化，便于 LLM 读结构
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except Exception:
            return text
    return text


def _strip_html(text: str) -> str:
    text = _SCRIPT_RE.sub(" ", text)
    text = _TAG_RE.sub(" ", text)
    return _WS_RE.sub(" ", text)


def _extract_ooxml(path: Path, member_prefix: str) -> str:
    """从 docx/xlsx 里抽纯文本（zip + XML 剥标签，零依赖）。

    ⚠️ 必须防御 zip 炸弹：只读白名单成员，并限制解压后总字节数。
    """
    parts: list[str] = []
    total = 0
    try:
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist()
                     if n.startswith(member_prefix) and n.endswith(".xml")]
            if not names:
                return ""
            for name in sorted(names)[:40]:        # 最多 40 个成员，防跑飞
                info = zf.getinfo(name)
                if info.file_size > MAX_FILE_BYTES:
                    continue
                raw = zf.read(name)[:MAX_FILE_BYTES]
                total += len(raw)
                if total > MAX_FILE_BYTES * 2:
                    break
                parts.append(_strip_html(raw.decode("utf-8", "replace")))
    except zipfile.BadZipFile:
        return ""
    text = " ".join(parts)
    # OOXML 里每个文本片段都在 <w:t>/<t> 中，剥标签后可能粘连；按多空格切一下
    return "\n".join(seg.strip() for seg in _WS_RE.sub(" ", text).split("  ") if seg.strip())


def extract_attachment(path: Path) -> dict[str, Any]:
    """抽取单个附件文本。

    Returns:
        {"path","filename","kind","text","chars","truncated","error"}
        kind: document | image | unsupported
    """
    ext = path.suffix.lower()
    base = {
        "path": str(path),
        "filename": path.name,
        "chars": 0, "truncated": False, "error": "", "text": "",
    }

    if ext in IMAGE_EXT:
        # 图片不作为文本附件（走 screenshot_paths 视觉通道）
        return {**base, "kind": "image",
                "error": "图片请走截图通道（screenshot_paths），不作为文本附件"}

    if ext in LEGACY_OFFICE_EXT:
        return {**base, "kind": "unsupported",
                "error": f"{ext} 是旧版二进制格式，无法可靠抽取文本；请另存为 .docx / .xlsx"}

    if ext not in ALL_ALLOWED_EXT:
        return {**base, "kind": "unsupported", "error": f"不支持的文件类型: {ext}"}

    try:
        if ext in TEXT_EXT:
            text = _read_text_file(path)
        elif ext in HTML_EXT:
            text = _strip_html(_read_text_file(path))
        elif ext in DOCX_EXT:
            text = _extract_ooxml(path, "word/")
        else:                                       # XLSX
            text = _extract_ooxml(path, "xl/")
    except Exception as exc:
        log.warning("附件抽取失败 %s: %s", path, exc)
        return {**base, "kind": "document", "error": f"抽取失败: {type(exc).__name__}"}

    text = text.strip()
    if not text:
        return {**base, "kind": "document", "error": "抽取结果为空（文件可能是扫描件/加密文档）"}

    truncated = False
    if len(text) > MAX_PER_FILE_CHARS:
        text = text[:MAX_PER_FILE_CHARS]
        truncated = True
    return {**base, "kind": "document", "text": text,
            "chars": len(text), "truncated": truncated}


def build_attachment_block(raw_paths: list[str]) -> tuple[str, list[dict[str, Any]]]:
    """把一组上传文件转成可直接拼进 user_message 的上下文块。

    Returns:
        (block_text, meta_list) —— block_text 为空表示没有可用附件（meta 里带原因）
    """
    metas: list[dict[str, Any]] = []
    chunks: list[str] = []
    used = 0

    for raw in raw_paths or []:
        path, err = resolve_upload_path(raw)
        if path is None:
            metas.append({"path": raw, "error": err, "kind": "rejected"})
            continue
        info = extract_attachment(path)
        metas.append({k: v for k, v in info.items() if k != "text"})
        if info.get("kind") != "document" or not info.get("text"):
            continue
        room = MAX_TOTAL_CHARS - used
        if room <= 0:
            metas[-1]["error"] = "已达附件上下文总量上限，后续附件被忽略"
            continue
        text = info["text"][:room]
        if len(text) < len(info["text"]):
            metas[-1]["truncated"] = True
        used += len(text)
        chunks.append(
            f"### 附件：{info['filename']}（{info['chars']} 字符"
            f"{'，已截断' if metas[-1].get('truncated') else ''}）\n{text}"
        )

    if not chunks:
        return "", metas
    block = "【用户上传的附件内容】\n" + "\n\n".join(chunks) + "\n【附件内容结束】"
    return block, metas


__all__ = [
    "ALL_ALLOWED_EXT", "UPLOAD_DIR", "extract_attachment",
    "build_attachment_block", "resolve_upload_path",
]
