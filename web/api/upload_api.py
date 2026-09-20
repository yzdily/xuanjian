"""附件上传 API（阶段 2 · 把"已实现但前端零调用"的上传能力真正接上）。

为什么单独建端点而不复用 `/api/screenshot/upload`
--------------------------------------------------
`screenshot/upload` 的语义是**截图**（它的产物会被 `/api/focused-test/screenshot`
当作视觉输入走截图测试流程），它的白名单也只有图片。往里塞 .docx 会让
"截图通道"语义漂移。所以：
- 图片 → 仍走 `/api/screenshot/upload`（前端按类型分派，原样不动）
- 图片 + 文档 → 走本端点 `/api/upload/attachment`

安全约束（全部落实）
--------------------
1. 扩展名白名单（用户 0919 指定）：`json / txt / word(doc,docx) / html / burp / xlsx(xls) / 图片`
2. 大小硬限 10MB（与既有上传端点一致）；抽取侧另有 2MB 读取限
3. **文件名净化**：只取 basename + uuid 前缀，杜绝 `../`、盘符、控制字符
4. 落盘目录固定 `data/uploads/`（与既有端点同目录），永不接受前端指定目录
5. 不解析宏/外链（.doc/.xls 只落盘，抽取时明确拒绝）
"""
from __future__ import annotations

import re
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.attachments import ALL_ALLOWED_EXT, UPLOAD_DIR
from core.log import get_logger
from web._security import PROJECT_ROOT
from web._paths import move_to_trash

log = get_logger("web.upload_api")

router = APIRouter()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FILES_PER_REQUEST = 10
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff-]+")

# ★ 附件孤儿清理：路径统一从 web._security.PROJECT_ROOT 单源拼出。
TASKS_DIR = PROJECT_ROOT / "data" / "tasks"
# ⚠️ 回收区固定 data/_trash/（禁止落在 data/reports/ 或 data/tasks/ 内，见 IMPACT R3）。
TRASH_DIR = PROJECT_ROOT / "data" / "_trash"
DEFAULT_CLEANUP_DAYS = 7


def _chat_blob() -> str:
    """把所有会话 chat.jsonl 拼成一段文本，用于"文件名是否被引用"的轻量包含检查。

    刻意不解析 JSON（chat 文件可能很大），只做字符串包含 —— 判定只需"出现过"。
    """
    if not TASKS_DIR.exists():
        return ""
    parts: list[str] = []
    for f in TASKS_DIR.glob("*-chat.jsonl"):
        try:
            parts.append(f.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            log.warning("读取 chat 历史失败 %s: %s", f, exc)
    return "\n".join(parts)


def _safe_filename(original: str, ext: str) -> str:
    """净化文件名：仅保留可读字符 + uuid 前缀（防覆盖、防穿越）。

    中文文件名保留（用户习惯），但去掉路径分隔符、控制字符与其余符号。
    """
    stem = Path(original or "").name                 # 先砍掉任何路径成分
    stem = stem.rsplit(".", 1)[0] if "." in stem else stem
    stem = _SAFE_NAME_RE.sub("_", stem).strip("._-")[:48] or "file"
    return f"{uuid.uuid4().hex[:8]}_{stem}{ext}"


@router.post("/api/upload/attachment")
async def upload_attachment(request: Request):
    """接收用户上传的附件（图片 / 文档），返回服务器路径供 chat 引用。"""
    content_type = request.headers.get("content-type", "")
    if "multipart" not in content_type:
        return JSONResponse(status_code=400,
                            content={"error": "请使用 multipart/form-data 上传"})

    content_length = request.headers.get("content-length", "")
    if content_length and content_length.isdigit() and int(content_length) > MAX_UPLOAD_BYTES * 11:
        # 多文件合计的粗粒度前置拦截（单文件在下面对每个 file 精确判定）
        return JSONResponse(status_code=413, content={"error": "上传内容过大"})

    form = await request.form()
    files = [f for key, f in form.multi_items() if key == "file"]
    if not files:
        return JSONResponse(status_code=400, content={"error": "未找到 file 字段"})
    if len(files) > MAX_FILES_PER_REQUEST:
        return JSONResponse(status_code=400,
                            content={"error": f"单次最多上传 {MAX_FILES_PER_REQUEST} 个文件"})

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    accepted: list[dict] = []
    rejected: list[dict] = []

    for f in files:
        original = getattr(f, "filename", "") or ""
        ext = Path(original).suffix.lower()
        if ext not in ALL_ALLOWED_EXT:
            rejected.append({
                "filename": original,
                "reason": f"不支持的文件类型 {ext or '(无扩展名)'}",
                "allowed": sorted(ALL_ALLOWED_EXT),
            })
            continue

        data = await f.read()
        if len(data) > MAX_UPLOAD_BYTES:
            rejected.append({"filename": original, "reason": "文件超过 10MB"})
            continue
        if not data:
            rejected.append({"filename": original, "reason": "文件为空"})
            continue

        name = _safe_filename(original, ext)
        dest = UPLOAD_DIR / name
        try:
            dest.write_bytes(data)
        except Exception as exc:
            log.warning("上传落盘失败 %s: %s", name, exc)
            rejected.append({"filename": original, "reason": f"写入失败: {type(exc).__name__}"})
            continue

        from core.attachments import IMAGE_EXT
        accepted.append({
            "path": str(dest),
            "filename": name,
            "original": original,
            "ext": ext,
            "size": len(data),
            "kind": "image" if ext in IMAGE_EXT else "document",
            # 前端据此分派：图片 → chat.screenshot_paths，文档 → chat.file_paths
            "channel": "screenshot_paths" if ext in IMAGE_EXT else "file_paths",
        })

    if accepted:
        log.info("附件上传成功 %d 个：%s", len(accepted), [a["filename"] for a in accepted])
    return {"files": accepted, "rejected": rejected,
            "upload_dir": str(UPLOAD_DIR)}


@router.get("/api/upload/allowed")
async def allowed_types():
    """返回允许的扩展名（前端 `＋` 菜单与校验用，避免前后端白名单漂移）。"""
    from core.attachments import (DOCX_EXT, HTML_EXT, IMAGE_EXT,
                                  LEGACY_OFFICE_EXT, TEXT_EXT, XLSX_EXT)
    return {
        "allowed": sorted(ALL_ALLOWED_EXT),
        "image": sorted(IMAGE_EXT),          # 走 screenshot_paths
        "document": sorted(TEXT_EXT | HTML_EXT | DOCX_EXT | XLSX_EXT | LEGACY_OFFICE_EXT),
        "max_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        "max_files": MAX_FILES_PER_REQUEST,
    }


@router.post("/api/upload/cleanup")
async def cleanup_uploads(request: Request):
    """清理 `data/uploads/` 里的附件孤儿。

    ★ 默认 dry-run：只返回"将被清理"的列表（文件名 / 大小 / mtime / 原因），
      不删任何东西；真删必须显式传 ``{"dry_run": false, "confirm": true}``。
    判定：mtime 超过 N 天（默认 7，可传 ``days`` 覆盖）**且**文件名未出现在任何
    ``data/tasks/*-chat.jsonl`` 里（轻量字符串包含，不解析 JSON）。真删同样先移入
    ``data/_trash/``。返回体含 ``total_bytes``（可回收空间）。
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    days = body.get("days", DEFAULT_CLEANUP_DAYS)
    try:
        days = float(days)
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "days 必须是数字"})
    if days < 0:
        return JSONResponse(status_code=400, content={"error": "days 不能为负数"})

    dry_run = bool(body.get("dry_run", True))
    confirm = bool(body.get("confirm", False))

    cutoff = time.time() - days * 86400
    ref_text = _chat_blob()
    candidates: list[dict] = []
    if UPLOAD_DIR.exists():
        for f in sorted(UPLOAD_DIR.iterdir()):
            if not f.is_file():
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            if st.st_mtime >= cutoff:
                continue
            if f.name in ref_text:                      # 被会话引用过 → 保留
                continue
            candidates.append({
                "filename": f.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "reason": f"超过 {days:g} 天未修改，且未被任何会话 chat 历史引用",
            })

    total_bytes = sum(c["size"] for c in candidates)
    result = {
        "status": "ok",
        "dry_run": dry_run,
        "days": days,
        "candidates": candidates,
        "count": len(candidates),
        "removed": 0,
        "total_bytes": total_bytes,
        "trashed_dir": "",
    }

    if dry_run:
        return result

    if not confirm:
        return JSONResponse(
            status_code=400,
            content={
                "error": "真删需要显式 confirm=true（建议先 dry_run 确认列表）",
                "candidates": candidates,
                "total_bytes": total_bytes,
            },
        )

    trashed_dir = move_to_trash([UPLOAD_DIR / c["filename"] for c in candidates], TRASH_DIR)
    result["trashed_dir"] = trashed_dir
    result["removed"] = len(candidates)
    log.info("附件清理: removed=%d bytes=%d trash=%s",
             result["removed"], total_bytes, trashed_dir or "(无)")
    return result
