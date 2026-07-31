"""
系统类 API：健康检查 + 扫描结果持久化查询 + 批量目标管理。

URL 保持不变：/api/health, /api/scans*
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
import uuid
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import JSONResponse

from core.log import get_logger
from web._state import get_session

router = APIRouter()
log = get_logger("web.system_api")


@router.get("/api/health")
async def health():
    checks = {}
    try:
        session = get_session()
        if session.llm:
            checks["llm"] = {"ok": True, "model": session.llm.config.model, "provider": session.llm.config.provider}
        else:
            checks["llm"] = {"ok": False, "error": "未配置 LLM（fast/无 LLM 模式可用）"}
    except Exception as e:
        checks["llm"] = {"ok": False, "error": str(e)}

    proxy_url = os.getenv("BROWSER_PROXY", "http://127.0.0.1:8080")
    try:
        import asyncio
        import urllib.parse
        parsed = urllib.parse.urlparse(proxy_url)
        proxy_host = parsed.hostname or "127.0.0.1"
        proxy_port = parsed.port or 8080
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        checks["proxy"] = {"ok": True, "url": proxy_url}
    except Exception:
        checks["proxy"] = {"ok": False, "url": proxy_url}

    try:
        import playwright  # noqa: F401
        checks["browser"] = {"ok": True}
    except Exception:
        checks["browser"] = {"ok": False}

    skills_root = Path(os.getenv("SKILLS_MY_PATH", "./skills_my"))
    all_skills = list(skills_root.rglob("SKILL.md"))
    skill_count = len(all_skills)
    playbook_count = len([p for p in all_skills if "scenario" in p.parts])
    checks["knowledge"] = {"ok": True, "skills": skill_count, "playbooks": playbook_count}

    return {"healthy": all(c.get("ok") for c in checks.values()), "checks": checks}


# ================================================================
# Scan Store API（扫描结果持久化查询）
# ================================================================

# ★ 注意路由先后顺序：/api/scans/stats 必须在 /api/scans/{task_id} 之前注册，
# 否则 "stats" 会被当作 task_id 匹配到详情接口。

@router.get("/api/scans")
async def list_scans(limit: int = 50, status: str = ""):
    """列出所有扫描记录。"""
    from core.scan_store import list_scans as _list
    return {"scans": _list(limit=limit, status=status or None)}


@router.get("/api/scans/stats")
async def get_scan_stats():
    """获取全局扫描统计。"""
    from core.scan_store import get_stats
    return get_stats()


@router.get("/api/scans/{task_id}")
async def get_scan_detail(task_id: str):
    """获取单条扫描详情（含漏洞列表）。"""
    from core.scan_store import get_scan as _get, get_vulns as _vulns
    scan = _get(task_id)
    if not scan:
        return {"error": f"扫描不存在: {task_id}"}
    scan["vulns"] = _vulns(task_id)
    return scan


@router.get("/api/vulns")
async def list_all_vulns(limit: int = 200, severity: str = ""):
    """★ 获取所有扫描的漏洞列表（聚合，按时间倒序）。

    供前端漏洞页面加载历史漏洞使用。关联 scans 表获取 target。
    """
    from core.scan_store import list_all_vulns as _list_all
    vulns = _list_all(limit=limit, severity=severity or None)
    return {"vulns": vulns, "count": len(vulns)}


# ================================================================
# 扫描策略 API
# ================================================================

@router.get("/api/scan-strategies")
async def list_scan_strategies():
    """列出可用的扫描策略。"""
    from core.scan_strategies import ScanMode, ScanConfig
    strategies = []
    for mode in ScanMode:
        cfg = ScanConfig.from_mode(mode)
        strategies.append({
            "mode": mode.value,
            "label": {
                "fast": "快速扫描",
                "standard": "标准扫描",
                "deep": "深度扫描",
                "smart": "智能扫描",
            }.get(mode.value, mode.value),
            "description": {
                "fast": "仅本地规则引擎，不走 LLM，速度最快（约2-5分钟）",
                "standard": "本地规则 + LLM 分析，平衡速度和深度（约10-30分钟）",
                "deep": "本地规则 + 完整 LLM 流程，最深度（约30-120分钟）",
                "smart": "根据目标特征自动选择策略",
            }.get(mode.value, ""),
            "config": cfg.to_dict(),
        })
    return {"strategies": strategies}


# ================================================================
# 批量目标管理 API
# ================================================================

@router.post("/api/targets/batch")
async def batch_add_targets(request: Request):
    """批量添加扫描目标。

    支持两种格式：
    1. JSON 数组: [{"url": "http://1.1.1.1", "name": "目标1", "auth_type": "none"}, ...]
    2. 纯文本（每行一个URL）: http://1.1.1.1\nhttp://2.2.2.2
    3. CSV 文本: name,url,auth_type,cookie\n目标1,http://1.1.1.1,none,
    """
    import csv
    import io
    import json as _json
    from pathlib import Path

    body = await request.body()
    content_type = request.headers.get("content-type", "")

    targets = []

    # 尝试 JSON 解析
    try:
        data = _json.loads(body)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    targets.append({"url": item.strip(), "name": "", "auth_type": "none", "cookie": ""})
                elif isinstance(item, dict):
                    targets.append({
                        "url": item.get("url", "").strip(),
                        "name": item.get("name", ""),
                        "auth_type": item.get("auth_type", "none"),
                        "cookie": item.get("cookie", ""),
                        "username": item.get("username", ""),
                        "password": item.get("password", ""),
                    })
        elif isinstance(data, dict) and "targets" in data:
            for item in data["targets"]:
                if isinstance(item, str):
                    targets.append({"url": item.strip(), "name": "", "auth_type": "none", "cookie": ""})
                elif isinstance(item, dict):
                    targets.append({
                        "url": item.get("url", "").strip(),
                        "name": item.get("name", ""),
                        "auth_type": item.get("auth_type", "none"),
                        "cookie": item.get("cookie", ""),
                    })
    except Exception:
        # 非JSON，尝试纯文本/CSV
        text = body.decode("utf-8", errors="ignore").strip()
        if not text:
            return {"error": "请求体为空"}

        # 检测是否为 CSV（第一行包含 url 或 name 关键字）
        first_line = text.split("\n")[0].lower()
        if "url" in first_line or "name" in first_line and "," in first_line:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                url = (row.get("url") or row.get("URL") or "").strip()
                if url:
                    targets.append({
                        "url": url,
                        "name": (row.get("name") or row.get("Name") or "").strip(),
                        "auth_type": (row.get("auth_type") or row.get("auth") or "none").strip(),
                        "cookie": (row.get("cookie") or row.get("Cookie") or "").strip(),
                        "username": (row.get("username") or "").strip(),
                        "password": (row.get("password") or "").strip(),
                    })
        else:
            # 纯文本，每行一个URL
            for line in text.split("\n"):
                url = line.strip()
                if url and not url.startswith("#"):
                    targets.append({"url": url, "name": "", "auth_type": "none", "cookie": ""})

    # 去重 + 验证
    seen = set()
    valid_targets = []
    for t in targets:
        url = t.get("url", "")
        if url and url not in seen:
            seen.add(url)
            valid_targets.append(t)

    # 持久化到 data/batch_targets.json
    targets_file = Path("data/batch_targets.json")
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if targets_file.exists():
        try:
            existing = _json.loads(targets_file.read_text(encoding="utf-8"))
        except Exception:
            existing = []
    existing.extend(valid_targets)
    targets_file.write_text(_json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "added": len(valid_targets),
        "total": len(existing),
        "targets": valid_targets,
    }


@router.get("/api/targets/list")
async def list_targets():
    """列出所有批量目标。"""
    import json as _json
    from pathlib import Path

    targets_file = Path("data/batch_targets.json")
    if not targets_file.exists():
        return {"targets": [], "total": 0}
    try:
        targets = _json.loads(targets_file.read_text(encoding="utf-8"))
        return {"targets": targets, "total": len(targets)}
    except Exception:
        return {"targets": [], "total": 0}


@router.post("/api/targets/clear")
async def clear_targets():
    """清空所有批量目标。"""
    from pathlib import Path
    targets_file = Path("data/batch_targets.json")
    if targets_file.exists():
        targets_file.unlink()
    return {"ok": True}


@router.post("/api/targets/scan-all")
async def scan_all_targets(request: Request):
    """批量启动所有目标的扫描。

    请求体: {"scan_mode": "fast", "concurrent": 3}
    """
    import asyncio
    import json as _json
    from pathlib import Path

    try:
        body = await request.json()
    except Exception:
        body = {}

    scan_mode = body.get("scan_mode", "fast")
    concurrent = min(body.get("concurrent", 3), 10)  # 最多并发10个

    targets_file = Path("data/batch_targets.json")
    if not targets_file.exists():
        return {"error": "没有批量目标"}

    targets = _json.loads(targets_file.read_text(encoding="utf-8"))
    if not targets:
        return {"error": "目标列表为空"}

    # 为每个目标创建扫描任务
    tasks = []
    for t in targets:
        url = t.get("url", "")
        if not url:
            continue
        task_id = f"batch_{int(time.time())}_{hash(url) % 10000}"
        tasks.append({
            "task_id": task_id,
            "url": url,
            "name": t.get("name", ""),
            "scan_mode": scan_mode,
            "status": "queued",
        })

    return {
        "ok": True,
        "tasks": tasks,
        "total": len(tasks),
        "concurrent": concurrent,
        "message": f"已创建 {len(tasks)} 个扫描任务，最大并发 {concurrent}",
    }


# ================================================================
# 批量目标管理 API（数据持久化在 data/targets.json）
# ================================================================

_TARGETS_FILE = Path("data/targets.json")
_TARGETS_LOCK = Lock()
_TARGETS_CACHE: list[dict] | None = None


def _targets_load() -> list[dict]:
    """加载目标列表到内存缓存。文件不存在或损坏则返回空列表。"""
    global _TARGETS_CACHE
    if _TARGETS_CACHE is not None:
        return _TARGETS_CACHE
    _TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    items: list[dict] = []
    if _TARGETS_FILE.exists():
        try:
            data = json.loads(_TARGETS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                items = [d for d in data if isinstance(d, dict)]
        except Exception as e:
            log.error("读取 targets.json 失败: %s", e)
    _TARGETS_CACHE = items
    return _TARGETS_CACHE


def _targets_flush() -> None:
    """把内存中的目标列表覆盖写回文件。"""
    items = _targets_load()
    _TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _TARGETS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _TARGETS_FILE)


def _new_target_id() -> str:
    """生成目标唯一 ID。"""
    return f"tgt_{int(time.time())}_{uuid.uuid4().hex[:6]}"


def _looks_like_url(text: str) -> bool:
    """简单判断字符串是否像 URL（http/https 开头）。"""
    t = (text or "").strip().lower()
    return t.startswith("http://") or t.startswith("https://")


def _add_targets_internal(items: list[dict]) -> tuple[int, int, list[str]]:
    """内部批量写入，返回 (成功数, 跳过数, 错误信息列表)。"""
    added = 0
    skipped = 0
    errors: list[str] = []
    with _TARGETS_LOCK:
        existing = _targets_load()
        # 已存在的 URL 集合，用于去重
        existing_urls = {it.get("url", "").rstrip("/").lower() for it in existing if it.get("url")}
        for raw in items:
            if not isinstance(raw, dict):
                skipped += 1
                continue
            url = (raw.get("url") or "").strip()
            name = (raw.get("name") or "").strip()
            if not url:
                skipped += 1
                errors.append("缺少 url 字段")
                continue
            # 自动补全协议
            if not _looks_like_url(url):
                url = "http://" + url
            key = url.rstrip("/").lower()
            if key in existing_urls:
                skipped += 1
                errors.append(f"URL 已存在，跳过: {url}")
                continue
            target = {
                "id": _new_target_id(),
                "url": url,
                "name": name or url,
                "status": "pending",
                "created_at": int(time.time()),
            }
            existing.append(target)
            existing_urls.add(key)
            added += 1
        if added > 0:
            _targets_flush()
    return added, skipped, errors


@router.get("/api/targets")
async def list_targets(status: str = "", keyword: str = "", limit: int = 0):
    """获取目标列表。

    可选过滤参数：
    - status: 按状态过滤（pending / scanning / done / failed）
    - keyword: 按 url 或 name 模糊匹配
    - limit: 限制返回条数（0 表示不限制）
    """
    with _TARGETS_LOCK:
        items = list(_targets_load())
    if status:
        items = [it for it in items if it.get("status") == status]
    if keyword:
        kw = keyword.lower()
        items = [it for it in items if kw in (it.get("url", "") + it.get("name", "")).lower()]
    # 按 created_at 倒序（最新在前）
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    if limit and limit > 0:
        items = items[:limit]
    return {"ok": True, "targets": items, "total": len(items)}


@router.post("/api/targets/batch")
async def batch_add_targets(request: Request):
    """批量添加目标。

    请求体：{"targets": [{"url": "http://1.1.1.1", "name": "目标1"}, ...]}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})
    items = body.get("targets")
    if not isinstance(items, list) or not items:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "targets 字段必须是非空数组"},
        )
    added, skipped, errors = _add_targets_internal(items)
    log.info("批量添加目标: 成功=%d 跳过=%d", added, skipped)
    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "message": f"成功添加 {added} 个目标，跳过 {skipped} 个",
    }


@router.post("/api/targets/csv")
async def csv_upload_targets(file: UploadFile = File(...)):
    """CSV 上传：解析 CSV 中的 URL 列并批量入库。

    - 自动识别表头（含 url/name 列名时按列名解析，否则取第一列作为 URL）
    - 支持逗号 / 分号分隔
    - 自动补全 http:// 前缀
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "请上传 .csv 文件"},
        )
    try:
        raw_bytes = await file.read()
    except Exception as e:
        return JSONResponse(status_code=400, content={"ok": False, "error": f"读取文件失败: {e}"})
    # 尝试常见编码（CSV 默认 UTF-8，兼容 GBK）
    text = None
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = raw_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "无法解码 CSV 文件"})

    # 嗅探分隔符
    try:
        sample = text.splitlines()[0] if text.splitlines() else ","
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except Exception:
        delimiter = ","

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = [row for row in reader if row and any(cell.strip() for cell in row)]
    if not rows:
        return JSONResponse(status_code=400, content={"ok": False, "error": "CSV 文件为空"})

    # 识别表头：若首行包含 url/name 关键字则视为表头
    header = [c.strip().lower() for c in rows[0]]
    has_header = any(h in ("url", "urls", "地址", "目标") for h in header) or \
                 any(h in ("name", "名称", "备注") for h in header)

    items: list[dict] = []
    if has_header:
        url_idx = next((i for i, h in enumerate(header) if h in ("url", "urls", "地址", "目标")), 0)
        name_idx = next((i for i, h in enumerate(header) if h in ("name", "名称", "备注")), None)
        data_rows = rows[1:]
        for row in data_rows:
            if url_idx >= len(row):
                continue
            url = row[url_idx].strip()
            if not url:
                continue
            name = row[name_idx].strip() if (name_idx is not None and name_idx < len(row)) else ""
            items.append({"url": url, "name": name})
    else:
        # 无表头：第一列作为 URL，第二列（可选）作为名称
        for row in rows:
            url = row[0].strip() if row else ""
            if not url:
                continue
            # 跳过明显不是 URL 的行（且不像 IP/域名）
            name = row[1].strip() if len(row) > 1 else ""
            items.append({"url": url, "name": name})

    if not items:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "CSV 中未解析到任何 URL"},
        )

    added, skipped, errors = _add_targets_internal(items)
    log.info("CSV 导入目标: 成功=%d 跳过=%d (文件=%s)", added, skipped, file.filename)
    return {
        "ok": True,
        "filename": file.filename,
        "parsed": len(items),
        "added": added,
        "skipped": skipped,
        "errors": errors[:20],  # 错误信息最多返回前 20 条，避免响应过大
        "message": f"从 CSV 解析到 {len(items)} 条，成功添加 {added} 个，跳过 {skipped} 个",
    }


@router.delete("/api/targets/{target_id}")
async def delete_target(target_id: str):
    """删除指定目标。"""
    if not target_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "缺少 target_id"})
    with _TARGETS_LOCK:
        items = _targets_load()
        before = len(items)
        items[:] = [it for it in items if it.get("id") != target_id]
        after = len(items)
        if before == after:
            return JSONResponse(
                status_code=404,
                content={"ok": False, "error": f"目标不存在: {target_id}"},
            )
        _targets_flush()
    log.info("删除目标: %s", target_id)
    return {"ok": True, "message": "目标已删除", "id": target_id}


# ================================================================
# ★ P1: 后台任务队列 API
# ================================================================

@router.post("/api/tasks/submit")
async def submit_scan_task(request: Request):
    """提交后台扫描任务，立即返回。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})
    url = (body.get("url") or "").strip()
    if not url:
        return JSONResponse(status_code=400, content={"ok": False, "error": "url 不能为空"})
    from core.task_queue import submit_task
    task_id = submit_task(
        url=url,
        scan_mode=body.get("scan_mode", "standard"),
        cookie=body.get("cookie", ""),
        username=body.get("username", ""),
        password=body.get("password", ""),
        notes=body.get("notes", ""),
    )
    return {"ok": True, "task_id": task_id, "status": "queued"}


@router.post("/api/tasks/batch-submit")
async def batch_submit_tasks(request: Request):
    """批量提交扫描任务。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})
    targets = body.get("targets", [])
    if not targets:
        return JSONResponse(status_code=400, content={"ok": False, "error": "targets 不能为空"})
    from core.task_queue import submit_batch_targets
    results = submit_batch_targets(targets)
    return {"ok": True, "tasks": results, "total": len(results)}


@router.get("/api/tasks")
async def list_tasks(limit: int = 50):
    """列出所有后台任务。"""
    from core.task_queue import list_tasks as _list
    return {"tasks": _list(limit=limit)}


@router.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    """获取单个任务状态。"""
    from core.task_queue import get_task_status
    task = get_task_status(task_id)
    if not task:
        return {"error": f"任务不存在: {task_id}"}
    return task


@router.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """取消一个任务。"""
    from core.task_queue import cancel_task as _cancel
    ok = _cancel(task_id)
    return {"ok": ok, "task_id": task_id}


# ================================================================
# ★ P3: MCP Server 健康检查
# ================================================================

_MCP_SERVERS = {
    "browser": {"module": "mcp_servers.browser_mcp", "port": None},
    "knowledge": {"module": "mcp_servers.knowledge_mcp", "port": None},
    "proxy": {"module": "mcp_servers.proxy_mcp", "port": None},
    "report": {"module": "mcp_servers.report_mcp", "port": None},
    "note": {"module": "mcp_servers.note_mcp", "port": None},
    "target": {"module": "mcp_servers.target_mcp", "port": None},
}


@router.get("/api/mcp/health")
async def mcp_health():
    """检查所有 MCP Server 的健康状态。"""
    results = {}
    all_ok = True

    for name, info in _MCP_SERVERS.items():
        try:
            mod_name = info["module"].replace("/", ".").replace(".py", "")
            import importlib
            mod = importlib.import_module(mod_name)
            mcp_obj = getattr(mod, "mcp", None)
            if mcp_obj is None:
                results[name] = {"ok": False, "error": "模块无 mcp 实例"}
                all_ok = False
                continue
            results[name] = {"ok": True, "status": "loaded"}
        except ImportError as e:
            results[name] = {"ok": False, "error": f"导入失败: {e}"}
            all_ok = False
        except Exception as e:
            results[name] = {"ok": False, "error": str(e)[:100]}
            all_ok = False

    return {"healthy": all_ok, "servers": results}


# ================================================================
# ★ P3: 扫描结果对比（两次 diff）
# ================================================================

@router.get("/api/scans/compare")
async def compare_scans(task_a: str = "", task_b: str = ""):
    """对比两次扫描结果的漏洞差异。

    返回三部分：
    - only_a: 在 A 中存在但在 B 中已修复的漏洞
    - only_b: 在 B 中新发现的漏洞
    - common: 两者都存在的漏洞
    """
    from core.sitemap import Sitemap, CheckResult

    if not task_a or not task_b:
        return {"error": "需要提供 task_a 和 task_b 两个任务 ID"}

    def _get_vulns(task_id: str) -> list[dict]:
        sitemap = Sitemap(target="", task_id=task_id)
        if not sitemap.load():
            return []
        vulns = []
        for fp in sitemap.features.values():
            for c in fp.checklist:
                if c.result == CheckResult.VULNERABLE:
                    key = f"{c.vuln_type}@{fp.url or fp.name}"
                    vulns.append({
                        "key": key,
                        "vuln_type": c.vuln_type,
                        "feature": fp.name,
                        "url": c.evidence_request or fp.url or "",
                        "severity": c.severity or "medium",
                        "detail": c.detail or "",
                    })
        return vulns

    vulns_a = _get_vulns(task_a)
    vulns_b = _get_vulns(task_b)

    keys_a = {v["key"] for v in vulns_a}
    keys_b = {v["key"] for v in vulns_b}

    common = [v for v in vulns_a if v["key"] in keys_b]
    only_a = [v for v in vulns_a if v["key"] not in keys_b]
    only_b = [v for v in vulns_b if v["key"] not in keys_a]

    return {
        "task_a": task_a,
        "task_b": task_b,
        "only_a": {"count": len(only_a), "items": only_a},
        "only_b": {"count": len(only_b), "items": only_b},
        "common": {"count": len(common), "items": common},
        "summary": {
            "vulns_a": len(vulns_a),
            "vulns_b": len(vulns_b),
            "fixed": len(only_a),
            "new": len(only_b),
            "unchanged": len(common),
        },
    }
