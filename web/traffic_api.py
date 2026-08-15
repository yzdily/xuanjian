"""
traffic_api.py — 流量管理页面专属后端接口

挂载到主 app：
    from web.traffic_api import traffic_router
    app.include_router(traffic_router)

接口列表：
    GET /traffic                        — 流量管理页面 HTML
    GET /api/traffic/{task_id}          — 汇总数据（功能点 + 合并数据包 + 统计）
    GET /api/traffic/{task_id}/packets  — 全量数据包列表（可按模块/方法/关键词筛选）
    GET /api/traffic/{task_id}/feature/{fp_id}  — 单个功能点详情 + 关联数据包
    GET /api/traffic/{task_id}/flow/{flow_id}   — 按 flow_id 查完整原始流量
    GET /api/traffic/{task_id}/evidence         — 所有漏洞 PoC 证据包
"""

from __future__ import annotations

import asyncio
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent))

# ★ D9 S6：web 路径单源
from web._paths import WEB_ROOT  # noqa: F401
# ★ S1 单源：task_id / fp_id / flow_id 校验统一复用 web._security.validate_task_id，
# 消除与 reports_api / system_api / sessions_api 各自实现正则的漂移（D9 S6 / D4 S1）。
from web._security import validate_task_id

from core.packet_merger import merge_packets, get_packets_for_feature, get_flow_by_id
from core.log import get_logger

log = get_logger("traffic_api")

traffic_router = APIRouter()

# ---- 运行中会话访问器（由 server.py 注入） ----
_get_active_session = None  # type: ignore  # Callable[[], AgentSession | None]

def register_session_accessor(getter):
    """由 server.py 调用，注入获取当前活跃会话的回调。"""
    global _get_active_session
    _get_active_session = getter


def _load_sitemap_data(task_id: str) -> dict | None:
    """加载 sitemap 数据：优先从内存（运行中任务），降级读磁盘文件。"""
    # ★ v4.2: 优先从内存中活跃会话获取（实时数据，爬虫运行中也可用）
    if _get_active_session:
        try:
            session = _get_active_session()
            if session and session.task_id == task_id and session.sitemap:
                from dataclasses import asdict
                sitemap = session.sitemap
                return {
                    "target": sitemap.target,
                    "task_id": sitemap.task_id,
                    "business_summary": sitemap.business_summary,
                    "tech_stack": sitemap.tech_stack,
                    "pages": {k: asdict(v) for k, v in sitemap.pages.items()},
                    "apis": {k: asdict(v) for k, v in sitemap.apis.items()},
                    "features": {k: asdict(v) for k, v in sitemap.features.items()},
                    "api_samples": sitemap.api_samples,
                    "js_routes": sitemap.js_routes,
                    "js_api_calls": sitemap.js_api_calls,
                    "extra_scope": getattr(sitemap, "extra_scope", []) or [],
                    "xss_findings": getattr(sitemap, "xss_findings", []) or [],
                    "csp_analyses": getattr(sitemap, "csp_analyses", {}) or {},
                    "business_understanding": getattr(sitemap, "business_understanding", {}) or {},
                    "reconcile_result": getattr(sitemap, "reconcile_result", {}) or {},
                    "harm_validation": getattr(sitemap, "harm_validation", {}) or {},
                }
        except Exception as e:
            log.debug("从内存获取 sitemap 失败，降级读磁盘: %s", e)

    # 降级：从磁盘加载
    path = Path("data/tasks") / f"{task_id}-sitemap.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("加载 sitemap 失败 %s: %s", task_id, e)
        return None


def _list_available_tasks() -> list[dict]:
    """列出所有可用任务（磁盘文件 + 运行中会话），运行中的排最前。"""
    seen_ids: set[str] = set()
    result: list[dict] = []

    # ★ v4.2: 优先加入运行中的活跃会话（即使 sitemap.json 还没落盘也能显示）
    if _get_active_session:
        try:
            session = _get_active_session()
            if session and session.sitemap:
                tid = session.task_id
                seen_ids.add(tid)
                result.append({
                    "task_id": tid,
                    "target": session.sitemap.target,
                    "features_count": len(session.sitemap.features),
                    "apis_count": len(session.sitemap.apis),
                    "mtime": 0,
                    "active": True,  # ★ 标记为运行中
                })
        except Exception:
            pass

    # 磁盘文件
    tasks_dir = Path("data/tasks")
    if tasks_dir.exists():
        for f in sorted(tasks_dir.glob("*-sitemap.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            task_id = f.name.replace("-sitemap.json", "")
            if task_id in seen_ids:
                continue  # 运行中已覆盖，跳过磁盘版
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                result.append({
                    "task_id": task_id,
                    "target": data.get("target", ""),
                    "features_count": len(data.get("features", {})),
                    "apis_count": len(data.get("apis", {})),
                    "mtime": f.stat().st_mtime,
                })
            except Exception:
                result.append({"task_id": task_id, "target": "", "features_count": 0, "apis_count": 0, "mtime": 0})
    return result


def _get_target_host(sitemap_data: dict) -> str:
    """从 sitemap 提取目标 host，用于 flows 过滤。"""
    try:
        from urllib.parse import urlparse
        return urlparse(sitemap_data.get("target", "")).netloc
    except Exception:
        return ""


def _build_feature_tree(sitemap_data: dict) -> list[dict]:
    """把 features 按 module 字段分组，构造树形结构供前端渲染。"""
    features = sitemap_data.get("features", {}) or {}
    modules: dict[str, list] = {}

    for fp_id, fp in features.items():
        module = fp.get("module", "") or _infer_module(fp.get("related_apis", []))
        if module not in modules:
            modules[module] = []

        # checklist 状态统计
        checklist = fp.get("checklist", []) or []
        status_counts = {"vulnerable": 0, "needs_review": 0, "not_vuln": 0, "pending": 0, "skipped": 0}
        for c in checklist:
            r = c.get("result", "pending")
            if r in status_counts:
                status_counts[r] += 1
            else:
                status_counts["pending"] += 1

        modules[module].append({
            "id": fp_id,
            "name": fp.get("name", fp_id),
            "description": fp.get("description", ""),
            "page_url": fp.get("page_url", ""),
            "related_apis": fp.get("related_apis", []),
            "priority": fp.get("priority", "medium"),
            "test_status": fp.get("test_status", "not_tested"),
            "status_counts": status_counts,
            "has_vuln": status_counts["vulnerable"] > 0,
            "has_review": status_counts["needs_review"] > 0,
            "checklist_total": len(checklist),
        })

    # 排序：有漏洞的模块优先
    tree = []
    for module_name, fps in sorted(modules.items()):
        has_vuln = any(f["has_vuln"] for f in fps)
        has_review = any(f["has_review"] for f in fps)
        tree.append({
            "module": module_name or "其他",
            "features": fps,
            "has_vuln": has_vuln,
            "has_review": has_review,
            "count": len(fps),
        })
    tree.sort(key=lambda m: (not m["has_vuln"], not m["has_review"], m["module"]))
    return tree


def _infer_module(related_apis: list[str]) -> str:
    """从 related_apis 推断模块名（取路径第2-3段）。"""
    if not related_apis:
        return ""
    try:
        from urllib.parse import urlparse
        url = related_apis[0].split(" ")[-1]
        parts = [p for p in urlparse(url).path.split("/") if p]
        skip = {"api", "v1", "v2", "v3", "v4"}
        meaningful = [p for p in parts if p.lower() not in skip]
        return meaningful[0] if meaningful else parts[0] if parts else ""
    except Exception:
        return ""


# ---- 路由 ----

@traffic_router.get("/traffic", response_class=HTMLResponse)
async def traffic_page():
    """流量管理页面。"""
    html_path = WEB_ROOT / "traffic.html"
    if not html_path.exists():
        return HTMLResponse("<h2>traffic.html not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@traffic_router.get("/api/traffic/tasks")
async def list_tasks():
    """列出所有可用任务。"""
    return JSONResponse({"tasks": _list_available_tasks()})


@traffic_router.get("/api/traffic/{task_id}")
async def get_traffic_summary(task_id: str):
    """
    汇总数据：功能点树 + 数据包统计 + 业务信息。
    不返回完整数据包内容（避免响应过大），前端需要再调 /packets 或 /feature/{fp_id}。
    """
    # ★ S6: 校验 task_id 防止路径穿越
    if not validate_task_id(task_id):
        return JSONResponse({"error": "task_id 含非法字符"}, status_code=400)
    data = _load_sitemap_data(task_id)
    if not data:
        return JSONResponse({"error": f"任务 {task_id} 不存在"}, status_code=404)

    target_host = _get_target_host(data)
    # ★ v3: merge_packets 会读 62MB+ flows 文件 + 解析 json，
    # 直接 await 在 async 函数里会阻塞整个 event loop（导致前端"加载失败"）
    # to_thread 把 sync IO 移到线程池，server 可同时响应其他请求
    merged = await asyncio.to_thread(merge_packets, data, None, target_host)

    return JSONResponse({
        "task_id": task_id,
        "target": data.get("target", ""),
        "business_summary": data.get("business_summary", ""),
        "tech_stack": data.get("tech_stack", ""),
        "feature_tree": _build_feature_tree(data),
        "stats": {
            **merged["stats"],
            "features_total": len(data.get("features", {})),
            "apis_total": len(data.get("apis", {})),
            "evidence_total": len(merged["evidence_packets"]),
        },
        "extra_scope": data.get("extra_scope", []),
    })


@traffic_router.get("/api/traffic/{task_id}/packets")
async def get_packets(
    task_id: str,
    method: Optional[str] = Query(None, description="过滤 HTTP 方法，如 GET/POST"),
    keyword: Optional[str] = Query(None, description="URL/path 关键词过滤"),
    source: Optional[str] = Query(None, description="来源过滤：mitmproxy/crawler/inferred/evidence"),
    sort: Optional[str] = Query(None, description="排序字段：status_code/path/method/timestamp"),
    sort_dir: Optional[str] = Query("asc", description="排序方向：asc/desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """
    全量数据包列表，支持过滤、排序和分页。
    每条只返回摘要（不含完整 response_body），避免响应过大。
    """
    # ★ S6: 校验 task_id 防止路径穿越
    if not validate_task_id(task_id):
        return JSONResponse({"error": "task_id 含非法字符"}, status_code=400)
    data = _load_sitemap_data(task_id)
    if not data:
        return JSONResponse({"error": f"任务 {task_id} 不存在"}, status_code=404)

    target_host = _get_target_host(data)
    merged = await asyncio.to_thread(merge_packets, data, None, target_host)
    packets = merged["packets"]

    # 过滤
    if method:
        packets = [p for p in packets if p["method"].upper() == method.upper()]
    if keyword:
        kw = keyword.lower()
        packets = [p for p in packets if kw in p["url"].lower() or kw in p["path"].lower()]
    if source:
        packets = [p for p in packets if p["source"] == source]

    # 排序
    if sort:
        reverse = (sort_dir or "asc").lower() == "desc"
        sort_field = sort.lower()
        if sort_field == "status_code":
            packets.sort(key=lambda p: p.get("status_code", 0) or 0, reverse=reverse)
        elif sort_field == "path":
            packets.sort(key=lambda p: p.get("path", ""), reverse=reverse)
        elif sort_field == "method":
            packets.sort(key=lambda p: p.get("method", ""), reverse=reverse)
        elif sort_field == "timestamp":
            packets.sort(key=lambda p: p.get("timestamp", 0) or 0, reverse=reverse)

    total = len(packets)
    start = (page - 1) * page_size
    page_packets = packets[start: start + page_size]

    # 返回完整数据包（response_body 已由 addon 截断到 10KB，直接透传）
    summaries = page_packets

    return JSONResponse({
        "total": total,
        "page": page,
        "page_size": page_size,
        "packets": summaries,
    })


@traffic_router.get("/api/traffic/{task_id}/feature/{fp_id}")
async def get_feature_detail(task_id: str, fp_id: str):
    """
    单个功能点完整详情：
    - 功能点基本信息
    - 完整 checklist（含漏洞证据）
    - 关联数据包（完整 response_body）
    """
    # ★ S6: 校验 task_id / fp_id 防止路径穿越
    if not validate_task_id(task_id) or not validate_task_id(fp_id):
        return JSONResponse({"error": "task_id 或 fp_id 含非法字符"}, status_code=400)
    data = _load_sitemap_data(task_id)
    if not data:
        return JSONResponse({"error": f"任务 {task_id} 不存在"}, status_code=404)

    features = data.get("features", {}) or {}
    fp = features.get(fp_id)
    if not fp:
        return JSONResponse({"error": f"功能点 {fp_id} 不存在"}, status_code=404)

    target_host = _get_target_host(data)
    merged = await asyncio.to_thread(merge_packets, data, None, target_host)
    related_packets = get_packets_for_feature(fp_id, data, merged["packets"])

    # 读取 samples 独立文件（最详细的数据包，含 JS 上下文）
    sample_text = ""
    sample_path = Path("data/tasks") / f"{task_id}-samples" / f"{fp_id}.txt"
    if sample_path.exists():
        try:
            sample_text = sample_path.read_text(encoding="utf-8")
        except Exception:
            pass

    return JSONResponse({
        "fp": fp,
        "packets": related_packets,
        "sample_file": sample_text,
        "sample_file_path": str(sample_path) if sample_path.exists() else "",
    })


@traffic_router.get("/api/traffic/{task_id}/flow/{flow_id}")
async def get_flow_detail(task_id: str, flow_id: str):
    """按 flow_id 查询完整原始流量（用于漏洞证据详情）。"""
    # ★ S6: 校验 task_id / flow_id 防止路径穿越
    if not validate_task_id(task_id) or not validate_task_id(flow_id):
        return JSONResponse({"error": "task_id 或 flow_id 含非法字符"}, status_code=400)
    # ★ v3: get_flow_by_id 也要扫 flows 文件，扔线程池
    flow = await asyncio.to_thread(get_flow_by_id, flow_id)
    if not flow:
        return JSONResponse({"error": f"flow {flow_id} 不存在"}, status_code=404)
    return JSONResponse({"flow": flow})


@traffic_router.get("/api/traffic/{task_id}/evidence")
async def get_evidence_packets(task_id: str):
    """所有漏洞 PoC 证据包列表。"""
    # ★ S6: 校验 task_id 防止路径穿越
    if not validate_task_id(task_id):
        return JSONResponse({"error": "task_id 含非法字符"}, status_code=400)
    data = _load_sitemap_data(task_id)
    if not data:
        return JSONResponse({"error": f"任务 {task_id} 不存在"}, status_code=404)

    target_host = _get_target_host(data)
    merged = await asyncio.to_thread(merge_packets, data, None, target_host)

    return JSONResponse({
        "total": len(merged["evidence_packets"]),
        "packets": merged["evidence_packets"],
    })
