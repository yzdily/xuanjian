"""
报告管理 API — 列表/预览/导出/删除安全扫描报告。

支持 PDF/JSON/HTML 多种导出格式。
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from core.log import get_logger
from web._state import _resolve_sitemap

log = get_logger("web.reports_api")

router = APIRouter()

REPORTS_DIR = Path(os.getenv("REPORT_PATH", "data/reports"))
TASKS_DIR = Path("data/tasks")


REALTIME_PATTERN = re.compile(r"^(.+)-realtime-report\.md$")
PROVEN_PATTERN = re.compile(r"^(.+)-proven-report\.md$")
# ★ report_mcp 生成的文件命名：{task_id}-{report_type}-latest.md
# report_type 可以是 pt（渗透测试报告）/ src（SRC 漏洞报告）/ custom（自定义模板）
SRC_LATEST_PATTERN = re.compile(r"^(.+)-src-latest\.md$")
PT_LATEST_PATTERN = re.compile(r"^(.+)-pt-latest\.md$")
CUSTOM_LATEST_PATTERN = re.compile(r"^(.+)-custom-latest\.md$")


def _group_reports_by_task() -> list[dict]:
    """将 data/reports/ 下的报告文件按 task_id 分组。

    返回按 latest_mtime 降序排列的 task 列表，每项含：
      - task_id / target / vuln_count / features_count / latest_mtime
      - files: { realtime: {...} | None, proven: {...} | None, full: {...} | None }
    """
    import json as _json

    if not REPORTS_DIR.exists():
        return []

    # 扫描文件，按 task_id 分组
    from collections import defaultdict
    groups: dict[str, dict] = defaultdict(lambda: {
        "task_id": "",
        "target": "",
        "vuln_count": 0,
        "features_count": 0,
        "latest_mtime": 0,
        "files": {"realtime": None, "proven": None, "full": None},
    })

    for f in REPORTS_DIR.iterdir():
        if f.suffix not in (".md", ".html", ".json", ".pdf", ".txt"):
            continue
        name = f.name
        mtime = f.stat().st_mtime
        finfo = {"name": name, "path": str(f), "size": f.stat().st_size, "mtime": mtime, "format": f.suffix.lstrip(".")}

        # 尝试匹配：{task_id}-realtime-report.md
        m = REALTIME_PATTERN.match(name)
        if m:
            tid = m.group(1)
            groups[tid]["task_id"] = tid
            # ★ 只在还没有 src-latest/pt-latest 时用 realtime-report 作为 realtime
            # （src-latest/pt-latest 是 report_mcp 的新版主报告，优先级更高）
            if not groups[tid]["files"]["realtime"]:
                groups[tid]["files"]["realtime"] = finfo
            if mtime > groups[tid]["latest_mtime"]:
                groups[tid]["latest_mtime"] = mtime
            continue

        # {task_id}-proven-report.md
        m = PROVEN_PATTERN.match(name)
        if m:
            tid = m.group(1)
            groups[tid]["task_id"] = tid
            groups[tid]["files"]["proven"] = finfo
            if mtime > groups[tid]["latest_mtime"]:
                groups[tid]["latest_mtime"] = mtime
            continue

        # ★ {task_id}-src-latest.md / {task_id}-pt-latest.md / {task_id}-custom-latest.md
        # report_mcp 生成的主报告，映射为 realtime（完整报告）
        for pat in (SRC_LATEST_PATTERN, PT_LATEST_PATTERN, CUSTOM_LATEST_PATTERN):
            m = pat.match(name)
            if m:
                tid = m.group(1)
                groups[tid]["task_id"] = tid
                # ★ pt-latest 和 src-latest 都作为 realtime（完整报告）
                # 优先级：pt-latest > src-latest > custom-latest > realtime-report
                cur_rt = groups[tid]["files"]["realtime"]
                if not cur_rt or cur_rt["name"].endswith("-realtime-report.md"):
                    # 用 -latest 版本覆盖 -report 版本（更新更完整）
                    groups[tid]["files"]["realtime"] = finfo
                if mtime > groups[tid]["latest_mtime"]:
                    groups[tid]["latest_mtime"] = mtime
                break
        if m:
            continue

        # {task_id}_report.{ext}
        underscore_parts = name.rsplit("_report.", 1)
        if len(underscore_parts) == 2:
            tid = underscore_parts[0]
            groups[tid]["task_id"] = tid
            groups[tid]["files"]["full"] = finfo
            if mtime > groups[tid]["latest_mtime"]:
                groups[tid]["latest_mtime"] = mtime

    # 尝试加载 sitemap 获取 target / vuln_count / features_count
    for tid, g in groups.items():
        g["task_id"] = tid
        sitemap = _resolve_sitemap(tid)
        if sitemap:
            g["target"] = sitemap.target or ""
            cov = sitemap.get_coverage()
            g["vuln_count"] = cov.get("vulns", 0)
            g["features_count"] = cov.get("total", 0)
        else:
            # sitemap 不可用时尝试从报告内容中提取 target
            rt = g["files"].get("realtime")
            if rt:
                try:
                    content = Path(rt["path"]).read_text(encoding="utf-8", errors="replace")
                    for line in content.split("\n"):
                        if line.startswith("| 目标 |"):
                            g["target"] = line.split("|")[2].strip()
                            break
                except Exception:
                    pass
            if not g["target"]:
                g["target"] = tid

    # 按 latest_mtime 降序
    result = sorted(groups.values(), key=lambda x: x["latest_mtime"], reverse=True)
    return result


@router.get("/api/reports")
@router.get("/api/reports/list")
async def list_reports():
    """列出所有报告（按任务分组）。"""
    reports = _group_reports_by_task()
    return {"reports": reports, "count": len(reports), "total": len(reports)}


def _find_report_file(task_id: str, kind: str) -> Path | None:
    """★ 查找报告文件，兼容新旧两种命名。

    新命名（report_mcp 生成）：{task_id}-pt-latest.md / {task_id}-src-latest.md
    旧命名（reports_api 生成）：{task_id}-realtime-report.md / {task_id}-proven-report.md

    kind=realtime → 优先 pt-latest > src-latest > realtime-report > _report.md
    kind=proven   → 优先 proven-report > _report.md
    """
    if kind == "realtime":
        candidates = [
            f"{task_id}-pt-latest.md",
            f"{task_id}-src-latest.md",
            f"{task_id}-custom-latest.md",
            f"{task_id}-realtime-report.md",
            f"{task_id}_report.md",
        ]
    elif kind == "proven":
        candidates = [
            f"{task_id}-proven-report.md",
            f"{task_id}_report.md",
        ]
    else:
        candidates = [
            f"{task_id}-{kind}-report.md",
            f"{task_id}-{kind}-latest.md",
            f"{task_id}_report.md",
        ]
    for name in candidates:
        p = REPORTS_DIR / name
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


@router.get("/api/reports/content")
async def get_report_content(task_id: str, kind: str = "realtime"):
    """获取指定任务的报告内容。

    kind: realtime | proven (报告类型)
    """
    content = ""

    # ★ proven 报告优先用 sitemap 动态生成（render_proven_only 有兜底逻辑：
    # 从 checklist 提取漏洞、展示测试覆盖摘要等），避免读到旧的"暂无数据"文件。
    # realtime 报告优先读文件（report_mcp 生成的 pt-latest.md 最完整）。
    if kind == "proven":
        sitemap = _resolve_sitemap(task_id)
        if sitemap:
            content = sitemap.flush_proven_report() or ""
        if not content:
            # sitemap 不可用或生成失败，fallback 读旧文件
            report_file = _find_report_file(task_id, kind)
            if report_file:
                try:
                    content = report_file.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    log.warning("读取报告文件失败 %s: %s", report_file, e)
    else:
        # realtime / full：优先读文件
        report_file = _find_report_file(task_id, kind)
        if report_file:
            try:
                content = report_file.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                log.warning("读取报告文件失败 %s: %s", report_file, e)
        if not content:
            sitemap = _resolve_sitemap(task_id)
            if sitemap:
                content = sitemap.flush_report() or ""

    if content:
        return {"status": "ok", "task_id": task_id, "kind": kind, "content": content}
    return {"status": "error", "message": f"任务 {task_id} 无报告"}


@router.get("/api/reports/download")
async def download_report(task_id: str, kind: str = "realtime", format: str = "md"):
    """下载报告文件（新版，前端兼容）。"""
    # ★ proven 报告优先用 sitemap 动态生成（render_proven_only 有兜底逻辑），
    # 避免读到旧的"暂无数据"文件。realtime 报告优先读文件。
    if kind == "proven":
        sitemap = _resolve_sitemap(task_id)
        if sitemap:
            content = sitemap.flush_proven_report() or ""
            if content:
                filename = f"{task_id}-proven-report.md"
                return Response(
                    content=content,
                    media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={filename}"},
                )
        # sitemap 不可用，fallback 读旧文件
        report_file = _find_report_file(task_id, kind)
        if report_file:
            content = report_file.read_text(encoding="utf-8", errors="replace")
            return Response(
                content=content,
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f"attachment; filename={report_file.name}"},
            )
    else:
        # realtime：优先读文件
        report_file = _find_report_file(task_id, kind)
        if report_file:
            content = report_file.read_text(encoding="utf-8", errors="replace")
            return Response(
                content=content,
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f"attachment; filename={report_file.name}"},
            )
        # fallback 到 sitemap 实时生成
        sitemap = _resolve_sitemap(task_id)
        if sitemap:
            report_md = sitemap.flush_report() or ""
            if report_md:
                return Response(
                    content=report_md,
                    media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={task_id}-{kind}-report.md"},
                )
    return {"error": f"任务 {task_id} 无报告"}


@router.get("/api/reports/{task_id}/download")
async def download_report_legacy(task_id: str, format: str = "pdf"):
    """下载报告文件（旧版兼容）。"""
    sitemap = _resolve_sitemap(task_id)
    if not sitemap:
        return {"error": f"任务 {task_id} 无站点地图"}
    report_md = _generate_report_md(task_id, sitemap)
    if not report_md:
        return {"error": "报告生成失败"}

    if format == "pdf":
        pdf_bytes = _md_to_pdf(report_md, task_id)
        _save_report_file(task_id, "pdf", pdf_bytes.decode("utf-8", errors="replace"))
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=xuanjian_report_{task_id}.pdf"},
        )
    if format == "html":
        html = _md_to_html(report_md, task_id)
        _save_report_file(task_id, "html", html)
        return Response(content=html, media_type="text/html")
    _save_report_file(task_id, "md", report_md)
    return Response(content=report_md, media_type="text/markdown; charset=utf-8")


@router.get("/api/reports/{task_id}")
async def get_report(task_id: str, format: str = "md"):
    """获取指定任务的报告。
    
    format: md | json | html | pdf (导出格式)
    """
    sitemap = _resolve_sitemap(task_id)
    if not sitemap:
        return {"error": f"任务 {task_id} 无站点地图"}

    if format == "json":
        data = {
            "task_id": task_id,
            "target": sitemap.target,
            "created_at": time.time(),
            "features": [],
        }
        for fp in sitemap.features.values():
            feature = {
                "id": fp.id,
                "name": fp.name,
                "module": fp.module or "",
                "url": getattr(fp, "url", "") or "",
                "checklist": [],
            }
            for c in fp.checklist:
                feature["checklist"].append({
                    "vuln_type": c.vuln_type,
                    "result": c.result.value if c.result else "pending",
                    "severity": c.severity or "",
                    "detail": c.detail or "",
                    "fix_suggestion": c.fix_suggestion or "",
                    "evidence_request": c.evidence_request or "",
                    "evidence_response": c.evidence_response or "",
                })
            data["features"].append(feature)
        _save_report_file(task_id, "json", json.dumps(data, ensure_ascii=False, indent=2))
        return data

    report_md = _generate_report_md(task_id, sitemap)
    if not report_md:
        return {"error": "报告生成失败"}

    if format == "pdf":
        pdf_bytes = _md_to_pdf(report_md, task_id)
        _save_report_file(task_id, "pdf", pdf_bytes.decode("utf-8", errors="replace"))
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=xuanjian_report_{task_id}.pdf"},
        )
    if format == "html":
        html = _md_to_html(report_md, task_id)
        _save_report_file(task_id, "html", html)
        return Response(content=html, media_type="text/html")
    _save_report_file(task_id, "md", report_md)
    return Response(content=report_md, media_type="text/markdown; charset=utf-8")


@router.delete("/api/reports/{task_id}")
async def delete_report(task_id: str):
    """删除任务相关的所有报告文件。"""
    deleted = 0
    for f in REPORTS_DIR.glob(f"{task_id}*"):
        f.unlink(missing_ok=True)
        deleted += 1
    return {"ok": True, "deleted": deleted}


@router.post("/api/reports/save")
async def save_report(request: Request):
    """保存（编辑后的）报告内容。"""
    try:
        body = await request.json()
        task_id = body.get("task_id", "default")
        kind = body.get("kind", "realtime")
        content = body.get("content", "")
        if not content:
            return {"ok": False, "error": "内容为空"}
        ext = "md"
        if kind == "html":
            ext = "html"
        _save_report_file(task_id, ext, content)
        return {"ok": True, "path": str(REPORTS_DIR / f"{task_id}_report.{ext}")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/reports/delete")
async def delete_report_post(request: Request):
    """通过 POST 删除报告。"""
    try:
        body = await request.json()
        task_id = body.get("task_id", "")
        if not task_id:
            return {"ok": False, "error": "缺少 task_id"}
        # 调用旧版删除逻辑
        result = await delete_report(task_id)
        return {"ok": True, **result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/reports/batch-delete")
async def batch_delete_reports(request: Request):
    """批量删除多个任务的报告文件。

    请求体: {"task_ids": ["task1", "task2", ...]}
    返回: {"ok": true, "deleted": 总文件数, "results": [{"task_id": "..., "deleted": N, "ok": true}, ...]}
    """
    try:
        body = await request.json()
        task_ids = body.get("task_ids", [])
        if not task_ids or not isinstance(task_ids, list):
            return {"ok": False, "error": "缺少 task_ids 或格式不正确"}
        results = []
        total_deleted = 0
        for tid in task_ids:
            if not isinstance(tid, str) or not tid.strip():
                continue
            tid = tid.strip()
            count = 0
            try:
                for f in REPORTS_DIR.glob(f"{tid}*"):
                    f.unlink(missing_ok=True)
                    count += 1
                results.append({"task_id": tid, "deleted": count, "ok": True})
                total_deleted += count
            except Exception as e:
                results.append({"task_id": tid, "deleted": 0, "ok": False, "error": str(e)})
        return {"ok": True, "deleted": total_deleted, "count": len(results), "results": results}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/reports/batch-download")
async def batch_download_reports(request: Request):
    """批量打包下载多个任务的报告文件（ZIP）。

    请求体: {"task_ids": ["task1", "task2", ...], "kinds": ["realtime", "proven"]}
    kinds 可选，默认下载所有可用报告。
    """
    import io as _io
    import zipfile as _zipfile

    try:
        body = await request.json()
        task_ids = body.get("task_ids", [])
        kinds = body.get("kinds", ["realtime", "proven"])
        if not task_ids or not isinstance(task_ids, list):
            return JSONResponse({"ok": False, "error": "缺少 task_ids 或格式不正确"}, status_code=400)

        buf = _io.BytesIO()
        added = 0
        with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as zf:
            for tid in task_ids:
                if not isinstance(tid, str) or not tid.strip():
                    continue
                tid = tid.strip()
                for kind in kinds:
                    report_file = _find_report_file(tid, kind)
                    if report_file and report_file.exists() and report_file.stat().st_size > 0:
                        try:
                            content_bytes = report_file.read_bytes()
                            # ZIP 内文件名：{task_id}/{kind}-{原文件名}
                            arcname = f"{tid}/{kind}-{report_file.name}"
                            zf.writestr(arcname, content_bytes)
                            added += 1
                        except Exception as e:
                            log.warning("打包报告失败 %s/%s: %s", tid, kind, e)
                    elif kind == "proven":
                        # proven 报告优先用 sitemap 动态生成
                        sitemap = _resolve_sitemap(tid)
                        if sitemap:
                            content = sitemap.flush_proven_report() or ""
                            if content:
                                arcname = f"{tid}/proven-{tid}-proven-report.md"
                                zf.writestr(arcname, content.encode("utf-8"))
                                added += 1
                    elif kind == "realtime":
                        # realtime fallback 到 sitemap 实时生成
                        sitemap = _resolve_sitemap(tid)
                        if sitemap:
                            content = sitemap.flush_report() or ""
                            if content:
                                arcname = f"{tid}/realtime-{tid}-report.md"
                                zf.writestr(arcname, content.encode("utf-8"))
                                added += 1

        if added == 0:
            return JSONResponse({"ok": False, "error": "未找到任何可下载的报告文件"}, status_code=404)

        buf.seek(0)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"reports_batch_{timestamp}.zip"
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Report-Count": str(added),
            },
        )
    except Exception as e:
        log.error("批量下载打包失败: %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def _generate_report_md(task_id: str, sitemap) -> str:
    """从站点地图生成 Markdown 报告。"""
    from core.sitemap import CheckResult

    target = sitemap.target or "未知目标"
    lines = [
        f"# 安全扫描报告: {target}",
        f"",
        f"**任务 ID**: {task_id}",
        f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**URL 覆盖**: {sitemap.get_coverage()}",
        f"",
        f"---",
        f"",
        f"## 漏洞汇总",
        f"",
    ]

    all_vulns = []
    total_checks = 0
    for fp in sitemap.features.values():
        for c in fp.checklist:
            total_checks += 1
            if c.result == CheckResult.VULNERABLE:
                all_vulns.append((fp, c))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_vulns.sort(key=lambda x: severity_order.get(x[1].severity or "info", 99))

    lines.append(f"| 严重级别 | 漏洞类型 | 功能点 | URL |")
    lines.append(f"|---------|---------|-------|-----|")
    for fp, c in all_vulns:
        sev = c.severity or "info"
        lines.append(f"| {sev} | {c.vuln_type} | {fp.name} | {c.evidence_request or ''} |")

    lines.extend([
        f"",
        f"**总计**: {len(all_vulns)} 个漏洞 / {total_checks} 项检测",
        f"",
        f"---",
        f"",
        f"## 漏洞详情",
        f"",
    ])

    for i, (fp, c) in enumerate(all_vulns, 1):
        lines.append(f"### {i}. {c.vuln_type} ({c.severity or 'info'})")
        lines.append(f"")
        lines.append(f"- **功能点**: {fp.name}")
        lines.append(f"- **URL**: {c.evidence_request or 'N/A'}")
        lines.append(f"- **严重级别**: {c.severity or 'info'}")
        if c.detail:
            lines.append(f"- **详情**: {c.detail}")
        if c.fix_suggestion:
            lines.append(f"- **修复建议**: {c.fix_suggestion}")
        lines.append(f"")

    return "\n".join(lines)


def _md_to_html(md_text: str, task_id: str) -> str:
    """Markdown 转简易 HTML。"""
    import html as _html

    lines = md_text.split("\n")
    html_lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>安全扫描报告 - {task_id}</title>",
        "<style>",
        "body{font-family:-apple-system,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#333;line-height:1.6}",
        "h1{color:#1a202c;border-bottom:2px solid #6366f1;padding-bottom:8px}",
        "h2{color:#2d3748;margin-top:32px}",
        "h3{color:#4a5568}",
        "table{border-collapse:collapse;width:100%;margin:16px 0}",
        "th,td{border:1px solid #e2e8f0;padding:8px 12px;text-align:left}",
        "th{background:#f7fafc;font-weight:600}",
        "code{background:#edf2f7;padding:2px 6px;border-radius:4px;font-size:13px}",
        "hr{border:none;border-top:1px solid #e2e8f0;margin:24px 0}",
        "</style></head><body>",
    ]
    for line in lines:
        if line.startswith("# "):
            html_lines.append(f"<h1>{_html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{_html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{_html.escape(line[4:])}</h3>")
        elif line.startswith("| "):
            html_lines.append(f"<p>{_html.escape(line)}</p>")
        elif line.startswith("**") and line.endswith("**"):
            html_lines.append(f"<p><strong>{_html.escape(line.strip('*'))}</strong></p>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{_html.escape(line[2:])}</li>")
        elif line.strip() == "---":
            html_lines.append("<hr>")
        elif line.strip() == "":
            html_lines.append("<br>")
        else:
            html_lines.append(f"<p>{_html.escape(line)}</p>")
    html_lines.append("</body></html>")
    return "\n".join(html_lines)


def _md_to_pdf(md_text: str, task_id: str) -> bytes:
    """Markdown 转简易 PDF（无第三方库时 fallback 到 HTML）"""
    # ★ io 必须在所有可能用到 io.BytesIO 的分支之前导入
    # 之前 xhtml2pdf 分支调用 io.BytesIO() 但 import io 在第 442 行才出现，会 NameError
    import io

    html = _md_to_html(md_text, task_id)
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except ImportError:
        pass
    try:
        from xhtml2pdf import pisa
        result = io.BytesIO()
        pisa.CreatePDF(io.StringIO(html), dest=result)
        return result.getvalue()
    except ImportError:
        pass
    try:
        import subprocess
        proc = subprocess.run(
            ["wkhtmltopdf", "-", "-"],
            input=html.encode("utf-8"),
            capture_output=True, timeout=30,
        )
        if proc.returncode == 0:
            return proc.stdout
    except Exception:
        pass
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        for line in md_text.split("\n"):
            if line.strip():
                story.append(Paragraph(line.replace("|", " "), styles["Normal"]))
        doc.build(story)
        return buf.getvalue()
    except Exception as e:
        # 所有 PDF 引擎都不可用时，返回 HTML 字节流兜底，避免整个下载接口 500
        log.warning("PDF 生成失败，fallback 到 HTML: %s", e)
        return html.encode("utf-8")


def _save_report_file(task_id: str, ext: str, content: str) -> Path:
    """保存报告文件到 data/reports/。"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{task_id}_report.{ext}"
    path.write_text(content, encoding="utf-8")
    log.info("报告已保存: %s", path)
    return path


# ============================================================
# 误报管理 API
# ============================================================

@router.post("/api/reports/{task_id}/false-positive")
async def mark_false_positive(
    task_id: str,
    vuln_type: str,
    url_pattern: str,
    reason: str = "",
):
    """标记漏洞为误报
    
    用户可以将特定漏洞标记为误报，系统会生成过滤规则，
    后续扫描将自动排除类似的误报。
    
    Args:
        task_id: 任务 ID
        vuln_type: 漏洞类型（如 "SQL注入", "XSS", "信息泄露" 等）
        url_pattern: URL 匹配模式（支持正则表达式）
        reason: 误报原因说明（可选）
        
    Returns:
        {"status": "ok", "rule_id": "..."} 成功时返回规则 ID
    """
    from core.false_positive_manager import get_fp_manager
    
    manager = get_fp_manager()
    rule = manager.mark_as_false_positive(
        vuln_type=vuln_type,
        url_pattern=url_pattern,
        reason=reason,
    )
    
    return {"status": "ok", "rule_id": rule.id}


@router.get("/api/reports/false-positives")
async def list_false_positives(vuln_type: str = ""):
    """获取误报规则列表
    
    Args:
        vuln_type: 可选，按漏洞类型筛选
        
    Returns:
        {"rules": [...], "count": N}
    """
    from core.false_positive_manager import get_fp_manager
    
    manager = get_fp_manager()
    rules = manager.get_rules(vuln_type=vuln_type if vuln_type else None)
    
    return {
        "rules": [
            {
                "id": r.id,
                "vuln_type": r.vuln_type,
                "pattern": r.pattern,
                "reason": r.reason,
                "created_at": r.created_at,
                "created_by": r.created_by,
                "hit_count": r.hit_count,
            }
            for r in rules
        ],
        "count": len(rules),
    }


@router.delete("/api/reports/false-positives/{rule_id}")
async def delete_false_positive(rule_id: str):
    """删除误报规则
    
    Args:
        rule_id: 规则 ID
        
    Returns:
        {"status": "ok"} 成功删除
        {"status": "error", "message": "..."} 规则不存在
    """
    from core.false_positive_manager import get_fp_manager
    
    manager = get_fp_manager()
    deleted = manager.delete_rule(rule_id)
    
    if deleted:
        return {"status": "ok"}
    else:
        return {"status": "error", "message": f"规则 {rule_id} 不存在"}
