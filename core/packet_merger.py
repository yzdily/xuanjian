"""
packet_merger.py — 三路流量数据合并

将以下三个来源的流量信息合并为统一的 Packet 结构：
  1. sitemap.api_samples  — 爬虫/mitmproxy 抓取的请求样本（含 js_context）
  2. pentest_agent_flows.jsonl — mitmproxy 全量流量（完整响应，不截断）
  3. sitemap.features[].checklist[].evidence_* — 漏洞 PoC 证据包

合并策略：
  - 以 "METHOD path" 为 key 去重
  - 同一接口多次抓取：response_body 优先取最长的（flows 通常比 api_samples 更完整）
  - 保留所有来源的独有字段（js_context / evidence_flow_id 等）
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# ★ XSS 扫描流量过滤（2026-05-29）
# XSS 扫描模块会发送大量探测请求（参数值为 xPmInE9 或含 XSS payload），
# 这些请求不应出现在流量管理页面和 sitemap 中。
# ---------------------------------------------------------------------------

# XSS 参数发现的固定 marker
_XSS_PARAM_MARKER = "xPmInE9"

# XSS payload 特征模式（用于识别注入测试流量）
_XSS_PAYLOAD_PATTERNS = re.compile(
    r'<script|<svg[/\s>]|<img\s|onerror\s*=|onload\s*=|alert\(|javascript:|<x[a-z]{8,}>',
    re.IGNORECASE
)


def _is_xss_scan_traffic(url: str = "", query_params: dict | None = None,
                         request_body: str = "") -> bool:
    """识别是否为 XSS 扫描产生的探测流量。

    识别规则：
    1. URL 或参数中包含固定 marker（xPmInE9）
    2. 参数值中包含明显的 XSS payload 特征
    """
    # 规则 1: 固定 marker 检测
    if _XSS_PARAM_MARKER in url:
        return True
    if query_params:
        values = [str(v) for v in query_params.values()]
        if any(_XSS_PARAM_MARKER in v for v in values):
            return True
    if _XSS_PARAM_MARKER in (request_body or ""):
        return True

    # 规则 2: 参数值含 XSS payload 特征
    all_values = ""
    if query_params:
        all_values = " ".join(str(v) for v in query_params.values())
    all_values += " " + (request_body or "")
    if _XSS_PAYLOAD_PATTERNS.search(all_values):
        return True

    return False


# ---------------------------------------------------------------------------
# 统一数据结构
# ---------------------------------------------------------------------------

def _empty_packet() -> dict:
    return {
        "id": "",
        "method": "GET",
        "url": "",
        "path": "",
        "query_params": {},
        "request_headers": {},
        "request_body": "",
        "status_code": 0,
        "response_headers": {},
        "response_body": "",
        "content_type": "",
        "source": "",           # mitmproxy / crawler / inferred / evidence
        "timestamp": 0,
        "discovered_by": "",
        "js_context": "",
        "evidence_flow_id": "",  # 漏洞证据关联的 flow id
    }


def _dedup_key(method: str, url: str, query_params: dict | None = None,
               body: str = "") -> str:
    """去重 key：METHOD + host + path + 参数指纹（2026-05-24 改进）

    GET 请求：参数指纹 = query_params 排序 JSON
    其他请求：参数指纹 = body 的 MD5 前 8 位
    空 query/空 body → 指纹为空串
    """
    import hashlib
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.netloc or ""
        path = p.path
        _method = method.upper()

        # 参数指纹
        if _method == "GET":
            param_fp = json.dumps(query_params or {}, sort_keys=True, ensure_ascii=False) if query_params else ""
        else:
            param_fp = hashlib.md5((body or "").encode("utf-8", errors="replace")).hexdigest()[:8] if body else ""

        base = f"{_method} {host}{path}" if host else f"{_method} {path}"
        return f"{base}|{param_fp}" if param_fp else base
    except Exception:
        return f"{method.upper()} {url}"


def _parse_raw_http_text(raw: str) -> dict:
    """将原始 HTTP 文本（'GET /path HTTP/1.1\\nHeader: val\\n\\nbody'）解析为 dict。"""
    headers = {}
    body = ""
    try:
        lines = raw.replace("\r\n", "\n").split("\n")
        # 找空行分隔 headers 和 body
        sep = next((i for i, l in enumerate(lines) if l.strip() == ""), len(lines))
        for line in lines[1:sep]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        body = "\n".join(lines[sep + 1:]).strip()
    except Exception:
        pass
    return {"headers": headers, "body": body}


# ---------------------------------------------------------------------------
# 来源 1：api_samples
# ---------------------------------------------------------------------------

def _from_api_samples(api_samples: dict) -> dict[str, dict]:
    """将 sitemap.api_samples 转为 {dedup_key: Packet}"""
    result: dict[str, dict] = {}
    for raw_key, s in api_samples.items():
        method = s.get("method", "GET")
        url = s.get("url", "")
        if not url:
            continue
        # ★ 过滤 XSS 扫描流量
        if _is_xss_scan_traffic(url, s.get("query_params"), s.get("body", "")):
            continue
        key = _dedup_key(method, url,
                         query_params=s.get("query_params"),
                         body=s.get("body", ""))
        p = _empty_packet()
        p["id"] = f"sample_{raw_key.replace(' ', '_')}"
        p["method"] = method
        p["url"] = url
        p["path"] = s.get("path", "")
        p["query_params"] = s.get("query_params", {}) or {}
        p["request_headers"] = s.get("headers", {}) or {}
        p["request_body"] = s.get("body", "") or ""
        p["status_code"] = s.get("status_code", 0) or 0
        p["response_headers"] = s.get("response_headers", {}) or {}
        p["response_body"] = s.get("response_body", "") or ""
        p["content_type"] = s.get("content_type", "") or ""
        p["discovered_by"] = s.get("discovered_by", "") or ""
        p["js_context"] = s.get("js_context", "") or ""
        p["source"] = "crawler" if "crawler" in p["discovered_by"].lower() else "mitmproxy"
        result[key] = p
    return result


# ---------------------------------------------------------------------------
# 来源 2：pentest_agent_flows.jsonl
# ---------------------------------------------------------------------------

# ★ 2026-05-22 v3: flows 文件解析缓存
# 问题：flows 文件大（实测 62MB / 8783 行），每次 /api/traffic/{task_id} 都全量
#       read_text() + splitlines() + json.loads()，导致流量管理页"加载失败"假象
# 方案：按 (path, size, mtime) 缓存解析结果（dict[key] -> packet）
#       文件追加时 mtime/size 变化自动失效
# 注意：缓存的是"解析后的全量条目"（按 host_in_scope 分组），按需过滤
_FLOWS_CACHE: dict[tuple, list[dict]] = {}
_FLOWS_CACHE_MAX_ENTRIES = 4  # 最多缓存 4 个不同状态的 flows 文件（够用）


def _load_flows_lines_cached(flows_path: Path) -> list[dict]:
    """按文件 (path, size, mtime) 缓存解析过的 flows 行（dict 列表）。
    流式逐行读 + json.loads，避免一次性 read_text 阻塞事件循环。
    """
    try:
        st = flows_path.stat()
        cache_key = (str(flows_path), st.st_size, int(st.st_mtime))
    except Exception:
        return []

    cached = _FLOWS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    parsed: list[dict] = []
    try:
        # 流式逐行读，避免 read_text() 一次性吃满内存（62MB → 60+MB peak）
        with flows_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []

    # 简单 LRU：超过容量丢最旧的（key 是 tuple，dict 插入顺序即时间序）
    if len(_FLOWS_CACHE) >= _FLOWS_CACHE_MAX_ENTRIES:
        try:
            oldest = next(iter(_FLOWS_CACHE))
            _FLOWS_CACHE.pop(oldest, None)
        except StopIteration:
            pass
    _FLOWS_CACHE[cache_key] = parsed
    return parsed


def _from_flows_file(flows_path: Path, target_host: str = "",
                     time_start: float = 0, time_end: float = 0,
                     in_scope_hosts: set[str] | None = None) -> dict[str, dict]:
    """从全量 flows 文件读取流量，可按 target_host 和时间范围过滤。

    Args:
        time_start: Unix 时间戳，只读取此时间之后的流量（0=不限）
        time_end:   Unix 时间戳，只读取此时间之前的流量（0=不限）
        in_scope_hosts: 完整 in-scope host 集合（target + extra_scope + 同 SLD 兜底）。
                        若提供，则覆盖 target_host 的简单匹配，按精确/后缀匹配。
                        ★ 2026-05-22 修复：避免 moa.jd.com 任务丢失 soa.jd.com 流量。
    """
    result: dict[str, dict] = {}
    if not flows_path.exists():
        return result

    # ★ v3: 用缓存版本读取（流式 + (path,size,mtime) 缓存）
    flows = _load_flows_lines_cached(flows_path)
    if not flows:
        return result

    for flow in flows:
        url = flow.get("url", "")
        method = flow.get("method", "GET")
        if not url or not method:
            continue

        # ★ 时间范围过滤：只取属于本次任务的流量，避免同一目标多次分析混合
        if time_start or time_end:
            ts = float(flow.get("timestamp", 0) or 0)
            if time_start and ts < time_start:
                continue
            if time_end and ts > time_end:
                continue

        # ★ 2026-05-22: scope 过滤
        # 优先用 in_scope_hosts（含 extra_scope + 同 SLD 兜底），否则降级到 target_host 子串匹配
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.lower()
        except Exception:
            host = ""

        if in_scope_hosts:
            # 精确匹配 或 后缀匹配（host=soa.jd.com 命中 jd.com）
            if not _host_matches_scope(host, in_scope_hosts):
                continue
        elif target_host:
            if target_host not in host:
                continue

        # 跳过静态资源
        if any(url.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".ico", ".woff", ".ttf", ".svg")):
            continue

        p = _empty_packet()
        p["id"] = flow.get("id", "")
        p["method"] = method
        p["url"] = url

        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            p["path"] = parsed.path
            p["query_params"] = {k: v[0] if len(v) == 1 else v
                                 for k, v in parse_qs(parsed.query).items()}
        except Exception:
            p["path"] = url

        # flows 的 headers 可能是 dict 或 JSON 字符串
        rh = flow.get("request_headers", {})
        if isinstance(rh, str):
            try:
                rh = json.loads(rh.replace("'", '"'))
            except Exception:
                rh = {}
        p["request_headers"] = rh or {}
        p["request_body"] = flow.get("request_body", "") or ""

        # ★ 过滤 XSS 扫描流量（不展示在流量管理页面）
        if _is_xss_scan_traffic(url, p["query_params"], p["request_body"]):
            continue

        # ★ 去重 key 含参数指纹（在 query_params 和 request_body 解析完之后计算）
        key = _dedup_key(method, url,
                         query_params=p["query_params"],
                         body=p["request_body"])

        p["status_code"] = int(flow.get("status_code", 0) or 0)

        resp_h = flow.get("response_headers", {})
        if isinstance(resp_h, str):
            try:
                resp_h = json.loads(resp_h.replace("'", '"'))
            except Exception:
                resp_h = {}
        p["response_headers"] = resp_h or {}
        p["response_body"] = flow.get("response_body", "") or ""
        p["content_type"] = flow.get("content_type", "") or ""

        ts = flow.get("timestamp", 0)
        try:
            p["timestamp"] = float(ts)
        except Exception:
            p["timestamp"] = 0

        p["source"] = "mitmproxy"

        # 同 key 已存在时，保留 response_body 更完整的那个
        if key in result:
            existing = result[key]
            if len(p["response_body"]) > len(existing["response_body"]):
                # 保留新的 response，但保留旧的 js_context / discovered_by
                p["js_context"] = existing.get("js_context", "")
                p["discovered_by"] = existing.get("discovered_by", "")
                result[key] = p
        else:
            result[key] = p

    return result


# ---------------------------------------------------------------------------
# 来源 3：checklist evidence
# ---------------------------------------------------------------------------

def _from_checklist_evidence(features: dict) -> list[dict]:
    """从 checklist 里提取漏洞 PoC 证据包，返回列表（不去重，每条漏洞独立）。"""
    packets = []
    for fp_id, fp in features.items():
        fp_name = fp.get("name", "")
        for c in fp.get("checklist", []):
            result = c.get("result", "")
            if result not in ("vulnerable", "needs_review"):
                continue
            ev_req = c.get("evidence_request", "") or ""
            ev_resp = c.get("evidence_response", "") or ""
            ev_flow = c.get("evidence_flow_id", "") or ""
            if not ev_req and not ev_flow:
                continue

            p = _empty_packet()
            p["source"] = "evidence"
            p["evidence_flow_id"] = ev_flow
            p["id"] = f"evidence_{fp_id}_{c.get('vuln_type','')}"

            if ev_req:
                # 解析原始 HTTP 文本
                first_line = ev_req.split("\n")[0].strip()
                parts = first_line.split()
                if len(parts) >= 2:
                    p["method"] = parts[0]
                    p["url"] = parts[1] if parts[1].startswith("http") else parts[1]
                    p["path"] = parts[1]
                parsed = _parse_raw_http_text(ev_req)
                p["request_headers"] = parsed["headers"]
                p["request_body"] = parsed["body"]

            if ev_resp:
                first_line = ev_resp.split("\n")[0].strip()
                m = re.search(r"\b(\d{3})\b", first_line)
                if m:
                    p["status_code"] = int(m.group(1))
                parsed = _parse_raw_http_text(ev_resp)
                p["response_headers"] = parsed["headers"]
                p["response_body"] = parsed["body"]

            # 附加漏洞元信息
            p["_vuln_meta"] = {
                "fp_id": fp_id,
                "fp_name": fp_name,
                "vuln_type": c.get("vuln_type", ""),
                "result": result,
                "detail": c.get("detail", ""),
                "severity": c.get("severity", ""),
                "reproduce_steps": c.get("reproduce_steps", ""),
                "fix_suggestion": c.get("fix_suggestion", ""),
            }
            packets.append(p)
    return packets


# ---------------------------------------------------------------------------
# 主合并入口
# ---------------------------------------------------------------------------

def _parse_task_time_range(task_id: str,
                           all_task_ids: list[str] | None = None) -> tuple[float, float]:
    """从 task_id（格式 task_{timestamp}_{hex6}）推算流量时间窗口。

    策略：
    - 开始：任务时间戳 - 5 分钟（容忍爬虫启动前的少量流量）
    - 结束：如果有 all_task_ids，取紧邻的下一个任务开始时间；否则 +24h
    """
    try:
        parts = task_id.split("_")
        if len(parts) >= 2:
            ts = float(parts[1])
            if ts > 1_000_000_000:
                time_start = ts - 300  # 前5分钟

                # 如果有全量 task_id 列表，找紧邻的下一个任务时间作为截止
                if all_task_ids:
                    next_ts = None
                    for other_id in all_task_ids:
                        if other_id == task_id:
                            continue
                        try:
                            other_ts = float(other_id.split("_")[1])
                            if other_ts > ts:  # 比当前任务晚
                                if next_ts is None or other_ts < next_ts:
                                    next_ts = other_ts
                        except Exception:
                            pass
                    if next_ts:
                        # 截止 = 下一个任务开始时间（重叠5分钟容忍）
                        time_end = next_ts + 60
                    else:
                        time_end = ts + 86400  # 最新任务，取24h
                else:
                    time_end = ts + 86400
                return time_start, time_end
    except Exception:
        pass
    return 0.0, 0.0


def _correct_inferred_host_via_flows(
    packets_map: dict[str, dict],
    flows_map: dict[str, dict],
) -> None:
    """对"JS 推测 + 状态码 0"的样本，用真实流量校正其 host。

    背景：JS 文件可能托管在 CDN 域名（如 storage.360buyimg.com），但调用的 API
    实际指向另一个真实后端（如 manx.jd.com）。js_result_to_crawl_data 仅靠 JS
    文件所在域来拼接，若白名单未覆盖该 CDN，就会拼出错误的 url。

    本函数在合并阶段做兜底校正：
    1. 找出 packets_map 里所有 "推测样本"（status_code=0 且 discovered_by 含 js_analysis）
    2. 对每个推测样本，在 flows_map 里搜索同 (method, path) 的真实流量
    3. 找到则：删除推测条目，让 flows 的真实条目走后续合并流程（不重复入图）
    4. 找不到则：保留推测条目，但打标 inferred_host=True，后续报表可识别

    修改 packets_map 就地生效。
    """
    # 1) 收集所有"推测样本" key
    inferred_keys: list[str] = []
    for key, pkt in packets_map.items():
        if pkt.get("status_code", 0) != 0:
            continue
        discovered = (pkt.get("discovered_by") or "").lower()
        if "js_analysis" not in discovered and "js" not in discovered.split("_"):
            continue
        inferred_keys.append(key)

    if not inferred_keys:
        return

    # 2) 给 flows_map 建一个 (method, path) → 真实 key 的索引（path 已去 query）
    flows_by_method_path: dict[tuple[str, str], str] = {}
    for fkey, fpkt in flows_map.items():
        m = (fpkt.get("method") or "").upper()
        p = fpkt.get("path") or ""
        if not m or not p:
            continue
        # 同 (method, path) 多 host 命中时，保留响应体最长的（最有用的那个真实流量）
        old_fkey = flows_by_method_path.get((m, p))
        if old_fkey is None:
            flows_by_method_path[(m, p)] = fkey
        else:
            if len(fpkt.get("response_body", "")) > len(flows_map[old_fkey].get("response_body", "")):
                flows_by_method_path[(m, p)] = fkey

    # 3) 对每个推测样本尝试校正
    corrected = 0
    orphaned = 0
    for ikey in inferred_keys:
        ipkt = packets_map[ikey]
        m = (ipkt.get("method") or "").upper()
        p = ipkt.get("path") or ""
        if not m or not p:
            continue
        real_fkey = flows_by_method_path.get((m, p))
        if real_fkey:
            # 真实流量存在 → 删掉推测条目，让 flows 的真实条目接管
            # 但把 js_context / discovered_by 留给 flow_p 用，避免丢失 JS 上下文
            real_pkt = flows_map[real_fkey]
            if ipkt.get("js_context") and not real_pkt.get("js_context"):
                real_pkt["js_context"] = ipkt["js_context"]
            if ipkt.get("discovered_by") and not real_pkt.get("discovered_by"):
                real_pkt["discovered_by"] = ipkt["discovered_by"]
            del packets_map[ikey]
            corrected += 1
        else:
            # 真实流量不存在 → 打标，让后续报表知道这是未验证的推测
            ipkt["inferred_host"] = True
            orphaned += 1

    # 4) 统计学兜底：CDN 域名上的孤立推测包，整体迁移到真实业务后端
    # 触发条件：某 CDN host 上 ≥ 3 个孤立推测，且 flows 里能找到一个"业务后端 host"
    # （即 flows 里出现最多 /api/ 路径的 host），就把推测包 url 改写过去
    if corrected or orphaned:
        try:
            from core.log import get_logger
            get_logger("packet_merger").info(
                "JS 推测样本 host 校正：%d 条对齐真实流量，%d 条孤立保留（标 inferred_host）",
                corrected, orphaned,
            )
        except Exception:
            pass

    _rewrite_orphans_to_dominant_backend(packets_map, flows_map)


def _rewrite_orphans_to_dominant_backend(
    packets_map: dict[str, dict],
    flows_map: dict[str, dict],
) -> None:
    """把孤立 inferred_host 推测包按"主流业务后端"启发式改写 url。

    背景：storage.360buyimg.com 是 CDN，里面的 JS 调用 path 全是 /api/...，
    但 mitmproxy 没抓到对应真实流量（用户没点到这些功能）。
    凭"path 风格 + 真实后端的 path 风格一致"可以高概率推断这些 path 也属于真实后端。

    策略：
    1) 从 flows_map 找出"业务后端 host"：path 以 /api/ 开头的请求数量最多的 host
    2) 对孤立推测包按"原 host -> path 前缀"分组，要求：
       - 原 host 是已知 CDN（_is_static_cdn_host）
       - 包数量 >= 3
       - 全部 path 都是 /api/ 风格
    3) 满足条件就把整组 url 的 host 替换为业务后端，并保留 inferred_host=True
       （让 LLM 知道这仍是推测，但 host 已校正到大概率正确的位置）
    """
    from urllib.parse import urlparse

    # 1) 找出业务后端 host（按 /api/ 路径数量排序）
    backend_score: dict[str, int] = {}
    for fpkt in flows_map.values():
        path = fpkt.get("path") or ""
        if not path.startswith("/api/") and not path.startswith("/API/"):
            continue
        url = fpkt.get("url") or ""
        host = urlparse(url).netloc.lower()
        if not host:
            continue
        backend_score[host] = backend_score.get(host, 0) + 1

    if not backend_score:
        return

    dominant_backend = max(backend_score.items(), key=lambda kv: kv[1])[0]
    dominant_count = backend_score[dominant_backend]
    if dominant_count < 5:
        # 业务后端真实流量太少（< 5 条），可信度不够，不做迁移
        return

    # 2) 按 CDN host 分组孤立推测包
    try:
        from core.js_analyzer import _is_static_cdn_host
    except Exception:
        return

    cdn_orphans: dict[str, list[str]] = {}  # cdn_host -> [packet keys]
    for key, pkt in packets_map.items():
        if not pkt.get("inferred_host"):
            continue
        url = pkt.get("url") or ""
        host = urlparse(url).netloc.lower()
        if not _is_static_cdn_host(host):
            continue
        path = pkt.get("path") or ""
        if not (path.startswith("/api/") or path.startswith("/API/")):
            continue
        cdn_orphans.setdefault(host, []).append(key)

    if not cdn_orphans:
        return

    # 3) 逐 CDN host 改写
    rewritten = 0
    for cdn_host, keys in cdn_orphans.items():
        if len(keys) < 3:
            continue
        for k in keys:
            pkt = packets_map[k]
            old_url = pkt.get("url") or ""
            parsed = urlparse(old_url)
            # 替换 host，保留 path / query / scheme
            new_url = f"{parsed.scheme}://{dominant_backend}{parsed.path}"
            if parsed.query:
                new_url += f"?{parsed.query}"
            pkt["url"] = new_url
            pkt["original_cdn_host"] = cdn_host  # 留个痕迹便于追溯
            # inferred_host 标记保留 — 因为这仍是推测
            rewritten += 1
        # 改写后 key 会重复（同 path 多次 CDN 推测会撞在新 backend 上），
        # 重新构造 dedup_key 防止后续误判
        # 但 packets_map 是从外面传进来的，最后再统一 dedup 即可

    if rewritten:
        try:
            from core.log import get_logger
            get_logger("packet_merger").info(
                "孤立 CDN 推测包改写到业务后端 %s：%d 条（基于 %d 条真实 /api/ 流量统计）",
                dominant_backend, rewritten, dominant_count,
            )
        except Exception:
            pass


def merge_packets(
    sitemap_data: dict,
    flows_path: Path | None = None,
    target_host: str = "",
) -> dict:
    """
    合并三路流量数据，返回：
    {
        "packets": [Packet, ...],        # 去重后的请求样本，按 path 排序
        "evidence_packets": [Packet, ...],# 漏洞 PoC 证据包（不去重）
        "stats": {...}
    }
    """
    api_samples = sitemap_data.get("api_samples", {}) or {}
    features = sitemap_data.get("features", {}) or {}

    # ★ 2026-05-22: 计算完整 in-scope host 集合
    # = target_host + extra_scope + 同 SLD 子域兜底
    # 解决场景: moa.jd.com 任务实际打到 soa.jd.com，但 extra_scope 为空导致流量被滤掉
    in_scope_hosts = _compute_in_scope_hosts(
        target_host=target_host,
        extra_scope=sitemap_data.get("extra_scope", []) or [],
        api_samples=api_samples,
    )

    # 来源 1：api_samples
    packets_map = _from_api_samples(api_samples)

    # 来源 2：flows（用 flows 的完整响应覆盖 api_samples 的截断响应）
    if flows_path is None:
        flows_path = Path("data/pentest_agent_flows.jsonl")

    # ★ 按 task_id 推算时间窗口，避免同一目标多次分析的 flows 混合
    task_id = sitemap_data.get("task_id", "")
    # 扫描所有已知任务 ID，用于计算相邻任务边界
    all_task_ids: list[str] = []
    try:
        tasks_dir = flows_path.parent / "tasks"
        if not tasks_dir.exists():
            tasks_dir = Path("data/tasks")
        all_task_ids = [
            f.name.replace("-sitemap.json", "")
            for f in tasks_dir.glob("*-sitemap.json")
        ]
    except Exception:
        pass
    time_start, time_end = _parse_task_time_range(task_id, all_task_ids)

    flows_map = _from_flows_file(flows_path, target_host=target_host,
                                 time_start=time_start, time_end=time_end,
                                 in_scope_hosts=in_scope_hosts)

    # ★ 2026-05-22 修复：JS 推测样本的 host 校正
    # 场景：JS 文件存在 storage.360buyimg.com（CDN），但真实后端在 manx.jd.com。
    # 之前 _from_api_samples 拼出的 url 是 https://storage.360buyimg.com/api/xxx（错），
    # 而 mitmproxy 实际抓到的是 https://manx.jd.com/api/xxx。
    # 这两条会因为 host 不同而被当成两个不同的 key。
    # 修复：对"status_code=0 且 discovered_by=js_analysis"的推测样本，
    # 若 flows 里能找到同 method + 同 path 的真实流量，则用真实 host 替换推测 host。
    _correct_inferred_host_via_flows(packets_map, flows_map)

    for key, flow_p in flows_map.items():
        if key in packets_map:
            existing = packets_map[key]
            # flows 的 response_body 更完整（不截断）→ 覆盖
            if len(flow_p["response_body"]) > len(existing["response_body"]):
                flow_p["js_context"] = existing.get("js_context", "")
                flow_p["discovered_by"] = existing.get("discovered_by", "")
                packets_map[key] = flow_p
            else:
                # 保留 api_samples 的，但补全 response_headers（flows 更完整）
                if not existing["response_headers"] and flow_p["response_headers"]:
                    existing["response_headers"] = flow_p["response_headers"]
                if not existing["id"]:
                    existing["id"] = flow_p["id"]
                existing["timestamp"] = flow_p["timestamp"]
        else:
            packets_map[key] = flow_p

    # 过滤掉纯推测（没有真实请求信息）且状态码为 0 的条目
    clean_packets = []
    for p in packets_map.values():
        if not p["url"]:
            continue
        # 跳过第三方域（google / cdn 等）
        if _is_third_party(p["url"]):
            continue
        clean_packets.append(p)

    # 按 path 排序
    clean_packets.sort(key=lambda p: (p.get("path", ""), p.get("method", "")))

    # 来源 3：evidence
    evidence_packets = _from_checklist_evidence(features)

    return {
        "packets": clean_packets,
        "evidence_packets": evidence_packets,
        "stats": {
            "total": len(clean_packets),
            "from_samples": len(api_samples),
            "from_flows": len(flows_map),
            "evidence": len(evidence_packets),
        },
    }


# ---------------------------------------------------------------------------
# 按功能点关联查询
# ---------------------------------------------------------------------------

def get_packets_for_feature(
    fp_id: str,
    sitemap_data: dict,
    all_packets: list[dict],
) -> list[dict]:
    """返回某个功能点关联的数据包列表。

    匹配策略（2026-05-22 修复）：
    related_apis 中条目可能是 "METHOD url"（带或不带 query）/ "METHOD /path"
    数据包 url 通常带 query string。所以按归一化 key 比对：
    - 标准化 key = "METHOD host+path"（去 query）
    - 同时支持 "METHOD path"（无 host）
    - 兼容只有 path 的 related_apis
    """
    features = sitemap_data.get("features", {}) or {}
    fp = features.get(fp_id)
    if not fp:
        return []

    raw_related = fp.get("related_apis", []) or []

    # 把 related_apis 归一化为多份 key 集合，用于宽松匹配
    related_full_keys: set[str] = set()    # METHOD host+path
    related_path_keys: set[str] = set()    # METHOD path
    for item in raw_related:
        if not item or not isinstance(item, str):
            continue
        parts = item.strip().split(None, 1)
        if len(parts) < 2:
            continue
        method = parts[0].upper()
        url_or_path = parts[1].strip()
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_or_path)
            if parsed.netloc:
                # 完整 URL：保留 host+path（去 query）
                related_full_keys.add(f"{method} {parsed.netloc}{parsed.path}")
                related_path_keys.add(f"{method} {parsed.path}")
            else:
                # 只有 path
                related_path_keys.add(f"{method} {parsed.path or url_or_path.split('?')[0]}")
        except Exception:
            related_path_keys.add(f"{method} {url_or_path.split('?')[0]}")

    result = []
    seen = set()
    for p in all_packets:
        method = (p.get("method") or "").upper()
        url = p.get("url") or ""
        path = p.get("path") or ""
        # 包归一化 key
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            full_key = f"{method} {parsed.netloc}{parsed.path}" if parsed.netloc else ""
        except Exception:
            full_key = ""
        path_key = f"{method} {path}"

        matched = False
        if full_key and full_key in related_full_keys:
            matched = True
        elif path_key in related_path_keys:
            matched = True

        if matched:
            key = _dedup_key(method, url,
                             query_params=p.get("query_params"),
                             body=p.get("request_body", ""))
            if key not in seen:
                seen.add(key)
                result.append(p)
    return result


def get_flow_by_id(flow_id: str, flows_path: Path | None = None) -> dict | None:
    """按 flow_id 从全量流量文件查找完整数据包。"""
    if not flow_id:
        return None
    if flows_path is None:
        flows_path = Path("data/pentest_agent_flows.jsonl")
    if not flows_path.exists():
        return None
    # ★ v3: 用缓存版（首次解析后命中即 O(N)，再次调用 O(N) on dict 列表，无 IO）
    try:
        for flow in _load_flows_lines_cached(flows_path):
            if flow.get("id") == flow_id:
                return flow
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _extract_sld(host: str) -> str:
    """从 host 提取二级域（SLD），用于同公司体系子域识别。

    例: soa.jd.com → jd.com, www.api.example.co.uk → example.co.uk
    简单实现：取最后 2 段；遇到 .co.uk / .com.cn 等已知二级 TLD 取最后 3 段。
    """
    if not host:
        return ""
    host = host.lower().lstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # 已知"二级 TLD"列表（公共后缀的常见情况）
    _DOUBLE_TLDS = {
        "co.uk", "co.jp", "co.kr", "co.in", "co.id", "co.za",
        "com.cn", "com.hk", "com.tw", "com.au", "com.sg", "com.my",
        "net.cn", "org.cn", "gov.cn", "ac.cn",
        "edu.cn", "edu.hk", "edu.tw",
    }
    last_two = ".".join(parts[-2:])
    if last_two in _DOUBLE_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _host_matches_scope(host: str, in_scope_hosts: set[str]) -> bool:
    """host 是否落在 scope 内：精确匹配或后缀匹配。"""
    if not host or not in_scope_hosts:
        return False
    host = host.lower().lstrip(".")
    if host in in_scope_hosts:
        return True
    for sc in in_scope_hosts:
        sc = (sc or "").lower().lstrip(".")
        if not sc:
            continue
        # host=soa.jd.com 命中 sc=jd.com（后缀匹配，必须是完整子域分隔）
        if host == sc or host.endswith("." + sc):
            return True
    return False


def _compute_in_scope_hosts(
    target_host: str,
    extra_scope: list,
    api_samples: dict,
) -> set[str]:
    """计算完整 in-scope host 集合。

    来源（按可信度从高到低）：
    1. target_host 本身
    2. sitemap.extra_scope（爬虫推断 + 用户提供）
    3. 与 target 同 SLD 的 host（兜底：避免 moa.jd.com 任务漏 soa.jd.com）
       仅从 api_samples 中提取，避免引入第三方域
    """
    result: set[str] = set()

    if target_host:
        result.add(target_host.lower().lstrip("."))

    for d in (extra_scope or []):
        if isinstance(d, str) and d:
            result.add(d.lower().lstrip("."))

    # ★ SLD 兜底：从 api_samples 里提取与 target 同 SLD 的子域
    target_sld = _extract_sld(target_host)
    if target_sld and target_sld not in _THIRD_PARTY_DOMAINS:
        try:
            from urllib.parse import urlparse
            for sample in (api_samples or {}).values():
                if not isinstance(sample, dict):
                    continue
                url = sample.get("url", "")
                if not url:
                    continue
                try:
                    h = urlparse(url).netloc.lower().lstrip(".")
                except Exception:
                    continue
                if not h:
                    continue
                # 同 SLD 才纳入
                sample_sld = _extract_sld(h)
                if sample_sld == target_sld:
                    result.add(h)
        except Exception:
            pass

    return result


_THIRD_PARTY_DOMAINS = {
    "google.com", "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "recaptcha.net", "gstatic.com", "doubleclick.net",
    "facebook.com", "fbcdn.net", "twitter.com", "linkedin.com",
    "getbeamer.com", "userpilot.io", "appcues.com", "appcues.net",
    "intercom.io", "hotjar.com", "mixpanel.com", "segment.com",
    "amplitude.com", "fullstory.com", "logrocket.com",
    "sentry.io", "bugsnag.com", "cdn.jsdelivr.net", "unpkg.com",
    "cloudflare.com", "fastly.net", "android.clients.google.com",
    "content-autofill.googleapis.com", "haystack.es",
}


def _is_third_party(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower()
        for blocked in _THIRD_PARTY_DOMAINS:
            if host == blocked or host.endswith("." + blocked):
                return True
        for kw in ("cdn.", "static.", "analytics.", "tracking.", "ads."):
            if host.startswith(kw):
                return True
    except Exception:
        pass
    return False
