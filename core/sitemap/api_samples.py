"""Sitemap — API 请求样本管理 Mixin。"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from core.sitemap.models import FeaturePoint
from core.sitemap.constants import STATIC_EXTS, STATIC_PATH_SEGS
from core.traffic_evidence import build_api_evidence, evidence_summary_lines

log = logging.getLogger("pentest_agent.sitemap")

# ★ 来源优先级：实际流量 > 爬虫/推测
_HIGH_PRIORITY_SOURCES = {
    "mitmproxy", "mitmproxy_sync", "mitmproxy_rescue",
    "browse_worker", "flow_watcher",
}

def _is_high_priority_source(discovered_by: str) -> bool:
    """判断来源是否为实际流量（模拟点击/代理抓包），优先级高于爬虫推测。"""
    return (discovered_by or "").lower() in _HIGH_PRIORITY_SOURCES


def classify_api_source(discovered_by: str = "", resource_type: str = "",
                        has_sample: bool = False) -> dict:
    """根据发现来源推导 API 可信度与测试策略。

    source_type:
      - real_flow：代理/浏览器/爬虫真实流量，可信度最高，可直接测试
      - crawler_flow：爬虫收集到的 xhr/fetch，通常也是真实流量
      - api_doc：Swagger/OpenAPI/Actuator/GraphQL 文档来源，需先验证可达性
      - js_static：JS 静态分析发现，需先校正 host/验证可达性
      - inferred：路径推测/CRUD 推测，低频验证优先
      - menu_api：菜单/路由接口来源，作为导航线索，测试前验证
      - unknown：未知来源，保守验证
    """
    source = (discovered_by or "").lower()
    rt = (resource_type or "").lower()

    if _is_high_priority_source(source) or source in {"supplemental", "phase2_flow"}:
        return {"source_type": "real_flow", "confidence": 0.95, "test_strategy": "direct"}
    if source in {"crawler", "crawl_worker"} or rt in {"xhr", "fetch", "proxy_captured"}:
        return {"source_type": "crawler_flow", "confidence": 0.9, "test_strategy": "direct"}
    if any(k in source for k in ("swagger", "openapi", "actuator", "graphql", "api_doc")):
        return {"source_type": "api_doc", "confidence": 0.78, "test_strategy": "verify_first"}
    if "js" in source or rt == "js_discovered":
        # 有真实样本时说明静态发现已被部分验证，置信度略升。
        return {
            "source_type": "js_static",
            "confidence": 0.68 if has_sample else 0.55,
            "test_strategy": "verify_first",
        }
    if "infer" in source or "path_inference" in source or rt == "inferred_verified":
        return {"source_type": "inferred", "confidence": 0.62, "test_strategy": "low_frequency"}
    if any(k in source for k in ("menu", "route", "router")):
        return {"source_type": "menu_api", "confidence": 0.72, "test_strategy": "verify_first"}
    if has_sample:
        return {"source_type": "real_flow", "confidence": 0.85, "test_strategy": "direct"}
    return {"source_type": "unknown", "confidence": 0.4, "test_strategy": "verify_first"}


class ApiSamplesMixin:
    """API 请求样本的存储、查询和文件输出。"""

    def add_api_sample(self, method: str, url: str, headers: dict = None,
                       body: str = "", status_code: int = 0,
                       discovered_by: str = "", response_body: str = "",
                       js_context: str = "",
                       response_headers: dict = None,
                       content_type: str = "",
                       flow_id: str = "",
                       trigger_context: dict | None = None,
                       evidence: dict | None = None) -> None:
        """存储一个 API 的完整请求样本（含参数），供 Phase 2 子 Agent 使用。

        去重规则（2026-05-24 改进）：
          key = METHOD + host + path + 参数指纹
          参数指纹：GET 请求取 query_params 的排序 JSON，其他请求取 body 的 MD5 前 8 位
          只有 host、path、请求参数完全相同的才视为重复，不同参数的请求各自保留。
          同 key 已存在时，仅在新样本有更完整响应时覆盖。
        """
        import hashlib
        from urllib.parse import urlparse, parse_qs

        # ★ 过滤静态资源（JS/CSS/图片/字体等不是 API）
        path_lower = url.split('?')[0].lower()
        if any(path_lower.endswith(ext) for ext in STATIC_EXTS):
            return

        # 也过滤明显的静态资源目录
        if any(seg in path_lower for seg in STATIC_PATH_SEGS):
            return

        parsed = urlparse(url)
        host = parsed.netloc or ""
        path = parsed.path.rstrip("/")

        # ★ 解析 query_params（先解析，用于去重 key 和后续存储）
        query_params = {}
        if parsed.query:
            query_params = {k: v[0] if len(v) == 1 else v
                           for k, v in parse_qs(parsed.query).items()}

        # ★ 过滤 XSS 扫描探测流量（不污染 sitemap）
        from core.packet_merger import _is_xss_scan_traffic
        if _is_xss_scan_traffic(url, query_params=query_params, request_body=body):
            return

        # ★ 去重 key：METHOD + host + path + 参数指纹
        _method_upper = method.upper()
        if _method_upper == "GET":
            param_fingerprint = json.dumps(query_params, sort_keys=True, ensure_ascii=False) if query_params else ""
        else:
            param_fingerprint = hashlib.md5((body or "").encode("utf-8", errors="replace")).hexdigest()[:8] if body else ""

        key = f"{_method_upper} {host}{path}|{param_fingerprint}" if host else f"{_method_upper} {path}|{param_fingerprint}"

        # ★ 跨 host 去重：如果同 path 已存在于不同 host 下，实际流量来源优先覆盖爬虫推测
        # 构造 path-only key 用于跨 host 查找
        _path_key = f"{_method_upper} {path}|{param_fingerprint}"
        _is_new_high_priority = _is_high_priority_source(discovered_by)
        for existing_key in list(self.api_samples.keys()):
            if existing_key == key:
                continue  # 同 key 的在下面处理
            # 提取已有样本的 path-only key 进行比较
            existing_sample = self.api_samples[existing_key]
            existing_path = existing_sample.get("path", "").rstrip("/")
            existing_method = existing_sample.get("method", "GET").upper()
            if existing_method == _method_upper and existing_path == path:
                # 同 method + 同 path，但 host 不同
                existing_source = existing_sample.get("discovered_by", "")
                _is_existing_high_priority = _is_high_priority_source(existing_source)
                if _is_new_high_priority and not _is_existing_high_priority:
                    # 新样本是实际流量，旧样本是爬虫推测 → 删除旧的，用新的替代
                    log.info("API 样本跨 host 覆盖: %s (来源:%s) → %s (来源:%s)",
                             existing_key, existing_source, key, discovered_by)
                    del self.api_samples[existing_key]
                    # 同步更新 sitemap.apis（如果存在的话）
                    old_api_key = f"{existing_method} {existing_sample.get('url', '')}"
                    if hasattr(self, 'apis') and old_api_key in self.apis:
                        del self.apis[old_api_key]
                    # ★ 同步更新功能点 related_apis 中的旧 URL 引用
                    old_api_ref = f"{existing_method} {existing_sample.get('url', '')}"
                    new_api_ref = f"{_method_upper} {url}"
                    if hasattr(self, 'features'):
                        for fp in self.features.values():
                            if old_api_ref in fp.related_apis:
                                fp.related_apis = [
                                    new_api_ref if r == old_api_ref else r
                                    for r in fp.related_apis
                                ]
                    break
                elif not _is_new_high_priority and _is_existing_high_priority:
                    # 旧样本是实际流量，新样本是爬虫推测 → 跳过新的
                    return

        # ★ 精确去重：只有 host + path + 参数完全相同才算重复
        if key in self.api_samples:
            existing = self.api_samples[key]
            # 实际流量来源始终覆盖爬虫推测来源（无论响应长度）
            existing_source = existing.get("discovered_by", "")
            if _is_new_high_priority and not _is_high_priority_source(existing_source):
                pass  # 高优先级覆盖低优先级
            elif len(response_body or "") > len(existing.get("response_body", "")):
                pass  # 继续往下，用新样本覆盖
            else:
                return  # 旧的更完整或一样，不覆盖

        # 用黑名单过滤无用 headers，保留所有可能的认证/业务 headers
        _SKIP_HEADERS = {
            "accept", "accept-encoding", "accept-language", "cache-control",
            "connection", "host", "origin", "referer", "sec-ch-ua",
            "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest",
            "sec-fetch-mode", "sec-fetch-site", "upgrade-insecure-requests",
            "user-agent", "pragma", "dnt", "te",
        }
        filtered_headers = {k: v for k, v in (headers or {}).items()
                           if k.lower() not in _SKIP_HEADERS}

        # ★ 保存安全相关的响应头（CORS/CSP/Set-Cookie/Server 等）
        _SECURITY_RESP_HEADERS = {
            "set-cookie", "location", "www-authenticate",
            "access-control-allow-origin", "access-control-allow-credentials",
            "access-control-allow-methods", "access-control-allow-headers",
            "x-frame-options", "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-powered-by", "server",
            "content-type", "content-disposition",
        }
        filtered_resp_headers = {}
        if response_headers:
            filtered_resp_headers = {k: v for k, v in response_headers.items()
                                    if k.lower() in _SECURITY_RESP_HEADERS}

        source_meta = classify_api_source(
            discovered_by=discovered_by,
            resource_type="proxy_captured" if status_code else "",
            has_sample=True,
        )
        evidence_obj = evidence or build_api_evidence(
            method=method,
            url=url,
            headers=filtered_headers or headers or {},
            body=body or "",
            status_code=status_code,
            response_headers=filtered_resp_headers or response_headers or {},
            response_body=response_body or "",
            flow_id=flow_id or "",
            discovered_by=discovered_by,
            trigger_context=trigger_context or {},
        )

        self.api_samples[key] = {
            "method": method,
            "url": url,
            "path": path,
            "query_params": query_params,
            "headers": filtered_headers,
            "body": body or "",
            "status_code": status_code,
            "discovered_by": discovered_by,
            "source_type": source_meta["source_type"],
            "confidence": source_meta["confidence"],
            "test_strategy": source_meta["test_strategy"],
            "response_body": (response_body or "")[:5000],
            "response_headers": filtered_resp_headers,
            "content_type": content_type or "",
            "js_context": (js_context or "")[:5000],
            "evidence_id": evidence_obj.get("evidence_id", ""),
            "flow_id": evidence_obj.get("flow_id", flow_id or ""),
            "trigger_context": evidence_obj.get("trigger_context", {}) or {},
            "evidence": evidence_obj,
        }

    def get_samples_for_feature(self, feature_id: str) -> list[dict]:
        """获取与某功能点关联的 API 请求样本列表。"""
        fp = self.features.get(feature_id)
        if not fp:
            return []

        samples = []
        for api_ref in fp.related_apis:
            from urllib.parse import urlparse
            parts = api_ref.split(" ", 1)
            if len(parts) == 2 and parts[0].isupper():
                method = parts[0]
                url_part = parts[1]
            else:
                method = ""
                url_part = api_ref

            parsed = urlparse(url_part)
            host = parsed.netloc or ""
            path = parsed.path.rstrip("/")

            # ★ 优先精确匹配：遍历 api_samples 找 METHOD + host + path 前缀完全一致的
            matched = False
            prefix = f"{method} {host}{path}|" if host else f"{method} {path}|"
            base_key = f"{method} {host}{path}" if host else f"{method} {path}"
            for k, v in self.api_samples.items():
                if k == base_key or k.startswith(prefix):
                    samples.append(v)
                    matched = True

            if not matched:
                # 模糊匹配：路径最后两段匹配
                path_tail = "/".join(path.split("/")[-2:]) if path else ""
                for k, v in self.api_samples.items():
                    if path_tail and path_tail in k:
                        samples.append(v)
                        break

        return samples

    @staticmethod
    def _pick_best_real_sample(candidates: list[dict], js_host: str = "") -> dict | None:
        """从多个真实流量样本中选出最可信的那个。

        选择优先级：
        1. 跟 JS 文件同域的 host（JS 从 a.com 加载 → API 大概率也是 a.com）
        2. 200 状态码 + JSON 响应（正常的业务响应，非重定向/错误）
        3. response_body 最长的（信息最完整）

        Args:
            candidates: 同 (method, path) 的多个真实流量样本
            js_host: JS 分析样本当前拼出的 host（通常是 JS 文件所在域名）
        """
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        from urllib.parse import urlparse

        def _score(sample: dict) -> tuple:
            """返回排序元组，值越大优先级越高"""
            url = sample.get("url", "")
            sample_host = urlparse(url).netloc.lower()

            # 因子 1: 跟 JS 文件同域 → 最高优先级
            same_domain = 1 if (js_host and sample_host == js_host.lower()) else 0

            # 因子 2: 200 状态码 + JSON 响应
            status = sample.get("status_code", 0)
            is_200 = 1 if status == 200 else 0
            resp_body = sample.get("response_body", "")
            is_json = 1 if ("json" in sample.get("content_type", "").lower()
                            or resp_body.strip().startswith("{")
                            or resp_body.strip().startswith("[")) else 0

            # 因子 3: response_body 长度
            body_len = len(resp_body)

            return (same_domain, is_200, is_json, body_len)

        return max(candidates, key=_score)

    def _correct_js_analysis_host(self) -> int:
        """对 js_analysis 来源的样本，用 mitmproxy/爬虫真实流量校正其 host。

        背景：JS 文件可能托管在 CDN 域名，js_result_to_crawl_data 仅靠 JS 文件所在域
        来拼接 url，可能拼出错误的 host（如 storage.360buyimg.com → 应为 manx.jd.com）。
        但 mitmproxy 实际抓到了同 path 的真实流量，host 是对的。

        本函数在校正后直接修改 api_samples 中的 url 和 path，确保后续
        flush_samples_to_files 写入 checklist 的 host 是正确的。

        Returns: 校正的样本数量
        """
        from urllib.parse import urlparse

        # 1) 建立 (method, path) → 真实流量样本列表的索引（mitmproxy/爬虫/crawl_worker 来源）
        _REAL_SOURCES = {"mitmproxy", "mitmproxy_sync", "crawler", "crawl_worker",
                         "browse_worker", "mitmproxy_rescue"}
        # 同 (method, path) 可能有多个 host 的真实流量，都收集起来
        real_by_method_path: dict[tuple[str, str], list[dict]] = {}
        for key, sample in self.api_samples.items():
            discovered = (sample.get("discovered_by") or "").lower()
            if not any(src in discovered for src in _REAL_SOURCES):
                continue
            m = (sample.get("method") or "").upper()
            p = (sample.get("path") or "").rstrip("/")
            if not m or not p:
                continue
            real_by_method_path.setdefault((m, p), []).append(sample)

        if not real_by_method_path:
            return 0

        # 2) 对 js_analysis 来源的样本做 host 校正
        corrected = 0
        keys_to_fix: list[tuple[str, dict, dict]] = []  # (old_key, sample, real_sample)
        for key, sample in list(self.api_samples.items()):
            discovered = (sample.get("discovered_by") or "").lower()
            if "js_analysis" not in discovered and "js" not in discovered.split("_"):
                continue
            m = (sample.get("method") or "").upper()
            p = (sample.get("path") or "").rstrip("/")
            if not m or not p:
                continue
            candidates = real_by_method_path.get((m, p))
            if not candidates:
                continue
            # JS 分析样本当前的 host
            old_host = urlparse(sample.get("url", "")).netloc.lower()
            # 多个 host 有同 path 的真实流量时，优先选：
            # 1. 跟 JS 文件同域的 host（JS 从 a.com 加载 → API 大概率也是 a.com）
            # 2. 200 + JSON 响应的（正常的业务响应）
            # 3. response_body 最长的（信息最完整）
            best = self._pick_best_real_sample(candidates, js_host=old_host)
            if best is None:
                continue
            # 检查 host 是否不同
            real_host = urlparse(best.get("url", "")).netloc.lower()
            if old_host == real_host:
                continue
            keys_to_fix.append((key, sample, best))

        for old_key, sample, real in keys_to_fix:
            # 用真实流量的 host 替换 JS 分析样本的 host
            old_url = sample.get("url", "")
            parsed = urlparse(old_url)
            real_parsed = urlparse(real.get("url", ""))
            new_url = f"{real_parsed.scheme}://{real_parsed.netloc}{parsed.path}"
            if parsed.query:
                new_url += f"?{parsed.query}"

            # 删除旧 key，用新 url 重新插入
            new_sample = dict(sample)
            new_sample["url"] = new_url
            new_sample["original_cdn_host"] = parsed.netloc.lower()
            del self.api_samples[old_key]

            # 构造新 key（与 add_api_sample 相同的逻辑）
            import hashlib
            _method_upper = sample.get("method", "GET").upper()
            _body = sample.get("body", "")
            _query_params = sample.get("query_params", {})
            if _method_upper == "GET":
                param_fp = json.dumps(_query_params, sort_keys=True, ensure_ascii=False) if _query_params else ""
            else:
                param_fp = hashlib.md5((_body or "").encode("utf-8", errors="replace")).hexdigest()[:8] if _body else ""
            new_host = real_parsed.netloc
            new_path = parsed.path.rstrip("/")
            new_key = f"{_method_upper} {new_host}{new_path}|{param_fp}"

            # 如果新 key 已存在真实流量，不覆盖（保留真实流量的完整信息）
            if new_key not in self.api_samples:
                self.api_samples[new_key] = new_sample
            corrected += 1

        if corrected:
            log.info("JS 分析样本 host 校正：%d 条已对齐真实流量 host", corrected)

        # 3) 统计学兜底：CDN 域名上的孤立 JS 分析样本，整体迁移到业务后端
        # 触发条件：某 CDN host 上 ≥ 3 个孤立样本，且真实流量中能找到一个
        # "业务后端 host"（/api/ 路径出现最多的 host），就把样本 url 的 host 改写过去
        try:
            from core.js_analyzer import _is_static_cdn_host
        except Exception:
            return corrected

        # 找出业务后端 host（按 /api/ 路径数量排序）
        # 统计所有真实流量来源的 /api/ 样本（不限于能精确匹配的）
        backend_score: dict[str, int] = {}
        for key, sample in self.api_samples.items():
            discovered = (sample.get("discovered_by") or "").lower()
            if not any(src in discovered for src in _REAL_SOURCES):
                continue
            p = (sample.get("path") or "")
            if not p.startswith("/api/"):
                continue
            url = sample.get("url", "")
            host = urlparse(url).netloc.lower()
            if not host:
                continue
            backend_score[host] = backend_score.get(host, 0) + 1

        if not backend_score:
            return corrected

        dominant_backend = max(backend_score.items(), key=lambda kv: kv[1])[0]
        dominant_count = backend_score[dominant_backend]
        if dominant_count < 2:
            return corrected  # 至少 2 条 /api/ 真实流量才可信

        # 按 CDN host 分组孤立样本（没被精确校正过的）
        cdn_orphans: dict[str, list[tuple[str, dict]]] = {}
        for key, sample in self.api_samples.items():
            discovered = (sample.get("discovered_by") or "").lower()
            if "js_analysis" not in discovered and "js" not in discovered.split("_"):
                continue
            url = sample.get("url", "")
            host = urlparse(url).netloc.lower()
            if not _is_static_cdn_host(host):
                continue
            p = (sample.get("path") or "")
            if not p.startswith("/api/"):
                continue
            cdn_orphans.setdefault(host, []).append((key, sample))

        rewritten = 0
        for cdn_host, items in cdn_orphans.items():
            if len(items) < 3:
                continue
            for old_key, sample in items:
                old_url = sample.get("url", "")
                parsed = urlparse(old_url)
                new_url = f"{parsed.scheme}://{dominant_backend}{parsed.path}"
                if parsed.query:
                    new_url += f"?{parsed.query}"

                new_sample = dict(sample)
                new_sample["url"] = new_url
                new_sample["original_cdn_host"] = cdn_host
                del self.api_samples[old_key]

                # 构造新 key
                import hashlib as _hl
                _method_upper = (sample.get("method") or "GET").upper()
                _body = sample.get("body", "")
                _qp = sample.get("query_params", {})
                if _method_upper == "GET":
                    _pfp = json.dumps(_qp, sort_keys=True, ensure_ascii=False) if _qp else ""
                else:
                    _pfp = _hl.md5((_body or "").encode("utf-8", errors="replace")).hexdigest()[:8] if _body else ""
                _new_path = parsed.path.rstrip("/")
                _new_key = f"{_method_upper} {dominant_backend}{_new_path}|{_pfp}"

                if _new_key not in self.api_samples:
                    self.api_samples[_new_key] = new_sample
                rewritten += 1

        if rewritten:
            log.info("孤立 CDN JS 样本改写到业务后端 %s：%d 条", dominant_backend, rewritten)
            corrected += rewritten

        # 4) 同步校正功能点 related_apis 中的 CDN host
        if corrected:
            self._fix_related_apis_cdn_host(dominant_backend if rewritten else None)

        return corrected

    def _fix_related_apis_cdn_host(self, dominant_backend: str | None = None) -> int:
        """校正功能点 related_apis 中残留的 CDN host。

        related_apis 格式为 'METHOD host/path'，如果 host 是 CDN 域名，
        需要替换为真实后端 host，否则 Phase 2 agent 用 related_apis 匹配样本时会匹配不到。
        """
        from urllib.parse import urlparse
        try:
            from core.js_analyzer import _is_static_cdn_host
        except Exception:
            return 0

        # 收集已知的 host 映射：CDN host → 真实 host（从 api_samples 的 original_cdn_host 字段获取）
        host_map: dict[str, str] = {}
        for sample in self.api_samples.values():
            orig_cdn = sample.get("original_cdn_host", "")
            if orig_cdn:
                real_host = urlparse(sample.get("url", "")).netloc.lower()
                if real_host and real_host != orig_cdn:
                    host_map[orig_cdn] = real_host

        # 如果有统计学兜底的 dominant_backend，也加入映射
        if dominant_backend:
            # 找所有 CDN host 上的孤立样本
            for key, sample in self.api_samples.items():
                discovered = (sample.get("discovered_by") or "").lower()
                if "js_analysis" not in discovered and "js" not in discovered.split("_"):
                    continue
                url = sample.get("url", "")
                host = urlparse(url).netloc.lower()
                if _is_static_cdn_host(host) and host not in host_map:
                    host_map[host] = dominant_backend

        if not host_map:
            return 0

        fixed = 0
        for fp in self.features.values():
            new_apis = []
            for api_ref in fp.related_apis:
                new_ref = api_ref
                for cdn_host, real_host in host_map.items():
                    if cdn_host in new_ref:
                        new_ref = new_ref.replace(cdn_host, real_host)
                        break
                if new_ref != api_ref:
                    fixed += 1
                new_apis.append(new_ref)
            fp.related_apis = new_apis

        if fixed:
            log.info("功能点 related_apis CDN host 校正：%d 处", fixed)
        return fixed

    def flush_samples_to_files(self) -> dict:
        """将每个功能点关联的 API 请求样本写入独立文件，供子 Agent 直接读取。

        文件路径: data/tasks/{task_id}-samples/{feature_id}.txt
        每个文件 ≤30K。分两个区域：
        - 「真实流量」：有完整请求信息（来自 mitmproxy/爬虫实际抓取）
        - 「推测接口」：只有 URL（来自 CRUD 推测验证，没有 body，需要子 Agent 自行探测参数）
        返回: {"total_files": N, "total_size_kb": M}
        """
        MAX_FILE_SIZE = 30000  # 30K

        # ★ 写入前校正 JS 分析样本的 host
        self._correct_js_analysis_host()

        samples_dir = Path("data/tasks") / f"{self.task_id}-samples"
        samples_dir.mkdir(parents=True, exist_ok=True)

        total_files = 0
        total_size = 0

        for fp_id, fp in self.features.items():
            samples = self.get_samples_for_feature(fp_id)
            if not samples:
                continue

            # 分类：真实流量 vs 推测接口
            real_samples = []
            inferred_samples = []
            for s in samples:
                discovered = (s.get("discovered_by", "") or "").lower()
                has_body = bool(s.get("body", ""))
                has_real_headers = len(s.get("headers", {})) > 1
                is_inferred = "infer" in discovered or "path_inference" in discovered
                is_empty_write = s.get("method", "GET") in ("POST", "PUT", "PATCH", "DELETE") and not has_body
                if is_inferred or (is_empty_write and not has_real_headers):
                    inferred_samples.append(s)
                else:
                    real_samples.append(s)

            # 按方法优先级排序：写操作优先
            method_priority = {"DELETE": 0, "PUT": 1, "POST": 2, "PATCH": 3, "GET": 4}
            real_samples.sort(key=lambda s: method_priority.get(s.get("method", "GET"), 5))

            lines = [
                f"# 功能点: {fp.name}",
                f"# 描述: {fp.description}",
                f"# 页面: {fp.page_url}",
                f"# 关联API: {', '.join(fp.related_apis)}",
                f"# 优先级: {fp.priority.value}",
                f"# 注意: Cookie/Token 可能已过期，以 session_info 中的认证信息为准。",
                "",
            ]

            # 如果有加密配置，写入头部
            if self.crypto_configs:
                lines.append("## 加密配置（目标网站使用前端加密，测试 payload 需先加密再发送）")
                lines.append("# 使用 crypto_encrypt 工具加密 payload，crypto_decrypt 解密响应")
                for i, cc in enumerate(self.crypto_configs):
                    algo = cc.get("algorithm", "?")
                    key_preview = (cc.get("key_hex", "") or "")[:16]
                    lines.append(f"# [{i}] {algo} key={key_preview}...")
                lines.append("")

            file_size = sum(len(l) for l in lines)

            # ====== Section 1: 真实流量 ======
            if real_samples:
                lines.append("## 真实流量（按 API 聚合，**同一 API 的多个变体都要逐个测试**）")
                lines.append("")
                api_groups = self._group_samples_by_api(real_samples)
                for (g_method, g_path), variants in api_groups.items():
                    block = self._format_api_group_block(g_method, g_path, variants)
                    block_text = "\n".join(block)
                    if file_size + len(block_text) > MAX_FILE_SIZE:
                        lines.append(f"# ... 已达 {MAX_FILE_SIZE // 1024}K 上限")
                        break
                    lines.extend(block)
                    file_size += len(block_text)

            # ====== Section 2: 推测接口 ======
            if inferred_samples:
                lines.append("")
                lines.append("## 推测接口（已验证真实存在，需根据 JS 源码构造请求参数）")
                lines.append("# ⛔ 禁止凭空猜测参数！必须根据下方 JS 代码理解调用逻辑后构造。")
                lines.append("# 如果没有 JS 上下文，先发 Content-Type: application/json + {} 观察报错再推断。")
                lines.append("")
                for sample in inferred_samples:
                    s_method = sample.get("method", "GET")
                    s_url = sample.get("url", "")
                    s_status = sample.get("status_code", 0)
                    js_ctx = sample.get("js_context", "")
                    status_info = f" (验证返回 {s_status})" if s_status else ""
                    lines.append(f"### {s_method} {s_url}{status_info}")

                    js_ctx_useful = bool(js_ctx) and len(js_ctx) > 100
                    if js_ctx_useful:
                        _low_markers = ("__vite__mapDeps", "chunkFileNames", "manualChunks", "assetFileNames")
                        if any(marker in js_ctx for marker in _low_markers):
                            js_ctx_useful = False

                    if js_ctx_useful:
                        lines.append("")
                        lines.append("**JS 调用代码（从前端源码中定位）：**")
                        lines.append("```javascript")
                        ctx_text = js_ctx[:3000]
                        if len(js_ctx) > 3000:
                            ctx_text += "\n// ... (截断)"
                        lines.append(ctx_text)
                        lines.append("```")
                        lines.append("⚠️ 请阅读上面的 JS 代码，理解该 API 的请求参数格式，然后构造测试请求。")
                    else:
                        lines.append("")
                        lines.append("**探测法构造请求（无 JS 源码可参考）：**")
                        if s_method in ("POST", "PUT", "PATCH"):
                            lines.append("1. 先发 `Content-Type: application/json` + `{}` 空 body → 观察报错")
                            lines.append("2. 报错通常会提示缺少的字段名（如 \"name 不能为空\"）")
                            lines.append("3. 根据报错补全字段，参考同前缀的真实流量推断字段类型")
                            lines.append("4. 如果返回 \"系统异常\" 无具体提示，尝试发 `{\"id\":1}` 或 `{\"name\":\"test\"}`")
                        elif s_method == "GET":
                            lines.append("1. 先发无参数请求 → 观察返回值")
                            lines.append("2. 如果返回列表数据，尝试添加 `?current=1&size=10` 分页参数")
                            lines.append("3. 如果返回 500，尝试 `?id=1` 或路径参数如 `/接口名/1`")
                        elif s_method in ("DELETE",):
                            lines.append("1. 先发 `?id=99999`（不存在的 ID）→ 观察返回值")
                            lines.append("2. 如果返回 \"数据不存在\" 则接口有效，可测未授权/IDOR")
                    lines.append("")

            file_path = samples_dir / f"{fp_id}.txt"
            content = "\n".join(lines)
            file_path.write_text(content, encoding="utf-8")
            total_files += 1
            total_size += len(content)

        return {"total_files": total_files, "total_size_kb": round(total_size / 1024, 1),
                "samples_dir": str(samples_dir)}

    @staticmethod
    def _format_sample_block(sample: dict) -> list[str]:
        """格式化单个 API 样本为文本块。（保留供兼容性使用）"""
        s_method = sample.get("method", "GET")
        s_url = sample.get("url", "")
        s_headers = sample.get("headers", {})
        s_body = sample.get("body", "")
        s_params = sample.get("query_params", {})
        s_status = sample.get("status_code", 0)
        s_resp_body = sample.get("response_body", "")
        s_resp_headers = sample.get("response_headers", {})
        s_content_type = sample.get("content_type", "")
        s_evidence = sample.get("evidence", {})

        block = ["---", f"{s_method} {s_url}"]
        block.extend(evidence_summary_lines(s_evidence))
        if s_status and s_status > 0:
            block.append(f"Status: {s_status}")
        if s_content_type:
            block.append(f"Content-Type: {s_content_type}")
        for hk, hv in s_headers.items():
            block.append(f"{hk}: {hv}")
        if s_params:
            block.append(f"QueryParams: {json.dumps(s_params, ensure_ascii=False)}")
        if s_body:
            block.append(f"Body: {s_body}")
        if s_resp_headers:
            resp_h_lines = [f"  {k}: {v}" for k, v in s_resp_headers.items()]
            block.append(f"ResponseHeaders:")
            block.extend(resp_h_lines)
        if s_resp_body:
            resp_preview = s_resp_body[:3000]
            if len(s_resp_body) > 3000:
                resp_preview += "...(截断)"
            block.append(f"Response: {resp_preview}")
        block.append("")
        return block

    @staticmethod
    def _group_samples_by_api(samples: list[dict]) -> dict:
        """把样本按 (method, path) 聚合分组。"""
        from urllib.parse import urlparse
        groups: dict[tuple, list[dict]] = {}
        for s in samples:
            method = (s.get("method", "GET") or "GET").upper()
            url = s.get("url", "") or s.get("path", "")
            try:
                path = urlparse(url).path.rstrip("/") or "/"
            except Exception:
                path = url.split("?")[0]
            key = (method, path)
            if key not in groups:
                groups[key] = []
            groups[key].append(s)
        return groups

    @staticmethod
    def _format_api_group_block(method: str, path: str,
                                 variants: list[dict]) -> list[str]:
        """格式化一个 API 分组（含多个参数变体）为文本块。"""
        block = ["---"]
        n = len(variants)
        if n == 1:
            block.append(f"### {method} {path}")
        else:
            block.append(f"### {method} {path}  ⚠️ 共 {n} 个参数变体，请**逐个测试**")
            if method == "GET":
                block.append(
                    f"# 提示：每个变体的 query 参数不同 → "
                    f"分页/排序参数测 IDOR/越权；搜索/过滤参数测 SQL注入/XSS"
                )
            else:
                block.append(
                    f"# 提示：每个变体的请求 body 不同 → "
                    f"对每个变体独立测试 SQL注入/Mass Assignment/越权（注意字段值差异是攻击线索）"
                )
            block.append("")

        for idx, sample in enumerate(variants, 1):
            s_url = sample.get("url", "")
            s_headers = sample.get("headers", {})
            s_body = sample.get("body", "")
            s_params = sample.get("query_params", {})
            s_status = sample.get("status_code", 0)
            s_resp_body = sample.get("response_body", "")
            s_resp_headers = sample.get("response_headers", {})
            s_content_type = sample.get("content_type", "")
            s_source_type = sample.get("source_type", "unknown")
            s_confidence = sample.get("confidence", 0)
            s_strategy = sample.get("test_strategy", "verify_first")
            s_evidence = sample.get("evidence", {})

            if n > 1:
                block.append(f"#### 变体 {idx}/{n}")
            block.append(f"```")
            block.append(f"{method} {s_url}")
            block.extend(evidence_summary_lines(s_evidence))
            block.append(
                f"Source: {s_source_type}; Confidence: {s_confidence}; Strategy: {s_strategy}"
            )
            if s_strategy == "verify_first":
                block.append("Hint: 先用当前方法和认证头验证接口可达，再进入漏洞测试。")
            elif s_strategy == "low_frequency":
                block.append("Hint: 低频探测，避免把推测接口当作真实完整流量批量 fuzz。")
            if s_status and s_status > 0:
                block.append(f"Status: {s_status}")
            if s_content_type:
                block.append(f"Content-Type: {s_content_type}")
            for hk, hv in s_headers.items():
                block.append(f"{hk}: {hv}")
            if s_params:
                block.append(f"QueryParams: {json.dumps(s_params, ensure_ascii=False)}")
            if s_body:
                block.append(f"Body: {s_body}")
            if s_resp_headers:
                block.append(f"ResponseHeaders:")
                for k, v in s_resp_headers.items():
                    block.append(f"  {k}: {v}")
            if s_resp_body:
                resp_preview = s_resp_body[:3000]
                if len(s_resp_body) > 3000:
                    resp_preview += "...(截断)"
                block.append(f"Response: {resp_preview}")
            block.append(f"```")
            block.append("")
        return block

    def get_sample_file_path(self, feature_id: str) -> str | None:
        """获取某功能点的流量样本文件路径。"""
        fp = self.features.get(feature_id)
        if not fp:
            return None
        file_path = Path("data/tasks") / f"{self.task_id}-samples" / f"{feature_id}.txt"
        return str(file_path) if file_path.exists() else None
