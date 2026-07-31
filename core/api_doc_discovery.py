"""
API Doc Discovery — API 文档自动发现 + 端点提取

当爬虫/mitmproxy 拦截到包含 API 文档特征的响应时，自动：
1. 识别文档类型（Swagger / OpenAPI / Actuator / GraphQL）
2. 请求文档端点，提取所有 API 端点
3. 补全 sitemap，让后续 Phase 自动覆盖

集成点：
- crawler_core.py on_response → detect_and_extract()
- 可被任何拿到 response_body 的地方调用
"""

from __future__ import annotations

import re
import json
import logging
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger("pentest_agent.api_doc_discovery")


# ============================================================
# 指纹规则 — 三类 API 文档
# ============================================================

@dataclass
class DocFingerprint:
    """API 文档指纹"""
    name: str               # "Swagger UI"
    category: str           # swagger / actuator / graphql
    pattern: re.Pattern     # 匹配响应体或 URL 的正则
    severity: str           # critical / high / medium


DOC_FINGERPRINTS: list[DocFingerprint] = [
    # ---- Swagger / OpenAPI ----
    DocFingerprint("Swagger UI", "swagger",
        re.compile(r'swagger-ui\.(html|css|bundle)|"swagger"\s*:', re.IGNORECASE),
        "high"),
    DocFingerprint("OpenAPI JSON", "swagger",
        re.compile(r'"openapi"\s*:\s*"[23]\.', re.IGNORECASE),
        "high"),
    DocFingerprint("Swagger API JSON", "swagger",
        re.compile(r'"swagger"\s*:\s*"[2]', re.IGNORECASE),
        "high"),
    DocFingerprint("api-docs 端点", "swagger",
        re.compile(r'/v[1-3]/api-docs\b|/api-docs\b|/swagger-resources\b', re.IGNORECASE),
        "high"),

    # ---- Spring Boot Actuator ----
    DocFingerprint("Actuator 端点", "actuator",
        re.compile(r'/actuator/(env|health|info|beans|configprops|metrics|mappings|trace|dump|loggers)', re.IGNORECASE),
        "high"),
    DocFingerprint("Actuator 响应", "actuator",
        re.compile(r'"_links"\s*:\s*\{.*?"self".*?/actuator', re.IGNORECASE | re.DOTALL),
        "high"),

    # ---- GraphQL ----
    DocFingerprint("GraphiQL IDE", "graphql",
        re.compile(r'graphiql|graphql-playground', re.IGNORECASE),
        "high"),
    DocFingerprint("GraphQL Introspection", "graphql",
        re.compile(r'"__schema"\s*:|"queryType"\s*:|"mutationType"\s*:', re.IGNORECASE),
        "high"),
]


# ============================================================
# 公共入口：检测 + 提取
# ============================================================

async def detect_and_extract(
    url: str,
    response_body: str,
    response_headers: dict | None = None,
    sitemap: Sitemap | None = None,
    http_client=None,
    auth_headers: dict | None = None,
) -> list[dict]:
    """检测响应是否包含 API 文档特征，若命中则自动提取端点。

    Args:
        url: 当前响应的 URL
        response_body: 响应体文本（前 5000 字符即可）
        response_headers: 响应头（可选，用于辅助判断）
        sitemap: 站点地图实例，若提供则自动补全
        http_client: httpx.AsyncClient 实例，若提供则用于请求文档端点
        auth_headers: 认证头，用于请求文档端点

    Returns:
        [{"type": "swagger", "endpoints": [...], "doc_url": "..."}]
    """
    results = []

    # Step 1: 指纹匹配
    matched = _match_fingerprints(url, response_body)
    if not matched:
        return results

    log.info("API 文档发现: %s → %s (来源: %s)", url[:80], matched[0].name, matched[0].category)

    # Step 2: 对每个命中类型，尝试提取端点
    for fp in matched:
        if fp.category == "swagger":
            endpoints = await _extract_swagger(url, http_client, auth_headers)
            if endpoints:
                results.append({
                    "type": "swagger",
                    "doc_url": url,
                    "fingerprint": fp.name,
                    "endpoints": endpoints,
                })
        elif fp.category == "actuator":
            endpoints = await _extract_actuator(url, http_client, auth_headers)
            if endpoints:
                results.append({
                    "type": "actuator",
                    "doc_url": url,
                    "fingerprint": fp.name,
                    "endpoints": endpoints,
                })
        elif fp.category == "graphql":
            endpoints = await _extract_graphql(url, http_client, auth_headers)
            if endpoints:
                results.append({
                    "type": "graphql",
                    "doc_url": url,
                    "fingerprint": fp.name,
                    "endpoints": endpoints,
                })

    # Step 3: 如果提供了 sitemap，自动补全
    if sitemap and results:
        total_added = _populate_sitemap(sitemap, results)
        if total_added > 0:
            log.info("API 文档提取: 向 sitemap 补充了 %d 个 API 端点", total_added)

    return results


# ============================================================
# 指纹匹配
# ============================================================

def _match_fingerprints(url: str, body: str) -> list[DocFingerprint]:
    """对 URL + 响应体执行指纹匹配，返回命中的指纹列表。"""
    hits = []
    seen_categories: set[str] = set()
    for fp in DOC_FINGERPRINTS:
        # 同一类别只返回一次
        if fp.category in seen_categories:
            continue
        if fp.pattern.search(body) or fp.pattern.search(url):
            hits.append(fp)
            seen_categories.add(fp.category)
    return hits


# ============================================================
# Swagger / OpenAPI 端点提取
# ============================================================

async def _extract_swagger(
    current_url: str,
    http_client=None,
    auth_headers: dict | None = None,
) -> list[dict]:
    """从 Swagger/OpenAPI 文档提取所有 API 端点。

    尝试多种常见的文档 URL 模式。
    """
    parsed = urlparse(current_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 常见的 Swagger/OpenAPI 文档路径（按优先级）
    doc_paths = [
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-resources",
        "/api-docs",
        "/openapi.json",
        "/swagger.json",
        "/api/swagger.json",
        "/api/v2/api-docs",
        "/api/v3/api-docs",
    ]

    # 如果当前 URL 已经是文档端点，也加入候选
    current_path = parsed.path
    if current_path not in doc_paths:
        doc_paths.insert(0, current_path)

    endpoints: list[dict] = []

    for path in doc_paths:
        doc_url = f"{base}{path}"
        try:
            doc_body = await _safe_get(doc_url, http_client, auth_headers)
            if not doc_body:
                continue

            doc = json.loads(doc_body)

            # Swagger 2.x 格式
            if "paths" in doc:
                base_path = doc.get("basePath", "")
                for path_str, methods_dict in doc.get("paths", {}).items():
                    full_path = f"{base_path}{path_str}"
                    for method in methods_dict:
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                            summary = ""
                            method_obj = methods_dict.get(method, {})
                            if isinstance(method_obj, dict):
                                summary = method_obj.get("summary", "") or method_obj.get("description", "")
                            endpoints.append({
                                "method": method.upper(),
                                "path": full_path,
                                "summary": summary[:200],
                                "source": f"swagger:{path}",
                            })
                if endpoints:
                    log.info("Swagger 文档 (%s): 提取到 %d 个端点", path, len(endpoints))
                    return endpoints

            # OpenAPI 3.x 格式
            if "openapi" in doc and "paths" in doc:
                servers = doc.get("servers", [])
                base_path = ""
                if servers and isinstance(servers, list):
                    server_url = servers[0].get("url", "")
                    sp = urlparse(server_url)
                    base_path = sp.path.rstrip("/")
                for path_str, methods_dict in doc.get("paths", {}).items():
                    full_path = f"{base_path}{path_str}"
                    for method in methods_dict:
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                            summary = ""
                            method_obj = methods_dict.get(method, {})
                            if isinstance(method_obj, dict):
                                summary = method_obj.get("summary", "") or method_obj.get("description", "")
                            endpoints.append({
                                "method": method.upper(),
                                "path": full_path,
                                "summary": summary[:200],
                                "source": f"openapi3:{path}",
                            })
                if endpoints:
                    log.info("OpenAPI 3.x 文档 (%s): 提取到 %d 个端点", path, len(endpoints))
                    return endpoints

        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        except Exception as e:
            log.debug("Swagger 端点请求失败 %s: %s", doc_url[:80], e)
            continue

    return endpoints


# ============================================================
# Actuator 端点提取
# ============================================================

async def _extract_actuator(
    current_url: str,
    http_client=None,
    auth_headers: dict | None = None,
) -> list[dict]:
    """从 Spring Boot Actuator 提取信息。"""
    parsed = urlparse(current_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    endpoints: list[dict] = []
    sensitive_paths = [
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/info",
    ]

    for path in sensitive_paths:
        url = f"{base}{path}"
        try:
            body = await _safe_get(url, http_client, auth_headers)
            if not body:
                continue
            # 验证是 JSON 且不是空/错误响应
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("status") == 404:
                    continue
            except json.JSONDecodeError:
                continue

            # 从 mappings 端点提取 API 路由
            if path == "/actuator/mappings" and isinstance(data, dict):
                contexts = data.get("contexts", {})
                for _ctx_name, ctx_data in contexts.items():
                    mappings = ctx_data.get("mappings", {}).get("dispatcherServlets", {})
                    if isinstance(mappings, dict):
                        for _servlet_name, handler_list in mappings.items():
                            if isinstance(handler_list, list):
                                for handler in handler_list:
                                    details = handler.get("details", {})
                                    request_mapping = details.get("requestMappingConditions", {})
                                    patterns = request_mapping.get("patterns", [])
                                    methods = request_mapping.get("methods", [])
                                    if patterns:
                                        method = methods[0] if methods else "GET"
                                        for p in patterns:
                                            endpoints.append({
                                                "method": method.upper(),
                                                "path": p,
                                                "summary": f"Actuator mapping: {handler.get('handler', '')[:100]}",
                                                "source": "actuator:mappings",
                                            })

            # env 端点标记为敏感信息（不提取具体值，只标记存在）
            elif path == "/actuator/env":
                endpoints.append({
                    "method": "GET",
                    "path": "/actuator/env",
                    "summary": "⚠️ 环境变量泄露（含数据库连接串、密钥等）",
                    "source": "actuator:env",
                })

        except Exception as e:
            log.debug("Actuator 端点请求失败 %s: %s", url[:80], e)

    if endpoints:
        log.info("Actuator: 提取到 %d 个端点/信息", len(endpoints))
    return endpoints


# ============================================================
# GraphQL Schema 提取
# ============================================================

# GraphQL Introspection Query（只取类型和字段名，不取参数细节，控制大小）
_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name } }
      }
    }
  }
}
"""


async def _extract_graphql(
    current_url: str,
    http_client=None,
    auth_headers: dict | None = None,
) -> list[dict]:
    """从 GraphQL 端点执行 introspection query 提取 schema。"""
    parsed = urlparse(current_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 常见 GraphQL 端点
    graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/query", "/v1/graphql"]

    # 如果当前 URL 已经是 GraphQL 端点，优先使用
    current_path = parsed.path
    if current_path not in graphql_paths:
        graphql_paths.insert(0, current_path)

    endpoints: list[dict] = []

    for path in graphql_paths:
        url = f"{base}{path}"
        try:
            headers = dict(auth_headers or {})
            headers["Content-Type"] = "application/json"

            body_str = json.dumps({"query": _INTROSPECTION_QUERY})

            resp_body = await _safe_post(url, body_str, http_client, headers)
            if not resp_body:
                continue

            result = json.loads(resp_body)
            schema = result.get("data", {}).get("__schema", {})
            if not schema:
                continue

            query_type = (schema.get("queryType") or {}).get("name", "Query")
            mutation_type = (schema.get("mutationType") or {}).get("name", None)

            # 从 types 中提取 query/mutation 字段作为端点
            for t in schema.get("types", []):
                type_name = t.get("name", "")
                # 跳过内部类型
                if type_name.startswith("__"):
                    continue

                kind = t.get("kind", "")
                if kind != "OBJECT":
                    continue

                fields = t.get("fields") or []
                for f in fields:
                    field_name = f.get("name", "")
                    if not field_name:
                        continue

                    method = "MUTATION" if type_name == mutation_type else "QUERY"
                    type_info = f.get("type", {})
                    return_type = type_info.get("name") or (type_info.get("ofType") or {}).get("name", "") or "Unknown"

                    endpoints.append({
                        "method": method,
                        "path": f"{type_name}.{field_name}",
                        "summary": f"返回类型: {return_type}",
                        "source": f"graphql:introspection:{path}",
                    })

            if endpoints:
                log.info("GraphQL Schema (%s): 提取到 %d 个查询/变更", path, len(endpoints))
                return endpoints

        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        except Exception as e:
            log.debug("GraphQL 端点请求失败 %s: %s", url[:80], e)

    return endpoints


# ============================================================
# 辅助函数
# ============================================================

async def _safe_get(url: str, http_client=None, auth_headers: dict | None = None) -> str | None:
    """安全 GET 请求，返回响应文本或 None。"""
    try:
        if http_client:
            headers = dict(auth_headers or {})
            resp = await http_client.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                return resp.text[:500000]  # 限制最大 500K
        else:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
                headers = dict(auth_headers or {})
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.text[:500000]
    except Exception:
        pass
    return None


async def _safe_post(url: str, body: str, http_client=None, headers: dict | None = None) -> str | None:
    """安全 POST 请求，返回响应文本或 None。"""
    try:
        if http_client:
            resp = await http_client.post(url, content=body, headers=headers or {}, timeout=8)
            if resp.status_code == 200:
                return resp.text[:500000]
        else:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
                resp = await client.post(url, content=body, headers=headers or {})
                if resp.status_code == 200:
                    return resp.text[:500000]
    except Exception:
        pass
    return None


def _populate_sitemap(sitemap: Sitemap, results: list[dict]) -> int:
    """将提取到的端点写入 sitemap。

    Returns:
        新增 API 数量
    """
    from core.sitemap_models import APIEndpoint

    added = 0
    for result in results:
        doc_type = result.get("type", "")
        endpoints = result.get("endpoints", [])

        for ep in endpoints:
            method = ep.get("method", "GET")
            path = ep.get("path", "")

            # 构造完整 URL
            if path.startswith("http"):
                full_url = path
            else:
                parsed_target = urlparse(sitemap.target)
                base = f"{parsed_target.scheme}://{parsed_target.netloc}"
                full_url = f"{base}{path}"

            # GraphQL 的 path 是 TypeName.fieldName 格式，直接用
            if doc_type == "graphql":
                # GraphQL 端点特殊处理：path 存为 graphql:Query.xxx
                key = f"GRAPHQL {path}"
                if key not in sitemap.apis:
                    sitemap.apis[key] = APIEndpoint(
                        method="GRAPHQL",
                        url=full_url,
                        content_type="graphql",
                    )
                    # 存请求样本（GraphQL 的 body 格式）
                    sitemap.api_samples[f"GRAPHQL {sitemap.target}/graphql|graphql"] = {
                        "method": "GRAPHQL",
                        "url": f"{sitemap.target}/graphql",
                        "path": path,
                        "query_params": {},
                        "headers": {},
                        "body": json.dumps({"query": f"{{ {path.split('.')[-1]} }}"}),
                        "status_code": 0,
                        "discovered_by": f"api_doc_discovery:{ep.get('source', '')}",
                        "source_type": "api_doc",
                        "confidence": 0.78,
                        "test_strategy": "verify_first",
                        "response_body": "",
                        "response_headers": {},
                        "content_type": "graphql",
                        "js_context": ep.get("summary", ""),
                    }
                    added += 1
            else:
                # HTTP API
                api = sitemap.add_api(
                    method,
                    full_url,
                    discovered_by=f"api_doc_discovery:{ep.get('source', '')}",
                )
                if api:
                    api.content_type = doc_type
                    api.request_body_sample = ep.get("summary", "")
                    added += 1

                # 同时存请求样本
                sitemap.add_api_sample(
                    method=method,
                    url=full_url,
                    discovered_by=f"api_doc_discovery:{ep.get('source', '')}",
                    response_body="",
                    js_context=ep.get("summary", ""),
                )

    return added
