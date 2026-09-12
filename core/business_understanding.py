"""
业务理解模块 (Phase 0.5) — 在爬取完成后、Phase 1 之前,对目标系统做深度业务理解。

设计原则:
- 单次 LLM 调用 (大 prompt + 完整 sitemap 摘要)
- 失败/超时降级: 不阻断主链, 标记 unavailable 继续
- 产物结构化(JSON) + 自然语言总结, 同时供下游 Agent 消费和报告渲染
- 落盘到 sitemap.business_understanding, 任务重启可恢复
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from core.llm import LLMClient
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).parent / "prompts" / "business_understanding.md"


# ============================================================
# Context 拼装 — 精挑细选喂给 LLM 的输入,不能粗暴塞全量
# ============================================================
def build_context_for_llm(
    sitemap: "Sitemap",
    crawl_result: Optional[dict] = None,
    max_pages: int = 30,
    max_apis: int = 60,
    max_api_samples: int = 30,
) -> str:
    """从 sitemap 拼装精炼上下文。

    取舍原则:
    - 页面: 前 N 个有代表性的 URL(去重 query)
    - API: 全部 distinct endpoint (method+path 去重)
    - api_samples: 取前 N 个有完整请求 body 的样例(看字段结构)
    - 角色登录信息: 如果多角色, 列出每个角色的访问差异
    - JS 路由表: 列出 SPA 路由
    """
    parts: list[str] = []

    # === 目标基本信息 ===
    target = getattr(sitemap, "target", "") or ""
    business_label = ""
    if hasattr(sitemap, "business_type") and sitemap.business_type:
        bt = sitemap.business_type
        if isinstance(bt, dict):
            business_label = bt.get("description", "") or bt.get("name", "")
        else:
            business_label = str(bt)
    tech_stack = ""
    if hasattr(sitemap, "tech_stack") and sitemap.tech_stack:
        ts = sitemap.tech_stack
        if isinstance(ts, list):
            tech_stack = ", ".join(str(t) for t in ts[:10])
        elif isinstance(ts, dict):
            tech_stack = ", ".join(f"{k}: {v}" for k, v in list(ts.items())[:10])
        else:
            tech_stack = str(ts)
    parts.append(f"# 目标系统\n\n- URL: {target}")
    if business_label:
        parts.append(f"- 初步业务标签(爬虫推测): {business_label}")
    if tech_stack:
        parts.append(f"- 技术栈: {tech_stack}")
    parts.append("")

    # === 角色信息(从 crawl_result) ===
    if crawl_result:
        rounds_data = crawl_result.get("rounds_data") or []
        if rounds_data:
            parts.append("# 已识别的角色(多角色登录测试)\n")
            seen_roles = set()
            for rd in rounds_data:
                role = rd.get("role") or "anonymous"
                if role in seen_roles:
                    continue
                seen_roles.add(role)
                login_ok = rd.get("login_success")
                api_count = len(rd.get("api_endpoints") or {})
                parts.append(f"- **{role}** (登录: {'✅' if login_ok else '❌'}, "
                             f"该角色可访问 API 数: {api_count})")
            parts.append("")

    # === 页面 URL 清单 ===
    pages = getattr(sitemap, "pages", {}) or {}
    if pages:
        parts.append(f"# 页面清单 ({len(pages)} 个,展示前 {max_pages} 个)\n")
        # 取层级深的 + 有意义路径名
        page_urls = list(pages.keys())[:max_pages]
        for purl in page_urls:
            # 尝试取 title
            page = pages[purl]
            if isinstance(page, dict):
                title = page.get("title", "")
            else:
                title = getattr(page, "title", "")
            t_str = f" — {title[:60]}" if title else ""
            parts.append(f"- {purl}{t_str}")
        parts.append("")

    # === API 端点清单 ===
    apis = getattr(sitemap, "apis", {}) or {}
    if apis:
        api_list = []
        for api_key, api_info in apis.items():
            if hasattr(api_info, "url"):
                method = getattr(api_info, "method", "GET")
                url = getattr(api_info, "url", "")
            elif isinstance(api_info, dict):
                method = api_info.get("method", "GET")
                url = api_info.get("url", "")
            else:
                # api_key 形如 "GET http://..."
                parts2 = api_key.split(" ", 1)
                if len(parts2) == 2:
                    method, url = parts2
                else:
                    continue
            if url:
                # 去除 query 后去重
                base = url.split("?")[0]
                api_list.append((method.upper(), base))
        # 去重
        seen = set()
        uniq = []
        for m, u in api_list:
            key = f"{m} {u}"
            if key not in seen:
                seen.add(key)
                uniq.append((m, u))
        uniq = uniq[:max_apis]
        parts.append(f"# API 端点清单 ({len(apis)} 条原始记录,去重后 {len(uniq)})\n")
        for m, u in uniq:
            parts.append(f"- {m} {u}")
        parts.append("")

    # === API 样例(看字段结构) ===
    samples = getattr(sitemap, "api_samples", {}) or {}
    if samples:
        parts.append(f"# API 请求样例(含字段结构) — 前 {max_api_samples} 个\n")
        count = 0
        for sk, sample in samples.items():
            if count >= max_api_samples:
                break
            if not isinstance(sample, dict):
                continue
            url = sample.get("url", "")
            method = sample.get("method", "GET")
            body = sample.get("request_body") or sample.get("post_data") or ""
            resp_excerpt = sample.get("response_body", "") or sample.get("response_excerpt", "")
            if not url:
                continue
            count += 1
            parts.append(f"## {method} {url}")
            if body:
                body_short = str(body)[:400]
                parts.append(f"请求 body: `{body_short}`")
            if resp_excerpt:
                resp_short = str(resp_excerpt)[:300]
                parts.append(f"响应片段: `{resp_short}`")
            parts.append("")

    # === JS 路由(SPA) ===
    js_routes = getattr(sitemap, "js_routes", []) or []
    if js_routes:
        parts.append(f"# 前端路由清单 ({len(js_routes)} 条,展示前 30)\n")
        for r in js_routes[:30]:
            if isinstance(r, dict):
                p = r.get("path", "") or r.get("url", "")
                name = r.get("name", "")
                parts.append(f"- {p}" + (f" ({name})" if name else ""))
            else:
                parts.append(f"- {r}")
        parts.append("")

    # === 字段名清单(辅助识别敏感数据) ===
    all_fields: set[str] = set()
    for sample in samples.values():
        if not isinstance(sample, dict):
            continue
        body = sample.get("request_body") or ""
        if isinstance(body, str) and body.startswith("{"):
            try:
                obj = json.loads(body)
                _collect_fields(obj, all_fields)
            except Exception:
                pass
        # form fields
        try:
            if "&" in body and "=" in body:
                for pair in body.split("&"):
                    if "=" in pair:
                        all_fields.add(pair.split("=", 1)[0])
        except Exception:
            pass
    if all_fields:
        sorted_fields = sorted(all_fields)[:80]
        parts.append(f"# 已观察到的请求字段名 ({len(all_fields)} 个,展示前 80)\n")
        parts.append("`" + "`, `".join(sorted_fields) + "`")
        parts.append("")

    return "\n".join(parts)


def _collect_fields(obj: Any, out: set[str], depth: int = 0):
    """递归收集 JSON 对象的所有 leaf 字段名。"""
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            if isinstance(v, (dict, list)):
                _collect_fields(v, out, depth + 1)
    elif isinstance(obj, list) and obj:
        _collect_fields(obj[0], out, depth + 1)


# ============================================================
# 主入口: 调用 LLM 做业务理解
# ============================================================
async def analyze_business(
    sitemap: "Sitemap",
    llm: "LLMClient",
    crawl_result: Optional[dict] = None,
    timeout: float = 120.0,
) -> dict:
    """主入口: 跑业务理解, 返回结构化结果。

    Returns:
        {
            "status": "ok" / "error" / "timeout",
            "understanding": dict (LLM 解析的 JSON),
            "summary": str (中文总结),
            "raw_response": str (LLM 原文,用于报告 details),
            "elapsed": float,
            "error": str (如有),
        }
    """
    started = time.time()
    if not PROMPT_PATH.exists():
        return {
            "status": "error",
            "error": f"业务理解提示词文件缺失: {PROMPT_PATH}",
            "elapsed": 0,
        }

    try:
        system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
        user_context = build_context_for_llm(sitemap, crawl_result)
    except Exception as e:
        log.exception("business_understanding context build failed")
        return {"status": "error", "error": f"上下文拼装失败: {e}", "elapsed": 0}

    if not callable(getattr(llm, "chat", None)):
        understanding = _fallback_rule_based_understanding(sitemap, crawl_result)
        if understanding:
            return {
                "status": "degraded",
                "understanding": understanding,
                "summary": understanding.get("summary", "（规则推导生成，LLM 不可用）"),
                "raw_response": "",
                "elapsed": time.time() - started,
                "error": "LLM 未配置或不可调用，已降级到规则推导",
            }
        return {
            "status": "error",
            "error": "LLM 未配置或不可调用，且规则推导失败",
            "elapsed": time.time() - started,
        }

    # 调 LLM (用 asyncio.wait_for + to_thread 避免阻塞主 event loop)
    from core.llm import Message
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=user_context),
    ]

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(llm.chat, messages, caller="business_understanding"),
            timeout=timeout,
        )
        raw_text = response.content or ""
    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "error": f"LLM 调用超过 {timeout}s",
            "elapsed": time.time() - started,
        }
    except Exception as e:
        log.exception("business_understanding LLM call failed")
        return {
            "status": "error",
            "error": f"LLM 调用失败: {e}",
            "elapsed": time.time() - started,
        }

    # 解析 JSON + 中文总结
    understanding, summary = _parse_response(raw_text)

    # ★ 第一次解析失败 → 重试一次，强制 LLM 只输出 JSON（解决 70% 的 JSON 解析失败）
    if understanding is None and raw_text.strip():
        log.warning("business_understanding: 第一次未返回有效 JSON，重试一次（强制 JSON only）...")
        retry_messages = list(messages)
        # 把上次输出回填，再追加一条强约束指令
        retry_messages.append(Message(role="assistant", content=raw_text))
        retry_messages.append(Message(
            role="user",
            content=(
                "你刚才的输出无法被解析为 JSON。\n"
                "请**严格只输出一个 JSON 对象**，包裹在 ```json ... ``` 代码块中。\n"
                "禁止输出任何 JSON 之外的解释文字、markdown 标题、注释。\n"
                "JSON 内部所有字符串必须正确转义双引号和反斜杠。\n"
                "如果你之前的中文总结很重要，把它放进 JSON 的 'summary' 字段里。"
            ),
        ))
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(llm.chat, retry_messages, caller="business_understanding_retry"),
                # 重试用一半超时（避免在已经慢的 LLM 上叠加全长超时）
                timeout=max(30.0, timeout / 2),
            )
            raw_text_retry = response.content or ""
            understanding, summary_retry = _parse_response(raw_text_retry)
            if understanding is not None:
                # 重试解析成功，使用新的 summary（如果非空）
                if summary_retry:
                    summary = summary_retry
                raw_text = raw_text_retry  # 报告里展示重试后的版本
                log.info("business_understanding: 重试成功，已解析 JSON")
        except asyncio.TimeoutError:
            log.warning("business_understanding: 重试也超时")
        except Exception as e:
            log.warning("business_understanding: 重试失败: %s", e)

    elapsed = time.time() - started

    if understanding is None:
        # ★ 降级策略：JSON 解析失败时不阻塞流程，用规则推导生成基础理解
        log.warning("business_understanding: JSON 解析失败，降级到规则推导")
        understanding = _fallback_rule_based_understanding(sitemap, crawl_result)
        if understanding:
            return {
                "status": "degraded",
                "understanding": understanding,
                "summary": understanding.get("summary", "（规则推导生成，LLM 解析失败）"),
                "raw_response": raw_text[:5000],
                "elapsed": elapsed,
                "error": "LLM 响应 JSON 解析失败，已降级到规则推导",
            }
        return {
            "status": "error",
            "error": "无法从 LLM 响应解析出 JSON（含一次重试），规则推导也失败",
            "raw_response": raw_text[:5000],
            "elapsed": elapsed,
        }

    return {
        "status": "ok",
        "understanding": understanding,
        "summary": summary,
        "raw_response": raw_text[:50000],
        "elapsed": elapsed,
    }


def _fallback_rule_based_understanding(
    sitemap: "Sitemap",
    crawl_result: Optional[dict] = None,
) -> Optional[dict]:
    """规则推导的业务理解降级方案。

    当 LLM JSON 解析失败时，从 sitemap 的已有数据中用规则推导出
    一个基础的业务理解结果，确保下游 Phase 不会因缺少理解而阻塞。
    """
    if not sitemap:
        return None

    # 推导业务领域
    target = getattr(sitemap, "target", "") or ""
    target_lower = target.lower()
    domain_label = "Web 应用"
    sub_type = ""
    domain_keywords = {
        "电商": ["shop", "mall", "store", "cart", "order", "product", "商品", "订单"],
        "CMS": ["cms", "content", "article", "post", "文章", "内容"],
        "OA": ["oa", "office", "workflow", "审批", "办公"],
        "ERP": ["erp", "resource", "库存", "采购"],
        "后台管理": ["admin", "manage", "dashboard", "后台", "管理"],
        "API 网关": ["api", "gateway", "rest", "graphql"],
        "金融": ["pay", "bank", "finance", "account", "支付", "账户", "金融"],
        "教育": ["edu", "course", "exam", "learn", "课程", "考试"],
        "医疗": ["medical", "health", "patient", "患者", "医疗"],
    }
    for label, keywords in domain_keywords.items():
        if any(kw in target_lower for kw in keywords):
            domain_label = label
            break

    # 推导角色
    roles = []
    roles_crawled = getattr(sitemap, "roles_crawled", []) or []
    login_status = getattr(sitemap, "login_status", {}) or {}
    if roles_crawled:
        for role in roles_crawled:
            roles.append({
                "name": role,
                "capabilities": [],
                "cannot": [],
                "auth_method": "session" if login_status.get(role) else "unknown",
            })
    else:
        roles = [{"name": "anonymous", "capabilities": [], "cannot": [], "auth_method": "none"}]

    # 推导数据资产（从 API samples 的字段名推测）
    data_assets = []
    samples = getattr(sitemap, "api_samples", {}) or {}
    sensitive_fields = {"password", "phone", "mobile", "email", "idcard", "token", "secret", "key"}
    seen_assets = set()
    for sample in samples.values():
        if not isinstance(sample, dict):
            continue
        body = sample.get("request_body") or ""
        if isinstance(body, str) and body.startswith("{"):
            try:
                obj = json.loads(body)
                for k in obj.keys():
                    k_lower = k.lower()
                    if k_lower in sensitive_fields and k_lower not in seen_assets:
                        seen_assets.add(k_lower)
                        data_assets.append({
                            "name": k,
                            "attack_surface": "请求参数",
                            "flow_to": "服务端处理",
                        })
            except Exception:
                pass

    # 推导攻击假设（基于功能点和 API 生成基础假设）
    hypotheses = []
    features = getattr(sitemap, "features", {}) or {}
    for fp in list(features.values())[:15]:
        fp_name = getattr(fp, "name", "")
        fp_apis = getattr(fp, "related_apis", []) or []
        for api in fp_apis[:2]:
            api_url = api.split(" ", 1)[-1] if " " in api else api
            # 基础假设：每个 API 都可能存在未授权访问和参数篡改
            hypotheses.append({
                "role": roles[0].get("name", "") if roles else "",
                "test_endpoint": api_url,
                "vulnerability_type": "未授权访问",
                "test_method": "去除认证头后重放请求",
                "why_worth_testing": f"功能点 {fp_name} 的 API 可能缺少鉴权",
            })
            # 如果 URL 含 id 参数，推测 IDOR
            if "id" in api_url.lower():
                hypotheses.append({
                    "role": roles[0].get("name", "") if roles else "",
                    "test_endpoint": api_url,
                    "vulnerability_type": "IDOR",
                    "test_method": "修改 id 参数为其他用户 id",
                    "why_worth_testing": f"功能点 {fp_name} 的 API 含 id 参数，可能存在越权",
                })

    # 推导系统承诺
    promises = []
    if roles and len(roles) > 1:
        promises.append({
            "id": "P-001",
            "priority": "P1",
            "statement": "不同角色只能访问各自权限范围内的功能",
            "mechanism_guess": "基于角色的访问控制(RBAC)",
        })
    if data_assets:
        promises.append({
            "id": "P-002",
            "priority": "P1",
            "statement": "敏感数据(密码/手机号等)在传输和存储时需要加密",
            "mechanism_guess": "HTTPS + 密码哈希",
        })

    summary = f"目标系统为{domain_label}，识别到 {len(roles)} 个角色、{len(features)} 个功能点。" \
              f"（此为规则推导结果，LLM 深度理解不可用）"

    return {
        "domain": {
            "label": domain_label,
            "sub_type": sub_type,
            "confidence": 0.4,
            "evidence": ["基于 URL 路径关键词推导"],
        },
        "roles": roles,
        "data_landscape": data_assets,
        "critical_flows": [],
        "promises": promises,
        "top_3_directions": hypotheses[:3] if hypotheses else [],
        "attack_hypotheses": hypotheses[:20],
        "unknowns": ["LLM 解析失败，部分深度理解可能缺失"],
        "summary": summary,
    }


# ============================================================
# 响应解析
# ============================================================
def _parse_response(raw_text: str) -> tuple[Optional[dict], str]:
    """从 LLM 响应中提取 JSON 对象和中文总结。"""
    if not raw_text:
        return None, ""

    understanding: Optional[dict] = None

    # 1. 尝试 ```json ... ``` 代码块
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", raw_text)
    if m:
        try:
            understanding = json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            understanding = None

    # 2. fallback: 找第一个 { 到匹配的 }
    if understanding is None:
        start = raw_text.find("{")
        if start >= 0:
            # 简单 brace 计数
            depth = 0
            for i in range(start, len(raw_text)):
                if raw_text[i] == "{":
                    depth += 1
                elif raw_text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            understanding = json.loads(raw_text[start:i + 1])
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break

    # 3. 提取中文总结(JSON 之后的自然语言)
    summary = ""
    sum_match = re.search(r"(?:中文总结|总结|summary)\s*[:：]?\s*\n?([\s\S]+)$",
                          raw_text, re.IGNORECASE)
    if sum_match:
        summary = sum_match.group(1).strip()
        # 截到 500 字
        summary = summary[:500]
    else:
        # 取 JSON 之后的所有非空文本
        if understanding is not None:
            # 找 JSON 块结束位置, 取后续
            json_end = raw_text.rfind("}")
            if json_end > 0:
                after = raw_text[json_end + 1:].strip()
                # 去掉 ``` 之类
                after = re.sub(r"^```\s*", "", after).strip()
                if after:
                    summary = after[:500]

    return understanding, summary


# ============================================================
# 渲染辅助(供报告使用)
# ============================================================
def render_to_markdown(bu_result: dict) -> str:
    """把 business_understanding 结果渲染为 Markdown,用于报告章节。"""
    if not bu_result or bu_result.get("status") not in ("ok", "degraded"):
        err = bu_result.get("error", "未执行") if bu_result else "未执行"
        return f"> ⚠️ 业务理解未完成: {err}\n"

    # degraded 状态额外加一行提示
    header = ""
    if bu_result.get("status") == "degraded":
        header = "> ⚠️ 业务理解已降级到规则推导（LLM 解析失败），以下内容为自动推导结果\n\n"

    u = bu_result.get("understanding") or {}
    summary = bu_result.get("summary", "")
    lines: list[str] = []

    # 1.2.1 系统定位 (中文总结)
    if summary:
        lines.append("### 1.2.1 系统定位")
        lines.append("")
        lines.append(summary)
        lines.append("")

    # 1.2.2 领域判定
    domain = u.get("domain") or {}
    if domain:
        lines.append("### 1.2.2 领域判定")
        lines.append("")
        label = domain.get("label", "") if isinstance(domain, dict) else str(domain)
        sub = domain.get("sub_type", "") if isinstance(domain, dict) else ""
        conf = domain.get("confidence", 0) if isinstance(domain, dict) else 0
        evidence = domain.get("evidence", []) if isinstance(domain, dict) else []
        lines.append(f"- **领域**: {label}" + (f" / {sub}" if sub else ""))
        lines.append(f"- **置信度**: {conf}")
        if evidence:
            lines.append(f"- **判定证据**:")
            for ev in (evidence[:8] if isinstance(evidence, list) else [str(evidence)]):
                lines.append(f"  - {ev}")
        lines.append("")

    # 1.2.3 角色清单
    roles = u.get("roles") or []
    if roles:
        lines.append("### 1.2.3 角色清单")
        lines.append("")
        lines.append("| 角色 | 能力 | 不能 | 鉴权方式 |")
        lines.append("|------|------|------|----------|")
        for r in roles[:10]:
            if not isinstance(r, dict):
                continue
            name = r.get("name", "")
            caps = r.get("capabilities", []) or []
            cannot = r.get("cannot", []) or r.get("restrictions", []) or []
            auth = r.get("auth_method", "") or r.get("authentication", "")
            caps_str = "; ".join(str(c) for c in caps[:5]) if isinstance(caps, list) else str(caps)[:200]
            cannot_str = "; ".join(str(c) for c in cannot[:3]) if isinstance(cannot, list) else str(cannot)[:120]
            lines.append(f"| {name} | {caps_str[:150]} | {cannot_str[:120]} | {auth[:60]} |")
        lines.append("")

    # 1.2.4 关键数据资产
    data_landscape = u.get("data_landscape") or u.get("data_assets") or []
    if data_landscape:
        lines.append("### 1.2.4 关键数据资产与流动")
        lines.append("")
        for d in data_landscape[:10]:
            if not isinstance(d, dict):
                continue
            name = d.get("name", "") or d.get("asset", "")
            lines.append(f"**{name}**")
            lines.append("")
            # 兼容多种字段命名
            flow_fields = [
                ("from", "来源"), ("source", "来源"),
                ("processing", "处理"), ("process", "处理"),
                ("storage", "存储"), ("store", "存储"),
                ("consumer", "消费"), ("consumed_by", "消费"),
                ("flow_to", "流向"), ("destination", "流向"),
                ("attack_surface", "攻击面"), ("attack_surfaces", "攻击面"),
                ("owner", "所有者"),
            ]
            shown_keys = set()
            for k, label in flow_fields:
                if k in shown_keys:
                    continue
                v = d.get(k)
                if v:
                    shown_keys.add(k)
                    if isinstance(v, list):
                        v_str = "; ".join(str(x) for x in v[:6])
                    else:
                        v_str = str(v)[:300]
                    lines.append(f"- {label}: {v_str}")
            lines.append("")

    # 1.2.5 核心业务流程
    flows = u.get("critical_flows") or []
    if flows:
        lines.append("### 1.2.5 核心业务流程")
        lines.append("")
        for i, f in enumerate(flows[:7], 1):
            if not isinstance(f, dict):
                continue
            name = f.get("name", "") or f.get("flow", "")
            steps = f.get("steps", []) or f.get("step", [])
            state = f.get("state_machine", "")
            apis_used = f.get("involved_apis", []) or f.get("apis", [])
            assumptions = f.get("key_assumptions", []) or f.get("assumptions", [])

            lines.append(f"**流程 {i}: {name}**")
            lines.append("")
            if steps:
                if isinstance(steps, list):
                    lines.append(f"- 步骤: {' → '.join(str(s) for s in steps[:10])}")
                else:
                    lines.append(f"- 步骤: {str(steps)[:300]}")
            if state:
                lines.append(f"- 状态机: `{str(state)[:200]}`")
            if apis_used:
                if isinstance(apis_used, list):
                    lines.append(f"- 涉及接口: {', '.join(f'`{a}`' for a in apis_used[:6])}")
            if assumptions:
                lines.append(f"- 关键假设:")
                for a in (assumptions[:5] if isinstance(assumptions, list) else [str(assumptions)]):
                    lines.append(f"  - {a}")
            lines.append("")

    # 1.2.6 系统承诺与安全契约
    promises = u.get("promises") or []
    if promises:
        lines.append("### 1.2.6 系统承诺与安全契约")
        lines.append("")
        lines.append("| 优先级 | 承诺 | 兑现机制(推测) | 测试覆盖 |")
        lines.append("|-------|------|----------------|----------|")
        # 兼容外部回填的覆盖状态(coverage_status)
        coverage_map = bu_result.get("coverage_map") or {}
        for i, p in enumerate(promises[:25], 1):
            if not isinstance(p, dict):
                continue
            pid = p.get("id", f"P-{i:03d}")
            prio = p.get("priority", p.get("p_level", "P1")).upper()
            stmt = p.get("statement", "") or p.get("promise", "") or p.get("description", "")
            mech = p.get("mechanism_guess", "") or p.get("mechanism", "") or ""
            cov = coverage_map.get(pid, "⏸ 待测")
            stmt_short = str(stmt).replace("|", "\\|")[:200]
            mech_short = str(mech).replace("|", "\\|")[:150]
            lines.append(f"| {prio} | {stmt_short} | {mech_short} | {cov} |")
        lines.append("")

    # 1.2.7 最值得深挖的方向
    top3 = u.get("top_3_directions") or u.get("top3") or []
    if top3:
        lines.append("### 1.2.7 最值得深挖的 3 个方向")
        lines.append("")
        for i, t in enumerate(top3[:5], 1):
            if isinstance(t, dict):
                title = t.get("direction", "") or t.get("name", "") or t.get("title", "")
                reason = t.get("reason", "") or t.get("rationale", "")
                lines.append(f"{i}. **{title}** — {reason}")
            else:
                lines.append(f"{i}. {t}")
        lines.append("")

    # 1.2.8 未覆盖信息
    unknowns = u.get("unknowns") or []
    if unknowns:
        lines.append("### 1.2.8 未覆盖信息(需要补爬)")
        lines.append("")
        for u_item in unknowns[:10]:
            if isinstance(u_item, dict):
                lines.append(f"- {u_item.get('item', '') or u_item.get('description', '')}")
            else:
                lines.append(f"- {u_item}")
        lines.append("")

    # 1.2.9 LLM 推导的攻击假设(给下游消费)
    hypotheses = u.get("attack_hypotheses") or []
    if hypotheses:
        lines.append(f"### 1.2.9 业务理解推导的攻击假设 ({len(hypotheses)} 条)")
        lines.append("")
        lines.append("| # | 角色 | 接口/参数 | 漏洞类型 | 测试方法 | 为什么值得测 |")
        lines.append("|---|------|-----------|---------|----------|--------------|")
        for i, h in enumerate(hypotheses[:30], 1):
            if not isinstance(h, dict):
                continue
            role = h.get("role", "") or h.get("as_role", "")
            ep = h.get("test_endpoint", "") or h.get("endpoint", "") or h.get("target_url", "")
            param = h.get("param_to_modify", "") or h.get("param", "")
            vtype = h.get("vulnerability_type", "") or h.get("vuln_type", "")
            method = h.get("test_method", "") or h.get("method_describe", "") or h.get("describe", "")
            why = h.get("why_value", "") or h.get("why_worth_testing", "") or h.get("rationale", "")
            ep_param = f"`{ep}` / `{param}`" if param else f"`{ep}`"
            method_safe = str(method).replace("|", "\\|")[:120]
            why_safe = str(why).replace("|", "\\|")[:120]
            lines.append(
                f"| {i} | {role[:30]} | {ep_param[:80]} | {vtype[:30]} | "
                f"{method_safe} | {why_safe} |"
            )
        if len(hypotheses) > 30:
            lines.append("")
            lines.append(f"> 还有 {len(hypotheses) - 30} 条假设未列出，详见 JSON 数据。")
        lines.append("")

    return header + "\n".join(lines)
