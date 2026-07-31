"""
Memory — 经验教训记忆库（Hermes 风格反馈学习）

设计目标：
- 让 Agent 从用户的对话纠正中沉淀经验，避免下次重蹈覆辙。
- 不依赖向量库 / Embedding，关键词召回足够覆盖 95% 场景。
- 单文件 JSONL 存储，可手动编辑、可备份、可同步。

数据结构（lessons.jsonl，每行一条）:
{
  "id": "lsn_xxx",
  "scope": "global | host | path | vuln_type",
  "scope_value": "" | "example.com" | "/api/user/*" | "sql_injection",
  "trigger": "短关键词（用于检索匹配，可多个，空格分隔）",
  "lesson": "经验内容（一句话），让 LLM 看了就知道怎么避坑",
  "evidence": "可选：原始误判的工具调用 / response 片段",
  "source": "user_correction | self_learn | manual",
  "created_at": "ISO time",
  "hits": 0,           # 被检索命中次数
  "enabled": true
}

API:
- record(scope, scope_value, trigger, lesson, ...) → 写入新教训
- recall(target_url, vuln_type, query) → 返回匹配的教训列表
- list_all(filters) → WebUI 列表
- toggle(id, enabled) / delete(id) / update(id, **fields)
- stats() → 统计

性能：内存里维护一个 list，写入时 append，启动时全读。
对一个项目（< 1 万条）完全够用。
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from core.log import get_logger

log = get_logger("memory")

_LESSONS_FILE = Path("data/memory/lessons.jsonl")
_LOCK = Lock()
_CACHE: list[dict] | None = None  # 内存缓存


# ============================================================
# 内部：加载 / 持久化
# ============================================================

def _ensure_dir() -> None:
    _LESSONS_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load() -> list[dict]:
    """加载所有教训到内存。文件不存在则返回空列表。"""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    _ensure_dir()
    items: list[dict] = []
    if _LESSONS_FILE.exists():
        try:
            for line in _LESSONS_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception as e:
                    log.warning("跳过损坏行: %s — %s", line[:80], e)
        except Exception as e:
            log.error("读取 lessons.jsonl 失败: %s", e)
    _CACHE = items
    return _CACHE


def _flush() -> None:
    """把全量缓存覆盖写回文件（适合 < 1 万条规模）。"""
    items = _load()
    _ensure_dir()
    tmp = _LESSONS_FILE.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    os.replace(tmp, _LESSONS_FILE)


def _new_id() -> str:
    return f"lsn_{int(time.time())}_{uuid.uuid4().hex[:6]}"


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ============================================================
# 公开 API：写入
# ============================================================

VALID_SCOPES = ("global", "host", "path", "vuln_type")


def record(
    scope: str,
    scope_value: str,
    trigger: str,
    lesson: str,
    evidence: str = "",
    source: str = "user_correction",
) -> dict:
    """记录一条教训。

    Args:
        scope: 作用域 — global / host / path / vuln_type
        scope_value: 值 — host="example.com", path="/api/login", vuln_type="sql_injection"
        trigger: 触发关键词（用于检索匹配，多个用空格分隔，建议 2-5 个）
        lesson: 经验本体，一句话说清楚"为什么之前错了 + 下次怎么做"
        evidence: 可选证据片段（误判的原文）
        source: 来源 — user_correction / self_learn / manual
    """
    if scope not in VALID_SCOPES:
        raise ValueError(f"scope 必须是 {VALID_SCOPES} 之一，得到: {scope}")
    if not lesson.strip():
        raise ValueError("lesson 不能为空")

    item = {
        "id": _new_id(),
        "scope": scope,
        "scope_value": scope_value or "",
        "trigger": (trigger or "").strip().lower(),
        "lesson": lesson.strip(),
        "evidence": (evidence or "")[:2000],
        "source": source,
        "created_at": _now(),
        "hits": 0,
        "enabled": True,
    }

    with _LOCK:
        items = _load()
        # 去重：同 scope+scope_value 下，lesson 高度相似就合并 trigger 而不是新加一条
        for it in items:
            if (it.get("scope") == scope and it.get("scope_value") == scope_value
                    and _similar(it.get("lesson", ""), lesson)):
                # 合并 trigger，不重复添加
                merged_triggers = set((it.get("trigger") or "").split()) | set(item["trigger"].split())
                it["trigger"] = " ".join(sorted(merged_triggers))
                it["lesson"] = lesson.strip()  # 用新版本（用户最新表达）
                if evidence:
                    it["evidence"] = item["evidence"]
                _flush()
                log.info("memory: 合并到已有教训 %s", it.get("id"))
                return it
        items.append(item)
        _flush()
    log.info("memory: 记录新教训 %s scope=%s value=%s", item["id"], scope, scope_value)
    return item


def _similar(a: str, b: str) -> bool:
    """简单相似度：去标点 + 前 30 字相同 → 视为同一条教训。"""
    norm = lambda s: re.sub(r"[\s，。,.!?！？\-\u3000]", "", s.lower())[:30]
    return bool(norm(a)) and norm(a) == norm(b)


# ============================================================
# 公开 API：检索
# ============================================================

def _host_of(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _path_of(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).path or ""
    except Exception:
        return ""


def _path_match(pattern: str, path: str) -> bool:
    """简易路径匹配：支持 * 通配符（如 /api/user/*）。"""
    if not pattern:
        return False
    if pattern == path:
        return True
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        try:
            return bool(re.match(regex, path))
        except Exception:
            return False
    return path.startswith(pattern)


# ★ 2026-05-22: vuln_type 命名不一致的兼容映射
# 问题：lessons 里 scope_value='idor'（英文小写），但 worker 实际传入 'IDOR越权'（中文）
#       原来用 `sv == vuln_type` 精确比对，永远不命中 → 记忆失效。
# 方案：把双方都归一化到一个语义簇，任一别名命中即视为匹配。
_VT_ALIASES: dict[str, set[str]] = {
    "idor": {"idor", "越权", "水平越权", "垂直越权", "越权查看", "越权导出",
             "broken object level authorization", "bola", "object_level_auth"},
    "unauth": {"未授权", "未授权访问", "unauthorized", "unauth", "auth_bypass",
               "401-403-bypass", "401_bypass", "403_bypass"},
    "sql_injection": {"sql", "sqli", "sql_injection", "sql注入", "注入"},
    "xss": {"xss", "cross_site_scripting", "跨站脚本", "stored_xss", "reflected_xss"},
    "csrf": {"csrf", "cross_site_request_forgery", "跨站请求伪造"},
    "ssrf": {"ssrf", "server_side_request_forgery", "服务器请求伪造"},
    "xxe": {"xxe", "xml_external_entity"},
    "rce": {"rce", "command_injection", "命令注入", "代码执行"},
    "info_disclosure": {"info_disclosure", "信息泄露", "敏感信息泄露", "information_disclosure"},
    "open_redirect": {"open_redirect", "开放重定向", "重定向"},
    "file_upload": {"file_upload", "文件上传", "文件上传绕过", "upload_bypass"},
    "race_condition": {"race_condition", "竞态条件", "并发", "并发领取", "重复使用"},
    "mass_assignment": {"mass_assignment", "属性覆盖", "参数注入"},
    "weak_password": {"weak_password", "弱密码", "默认密码", "弱密码/默认密码"},
    "user_enum": {"user_enum", "用户枚举", "枚举遍历", "枚举"},
    "captcha_bypass": {"captcha_bypass", "验证码绕过", "短信轰炸"},
    "amount_tamper": {"amount_tamper", "金额篡改", "状态篡改"},
    "cors": {"cors", "cors配置", "cors_misconfig"},
    "cookie_jwt": {"cookie_jwt", "cookie/jwt安全", "jwt", "session"},
    "password_reset": {"password_reset", "密码重置", "密码重置逻辑"},
    "js_audit": {"js_audit", "js代码审计", "hardcoded_secret", "硬编码密钥"},
}


def _vt_normalize(s: str) -> str:
    """归一化 vuln_type 文本：小写 + 去空格/斜杠/括号内容。"""
    if not s:
        return ""
    s = s.lower().strip()
    # 去掉括号注释，如 'JS代码审计(硬编码密钥/绕过逻辑)' → 'js代码审计'
    s = re.sub(r"[\(\（].*?[\)\）]", "", s)
    # 统一分隔符
    s = re.sub(r"[\s/\-_]+", "", s)
    return s


def _vt_match(sv: str, vt: str) -> bool:
    """vuln_type 模糊匹配：归一化 + 同义词簇 + 子串兜底。

    匹配链：
    1. 归一化后精确相等
    2. 双方落入同一同义词簇
    3. 任一方在另一方的归一化字符串中（子串）
    """
    if not sv or not vt:
        return False
    sv_n = _vt_normalize(sv)
    vt_n = _vt_normalize(vt)
    if not sv_n or not vt_n:
        return False
    if sv_n == vt_n:
        return True

    # 找出 sv / vt 各自落入的语义簇
    def _clusters_of(token: str) -> set[str]:
        clusters: set[str] = set()
        for cluster_key, aliases in _VT_ALIASES.items():
            # 归一化每个别名后比对
            normalized_aliases = {_vt_normalize(a) for a in aliases} | {cluster_key}
            for a in normalized_aliases:
                if a and (a == token or a in token or token in a):
                    clusters.add(cluster_key)
                    break
        return clusters

    sv_clusters = _clusters_of(sv_n)
    vt_clusters = _clusters_of(vt_n)
    if sv_clusters & vt_clusters:
        return True

    # 子串兜底（长度 ≥ 3 才生效，避免 'ss' 误匹配）
    if len(sv_n) >= 3 and (sv_n in vt_n or vt_n in sv_n):
        return True

    return False


def recall(
    target_url: str = "",
    vuln_type: str = "",
    query: str = "",
    limit: int = 8,
) -> list[dict]:
    """检索相关教训。

    匹配规则（按优先级排序，命中即纳入候选，最后取 top-N）：
    1. scope=global 永远纳入（除非 enabled=False）
    2. scope=host 且 scope_value == host(target_url)
    3. scope=path 且 scope_value 匹配 target_url 的路径（支持通配符）
    4. scope=vuln_type 且 scope_value 与 vuln_type 同义（中英别名、子串兜底）
    5. trigger 关键词与 query / vuln_type 子串命中
    """
    items = _load()
    host = _host_of(target_url)
    path = _path_of(target_url)
    q_raw = (query or "").lower()
    vt_raw = (vuln_type or "").lower()
    # 用于关键词召回的语料：query + vuln_type 合并
    haystack = f"{q_raw} {vt_raw}".strip()

    candidates: list[tuple[int, dict]] = []
    for it in items:
        if not it.get("enabled", True):
            continue
        score = 0
        scope = it.get("scope")
        sv = it.get("scope_value", "")

        if scope == "global":
            score += 1
        elif scope == "host" and host and sv == host:
            score += 5
        elif scope == "path" and path and _path_match(sv, path):
            score += 4
        elif scope == "vuln_type" and vuln_type and _vt_match(sv, vuln_type):
            score += 4
        else:
            # 不属于上述 scope 命中，仅靠 trigger 关键词召回（弱信号）
            pass

        # trigger 关键词命中：支持中英混合（按逗号/空格切分，子串匹配 haystack）
        trigger_raw = (it.get("trigger") or "").lower()
        trigger_tokens = [t.strip() for t in re.split(r"[\s,，;；]+", trigger_raw) if t.strip()]
        if haystack and trigger_tokens:
            for tk in trigger_tokens:
                if len(tk) >= 2 and tk in haystack:
                    score += 2
                    break

        if score > 0:
            candidates.append((score, it))

    # 按得分降序，再按创建时间降序（新经验优先）
    candidates.sort(key=lambda x: (x[0], x[1].get("created_at", "")), reverse=True)
    result = [it for _, it in candidates[:limit]]

    # 自增 hits（异步友好：直接修改缓存对象，定期 flush）
    if result:
        with _LOCK:
            for it in result:
                it["hits"] = int(it.get("hits", 0)) + 1
            _flush()
    return result


def format_for_prompt(lessons: list[dict]) -> str:
    """把召回的教训格式化成可注入 system prompt 的字符串。"""
    if not lessons:
        return ""
    lines = ["## 📚 历史经验（来自此前的纠正/总结，必须遵守）\n"]
    for i, it in enumerate(lessons, 1):
        scope_desc = it.get("scope", "")
        sv = it.get("scope_value", "")
        if sv:
            scope_desc += f"={sv}"
        lines.append(f"{i}. [{scope_desc}] {it.get('lesson', '')}")
    lines.append("\n⛔ 如果当前判断与上述经验冲突，请优先采纳经验，"
                 "并在结论里说明本案如何不同（避免再次误判）。")
    return "\n".join(lines)


# ============================================================
# 公开 API：管理
# ============================================================

def list_all(scope: str = "", enabled: str = "all", limit: int = 0) -> list[dict]:
    """列出全部教训（用于 WebUI）。

    Args:
        scope: 过滤作用域；空串 = 不过滤
        enabled: "true" / "false" / "all"
        limit: 0 = 不限
    """
    items = _load()
    out = []
    for it in items:
        if scope and it.get("scope") != scope:
            continue
        en = it.get("enabled", True)
        if enabled == "true" and not en:
            continue
        if enabled == "false" and en:
            continue
        out.append(dict(it))
    out.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    if limit > 0:
        out = out[:limit]
    return out


def get(lesson_id: str) -> dict | None:
    for it in _load():
        if it.get("id") == lesson_id:
            return dict(it)
    return None


def update(lesson_id: str, **fields) -> bool:
    allowed = {"scope", "scope_value", "trigger", "lesson", "evidence", "enabled"}
    bad = set(fields) - allowed
    if bad:
        raise ValueError(f"不允许修改字段: {bad}")
    if "scope" in fields and fields["scope"] not in VALID_SCOPES:
        raise ValueError(f"非法 scope: {fields['scope']}")
    with _LOCK:
        items = _load()
        for it in items:
            if it.get("id") == lesson_id:
                it.update({k: v for k, v in fields.items() if v is not None})
                _flush()
                return True
    return False


def toggle(lesson_id: str, enabled: bool) -> bool:
    return update(lesson_id, enabled=bool(enabled))


def delete(lesson_id: str) -> bool:
    with _LOCK:
        items = _load()
        before = len(items)
        items[:] = [it for it in items if it.get("id") != lesson_id]
        if len(items) == before:
            return False
        _flush()
    return True


def stats() -> dict:
    items = _load()
    by_scope: dict[str, int] = {}
    enabled_count = 0
    total_hits = 0
    for it in items:
        by_scope[it.get("scope", "?")] = by_scope.get(it.get("scope", "?"), 0) + 1
        if it.get("enabled", True):
            enabled_count += 1
        total_hits += int(it.get("hits", 0))
    return {
        "total": len(items),
        "enabled": enabled_count,
        "by_scope": by_scope,
        "total_hits": total_hits,
    }


def reload() -> int:
    """强制重读文件（外部修改了 jsonl 后调用）。返回总数。"""
    global _CACHE
    with _LOCK:
        _CACHE = None
        items = _load()
    return len(items)
