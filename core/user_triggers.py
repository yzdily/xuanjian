"""
User Triggers — 用户自定义的"关键词→漏洞类型"触发规则。

设计目标：
- 让用户在 WebUI 上自助维护 FEATURE_VULN_MAPPING 的扩展规则
- 不污染 core/config.py 的默认精选表（保持只读基线）
- 持久化到 skills_my/_user_triggers.yaml（独立文件，可手编、可 diff、可入库）
- 启动 / 热重载时由 core.skill_registry.scan_skills 调用 load_user_triggers() 合并

YAML 文件格式（skills_my/_user_triggers.yaml）：

    rules:
      - keywords: [上传, upload]
        vuln_types: [文件上传绕过, XXE]
        note: "用户自定义：覆盖默认上传场景"  # 可选
      - keywords: [api, /v1/, /api/]
        vuln_types: [SSRF, IDOR越权]
        note: "API 路径全量增强"

规则与默认表的关系：
- 默认表（core/config.py FEATURE_VULN_MAPPING）保持只读
- 用户规则**追加**在默认表之后；功能点匹配时按顺序 OR 命中（不去重，去重逻辑在
  feature_gen._auto_suggest_tests 末端的 MAX_CHECKLIST_PER_FP 裁剪中处理）
"""

from __future__ import annotations

from pathlib import Path
import logging

log = logging.getLogger(__name__)

# 持久化路径：放在 skills_my/ 下方便和 SKILL.md 一起 git 管理
USER_TRIGGERS_PATH = Path("skills_my") / "_user_triggers.yaml"


def _try_import_yaml():
    """尝试导入 yaml；项目其他地方已用，此处兜底。"""
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        return None


def load_user_triggers(path: Path = USER_TRIGGERS_PATH) -> list[tuple[list[str], list[str]]]:
    """从 yaml 加载用户自定义触发规则。

    返回与 FEATURE_VULN_MAPPING 同结构的 list[(keywords, vuln_types)]。
    文件不存在 / yaml 不可用 / 解析失败时静默返回空列表（不抛异常）。
    """
    if not path.exists():
        return []

    yaml = _try_import_yaml()
    if yaml is None:
        log.warning("PyYAML 未安装，无法加载 %s", path)
        return []

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as ex:
        log.warning("解析 %s 失败: %s", path, ex)
        return []

    rules_raw = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules_raw, list):
        return []

    result: list[tuple[list[str], list[str]]] = []
    for idx, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            continue
        kws = item.get("keywords") or []
        vts = item.get("vuln_types") or []
        if not isinstance(kws, list) or not isinstance(vts, list):
            log.warning("规则 #%d 字段类型错误，已跳过", idx)
            continue
        # 清洗：去空白、去 None、强制 str
        kws = [str(k).strip() for k in kws if k is not None and str(k).strip()]
        vts = [str(v).strip() for v in vts if v is not None and str(v).strip()]
        if not kws or not vts:
            continue
        result.append((kws, vts))
    return result


def save_user_triggers(rules: list[dict], path: Path = USER_TRIGGERS_PATH) -> None:
    """把规则写回 yaml（原子写）。

    rules 形如 [{"keywords": [...], "vuln_types": [...], "note": "..."}, ...]
    """
    yaml = _try_import_yaml()
    if yaml is None:
        raise RuntimeError("PyYAML 未安装，无法保存触发规则")

    # 清洗 + 校验
    cleaned: list[dict] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        kws = [str(k).strip() for k in (item.get("keywords") or []) if str(k).strip()]
        vts = [str(v).strip() for v in (item.get("vuln_types") or []) if str(v).strip()]
        if not kws or not vts:
            continue
        entry = {"keywords": kws, "vuln_types": vts}
        note = item.get("note")
        if note:
            entry["note"] = str(note).strip()
        cleaned.append(entry)

    payload = {"rules": cleaned}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    tmp.replace(path)


def list_user_triggers(path: Path = USER_TRIGGERS_PATH) -> list[dict]:
    """列出所有用户规则（含 note），用于 WebUI 渲染。"""
    if not path.exists():
        return []
    yaml = _try_import_yaml()
    if yaml is None:
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    rules_raw = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules_raw, list):
        return []
    out: list[dict] = []
    for item in rules_raw:
        if not isinstance(item, dict):
            continue
        kws = [str(k) for k in (item.get("keywords") or []) if str(k).strip()]
        vts = [str(v) for v in (item.get("vuln_types") or []) if str(v).strip()]
        if not kws or not vts:
            continue
        out.append({
            "keywords": kws,
            "vuln_types": vts,
            "note": item.get("note") or "",
        })
    return out
