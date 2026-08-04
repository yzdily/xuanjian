"""
grouping — 功能点分组逻辑

- _group_features_by_api_prefix: 按 API 路径前缀分组（代码 fallback）
- _smart_group_features: LLM 智能分组 + 代码 fallback
- _record_unsupported_method: 记录不支持的脚本方法
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

from core.sitemap import FeaturePoint
from core.prompts.phases import GROUPING_SYSTEM_PROMPT, GROUPING_USER_TEMPLATE
from core.log import get_logger

if TYPE_CHECKING:
    from core.llm import LLMClient

log = get_logger("parallel.grouping")


def _group_features_by_api_prefix(features: list[FeaturePoint]) -> list[tuple[str, list[FeaturePoint]]]:
    """按 API 路径前缀分组（fallback 策略，当 LLM 分组失败时使用）。"""
    from urllib.parse import urlparse
    from collections import defaultdict

    groups: dict[str, list] = defaultdict(list)
    for fp in features:
        prefix = "other"
        for api in fp.related_apis:
            url_part = api.split(" ")[-1] if " " in api else api
            path = urlparse(url_part).path
            parts = [p for p in path.split("/") if p][:2]
            if parts:
                prefix = "/".join(parts)
                break
        groups[prefix].append(fp)

    return sorted(groups.items(), key=lambda x: -len(x[1]))


def _record_unsupported_method(method: str, check_type: str, feature_ids: list, reason: str):
    """持久化记录 LLM 建议但脚本不支持的方法，供后续能力扩充参考。

    记录到 data/logs/unsupported_methods.jsonl，格式：
    {"time": "...", "method": "xxx", "check_type": "...", "count": N, "reason": "..."}
    """
    from pathlib import Path
    import time as _time

    log_file = Path("data/logs/unsupported_methods.jsonl")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "time": _time.strftime("%Y-%m-%d %H:%M:%S"),
        "method": method,
        "check_type": check_type,
        "feature_count": len(feature_ids),
        "feature_ids": feature_ids[:10],  # 只记前 10 个
        "reason": reason[:200],
    }

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


async def _smart_group_features(
    features: list[FeaturePoint],
    llm: "LLMClient",
    target: str = "",
    business_type: str = "",
    tech_stack: str = "",
) -> list[tuple[str, list[FeaturePoint]]]:
    """智能分组：LLM 判断业务关联 + 代码 fallback。

    流程：
    1. 代码先做一轮 API 前缀分组（作为 LLM 的参考）
    2. 把功能点列表 + 代码预分组 + 业务上下文发给 LLM
    3. LLM 返回 JSON 分组方案
    4. 解析 LLM 输出，校验完整性
    5. 失败则 fallback 到代码分组
    """
    # 功能点太少（≤5），没必要让 LLM 分组
    if len(features) <= 5:
        log.info("功能点 ≤5 个，跳过 LLM 分组，直接使用代码分组")
        return _group_features_by_api_prefix(features)

    # ★ LLM 未配置时直接使用代码分组（FAST 模式下 llm 为 None）
    if llm is None:
        log.info("LLM 未配置，使用代码分组")
        return _group_features_by_api_prefix(features)

    # 构建功能点描述列表
    feature_map = {fp.id: fp for fp in features}
    feature_lines = []
    for fp in features:
        apis = ", ".join(fp.related_apis[:3]) if fp.related_apis else "无 API"
        checks = ", ".join(c.vuln_type for c in fp.get_http_pending()[:5])
        feature_lines.append(
            f"- **{fp.id}** | {fp.name} | {fp.priority.value} | "
            f"API: {apis} | 待测: {checks}"
        )
    feature_list = "\n".join(feature_lines)

    # 代码预分组作为参考
    code_groups_raw = _group_features_by_api_prefix(features)
    code_group_lines = []
    for name, fps in code_groups_raw:
        ids = ", ".join(fp.id for fp in fps)
        code_group_lines.append(f"- {name}: [{ids}]")
    code_groups = "\n".join(code_group_lines)

    # 构建 LLM 请求
    user_msg = GROUPING_USER_TEMPLATE.format(
        feature_list=feature_list,
        code_groups=code_groups,
        target=target or "未知",
        business_type=business_type or "待分析",
        tech_stack=tech_stack or "待识别",
    )

    from core.llm import Message
    messages = [
        Message(role="system", content=GROUPING_SYSTEM_PROMPT),
        Message(role="user", content=user_msg),
    ]

    try:
        log.info("发送 LLM 分组请求: %d 个功能点", len(features))
        response = await asyncio.to_thread(llm.chat, messages)
        result_text = response.content or ""

        # 提取 JSON（可能包在 ```json ... ``` 中）
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', result_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # 尝试直接解析整个响应
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            json_str = json_match.group(0) if json_match else ""

        if not json_str:
            log.warning("LLM 分组响应中未找到 JSON，fallback 到代码分组")
            return _group_features_by_api_prefix(features)

        grouping = json.loads(json_str)
        groups_data = grouping.get("groups", [])

        if not groups_data:
            log.warning("LLM 返回空分组，fallback")
            return _group_features_by_api_prefix(features)

        # 解析并校验分组
        result: list[tuple[str, list[FeaturePoint]]] = []
        assigned_ids: set[str] = set()

        for g in groups_data:
            group_name = g.get("name", "未命名组")
            fids = g.get("feature_ids", [])
            group_fps = []
            for fid in fids:
                if fid in feature_map and fid not in assigned_ids:
                    group_fps.append(feature_map[fid])
                    assigned_ids.add(fid)
            if group_fps:
                result.append((group_name, group_fps))

        # 检查是否有遗漏的功能点 → 补到 "未分组" 组
        missing = [fp for fp in features if fp.id not in assigned_ids]
        if missing:
            log.warning("LLM 分组遗漏 %d 个功能点，自动补组", len(missing))
            result.append(("补充测试", missing))

        # 检查组规模，超大组拆分
        final_result: list[tuple[str, list[FeaturePoint]]] = []
        for name, fps in result:
            if len(fps) > 12:
                # 按 API 前缀二次拆分
                sub_groups = _group_features_by_api_prefix(fps)
                for i, (sub_name, sub_fps) in enumerate(sub_groups):
                    final_result.append((f"{name}/{sub_name}", sub_fps))
                log.info("组「%s」有 %d 个功能点，已拆分为 %d 子组", name, len(fps), len(sub_groups))
            else:
                final_result.append((name, fps))

        log.info("LLM 智能分组完成: %d 个功能点 → %d 组", len(features), len(final_result))
        if grouping.get("notes"):
            log.info("LLM 分组说明: %s", grouping["notes"][:200])

        return sorted(final_result, key=lambda x: -len(x[1]))

    except json.JSONDecodeError as e:
        log.warning("LLM 分组响应 JSON 解析失败: %s，fallback", e)
        return _group_features_by_api_prefix(features)
    except Exception as e:
        log.warning("LLM 智能分组出错: %s，fallback 到代码分组", e)
        return _group_features_by_api_prefix(features)
