"""
AnalyzeWorker — Phase 1 功能分析子 Agent

当 JS 分析发现的 API 数量超过阈值时，按 URL 前缀分组，
每个 AnalyzeWorker 独立会话分析一组 API，输出功能点列表。

设计原则：
- 每个子 Agent 只看自己那组 API（≤50 个），上下文干净不幻觉
- 和主 Agent Phase 1 做的事完全一样：理解业务逻辑 → 添加功能点
- 独立 LLM 上下文，互不污染
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator

from core.llm import LLMClient, Message
from core.context import ContextManager
from core.log import get_logger
from core.prompts import load_prompt

log = get_logger("analyze_worker")

# 阈值：API 数量超过这个值就启用子 Agent 分组分析
ANALYZE_SPLIT_THRESHOLD = 50


def group_apis_by_prefix(apis: list[str], max_per_group: int = 50) -> list[tuple[str, list[str]]]:
    """按 URL 前缀将 API 分组，每组不超过 max_per_group 个。

    分组逻辑：取路径前两段作为前缀（如 /api/user/list → /api/user）。
    如果某前缀下超过 max_per_group，再按第三段细分。
    """
    from collections import defaultdict
    from urllib.parse import urlparse

    groups: dict[str, list[str]] = defaultdict(list)

    for api in apis:
        # 提取路径部分
        parts = api.split(" ", 1)
        url_part = parts[-1]
        parsed = urlparse(url_part)
        path = parsed.path.strip("/")
        segments = [s for s in path.split("/") if s]

        # 取前2段作为分组前缀
        if len(segments) >= 2:
            prefix = "/".join(segments[:2])
        elif segments:
            prefix = segments[0]
        else:
            prefix = "其他"

        groups[prefix].append(api)

    # 如果某组超过 max_per_group，按第3段细分
    result: list[tuple[str, list[str]]] = []
    for prefix, api_list in sorted(groups.items()):
        if len(api_list) <= max_per_group:
            result.append((prefix, api_list))
        else:
            sub_groups: dict[str, list[str]] = defaultdict(list)
            for api in api_list:
                parts = api.split(" ", 1)
                url_part = parts[-1]
                path = urlparse(url_part).path.strip("/")
                segments = [s for s in path.split("/") if s]
                sub_prefix = "/".join(segments[:3]) if len(segments) >= 3 else prefix
                sub_groups[sub_prefix].append(api)

            for sub_prefix, sub_list in sorted(sub_groups.items()):
                result.append((sub_prefix, sub_list))

    # 最终合并过小的组（< 5 个的合并到"其他"）
    merged: list[tuple[str, list[str]]] = []
    misc: list[str] = []
    for name, apis_in_group in result:
        if len(apis_in_group) < 5:
            misc.extend(apis_in_group)
        else:
            merged.append((name, apis_in_group))
    if misc:
        merged.append(("其他", misc))

    return merged


class AnalyzeWorker:
    """Phase 1 分析子 Agent：将一组 API 转化为功能点列表。"""

    def __init__(
        self,
        worker_id: str,
        llm: LLMClient,
        target_url: str,
        business_info: str,
        tech_stack: str,
        group_name: str,
        api_list: list[str],
        has_credentials: bool = False,
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.target_url = target_url
        self.business_info = business_info
        self.tech_stack = tech_stack
        self.group_name = group_name
        self.api_list = api_list
        self.has_credentials = has_credentials

        # 输出：解析出的功能点列表
        self.features: list[dict] = []
        self.error: str | None = None

    async def run(self) -> list[dict]:
        """运行分析，返回功能点列表。

        每个功能点格式：
        {
            "name": "用户管理",
            "description": "管理系统用户，支持增删改查",
            "module": "系统管理/用户管理",
            "page_url": "/admin/system/users",
            "related_apis": ["GET /api/user/list", "POST /api/user/create", ...],
            "priority": "high",
            "requires_auth": true
        }
        """
        try:
            ctx = ContextManager(llm=self.llm)

            # 系统提示
            ctx.add_system(
                load_prompt("analyze_worker_system", with_common=True)
            )

            # 用户提示：目标信息 + API 列表
            api_text = "\n".join(f"  - {api}" for api in self.api_list)
            ctx.add_user(
                f"## 目标信息\n"
                f"- URL: {self.target_url}\n"
                f"- 业务: {self.business_info}\n"
                f"- 技术栈: {self.tech_stack}\n"
                f"- 模块分组: {self.group_name}\n\n"
                f"## API 列表（共 {len(self.api_list)} 个）\n\n{api_text}\n\n"
                f"请将以上 API 归类为功能点，直接输出 JSON 数组。"
            )

            # 调用 LLM
            messages = ctx.get_messages()
            response = await asyncio.to_thread(self.llm.chat, messages, None, 0.2, 4096)

            # 解析 JSON 输出
            content = response.content or ""
            self.features = self._parse_features(content)

            # 解析失败 → 重试一次，要求严格 JSON
            if not self.features and content.strip():
                log.warning("[%s] 首次解析失败，重试中...", self.worker_id)
                ctx.add_assistant(response)
                ctx.add_user(
                    "你的输出格式不正确，无法解析。请严格按以下格式重新输出，不要包含任何解释文字：\n"
                    '```json\n[{"name":"功能名","description":"描述","module":"一级/二级",'
                    '"page_url":"/path","related_apis":["GET /api/xxx"],'
                    '"priority":"high","requires_auth":true}]\n```'
                )
                retry_resp = await asyncio.to_thread(self.llm.chat, ctx.get_messages(), None, 0.1, 4096)
                self.features = self._parse_features(retry_resp.content or "")

            log.info("[%s] 分析完成: %d 个 API → %d 个功能点",
                     self.worker_id, len(self.api_list), len(self.features))
            return self.features

        except Exception as e:
            self.error = str(e)
            log.error("[%s] 分析出错: %s", self.worker_id, e)
            return []

    def _parse_features(self, content: str) -> list[dict]:
        """从 LLM 输出中提取 JSON 功能点列表，兼容各种格式差异。"""
        import re

        # Step 1: 提取 JSON 文本
        text = ""
        # 尝试从 markdown code block 中提取
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if json_match:
            text = json_match.group(1).strip()
        else:
            text = content.strip()

        # Step 2: 尝试解析 JSON
        raw_list = None
        # 方式 A：直接解析
        try:
            data = json.loads(text)
            if isinstance(data, list):
                raw_list = data
            elif isinstance(data, dict):
                # 兼容 {"features": [...]} 或 {"data": [...]} 等包裹格式
                for key in ("features", "data", "result", "功能点", "list"):
                    if key in data and isinstance(data[key], list):
                        raw_list = data[key]
                        break
        except json.JSONDecodeError:
            pass

        # 方式 B：尝试找内容中第一个 [ 到最后一个 ] 之间的部分
        if raw_list is None:
            bracket_match = re.search(r'\[.*\]', text, re.DOTALL)
            if bracket_match:
                try:
                    raw_list = json.loads(bracket_match.group(0))
                except json.JSONDecodeError:
                    pass

        # 方式 C：逐行找 JSON 数组
        if raw_list is None:
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("["):
                    try:
                        raw_list = json.loads(line)
                        if isinstance(raw_list, list):
                            break
                    except json.JSONDecodeError:
                        continue

        if not raw_list or not isinstance(raw_list, list):
            log.warning("[%s] 无法解析为 JSON 列表，原始内容: %s", self.worker_id, content[:300])
            return []

        # Step 3: 标准化每个功能点的字段
        result = []
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            feat = self._normalize_feature(item)
            if feat.get("name"):
                result.append(feat)

        return result

    @staticmethod
    def _normalize_feature(raw: dict) -> dict:
        """将 LLM 输出的功能点字段标准化。兼容中英文字段名、各种格式差异。"""
        # 字段名映射（中文/别名 → 标准名）
        name_map = {
            "name": "name", "功能名": "name", "功能名称": "name", "feature_name": "name", "title": "name",
            "description": "description", "描述": "description", "desc": "description", "说明": "description",
            "module": "module", "模块": "module", "分类": "module", "category": "module",
            "page_url": "page_url", "页面": "page_url", "url": "page_url", "path": "page_url",
            "related_apis": "related_apis", "api": "related_apis", "apis": "related_apis",
            "api列表": "related_apis", "api_list": "related_apis", "endpoints": "related_apis",
            "priority": "priority", "优先级": "priority", "level": "priority",
            "requires_auth": "requires_auth", "需要认证": "requires_auth", "auth": "requires_auth",
            "need_auth": "requires_auth", "需要登录": "requires_auth",
        }

        feat: dict = {}
        for key, value in raw.items():
            std_key = name_map.get(key.lower().strip(), key.lower().strip())
            feat[std_key] = value

        # priority 标准化（中文 → 英文）
        priority_normalize = {
            "严重": "critical", "高危": "critical", "紧急": "critical",
            "高": "high", "中": "medium", "低": "low",
            "critical": "critical", "high": "high", "medium": "medium", "low": "low",
        }
        p = str(feat.get("priority", "medium")).lower().strip()
        feat["priority"] = priority_normalize.get(p, "medium")

        # related_apis：确保是列表
        apis = feat.get("related_apis", [])
        if isinstance(apis, str):
            # "GET /api/xxx, POST /api/yyy" → 列表
            apis = [a.strip() for a in apis.replace("\n", ",").split(",") if a.strip()]
        elif not isinstance(apis, list):
            apis = []
        feat["related_apis"] = apis

        # requires_auth：确保是 bool
        auth = feat.get("requires_auth", True)
        if isinstance(auth, str):
            auth = auth.lower() in ("true", "1", "yes", "是")
        feat["requires_auth"] = bool(auth)

        return feat


async def run_analyze_workers(
    llm: LLMClient,
    target_url: str,
    business_info: str,
    tech_stack: str,
    api_groups: list[tuple[str, list[str]]],
    has_credentials: bool = False,
    max_concurrent: int = 3,
) -> AsyncGenerator[tuple[str, list[dict]], None]:
    """并行运行多个分析子 Agent。

    Args:
        api_groups: [(组名, [API列表]), ...]
        max_concurrent: 最大并行数

    Yields:
        (worker_id, features_list) 每个子 Agent 完成时 yield 结果
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _run_one(idx: int, group_name: str, apis: list[str]) -> tuple[str, list[dict]]:
        async with semaphore:
            worker_id = f"a{idx+1}"
            worker = AnalyzeWorker(
                worker_id=worker_id,
                llm=llm,
                target_url=target_url,
                business_info=business_info,
                tech_stack=tech_stack,
                group_name=group_name,
                api_list=apis,
                has_credentials=has_credentials,
            )
            features = await worker.run()
            return worker_id, features

    # 并行启动所有子 Agent
    tasks = [
        asyncio.create_task(_run_one(i, name, apis))
        for i, (name, apis) in enumerate(api_groups)
    ]

    for coro in asyncio.as_completed(tasks):
        worker_id, features = await coro
        yield worker_id, features
