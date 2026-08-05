"""
WorkerAgent — Phase 2 并行测试子 Agent

每个 WorkerAgent 负责测试**一组**功能点的 HTTP checklist 项。
同组功能点共享上下文（业务关联、Session 信息），串行测试。

- 独立 LLM 上下文（独立 token 消耗）
- 只用 HTTP 工具（proxy_send_request/proxy_replay），不用浏览器
- checklist_mark 写入共享 Sitemap（线程安全）
- 主 Agent 分发 Cookie/Token，子 Agent 携带发请求
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator, Callable

from core.llm import LLMClient, Message, parse_tool_call_arguments
from core.context import ContextManager
from core.sitemap import Sitemap, FeaturePoint, CheckResult, TestStatus
from core.config import WORKER_MAX_ROUNDS
from core.tools import build_worker_tools
from core.tool_executor import ToolExecutor
from core.prompts.phases import WORKER_SYSTEM_PROMPT
from core.log import get_logger

log = get_logger("worker")


class WorkerAgent:
    """测试一组功能点的子 Agent。

    同组功能点共享上下文（认证信息、SKILL 方法论），串行逐个测试。
    支持向后兼容：如果传入单个 feature（旧调用方式），自动包装为列表。
    """

    def __init__(
        self,
        worker_id: str,
        llm: LLMClient,
        sitemap: Sitemap,
        session_info: dict,
        # 新参数：一组功能点
        features: list[FeaturePoint] | None = None,
        group_name: str = "",
        # 兼容旧参数：单个功能点
        feature: FeaturePoint | None = None,
        on_event: Callable | None = None,
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.sitemap = sitemap
        self.session_info = session_info
        self.on_event = on_event

        # 兼容：旧代码传 feature=单个功能点
        if features:
            self.features = features
        elif feature:
            self.features = [feature]
        else:
            self.features = []

        self.group_name = group_name or (self.features[0].name if self.features else "未知组")

        # 当前正在测试的功能点索引
        self._current_idx = 0
        self.feature = self.features[0] if self.features else None  # 兼容旧属性

        self.context = ContextManager(llm=self.llm)
        self._init_context()

        self.completed = False
        self.error: str | None = None
        self._done_reject_count = 0

        # ★ 反内卷保护：跟踪同一接口连续测试次数 + 连续轮数无 checklist_mark
        self._url_method_streak: dict[str, int] = {}  # key="METHOD path", value=连续测试次数
        self._last_url_method_key: str = ""           # 上一次测试的 key
        self._rounds_without_mark: int = 0            # 连续多少轮没 checklist_mark
        self._anti_loop_warned: bool = False          # 是否已发过反内卷警告（防重复）
        self._vuln_nudge_sent: bool = False           # 是否已发过"漏洞证据未 mark"强提示（防重复）

        # ★ 必须传入 task_id，否则 note_add/note_read 会写到 default-*.md，
        # 导致子 Agent 的 info/infer/result 笔记与漏洞报告全部丢失。
        self.tool_executor = ToolExecutor(
            sitemap=sitemap,
            has_credentials=True,
            task_id=getattr(sitemap, "task_id", "default"),
        )

        # ★ 决策剧场：缓存 task_id / target，emit 时统一带上
        self._replay_task_id: str = getattr(sitemap, "task_id", "") or ""
        self._replay_target: str = getattr(sitemap, "target", "") or ""

    @property
    def current_feature(self) -> FeaturePoint | None:
        if 0 <= self._current_idx < len(self.features):
            return self.features[self._current_idx]
        return None

    def _init_context(self):
        prompts_dir = Path(__file__).parent / "prompts"
        if (prompts_dir / "solver.md").exists():
            self.context.add_system(
                (prompts_dir / "solver.md").read_text(encoding="utf-8")
            )

        self.context.add_system(WORKER_SYSTEM_PROMPT)

        sampling_path = Path("skills_my/core/sampling-inference/SKILL.md")
        if sampling_path.exists():
            self.context.add_system(
                f"## 核心策略（必须遵守）\n\n{sampling_path.read_text(encoding='utf-8')}"
            )

        if self.session_info:
            auth_info = json.dumps(self.session_info, ensure_ascii=False)
            headers_dict = self.session_info.get("headers", {}) if isinstance(self.session_info, dict) else {}
            custom_header_names = [k for k in headers_dict.keys()
                                   if k.lower() not in ("cookie", "authorization")]
            custom_hint = ""
            if custom_header_names:
                custom_hint = (
                    f"\n⚠️ **包含 {len(custom_header_names)} 个自定义认证头**："
                    f"`{', '.join(custom_header_names)}`，"
                    "这些通常是签名/租户/API Key 等业务自定义头，"
                    "**proxy_send_request 调用时必须把它们一起放进 headers 参数**，否则会 401/403。"
                )
            self.context.add_system(
                f"## 认证信息（所有请求必须携带，最高优先级）\n\n```json\n{auth_info}\n```\n"
                "发送 HTTP 请求时，**必须把上面 headers 字典里的全部字段都带上**（不只是 Cookie/Authorization）。\n"
                "⚠️ API 请求样本中可能包含爬取时的旧 Cookie/签名，**以此处的认证信息为准**，样本中的对应字段仅供参考请求格式。"
                f"{custom_hint}"
            )

        # ---- 加密配置注入 ----
        if self.sitemap and self.sitemap.crypto_configs:
            crypto_info = ["## 目标网站使用前端加密\n"]
            crypto_info.append("该网站的请求参数经过前端加密，你需要：")
            crypto_info.append("1. 构造测试 payload 后，先调用 `crypto_encrypt` 加密")
            crypto_info.append("2. 用加密后的密文发送 `proxy_send_request`")
            crypto_info.append("3. 收到加密响应后，调用 `crypto_decrypt` 解密查看结果\n")
            crypto_info.append("可用的加密配置：")
            from core.crypto_engine import get_configs, CryptoConfig
            # 也从 sitemap 恢复到内存（子 Agent 进程可能没跑过 detect）
            if not get_configs():
                for cc in self.sitemap.crypto_configs:
                    from core.crypto_engine import _crypto_configs
                    _crypto_configs.append(CryptoConfig(**cc))
            for i, cc in enumerate(self.sitemap.crypto_configs):
                algo = cc.get("algorithm", "?")
                crypto_info.append(f"  [{i}] {algo}")
            crypto_info.append("\n示例：crypto_encrypt({\"plaintext\": \"' OR 1=1--\", \"config_index\": 0})")
            self.context.add_system("\n".join(crypto_info))

        # ---- ★ SKILL 策略：只注入当前第一个功能点最关键的 1-2 个，其余按需加载 ----
        # 这样初始上下文从 100K+ 降到 ~15K，大幅减少幻觉风险
        from core.config import VULN_TO_SKILL
        injected_skills: set[str] = set()
        skills_dir = Path("skills_my")

        # 只注入第一个功能点的核心 SKILL（最多 2 个），其余由提示词引导按需加载
        if self.features:
            first_fp = self.features[0]
            first_checks = first_fp.get_http_pending()
            injected_count = 0
            MAX_INITIAL_SKILLS = 2  # 初始只注入 2 个，保持上下文轻量

            for c in first_checks:
                if injected_count >= MAX_INITIAL_SKILLS:
                    break
                skill_name = VULN_TO_SKILL.get(c.vuln_type, "")
                if skill_name and skill_name not in injected_skills:
                    skill_path = self._find_skill(skills_dir, skill_name)
                    if skill_path:
                        content = skill_path.read_text(encoding="utf-8")
                        # ★ 拆分注入策略（2026-05-19 改造）：
                        # 1) 必测自检清单 + 工具速查附录 完整保留（这是 SKILL 末尾追加的关键约束段）
                        # 2) SKILL 主体（Phase 1...）按 max_len 截断
                        # 这样能保证 LLM 即使没加载完整 SKILL，也至少看到自检清单
                        body, checklist_appendix = self._split_skill_content(content)

                        _HIGH_VALUE = {"sql-injection-methodology", "idor-methodology",
                                       "xss-methodology", "ssrf-methodology",
                                       "file-upload-methodology", "auth-bypass-methodology",
                                       "401-403-bypass", "csrf-methodology",
                                       "user-enum-data-leak", "command-injection-methodology",
                                       "password-reset-attack", "payment-logic-attack"}
                        max_body_len = 8000 if skill_name in _HIGH_VALUE else 5000
                        if len(body) > max_body_len:
                            body = body[:max_body_len] + (
                                "\n\n... (主体截断，用 `knowledge_load_skill(\"" +
                                skill_name + "\")` 加载完整版)")

                        # 必测清单 + 速查附录无截断完整保留（关键约束段）
                        full_content = body + ("\n\n" + checklist_appendix if checklist_appendix else "")

                        self.context.add_system(
                            f"## 方法论：{c.vuln_type}\n"
                            f"以下是 {c.vuln_type} 的方法论。\n"
                            f"**⛔ 严格按 SKILL 的流程和决策树执行，不得用自己的推理覆盖 SKILL 的判定结论。**\n"
                            f"**测试时按 SKILL 主体的 Phase 步骤执行**；\n"
                            f"**SKILL 决策树中明确写了「满足 X → 标 vulnerable」时，必须照办，不得降级为 needs_review 或标 not_vuln**；\n"
                            f"**标 not_vuln/skipped 前必须按 SKILL 末尾的「最低必测自检清单」逐条交账**。\n\n"
                            f"{full_content}"
                        )
                        injected_skills.add(skill_name)
                        injected_count += 1
                        log.info("[%s] 预注入 SKILL: %s → %s (body %d / appendix %d)",
                                 self.worker_id, c.vuln_type, skill_name,
                                 len(body), len(checklist_appendix))
                        # ★ 决策剧场：SKILL 注入也作为一帧决策（让用户看到 worker 装备了什么方法论）
                        try:
                            from core.replay import emit_decision as _ed
                            _ed(
                                task_id=getattr(self.sitemap, "task_id", "") or "",
                                worker_id=self.worker_id,
                                feature_id=first_fp.id,
                                feature_name=first_fp.name,
                                vuln_type=c.vuln_type,
                                skill_used=skill_name,
                                target_url=getattr(self.sitemap, "target", "") or "",
                                llm_summary=f"📚 预注入 SKILL「{skill_name}」用于测试 {c.vuln_type}",
                                track="system",
                                event="skill_injected",
                                body_size=len(body),
                                appendix_size=len(checklist_appendix),
                            )
                        except Exception as _e:
                            log.debug("[%s] SKILL 注入决策剧场 emit 失败: %s", self.worker_id, _e)

        # 收集所有需要但没预注入的 SKILL，在提示词中告知按需加载
        self._pending_skills: dict[str, str] = {}  # vuln_type → skill_name
        for fp in self.features:
            for c in fp.get_http_pending():
                skill_name = VULN_TO_SKILL.get(c.vuln_type, "")
                if skill_name and skill_name not in injected_skills:
                    self._pending_skills[c.vuln_type] = skill_name

        if self._pending_skills:
            log.info("[%s] %d 个漏洞类型的 SKILL 待按需加载: %s",
                     self.worker_id, len(self._pending_skills),
                     list(self._pending_skills.keys()))

        # ---- ★ 业务理解注入（2026-05-19 改造）：
        # 把 Phase 1.5 产出的 attack_hypotheses 和 promises 按相关性筛选后注入 worker 上下文
        # 让 worker 测试时能看到「业务驱动的具体假设」和「系统承诺的契约」
        # 注意：这是 SKILL 主导之上的「业务针对性补充」，不是替代 SKILL
        # ---- ★ Hermes 风格历史经验注入（2026-05-20 新增）：
        # 按本组涉及的 vuln_type 分别召回历史教训，注入到 worker 上下文。
        # 这是子 Agent 拿到「上次踩过的坑」最关键的一环。
        # 之前主 session 已注入过 phase 级经验（无 vuln_type 过滤），这里做"漏洞类型级"精准召回。
        self._inject_lessons_by_vuln_type()

        self._inject_business_understanding()

        # ---- 构建组任务总览 ----
        self._build_group_task_message(injected_skills)

    @staticmethod
    def _best_api_for_vuln(vuln_type: str, apis: list[str]) -> str:
        """根据漏洞类型选最适合测试的 API。"""
        if not apis:
            return ""
        parsed = []
        for a in apis:
            parts = a.strip().split(" ", 1)
            m = parts[0].upper() if len(parts) >= 2 and parts[0].isupper() else "GET"
            u = parts[1] if len(parts) >= 2 else parts[0]
            parsed.append((m, u, a))

        if vuln_type in ("IDOR越权", "越权查看", "越权操作"):
            for m, u, a in parsed:
                if m in ("PUT", "PATCH", "DELETE"):
                    return a
            for m, u, a in parsed:
                if "id" in u.lower() or any(seg.isdigit() for seg in u.split("/")):
                    return a
        elif vuln_type == "SQL注入":
            for m, u, a in parsed:
                if m == "GET" and "?" in u:
                    return a
            for m, u, a in parsed:
                if m == "POST":
                    return a
        elif vuln_type == "CSRF":
            for m, u, a in parsed:
                if m in ("POST", "PUT", "PATCH", "DELETE"):
                    return a
        elif vuln_type in ("文件上传绕过",):
            for m, u, a in parsed:
                if any(kw in u.lower() for kw in ("upload", "import", "attach")):
                    return a
        elif vuln_type in ("越权导出",):
            for m, u, a in parsed:
                if any(kw in u.lower() for kw in ("export", "download")):
                    return a
        elif vuln_type == "信息泄露":
            for m, u, a in parsed:
                if m == "GET":
                    return a
        return apis[0]

    def _build_group_task_message(self, injected_skills: set[str]):
        """构建包含所有功能点 checklist 的任务消息。

        【SKILL 主导改造，2026-05-19】
        ★ 不再注入 test_templates 的 Step 1/2/3 死板步骤模板，改为：
          - 每个 checklist 项标 SKILL 名 → 强制 LLM 先加载 SKILL
          - SKILL 主体 + SKILL 末尾「最低必测自检清单」是唯一权威
          - 标 not_vuln/skipped 前必须对自检清单逐条交账（detail 字段记录）
        ★ test_templates.py 文件保留，但仅作为 SKILL 写作时的参考样例（不再运行时注入）
        ★ 业务理解的 attack_hypotheses / promises 在 _init_context 中按相关性注入
        """
        from core.config import VULN_TO_SKILL

        # 提取认证 Cookie（仅用于提示 LLM，工具默认会自动注入）
        auth_cookie = ""
        if self.session_info:
            headers = self.session_info.get("headers", {})
            auth_cookie = headers.get("Cookie", "")

        lines = [
            f"## 你的任务组：「{self.group_name}」（{len(self.features)} 个功能点）\n",
            f"这些功能点属于同一业务模块/流程，你需要**按顺序**逐个测试。\n",
            f"同组功能点共享上下文，前面的测试结果可以为后续测试提供线索。\n",
        ]

        total_checks = 0
        for i, fp in enumerate(self.features, 1):
            http_checks = fp.get_http_pending()
            browser_checks = fp.get_browser_pending()
            total_checks += len(http_checks)

            lines.append(f"\n### 功能点 {i}/{len(self.features)}: {fp.name}")
            lines.append(f"- 描述: {fp.description}")
            lines.append(f"- 页面: {fp.page_url}")
            lines.append(f"- 优先级: {fp.priority.value}")
            lines.append(f"- 关联 API: {', '.join(fp.related_apis) if fp.related_apis else '待发现'}")

            # ★ 注入 API 请求样本（从独立文件读取，区分真实流量和推测接口）
            # ★ 限制每个功能点的样本大小，防止上下文爆炸
            MAX_SAMPLE_PER_FP = 8000  # 每个功能点最多 8K 字符的样本
            sample_file = self.sitemap.get_sample_file_path(fp.id)
            if sample_file:
                try:
                    from pathlib import Path
                    sample_content = Path(sample_file).read_text(encoding="utf-8")
                    if len(sample_content) > MAX_SAMPLE_PER_FP:
                        sample_content = sample_content[:MAX_SAMPLE_PER_FP] + "\n... (样本截断，完整版在文件中)"
                    lines.append(f"- **API 流量样本文件**:")
                    lines.append(f"  ```")
                    lines.append(sample_content)
                    lines.append(f"  ```")
                    lines.append(f"  💡 **使用说明**:")
                    lines.append(f"    - 「真实流量」区域：有完整请求格式，直接基于此构造测试请求")
                    lines.append(f"    - 「推测接口」区域：只有 URL，你需要先发空 body 请求观察报错，从报错推断参数字段后再测试")
                    lines.append(f"    - ⚠️ **同一 API 有多个参数变体时**（标 `⚠️ 共 N 个参数变体` / `#### 变体 X/N`）："
                                 f"必须**逐个变体独立测试**，不要只测第一个！")
                    lines.append(f"      · GET 不同 query → 分页类测 IDOR/越权，搜索类测 SQL注入/XSS")
                    lines.append(f"      · POST/PUT 不同 body → 每个变体测注入和 Mass Assignment（字段值差异本身就是攻击线索）")
                    log.info("[%s] 注入流量样本文件: %s (%d bytes, 限制 %d)",
                             self.worker_id, sample_file, len(sample_content), MAX_SAMPLE_PER_FP)
                except Exception as e:
                    log.warning("[%s] 读取流量样本失败: %s", self.worker_id, e)
            else:
                # fallback: 从内存中取（兼容没有写文件的场景）
                api_samples = self.sitemap.get_samples_for_feature(fp.id)
                if api_samples:
                    method_priority = {"DELETE": 0, "PUT": 1, "POST": 2, "PATCH": 3, "GET": 4}
                    api_samples.sort(key=lambda s: method_priority.get(s.get("method", "GET"), 5))
                    # ★ 2026-05-24: 按 (method, path) 聚合，让子 Agent 看出"同 API 多变体"
                    api_groups = self.sitemap._group_samples_by_api(api_samples)
                    multi_variant_count = sum(1 for variants in api_groups.values() if len(variants) > 1)
                    if multi_variant_count > 0:
                        lines.append(
                            f"- **API 请求样本**（已从流量中抓取，按 API 聚合；"
                            f"⚠️ 其中 {multi_variant_count} 个 API 有多个参数变体，请逐个测试）:"
                        )
                    else:
                        lines.append(f"- **API 请求样本**（已从流量中抓取，直接基于此构造测试请求）:")
                    sample_size = 0
                    MAX_SAMPLE_SIZE = 30000
                    for (g_method, g_path), variants in api_groups.items():
                        block = self.sitemap._format_api_group_block(g_method, g_path, variants)
                        block_text = "\n".join(block)
                        if sample_size + len(block_text) > MAX_SAMPLE_SIZE:
                            break
                        # 加缩进让块在 lines 列表里有视觉边界
                        for line in block:
                            lines.append(f"  {line}")
                        sample_size += len(block_text)
            lines.append(f"- feature_id: {fp.id}")

            if http_checks:
                lines.append(f"\n**待测项（{len(http_checks)} 项，纯 HTTP）：**\n")
                if fp.related_apis and len(fp.related_apis) > 1:
                    lines.append(f"📌 本功能点有 **{len(fp.related_apis)} 个 API**，"
                                 f"每种漏洞类型应优先测最相关的 API：\n")
                for c in http_checks:
                    best_api = self._best_api_for_vuln(c.vuln_type, fp.related_apis)
                    skill_name = VULN_TO_SKILL.get(c.vuln_type, "")
                    # ★ SKILL 主导：每个项强制要求加载/参考 SKILL，并按 SKILL 末尾的「最低必测自检清单」交账
                    lines.append(f"⬜ **{c.vuln_type}**  推荐 API: `{best_api or '需自行选择'}`  feature_id: `{fp.id}`")
                    if skill_name:
                        if skill_name in injected_skills:
                            lines.append(f"   📚 方法论已注入上下文（标题为「方法论：{c.vuln_type}」），"
                                         f"**直接按 SKILL 主体的 Phase 步骤逐个执行**。")
                        else:
                            lines.append(f"   📚 **必须先调** `knowledge_load_skill(\"{skill_name}\")` "
                                         f"加载方法论，再按 SKILL 主体的 Phase 步骤执行。")
                        lines.append(f"   📋 **标 not_vuln/skipped 前**必须对照该 SKILL 末尾的"
                                     f"「最低必测自检清单」**逐条回答你做了什么**，"
                                     f"答案精简版写进 `checklist_mark` 的 `detail` 字段。")
                    else:
                        # 没有 SKILL 映射的情况：要求 LLM 用 knowledge_search 找
                        lines.append(f"   📚 没有专属 SKILL，先调 `knowledge_search(\"{c.vuln_type}\")` "
                                     f"找相关方法论再执行。")
                    lines.append("")  # 空行分隔

            if browser_checks:
                lines.append(f"\n**以下项由主 Agent 浏览器测试（你不用管）：**")
                for c in browser_checks:
                    lines.append(f"  🌐 {c.vuln_type}（浏览器专属）")

        lines.append(f"\n---\n")
        lines.append(f"## 工作流程（SKILL 主导，2026-05 改造）\n")
        lines.append(f"**共 {len(self.features)} 个功能点, {total_checks} 项 HTTP checklist**\n")
        lines.append(
            f"### 单项测试 5 步法（每个 ⬜ 项都按这个流程）\n\n"
            f"1. **加载/确认 SKILL**：\n"
            f"   - 项标了「📚 必须先调 knowledge_load_skill(\"xxx\")」→ 立刻调，加载完整方法论到上下文\n"
            f"   - 项标了「方法论已注入」→ 翻到该方法论标题，开始读\n"
            f"   - 没专属 SKILL → 用 `knowledge_search` 找最相关的，加载\n\n"
            f"2. **按 SKILL 主体的 Phase 执行测试动作**：\n"
            f"   - SKILL 里写的 Phase 1 / Phase 2 / Phase 3... 都要走一遍（除非 SKILL 自己说「不适用」）\n"
            f"   - 用 `proxy_send_request` / `proxy_replay` / `proxy_batch_send` / `proxy_diff_responses` 发请求\n"
            f"   - 撞墙（403/CSRF/WAF/参数白名单）时**优先继续读 SKILL 同一份的「绕过技巧 / 必测自检」段落**，按里面的方法换路径再试\n\n"
            f"3. **对照 SKILL 末尾的「最低必测自检清单」交账**：\n"
            f"   - SKILL 末尾有一份 7-8 项的必测清单，每项问你"
            f"「试过 X 了吗」「试过 Y 了吗」\n"
            f"   - 标 not_vuln/skipped 前，逐条回答（精简版即可）\n"
            f"   - 自检清单里"
            f"明确列了「跳过的非法理由」(\"业务正常\"/\"无入口\"/\"受 CSRF 保护\"/\"需要 JWT\" 等) — **看到这些理由要警惕**，可能你只是没换路径\n\n"
            f"4. **`checklist_mark` 记录结论**：\n"
            f"   - feature_id 必须对应当前功能点（不要写错）\n"
            f"   - `detail` 字段 ≤ 300 字，说明：① 试了哪几个必测项 ② 关键证据 ③ 结论理由\n"
            f"   - 发现漏洞（result=vulnerable）必须同时填 severity / reproduce_steps / fix_suggestion\n"
            f"   - **未经实际请求验证的发现 → result=needs_review，不是 vulnerable**\n\n"
            f"5. **下一项**：当前 ⬜ 项完成 → 移到下一项；当前功能点全部完成 → 移到下一个功能点\n\n"
            f"### 全部完成后调用 `worker_done`\n\n"
            f"### 💡 组内关联提示\n"
            f"- 这些功能点属于同一业务流程，前面的响应数据（资源 ID、Token、CSRF token）可以用于后续测试\n"
            f"- 如果发现统一鉴权中间件，后续未授权访问可以采样推断（必须**先用 SKILL 401-403-bypass 的"
            f"「跨模块统一性验证」**确认是统一中间件，不是猜的）\n\n"
            f"### ⚠️ 每个功能点必须独立测试\n"
            f"- 即使多个功能点共用同一个登录接口，每个功能点的 checklist 必须独立标记\n"
            f"- 不要写「与 fp_1 相同」然后跳过——每个 API 端点都要实际发请求验证\n"
            f"- **deferred 功能点（只有'未授权访问'一项）**：用 `proxy_send_request(..., drop_auth=True)` "
            f"直接请求 related_apis 中的后端 API，看返回 401 还是业务数据。"
            f"⚠️ 前后端分离架构下前端页面 URL 永远返回 SPA 空壳 200，必须测后端 /api/* 才有意义\n\n"
            f"### ⛔ 严禁\n"
            f"- 你只能用 HTTP 工具（proxy_*），不能用浏览器工具（browser_*，主 Agent 独占）\n"
            f"- 不要测 🌐 标记的浏览器专属项（主 Agent 负责）\n"
            f"- **严禁不加载 SKILL 就直接 mark not_vuln**（除非 SKILL 完全不存在的情况）\n"
            f"- 严禁用「业务正常」「无入口」「受 X 保护」这种笼统话术 mark — 必须给 SKILL 自检清单逐条交账\n"
            f"- 不要在还有功能点未测完时调用 worker_done\n\n"
            f"### 🔑 漏洞验证原则\n"
            f"- 发现泄露的账号密码 → 必须用 proxy_send_request 向登录接口发请求，证明能登录成功\n"
            f"- 发现未授权访问 → 必须证明能读到业务数据（不只是 200，要看 body 是不是 SPA HTML）\n"
            f"- 发现信息泄露 → 必须说明泄露了什么具体敏感字段\n"
            f"- **未经验证的发现 = needs_review，验证成功的 = vulnerable**"
        )

        self.context.add_user("\n".join(lines))

    @staticmethod
    def _find_skill(skills_dir: Path, skill_name: str) -> Path | None:
        """在 skills 目录树中查找指定 SKILL.md。"""
        for skill_md in skills_dir.rglob("SKILL.md"):
            if skill_md.parent.name == skill_name:
                return skill_md
        return None

    @staticmethod
    def _split_skill_content(content: str) -> tuple[str, str]:
        """把 SKILL 内容拆成「主体」和「最低必测自检 + 工具速查附录」两部分。

        2026-05-19 改造：
        - SKILL 末尾追加了「## ⛔ 「最低必测自检」」和「## 附录 A：工具调用速查」两个段落
        - 这两个段落是关键的"约束 + 速查"，必须无截断保留
        - SKILL 主体（Phase 1...Phase N）按 max_len 截断
        """
        # 优先按必测自检的标题分割
        anchors = [
            "## ⛔ 「最低必测自检」",
            "## ⛔「最低必测自检」",
            "## 最低必测自检",
        ]
        for anchor in anchors:
            idx = content.find(anchor)
            if idx > 0:
                return content[:idx].rstrip(), content[idx:].strip()
        # 没找到 anchor 就整段当主体，appendix 为空
        return content, ""

    # ============================================================
    # 反内卷漏洞证据扫描（2026-05-20 新增）
    # ============================================================
    # 触发反内卷前/收尾时调用，检查最近 LLM 输出里是否有"发现漏洞但还没 mark"的证据，
    # 用于：1) 豁免反内卷给 LLM 完成验证   2) 强制收尾前抢救保留 needs_review
    _VULN_EVIDENCE_KEYWORDS = (
        # SQL 注入证据（必须是"确认/触发/泄露"的强信号词，不要光匹配 "sql 注入"）
        "mysql 语法错误", "mysql syntax error",
        "sql syntax", "you have an error in your sql",
        "ora-00", "ora-0", "sqlstate", "unclosed quotation",
        "postgresql 错误", "postgres 错误", "mssql 错误",
        "发现 sql 注入", "确认 sql 注入", "🚨 sql", "🚨 **发现 sql",
        "sql 注入漏洞", "存在 sql 注入", "存在sql注入",
        # 命令注入
        "命令注入成功", "rce 成功", "远程命令执行", "command injection confirmed",
        # XSS
        "反射 xss 触发", "存储 xss 触发", "stored xss confirmed", "reflected xss confirmed",
        "xss payload 触发",
        # 堆栈泄露
        "堆栈泄露", "stack trace", "stacktrace",
        "exception in thread", "at java.lang", "at sun.", "at com.",
        # 敏感信息泄露
        "源码泄露", "密钥泄露", ".env 泄露", "config 泄露", "敏感数据泄露",
        # 越权
        "idor 确认", "idor 漏洞", "越权访问成功", "越权操作成功",
        "horizontal privilege escalation", "vertical privilege escalation",
        # SSRF
        "ssrf 漏洞", "ssrf 成功", "ssrf 利用",
        # 路径遍历
        "路径遍历成功", "目录穿越成功", "../../etc/passwd",
        # XXE
        "xxe 注入", "xxe 漏洞", "xml 外部实体注入",
        # 反序列化
        "反序列化漏洞", "deserialization vulnerability",
        "java.io.objectinputstream",
        # 任意文件上传
        "任意文件上传成功", "shell 上传成功", "webshell 上传",
        # 通用确认词（强信号 — 必须是带"漏洞/确认/成功"的组合）
        "🚨", "发现漏洞", "确认漏洞", "存在漏洞", "证实漏洞",
        "成功利用", "成功复现", "漏洞已确认",
        "vulnerability confirmed", "exploit success", "exploit succeed",
    )

    def _detect_vuln_evidence_in_history(self) -> str:
        """扫描最近 12 条 history 消息，查找"发现漏洞但还没 mark"的证据。

        - 只看 LLM 自己的 message/reasoning 输出 + 工具返回结果
        - 命中关键词即返回该关键词（用于日志和提示），否则返回空字符串
        - 性能保护：仅扫描最近 12 条，每条只取前 2000 字符
        - 已 mark 保护：如果最近 5 条里有 checklist_mark 调用，认为已经在固化中，不需要再提示
        """
        try:
            history = list(self.context.history)
        except Exception:
            return ""
        if not history:
            return ""

        recent = history[-12:]

        # 已 mark 保护：检查最近 5 条里有没有 checklist_mark tool_call
        for m in history[-5:]:
            if getattr(m, "tool_calls", None):
                for tc in m.tool_calls or []:
                    fn = tc.get("function", {}).get("name", "") if isinstance(tc, dict) else ""
                    if fn == "checklist_mark":
                        return ""  # 已经在 mark，不打扰

        # 关键词扫描
        for m in recent:
            content = getattr(m, "content", "") or ""
            if not content:
                continue
            content_lower = content[:2000].lower()
            for kw in self._VULN_EVIDENCE_KEYWORDS:
                if kw in content_lower:
                    return kw
        return ""

    def _inject_lessons_by_vuln_type(self) -> None:
        """按本组功能点涉及的 vuln_type 分别召回历史教训并注入上下文。

        2026-05-20 新增（修复集成断层）：
        - core/memory.py 的 recall() 一直支持 vuln_type 精准召回，
          但之前 worker_agent 没接入，导致 Hermes 风格"针对漏洞类型的踩坑教训"白做了。
        - 召回策略：每个 vuln_type 最多取 3 条最相关教训；总条数上限 12。
        - 失败保护：memory 模块异常不影响 worker 主流程。
        """
        try:
            from core import memory
        except Exception as e:
            log.warning("[%s] 加载 memory 模块失败，跳过历史经验注入: %s", self.worker_id, e)
            return

        # 收集本组涉及的所有 vuln_type（去重，保持顺序）
        vuln_types: list[str] = []
        seen: set[str] = set()
        for fp in self.features:
            for c in fp.get_http_pending():
                if c.vuln_type and c.vuln_type not in seen:
                    seen.add(c.vuln_type)
                    vuln_types.append(c.vuln_type)
        if not vuln_types:
            return

        target_url = getattr(self.sitemap, "target", "") or ""
        all_lessons: list[dict] = []
        seen_ids: set[str] = set()

        # 每个 vuln_type 最多取 3 条
        for vt in vuln_types:
            try:
                lessons = memory.recall(
                    target_url=target_url,
                    vuln_type=vt,
                    query=vt,
                    limit=3,
                )
            except Exception as e:
                log.warning("[%s] memory.recall(%s) 失败: %s", self.worker_id, vt, e)
                continue
            for ls in lessons:
                lid = ls.get("id", "")
                if lid and lid not in seen_ids:
                    seen_ids.add(lid)
                    all_lessons.append(ls)
                    if len(all_lessons) >= 12:
                        break
            if len(all_lessons) >= 12:
                break

        if not all_lessons:
            return

        try:
            block = memory.format_for_prompt(all_lessons)
        except Exception as e:
            log.warning("[%s] format_for_prompt 失败: %s", self.worker_id, e)
            return

        if not block:
            return

        self.context.add_system(block)
        log.info("[%s] 注入 %d 条历史经验（覆盖 %d 个 vuln_type）",
                 self.worker_id, len(all_lessons), len(vuln_types))

    def _inject_business_understanding(self) -> None:
        """把 Phase 1.5 业务理解的 attack_hypotheses 和 promises 注入 worker 上下文。

        2026-05-19 新增：
        - 让 worker 能看到「业务驱动的具体假设」（不只是通用漏洞类型清单）
        - 按当前组功能点的 API 路径前缀做相关性筛选（避免无关假设干扰）
        - 失败降级：找不到业务理解就跳过，不影响 worker 运行
        """
        try:
            bu_data = getattr(self.sitemap, "business_understanding", None) or {}
            if not bu_data or bu_data.get("status") != "ok":
                return
            understanding = bu_data.get("understanding") or {}
            if not isinstance(understanding, dict):
                return

            promises = understanding.get("promises") or []
            hypotheses = understanding.get("attack_hypotheses") or []
            top3 = understanding.get("top_3_directions") or []

            if not (promises or hypotheses or top3):
                return

            # 收集当前组功能点涉及的 API 路径片段（用于相关性筛选）
            from urllib.parse import urlparse
            group_path_segments: set[str] = set()
            for fp in self.features:
                for api in fp.related_apis or []:
                    url_part = api.split(" ", 1)[-1] if " " in api else api
                    try:
                        path = urlparse(url_part).path or url_part
                    except Exception:
                        path = url_part
                    # 取前两段作为相关性匹配键（如 /api/_/tickets → "api,_,tickets"）
                    parts = [p for p in path.split("/") if p][:3]
                    for p in parts:
                        if len(p) >= 3 and not p.isdigit():
                            group_path_segments.add(p.lower())

            # 筛选与本组相关的 hypotheses（endpoint 路径包含组内任一片段）
            related_hypotheses = []
            for h in hypotheses:
                if not isinstance(h, dict):
                    continue
                endpoint = (h.get("endpoint") or "").lower()
                # 没有 endpoint 字段的，按 vulnerability_category 也保留 P0 级
                if not endpoint:
                    related_hypotheses.append(h)
                    continue
                if any(seg in endpoint for seg in group_path_segments):
                    related_hypotheses.append(h)
            # 如果筛完是空的，至少保留前 3 条（业务理解的 top hypotheses 通常通用）
            if not related_hypotheses and hypotheses:
                related_hypotheses = [h for h in hypotheses[:3] if isinstance(h, dict)]

            # P0/P1 promises 全部保留（数量本来就不多）
            high_pri_promises = [p for p in promises if isinstance(p, dict)
                                 and p.get("priority", "").upper() in ("P0", "P1")]
            if not high_pri_promises:
                high_pri_promises = [p for p in promises[:6] if isinstance(p, dict)]

            # 拼成 system 消息
            lines = [
                "## 业务理解：本目标的攻击焦点（来自 Phase 1.5 业务分析）",
                "",
                "以下是业务分析师对本目标的理解。**测试时优先围绕这些假设和承诺验证**，",
                "不要只跑通用漏洞清单（通用清单只是底线，业务针对性测试才是出洞关键）。",
                "",
            ]

            if top3:
                lines.append("### 🎯 Top 攻击方向（业务分析师推荐的 3 个最高 ROI 方向）")
                lines.append("")
                for i, t in enumerate(top3[:3]):
                    if not isinstance(t, dict):
                        continue
                    direction = t.get("direction", "")
                    reason = t.get("reason", "")
                    lines.append(f"{i+1}. **{direction}**")
                    if reason:
                        lines.append(f"   理由：{reason[:200]}")
                lines.append("")

            if high_pri_promises:
                lines.append(f"### 🤝 系统承诺（必须证伪/打破才算真测过）")
                lines.append("")
                lines.append("以下是系统对用户/对自身的明确承诺。")
                lines.append("**任何打破其中一条 = 真漏洞**。在 detail 中说明你尝试打破了哪些 promise。")
                lines.append("")
                lines.append("| ID | 优先级 | 承诺内容 | 攻击焦点 |")
                lines.append("|---|---|---|---|")
                for p in high_pri_promises[:8]:
                    pid = p.get("id", "P-?")
                    prio = p.get("priority", "")
                    desc = (p.get("description") or "")[:120]
                    focus = (p.get("attack_focus") or "")[:80]
                    lines.append(f"| {pid} | {prio} | {desc} | {focus} |")
                lines.append("")

            if related_hypotheses:
                lines.append(f"### 💡 与本组相关的攻击假设（{len(related_hypotheses)} 条）")
                lines.append("")
                lines.append("**这是业务分析师针对本目标定制的具体假设，不是通用漏洞类型**。")
                lines.append("每条假设都说明了：用什么角色、改哪个 endpoint 的哪个参数、期望响应、对应漏洞类型。")
                lines.append("**对应的 checklist 项**测试时优先验证这些假设。")
                lines.append("")
                for h in related_hypotheses[:10]:
                    hid = h.get("id", "ATH-?")
                    role = h.get("role", "")
                    endpoint = (h.get("endpoint") or "")[:160]
                    expected = (h.get("expected_response") or "")[:140]
                    vcat = h.get("vulnerability_category", "")
                    reason = (h.get("reason") or "")[:160]
                    lines.append(f"- **{hid}** [{role}] → `{endpoint}`")
                    if vcat:
                        lines.append(f"  - 漏洞类型: {vcat}")
                    if expected:
                        lines.append(f"  - 期望响应: {expected}")
                    if reason:
                        lines.append(f"  - 为什么值得测: {reason}")
                lines.append("")

            lines.append("---")
            lines.append("⚠️ **如何与 SKILL 配合**：SKILL 是通用方法论，业务理解是针对本目标的具体假设。")
            lines.append("测试时**两者都要参考**：用 SKILL 的 Phase 步骤展开测试动作，但优先选择能验证业务假设的 endpoint/参数。")

            self.context.add_system("\n".join(lines))
            log.info("[%s] 注入业务理解: %d promises, %d hypotheses (筛选后 %d), %d top_directions",
                     self.worker_id, len(high_pri_promises), len(hypotheses),
                     len(related_hypotheses), len(top3))
        except Exception as e:
            log.warning("[%s] 注入业务理解失败: %s", self.worker_id, e)

    async def run(self) -> AsyncGenerator[dict, None]:
        """运行子 Agent 直到所有功能点测试完成或出错。"""
        round_num = 0
        tools = build_worker_tools()
        # 增加 max_rounds：多功能点组需要更多轮次
        max_rounds = WORKER_MAX_ROUNDS * max(len(self.features), 1)

        # ★ 跟踪当前正在测试的功能点，切换时压缩上下文
        _prev_feature_id = self.features[0].id if self.features else None

        while round_num < max_rounds and not self.completed:
            round_num += 1

            # 更新当前功能点引用
            self.feature = self.current_feature

            # ★ 功能点切换检测 → 强制压缩上下文（释放前一个功能点的对话历史）
            curr_fid = self.feature.id if self.feature else None
            if curr_fid and curr_fid != _prev_feature_id:
                log.info("[%s] 功能点切换: %s → %s，压缩上下文",
                         self.worker_id, _prev_feature_id, curr_fid)
                self.context.compress()
                _prev_feature_id = curr_fid

            yield {"type": "worker_thinking", "worker": self.worker_id,
                   "feature": self.feature.name if self.feature else self.group_name,
                   "round": round_num}

            # ★ LLM 调用超时保护：asyncio.wait_for 兜底，防止 API 挂起导致 Worker 永久卡死
            # SDK 层已设 120s timeout，这里 180s 兜底（给 SDK 先抛出有意义的错误）
            _LLM_CALL_TIMEOUT = 180
            try:
                messages = self.context.get_messages()
                response = await asyncio.wait_for(
                    asyncio.to_thread(self.llm.chat, messages, tools, caller=f"worker:{self.worker_id}"),
                    timeout=_LLM_CALL_TIMEOUT,
                )
            except Exception as e:
                # ★ asyncio.TimeoutError → 转成可读消息，走重试逻辑
                if isinstance(e, asyncio.TimeoutError):
                    e = TimeoutError(f"LLM 调用超时（{_LLM_CALL_TIMEOUT}s），可能 API 挂起或模型无响应")
                # ★ 自动重试：网络错误/限流/5xx 最多重试 5 次（间隔递增），避免偶发抖动直接退出
                err_str = str(e).lower()
                err_type = type(e).__name__.lower()
                is_network_err = (
                    "connection error" in err_str or "connecterror" in err_type
                    or "timeout" in err_type or "dns" in err_type
                    or "could not resolve" in err_str or "nodename nor servname" in err_str
                    or "name or service not known" in err_str
                    or "connection refused" in err_str or "connection reset" in err_str
                    or "network is unreachable" in err_str
                    # ★ 限流与服务端临时错误（与 LLMClient._RETRYABLE_ERROR_KEYWORDS 对齐）
                    or "429" in err_str or "rate limit" in err_str or "rate_limit" in err_str
                    or "too many requests" in err_str
                    or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str
                    or "overloaded" in err_str or "server_error" in err_str
                )
                _retried_ok = False
                if is_network_err:
                    for _retry in range(1, 6):
                        _wait = _retry * 5
                        log.info("Worker %s LLM 网络异常，重试 %d/5（等待 %ds）: %s",
                                 self.worker_id, _retry, _wait, e)
                        await asyncio.sleep(_wait)
                        try:
                            messages = self.context.get_messages()
                            response = await asyncio.wait_for(
                                asyncio.to_thread(self.llm.chat, messages, tools, caller=f"worker:{self.worker_id}"),
                                timeout=_LLM_CALL_TIMEOUT,
                            )
                            _retried_ok = True
                            break
                        except Exception:
                            continue
                if not _retried_ok:
                    self.error = str(e)
                    yield {"type": "worker_error", "worker": self.worker_id,
                           "feature": self.group_name, "error": str(e)}
                    break

            self.context.add_assistant(response)

            if response.content:
                # ★ 过滤无意义的推理文本（"Let me examine..." / "I'll work through..." 等）
                # 只在有实质内容时才推送，避免前端被废话刷屏
                _content = response.content.strip()
                _is_boilerplate = any(
                    _content.lower().startswith(p)
                    for p in ("let me ", "i'll ", "i will ", "now let me ", "first, let me ")
                ) and len(_content) < 150
                if not _is_boilerplate:
                    yield {"type": "worker_message", "worker": self.worker_id,
                           "feature": self.feature.name if self.feature else self.group_name,
                           "content": _content[:800]}

            if response.tool_calls:
                # ★ 反内卷跟踪：本轮是否有 checklist_mark
                this_round_has_mark = False
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller=f"worker:{self.worker_id}")

                    # ★ tool_call arguments 解析失败时，不要用空 args 继续执行
                    # （会导致工具用默认参数跑、行为不可预期），而是回填错误让 LLM 重发。
                    if args_failed:
                        _err_hint = (
                            f"⚠️ 工具 `{func_name}` 的 arguments 解析失败，"
                            f"无法识别参数。请重新调用该工具，arguments 必须是合法 JSON "
                            f"（如 {chr(123)}\"url\": \"...\", \"method\": \"GET\"{chr(125)}）。"
                        )
                        try:
                            self.context.add_tool_result(tc["id"], _err_hint)
                        except Exception:
                            pass
                        log.warning("[%s] tool_call %s args 解析失败，已回填提示 LLM 重发",
                                    self.worker_id, func_name)
                        continue

                    # ★ 反内卷：跟踪同一接口连续测试次数
                    if func_name in ("proxy_send_request", "proxy_replay", "proxy_batch_send"):
                        try:
                            from urllib.parse import urlparse as _up
                            url_arg = args.get("url") or args.get("base_url") or ""
                            method_arg = (args.get("method") or "GET").upper()
                            if url_arg:
                                parsed = _up(url_arg)
                                # 只取 host+path，去掉 query 和 fragment
                                _key = f"{method_arg} {parsed.netloc}{parsed.path}"
                                if _key == self._last_url_method_key:
                                    self._url_method_streak[_key] = self._url_method_streak.get(_key, 0) + 1
                                else:
                                    self._url_method_streak[_key] = 1
                                self._last_url_method_key = _key
                        except Exception as _e:
                            log.debug("[%s] 反内卷 URL 跟踪失败: %s", self.worker_id, _e)
                    if func_name == "checklist_mark":
                        this_round_has_mark = True
                        # mark 后重置该 URL 的内卷计数（因为已经下结论了）
                        self._url_method_streak.clear()
                        self._last_url_method_key = ""

                    # 摘要：隐藏 headers/Cookie，只显示关键参数
                    args_full_str = json.dumps(args, ensure_ascii=False)
                    brief_args = {k: ("{...}" if k.lower() in ("headers", "cookie") else
                                      (v[:60] + "..." if isinstance(v, str) and len(v) > 60 else v))
                                  for k, v in args.items()}
                    args_brief_str = json.dumps(brief_args, ensure_ascii=False)[:150]

                    yield {"type": "worker_tool", "worker": self.worker_id,
                           "feature": self.feature.name if self.feature else self.group_name,
                           "tool_brief": f"{func_name}({args_brief_str})",
                           "tool_full": f"{func_name}({args_full_str})"}

                    # ★ 决策剧场：每个 tool_call 都是一次"LLM 决策"
                    # 注意：checklist_mark 走 HARM_VALIDATED 帧（在 tool_executor 里 emit），这里不重复
                    if func_name != "checklist_mark":
                        try:
                            from core.replay import emit_decision as _ed
                            # vuln_type 推断：args 里有 vuln_type 直接用，否则从当前 feature 取第一个 pending
                            _vt = args.get("vuln_type", "") if isinstance(args, dict) else ""
                            if not _vt and self.current_feature:
                                _pending = self.current_feature.get_http_pending()
                                if _pending:
                                    _vt = _pending[0].vuln_type
                            # LLM 思考摘要：本次 response.content / reasoning_content
                            _summary = (response.content or "")[:1500]
                            if not _summary and getattr(response, "reasoning_content", ""):
                                _summary = (response.reasoning_content or "")[:1500]
                            # target_url 优先从 args 里抠
                            _turl = ""
                            if isinstance(args, dict):
                                _turl = args.get("url") or args.get("base_url") or ""
                            _ed(
                                task_id=self._replay_task_id,
                                worker_id=self.worker_id,
                                feature_id=self.current_feature.id if self.current_feature else "",
                                feature_name=self.current_feature.name if self.current_feature else self.group_name,
                                vuln_type=_vt,
                                skill_used=func_name,
                                payload=args_brief_str,
                                target_url=_turl or self._replay_target,
                                llm_summary=_summary,
                                track="llm",
                                round=round_num,
                            )
                        except Exception as _e:
                            log.debug("[%s] 决策剧场 emit 失败: %s", self.worker_id, _e)

                    try:
                        # 传入当前功能点（checklist_mark 需要 feature 上下文）
                        result, is_completed, self._done_reject_count = \
                            await self._execute_tool(func_name, args)
                    except Exception as e:
                        result = f"工具执行出错: {e}"
                        is_completed = False

                    # ★ 截图工具：实时向前端推送截图事件
                    if func_name == "browser_screenshot" and isinstance(result, str) \
                            and "截图已保存" in result:
                        ss_name = args.get("name", "screenshot") if isinstance(args, dict) else "screenshot"
                        yield {"type": "worker_screenshot", "worker": self.worker_id,
                               "feature": self.feature.name if self.feature else self.group_name,
                               "name": ss_name}

                    if len(result) > 6000:
                        result = result[:6000] + "\n... (截断)"

                    self.context.add_tool_result(tc["id"], result)

                    if is_completed:
                        self.completed = True
                        break

                # ★ 反内卷判定（在 tool_calls 循环结束后做一次）
                if not self.completed:
                    self._rounds_without_mark = 0 if this_round_has_mark else (self._rounds_without_mark + 1)
                    streak_max = max(self._url_method_streak.values(), default=0)

                    # 触发条件：①同一接口连续 ≥ 30 次  或  ②连续 ≥ 30 轮没 mark
                    # 2026-05-23: no_mark 阈值从 10 放宽到 20（单个漏洞类型正常探测需 5-8 轮）
                    # 2026-05-29: no_mark 阈值从 20 放宽到 30（复杂漏洞深度测试需更多轮次）
                    should_warn = (streak_max >= 30) or (self._rounds_without_mark >= 30)

                    # ★ 2026-05-20 修复（A）：漏洞验证豁免
                    # 如果最近几轮 LLM 输出里已经出现明确的"发现漏洞/泄露"证据，
                    # 但还没来得及 checklist_mark，反内卷应该让步给 LLM 完成验证标记。
                    # 否则会出现"发现 SQL 注入但被强制收尾，最终 0 漏洞"的严重 bug。
                    if should_warn:
                        vuln_evidence = self._detect_vuln_evidence_in_history()
                        if vuln_evidence:
                            # 不触发反内卷，但插入一条强提醒：立刻 mark
                            if not getattr(self, "_vuln_nudge_sent", False):
                                self.context.add_system(
                                    "## 🚨 检测到漏洞证据但未 mark — 立即固化\n\n"
                                    f"你最近的输出里出现了漏洞证据关键词：**{vuln_evidence}**。\n"
                                    "**强制要求：你的下一个动作必须是 `checklist_mark`**：\n"
                                    "- `result=\"vulnerable\"` + 详细 `detail`（payload / 响应特征 / 影响）\n"
                                    "- 或 `result=\"needs_review\"` + 复现步骤（如果还需补一两个 payload 才能盖章）\n\n"
                                    "**禁止继续发新 payload 探测**——证据已经够了，先固化再说。"
                                )
                                self._vuln_nudge_sent = True
                                log.warning("[%s] 反内卷豁免: 检测到漏洞证据 [%s]，已强提示 LLM mark",
                                            self.worker_id, vuln_evidence)
                                yield {"type": "worker_message", "worker": self.worker_id,
                                       "feature": self.feature.name if self.feature else self.group_name,
                                       "content": f"🛡️ 反内卷豁免：检测到漏洞证据「{vuln_evidence}」，已强提示 LLM 立即固化"}
                            # 给 LLM 5 轮额外时间完成 mark（reset 计数，不让反内卷立刻再触发）
                            self._url_method_streak.clear()
                            self._last_url_method_key = ""
                            # _rounds_without_mark 不重置：如果给了豁免还不 mark，下一轮该触发还得触发
                            should_warn = False  # 跳过本轮 nudge

                    if should_warn and not self._anti_loop_warned:
                        # 找到最热的 URL（仅用于提示）
                        hot_key = max(self._url_method_streak.items(), key=lambda x: x[1])[0] \
                            if self._url_method_streak else "(无)"
                        nudge = (
                            "## ⚠️ 反内卷强制收尾\n\n"
                            f"检测到你在同一接口反复测试无进展：\n"
                            f"- 最热接口：`{hot_key}` 已连续测试 {streak_max} 次\n"
                            f"- 连续 {self._rounds_without_mark} 轮未调用 checklist_mark\n\n"
                            "**立即执行以下二选一：**\n"
                            "1. 如果你已得出结论 → 调用 `checklist_mark` 给当前 checklist 项打分"
                            "（result=`not_vuln` / `skipped` / `vulnerable`，附 detail 简述判断依据），"
                            "然后切到下一个测试方向；\n"
                            "2. 如果该接口确实没有可测点 → 直接对当前功能点的所有未测项标 `skipped` "
                            "（reason=\"接口无回显/参数不影响响应/已穷举无可疑点\"），然后调用 `worker_done` 收尾。\n\n"
                            "⚠️ **如果你已发现可疑漏洞（如 SQL 错误、堆栈泄露、敏感数据回显），"
                            "请立即 `checklist_mark vulnerable` 并把证据写到 detail 里——不要再换 payload 试**！\n\n"
                            "⛔ 不允许继续在同一接口换载荷试探，浪费预算。"
                        )
                        self.context.add_system(nudge)
                        log.warning("[%s] 反内卷触发: hot=%s streak=%d no_mark=%d",
                                    self.worker_id, hot_key, streak_max, self._rounds_without_mark)
                        yield {"type": "worker_message", "worker": self.worker_id,
                               "feature": self.feature.name if self.feature else self.group_name,
                               "content": f"⚠️ 反内卷触发：同接口连测 {streak_max} 次或连续 {self._rounds_without_mark} 轮未 mark — 已强制提示收尾"}
                        self._anti_loop_warned = True
                        # 重置计数：给 LLM 一次机会响应，没响应再触发一次升级
                        self._url_method_streak.clear()
                        self._last_url_method_key = ""
                        self._rounds_without_mark = 0
                    elif should_warn and self._anti_loop_warned:
                        # 第二次触发 → 直接给所有未测项标 skipped + 强制 worker_done
                        # ★ 2026-05-20 修复（A）：强制收尾前抢救漏洞证据
                        # 如果历史里有未 mark 的漏洞证据，自动写一个 needs_review 项保留线索
                        log.warning("[%s] 反内卷二次触发 → 强制收尾", self.worker_id)
                        from core.sitemap import CheckResult as _CR
                        salvage_evidence = self._detect_vuln_evidence_in_history()
                        salvaged_count = 0
                        if salvage_evidence:
                            # 尝试找一个相关的 pending checklist 项标 needs_review
                            for fp in self.features:
                                for c in fp.checklist:
                                    if c.result == _CR.PENDING:
                                        # 优先把最相关的 vuln_type 标 needs_review（粗略匹配）
                                        if any(kw in c.vuln_type.lower() for kw in
                                               (salvage_evidence.lower(), "注入" if "sql" in salvage_evidence.lower() else "")):
                                            c.result = _CR.NEEDS_REVIEW
                                            c.detail = (
                                                f"⚠️ 反内卷强制收尾前抢救保留：worker 输出包含漏洞证据「{salvage_evidence}」"
                                                f"但未完成 checklist_mark，请人工复测验证。"
                                            )
                                            salvaged_count += 1
                                            break  # 只标第一个匹配项
                                if salvaged_count > 0:
                                    break
                        forced_skip_count = 0
                        for fp in self.features:
                            for c in fp.checklist:
                                if c.result == _CR.PENDING:
                                    c.result = _CR.SKIPPED
                                    # ★ 补全 detail：标注反内卷触发条件，让报告可追溯
                                    c.detail = (
                                        f"反内卷强制收尾：worker 在同一接口连续测试 {streak_max} 次 "
                                        f"且连续 {self._rounds_without_mark} 轮无 checklist_mark，"
                                        f"未得出明确结论，建议人工补测。"
                                    )
                                    forced_skip_count += 1
                        self.completed = True
                        salvage_msg = f"，⚠️ 抢救保留 {salvaged_count} 项 needs_review（检测到证据「{salvage_evidence}」）" if salvaged_count else ""
                        yield {"type": "worker_message", "worker": self.worker_id,
                               "feature": self.group_name,
                               "content": f"🛑 反内卷强制收尾：自动跳过 {forced_skip_count} 个未结论项{salvage_msg}"}
            else:
                break

            if self.context.should_compress():
                self.context.compress()

        # 完成后标记所有功能点状态
        # ★ 根据 worker 退出原因区分 normal/error/anti_loop，
        # 让报告能区分"正常结束未覆盖" vs "worker 崩溃漏测"
        exit_reason = "normal"
        if self.error:
            exit_reason = "error"
        elif getattr(self, "_anti_loop_warned", False):
            exit_reason = "anti_loop"
        for fp in self.features:
            if fp.test_status in (TestStatus.NOT_TESTED, TestStatus.IN_PROGRESS):
                self.sitemap.finish_test(fp.id, reason=exit_reason)
        self.sitemap.save()

        # 汇总统计
        total_vulns = sum(
            1 for fp in self.features for c in fp.checklist
            if c.result == CheckResult.VULNERABLE
        )
        total_completed = sum(
            1 for fp in self.features for c in fp.checklist
            if c.result != CheckResult.PENDING
        )
        total_checks = sum(len(fp.checklist) for fp in self.features)
        features_done = sum(
            1 for fp in self.features
            if fp.test_status in (TestStatus.TESTED, TestStatus.VULN_FOUND)
        )

        yield {"type": "worker_done", "worker": self.worker_id,
               "group": self.group_name,
               "features_done": features_done,
               "features_total": len(self.features),
               "vulns": total_vulns,
               "completed": total_completed,
               "total": total_checks}

    async def _execute_tool(self, func_name: str, args: dict) -> tuple[str, bool, int]:
        """执行工具调用，处理 checklist_mark 的 feature_id 路由。

        对于 checklist_mark，需要根据 feature_id 找到正确的功能点。
        对于 worker_done，检查是否所有功能点都已测完。
        """
        if func_name == "worker_done":
            # 检查是否所有功能点的 checklist 都已标记
            all_pending = []
            for fp in self.features:
                pending = [c for c in fp.checklist if c.result == CheckResult.PENDING and not c.needs_browser]
                if pending:
                    all_pending.append((fp, [c for c in pending]))

            if all_pending and self._done_reject_count < 3:
                self._done_reject_count += 1
                detail = "\n".join(
                    f"- {fp.name} ({fp.id}): {', '.join(c.vuln_type for c in checks)}"
                    for fp, checks in all_pending
                )

                if self._done_reject_count <= 2:
                    # 前 2 次：明确告诉 LLM 还有哪些没测，要求补测
                    return (
                        f"⛔ 拒绝完成（第 {self._done_reject_count}/3 次）：\n"
                        f"还有 {len(all_pending)} 个功能点共 "
                        f"{sum(len(checks) for _, checks in all_pending)} 个未测项：\n{detail}\n\n"
                        f"**请对每个未测项执行测试并 checklist_mark，或标记 skipped（附说明原因）。**\n"
                        f"⚠️ 不允许直接跳过未测项！每个 checklist 项必须有结论。",
                        False, self._done_reject_count
                    )
                else:
                    # 第 3 次：自动把遗漏项标为 skipped，然后放行（防止死循环）
                    auto_skipped = 0
                    for fp, checks in all_pending:
                        for c in checks:
                            c.result = CheckResult.SKIPPED
                            # ★ 补全 detail：明确标注是 worker_done 拒绝后强制 skip，
                            # 让报告能区分"LLM 主动跳过" vs "系统强制兜底"
                            c.detail = (
                                "⚠️ 子 Agent 多次拒绝完成（worker_done 被拒 3 次），"
                                "系统强制标记 skipped。该项未实际测试，建议人工补测。"
                            )
                            auto_skipped += 1
                    log.warning("[%s] worker_done 第3次拒绝后自动 skip %d 个未测项",
                                self.worker_id, auto_skipped)
                    return (
                        f"⚠️ 强制完成：{auto_skipped} 个未测项已自动标记为 skipped（漏检）。\n"
                        f"这些项会在报告中标注为「子 Agent 未覆盖」。",
                        True, self._done_reject_count
                    )
            else:
                return "✅ 所有功能点测试完成", True, self._done_reject_count

        if func_name == "checklist_mark":
            # 如果 args 中没有 feature_id，尝试推断
            if "feature_id" not in args and self.current_feature:
                args["feature_id"] = self.current_feature.id

        # 根据 feature_id 找到组内正确的功能点
        target_feature = self.current_feature or (self.features[0] if self.features else None)
        if "feature_id" in args:
            fid = args["feature_id"]
            for fp in self.features:
                if fp.id == fid:
                    target_feature = fp
                    break

        # 委托给 ToolExecutor
        result, is_completed, reject_count = await self.tool_executor.execute_for_worker(
            func_name, args, target_feature, self._done_reject_count
        )

        # 如果是 worker_done 从 execute_for_worker 返回的 complete 信号
        if is_completed and func_name == "worker_done":
            return result, True, reject_count

        # ★ checklist_mark 后检测：当前功能点是否所有 HTTP 项都完成了？
        # 如果完成 → 自动递增 _current_idx 推进到下一个功能点
        if func_name == "checklist_mark" and self.current_feature:
            curr_pending = self.current_feature.get_http_pending()
            if not curr_pending:
                # 当前功能点所有 HTTP 项已完成
                old_idx = self._current_idx
                if self._current_idx < len(self.features) - 1:
                    self._current_idx += 1
                    next_fp = self.features[self._current_idx]
                    log.info("[%s] 功能点 %s 全部完成，推进到 %s (idx %d→%d)",
                             self.worker_id, self.current_feature.name if old_idx < len(self.features) else "?",
                             next_fp.name, old_idx, self._current_idx)
                    # 在结果中提示 LLM 继续下一个功能点
                    result += f"\n\n✅ 当前功能点已全部测完。请继续测试下一个功能点：{next_fp.name} ({next_fp.id})"

        return result, False, reject_count
