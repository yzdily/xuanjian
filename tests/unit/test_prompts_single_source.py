"""
test_prompts_single_source — 验证 LLM 提示词已外置到 core/prompts/*.md 单源文件。

覆盖：
1. 所有 .md 提示词文件存在且可通过 load_prompt / load_template 加载
2. 静态提示词内容完整（包含期望标记文本）
3. 模板提示词的占位符正确填充、字面花括号 {{ }} 正确转义为 { }
4. .py 文件中不再包含大段内联提示词（已迁移到 .md）
5. core.prompts 仅依赖标准库（无循环导入风险）
6. 受影响模块可正常导入（回归冒烟）

设计原则：零网络、零 LLM；纯文件 / 导入级测试。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.prompts import load_prompt, load_template  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PROMPTS_DIR = ROOT / "core" / "prompts"

# ============================================================
# 外置提示词清单
# ============================================================

STATIC_PROMPTS = [
    "compress",
    "browse_compress",
    "intent_parse",
    "lesson_extract",
    "screenshot_analysis",
    "xss_judge",
    "xss_waf_bypass",
    "meta_analysis",
    "exploit_system",
    "rescue_system",
    "analyze_worker_system",
    "browse_worker_group",
    "browse_worker_phase_end",
    "explore_domain_judge",
    "chat_loop_no_target",
    "js_analyzer_system",
]

TEMPLATE_PROMPTS = [
    "screenshot_filter",
    "ocr_analysis",
    "packet_analysis",
    "focused_test_suggest",
    "js_api_extract",
]


# ============================================================
# 1. .md 文件存在且可加载
# ============================================================

class TestPromptFilesExist:
    """每个 .md 文件存在于磁盘且 load_prompt 返回非空字符串。"""

    @pytest.mark.parametrize("name", STATIC_PROMPTS + TEMPLATE_PROMPTS)
    def test_md_file_exists_on_disk(self, name):
        path = PROMPTS_DIR / f"{name}.md"
        assert path.is_file(), f"提示词文件不存在: {path}"

    @pytest.mark.parametrize("name", STATIC_PROMPTS)
    def test_static_prompt_loads_nonempty(self, name):
        p = load_prompt(name)
        assert isinstance(p, str)
        assert len(p) > 0, f"load_prompt('{name}') 返回空字符串"

    @pytest.mark.parametrize("name", TEMPLATE_PROMPTS)
    def test_template_prompt_loads_nonempty(self, name):
        p = load_prompt(name)
        assert isinstance(p, str)
        assert len(p) > 0, f"load_prompt('{name}') 返回空字符串"

    @pytest.mark.parametrize("name", STATIC_PROMPTS + TEMPLATE_PROMPTS)
    def test_no_crlf_in_loaded_prompt(self, name):
        """Windows CRLF 应被 read_text 统一为 LF。"""
        p = load_prompt(name)
        assert "\r\n" not in p, f"提示词 '{name}' 包含 CRLF（应已归一化为 LF）"


# ============================================================
# 2. 静态提示词内容标记
# ============================================================

class TestStaticPromptContent:
    """加载的提示词包含期望的首行标记，确认内容未被截断。"""

    EXPECTED_FIRST_LINE = {
        "compress": "你是一个渗透测试过程记录压缩器",
        "browse_compress": "你是一个浏览器操作过程记录压缩器",
        "intent_parse": "你是一个意图解析器",
        "lesson_extract": "经验提炼器",
        "screenshot_analysis": "你是一个 Web 安全测试专家。请分析这张网页截图",
        "xss_judge": "你是 XSS 漏洞研判专家",
        "xss_waf_bypass": "你是 XSS WAF 绕过专家",
        "meta_analysis": "你是一个渗透测试任务调度器",
        "exploit_system": "你是游刃AISec的漏洞利用专家 Agent",
        "rescue_system": "你是 SRC 漏洞审核员",
        "analyze_worker_system": "你是渗透测试功能分析专家",
        "browse_worker_group": "## 你的角色：Phase 1",
        "browse_worker_phase_end": "你是子 Agent",
        "explore_domain_judge": "你是安全测试助手，负责判断域名是否属于目标业务",
        "chat_loop_no_target": "你是游刃AISec自动化渗透智能体",
        "js_analyzer_system": "你是一个 JS 代码分析专家",
    }

    @pytest.mark.parametrize("name,marker", list(EXPECTED_FIRST_LINE.items()))
    def test_prompt_contains_expected_marker(self, name, marker):
        p = load_prompt(name)
        assert marker in p, f"提示词 '{name}' 缺少期望标记: {marker!r}"


# ============================================================
# 3. 模板占位符填充
# ============================================================

class TestTemplateFormatting:
    """load_template 正确填充 {placeholder} 占位符。"""

    def test_screenshot_filter_placeholders_filled(self):
        result = load_template(
            "screenshot_filter",
            analysis_json='{"test": 1}',
            user_instruction="测试登录功能",
        )
        assert '{"test": 1}' in result
        assert "测试登录功能" in result
        # 不应残留未填充占位符
        assert "{analysis_json}" not in result
        assert "{user_instruction}" not in result

    def test_ocr_analysis_placeholder_filled(self):
        result = load_template("ocr_analysis", ocr_text="用户名 密码 登录按钮")
        assert "用户名 密码 登录按钮" in result
        assert "{ocr_text}" not in result

    def test_packet_analysis_placeholder_filled(self):
        result = load_template("packet_analysis", packet_summary="GET /api/users HTTP/1.1")
        assert "GET /api/users HTTP/1.1" in result
        assert "{packet_summary}" not in result

    def test_focused_test_suggest_placeholders_filled(self):
        result = load_template(
            "focused_test_suggest",
            feat_name="登录功能",
            description="用户登录页面",
            estimated_api="POST /api/login",
            interaction_type="form",
        )
        assert "登录功能" in result
        assert "POST /api/login" in result
        assert "{feat_name}" not in result
        assert "{description}" not in result
        assert "{estimated_api}" not in result
        assert "{interaction_type}" not in result

    def test_js_api_extract_placeholders_filled(self):
        result = load_template(
            "js_api_extract",
            file_name="app.bundle.js",
            combined_code="fetch('/api/v1/users')",
        )
        assert "app.bundle.js" in result
        assert "fetch('/api/v1/users')" in result
        assert "{file_name}" not in result
        assert "{combined_code}" not in result

    def test_literal_braces_preserved(self):
        """模板中的 {{ }} 转义后应输出为单 { }，不被 str.format 吞掉。"""
        # screenshot_filter / ocr_analysis / js_api_extract 包含 JSON 示例
        for name, fields in [
            ("screenshot_filter", {"analysis_json": "X", "user_instruction": "Y"}),
            ("ocr_analysis", {"ocr_text": "Z"}),
            ("js_api_extract", {"file_name": "f.js", "combined_code": "c"}),
        ]:
            result = load_template(name, **fields)
            # 不应残留 {{ 或 }}（说明转义正确处理）
            assert "{{" not in result, f"'{name}' 模板残留未转义的 {{{{"
            assert "}}" not in result, f"'{name}' 模板残留未转义的 }}}}"


# ============================================================
# 4. .py 文件中不再包含大段内联提示词
# ============================================================

class TestNoInlinePrompts:
    """验证 .py 文件中已移除内联提示词内容，改用 load_prompt / load_template。

    每个条目: (py相对路径, 应存在于.md但不应存在于.py的唯一标记短语)
    """

    INLINE_CHECKS = [
        # static prompts
        ("core/context.py", "渗透测试过程记录压缩器"),
        ("core/context.py", "浏览器操作过程记录压缩器"),
        ("core/intent.py", "你是一个意图解析器"),
        ("core/lesson_extractor.py", "经验提炼器"),
        ("core/vision.py", "你是一个 Web 安全测试专家。请分析这张网页截图"),
        ("core/xss/llm_judge.py", "XSS 漏洞研判专家"),
        ("core/xss/waf_bypass.py", "XSS WAF 绕过专家"),
        ("core/parallel/batch_test.py", "渗透测试任务调度器"),
        ("core/harm_validation/exploit.py", "你是游刃AISec的漏洞利用专家 Agent"),
        ("core/harm_validation/tools.py", "你是 SRC 漏洞审核员"),
        ("core/analyze_worker.py", "你是渗透测试功能分析专家"),
        ("core/browse_worker/_worker.py", "## 你的角色：Phase 1"),
        ("core/session/explore_mixin.py", "判断域名是否属于目标业务"),
        ("core/session/chat_loop.py", "用户还没有给你明确的目标"),
        ("core/js_analyzer/_llm.py", "JS 代码分析专家"),
        # template prompts
        ("core/vision.py", "用户上传了一张网页截图，并指定了要测试的功能"),
        ("core/vision.py", "通过 OCR 从一张网页截图中提取的文字内容"),
        ("core/session/idle_mixin.py", "请分析以下 HTTP 数据包，判断该接口"),
        ("core/session/focused_test_mixin.py", "请分析以下 Web 功能，判断最可能存在的漏洞类型"),
        ("core/js_analyzer/_llm.py", "提取所有 API 端点调用"),
    ]

    @pytest.mark.parametrize("py_rel,marker", INLINE_CHECKS)
    def test_no_inline_prompt_in_py(self, py_rel, marker):
        py_path = ROOT / py_rel
        content = py_path.read_text(encoding="utf-8")
        assert marker not in content, (
            f"内联提示词标记 '{marker}' 仍存在于 {py_rel}（应已迁移到 .md）"
        )

    # ---- .py 文件应包含 load_prompt / load_template 导入 ----

    PY_IMPORT_CHECKS = [
        ("core/context.py", "load_prompt"),
        ("core/intent.py", "load_prompt"),
        ("core/lesson_extractor.py", "load_prompt"),
        ("core/vision.py", "load_prompt"),
        ("core/vision.py", "load_template"),
        ("core/session/idle_mixin.py", "load_template"),
        ("core/xss/llm_judge.py", "load_prompt"),
        ("core/xss/waf_bypass.py", "load_prompt"),
        ("core/parallel/batch_test.py", "load_prompt"),
        ("core/browse_worker/_worker.py", "load_prompt"),
        ("core/session/chat_loop.py", "load_prompt"),
        ("core/session/focused_test_mixin.py", "load_template"),
        ("core/session/explore_mixin.py", "load_prompt"),
        ("core/analyze_worker.py", "load_prompt"),
        ("core/harm_validation/exploit.py", "load_prompt"),
        ("core/harm_validation/tools.py", "load_prompt"),
        ("core/js_analyzer/_llm.py", "load_prompt"),
        ("core/js_analyzer/_llm.py", "load_template"),
    ]

    @pytest.mark.parametrize("py_rel,symbol", PY_IMPORT_CHECKS)
    def test_py_uses_loader(self, py_rel, symbol):
        py_path = ROOT / py_rel
        content = py_path.read_text(encoding="utf-8")
        assert symbol in content, f"{py_rel} 未使用 {symbol}（应通过 loader 加载提示词）"


# ============================================================
# 5. core.prompts 仅依赖标准库
# ============================================================

class TestPromptsModuleStdlibOnly:
    """core/prompts/__init__.py 仅导入标准库模块，避免循环导入。"""

    STDLIB_PREFIXES = {
        "os", "sys", "pathlib", "functools", "typing",
        "json", "re", "abc", "io", "collections",
        "__future__",
    }

    def test_no_third_party_imports(self):
        init_path = PROMPTS_DIR / "__init__.py"
        tree = ast.parse(init_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in self.STDLIB_PREFIXES, (
                        f"core.prompts 导入了非标准库: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                top = node.module.split(".")[0]
                assert top in self.STDLIB_PREFIXES, (
                    f"core.prompts 导入了非标准库: {node.module}"
                )


# ============================================================
# 6. 回归冒烟 — 受影响模块可导入
# ============================================================

class TestModuleImportSmoke:
    """所有修改过的模块可正常导入，验证无导入错误。"""

    def test_import_context(self):
        import core.context  # noqa: F401

    def test_import_intent(self):
        import core.intent  # noqa: F401

    def test_import_lesson_extractor(self):
        import core.lesson_extractor  # noqa: F401

    def test_import_vision(self):
        import core.vision  # noqa: F401

    def test_import_xss_judge(self):
        from core.xss import llm_judge  # noqa: F401

    def test_import_xss_waf_bypass(self):
        from core.xss import waf_bypass  # noqa: F401

    def test_import_batch_test(self):
        from core.parallel import batch_test  # noqa: F401

    def test_import_exploit(self):
        from core.harm_validation import exploit  # noqa: F401

    def test_import_harm_tools(self):
        from core.harm_validation import tools  # noqa: F401

    def test_import_analyze_worker(self):
        import core.analyze_worker  # noqa: F401

    def test_import_js_analyzer_llm(self):
        from core.js_analyzer import _llm  # noqa: F401

    def test_import_chat_loop(self):
        from core.session import chat_loop  # noqa: F401

    def test_import_focused_test_mixin(self):
        from core.session import focused_test_mixin  # noqa: F401

    def test_import_explore_mixin(self):
        from core.session import explore_mixin  # noqa: F401

    def test_import_idle_mixin(self):
        from core.session import idle_mixin  # noqa: F401

    def test_import_browse_worker(self):
        from core.browse_worker import _worker  # noqa: F401

    def test_prompt_constants_are_strings(self):
        """模块级提示词常量加载后应为 str 类型。"""
        from core.context import COMPRESS_PROMPT, BROWSE_COMPRESS_PROMPT
        from core.intent import INTENT_PARSE_PROMPT
        from core.lesson_extractor import _EXTRACT_PROMPT
        from core.xss.llm_judge import JUDGE_SYSTEM_PROMPT
        from core.xss.waf_bypass import LLM_BYPASS_SYSTEM_PROMPT
        from core.parallel.batch_test import META_ANALYSIS_PROMPT

        for p in [COMPRESS_PROMPT, BROWSE_COMPRESS_PROMPT, INTENT_PARSE_PROMPT,
                   _EXTRACT_PROMPT, JUDGE_SYSTEM_PROMPT, LLM_BYPASS_SYSTEM_PROMPT,
                   META_ANALYSIS_PROMPT]:
            assert isinstance(p, str)
            assert len(p) > 0
