"""
Vision — 截图识别模块

通过多模态 LLM（OpenAI vision / Claude vision）分析用户上传的截图，
识别页面中的功能点，返回结构化描述供 focused_test 模式使用。

独立模块，不依赖 Session 状态，可被任何地方调用。
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from typing import Any

from core.log import get_logger
from core.prompts import load_prompt, load_template

log = get_logger("vision")

# ============================================================
# 截图分析 Prompt
# ============================================================

_SCREENSHOT_ANALYSIS_PROMPT = load_prompt("screenshot_analysis", with_common=True)


# ============================================================
# 核心函数
# ============================================================

def encode_image_to_base64(image_path: str | Path) -> str:
    """将图片文件编码为 base64 字符串。"""
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"图片文件不存在: {path}")
    return base64.b64encode(path.read_bytes()).decode("utf-8")


def _detect_mime_type(image_path: str | Path) -> str:
    """根据文件扩展名检测 MIME 类型。"""
    ext = Path(image_path).suffix.lower()
    mime_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
    }
    return mime_map.get(ext, "image/png")


async def analyze_screenshot(
    llm_client,
    image_path: str | Path | None = None,
    image_base64: str | None = None,
    mime_type: str = "image/png",
) -> dict:
    """用多模态 LLM 分析截图，返回结构化的功能点描述。

    支持两种输入方式：
    - image_path: 本地图片文件路径
    - image_base64: 已编码的 base64 字符串

    降级策略：
    - 优先使用多模态 LLM（vision）分析截图
    - 如果 vision 调用失败（模型不支持、API 不兼容等），自动降级到 OCR + 普通 LLM

    Returns:
        {
            "page_type": "...",
            "page_title": "...",
            "visible_url": "...",
            "features": [...],
            "navigation": [...],
            "notes": "..."
        }
    """
    if image_path and not image_base64:
        image_base64 = encode_image_to_base64(image_path)
        mime_type = _detect_mime_type(image_path)

    if not image_base64:
        raise ValueError("必须提供 image_path 或 image_base64")

    # 优先尝试多模态 LLM
    try:
        result = await _call_vision_llm(
            llm_client,
            system_prompt=_SCREENSHOT_ANALYSIS_PROMPT,
            image_base64=image_base64,
            mime_type=mime_type,
            user_text="请分析这张网页截图中的功能点。",
            caller="vision_analyze",
        )
        return result
    except Exception as e:
        log.warning("多模态 LLM 分析失败，降级到 OCR + 文本 LLM: %s", e)

    # 降级：OCR 提取文字 → 普通 LLM 分析功能点
    return await _ocr_fallback_analyze(llm_client, image_path, image_base64)


async def filter_features_by_instruction(
    llm_client,
    analysis_result: dict,
    user_instruction: str,
) -> list[dict]:
    """根据用户指令，从截图分析结果中筛选要测试的功能点。

    Args:
        llm_client: LLM 客户端
        analysis_result: analyze_screenshot 的返回结果
        user_instruction: 用户的指令（如"只测登录功能"）

    Returns:
        筛选后的功能点列表
    """
    from core.llm import Message

    # 模板中字面花括号已转义（{{ }}），load_template 用 str.format 填充占位符
    prompt = load_template(
        "screenshot_filter",
        analysis_json=json.dumps(analysis_result, ensure_ascii=False, indent=2),
        user_instruction=user_instruction,
    )

    messages = [
        Message(role="system", content=prompt),
        Message(role="user", content="请筛选出用户想要测试的功能点。"),
    ]

    try:
        response = await asyncio.to_thread(
            llm_client.chat, messages, None, 0.1, 2048, "vision_filter"
        )
        text = response.content or ""
        # 兼容思考模式模型：content 为空时尝试 reasoning_content
        if not text.strip() and response.reasoning_content:
            text = response.reasoning_content
        # 去掉 <think>...</think> 标签
        text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
        json_match = re.search(r'\[[\s\S]*\]', text)
        if json_match:
            features = json.loads(json_match.group())
            if isinstance(features, list):
                # 确保列表元素都是 dict（防止 LLM 返回字符串列表）
                valid_features = [f for f in features if isinstance(f, dict) and f.get("name")]
                if valid_features:
                    return valid_features
    except Exception as e:
        log.warning("筛选功能点失败: %s", e)

    # fallback: 返回全部功能点
    return analysis_result.get("features", [])


# ============================================================
# OCR 降级方案：OCR 提取文字 → 普通 LLM 分析功能点
# ============================================================


async def _ocr_fallback_analyze(
    llm_client,
    image_path: str | Path | None,
    image_base64: str | None,
) -> dict:
    """OCR 降级方案：用 OCR 提取截图文字，再用普通 LLM 分析功能点。

    当多模态 LLM 不可用时（模型不支持 vision、API 不兼容等），
    自动降级到此方案。

    流程：OCR 提取文字 → 构造文本 prompt → 普通 LLM 分析 → 返回结构化结果
    """
    from core.llm import Message

    # 1) OCR 提取文字
    ocr_text = await _run_ocr(image_path, image_base64)

    if not ocr_text or not ocr_text.strip():
        log.warning("OCR 未提取到任何文字，返回空结果")
        return {
            "page_type": "unknown",
            "page_title": "",
            "visible_url": "",
            "features": [],
            "navigation": [],
            "notes": "OCR 降级：未能从截图中提取到文字内容",
        }

    log.info("OCR 提取到 %d 个字符，开始用 LLM 分析功能点", len(ocr_text))

    # 2) 用普通 LLM 分析 OCR 文字
    prompt = load_template("ocr_analysis", ocr_text=ocr_text[:3000])  # 限制长度防止 token 爆炸

    messages = [
        Message(role="system", content=prompt),
        Message(role="user", content="请根据 OCR 提取的文字内容，分析页面中的功能点。"),
    ]

    try:
        response = await asyncio.to_thread(
            llm_client.chat, messages, None, 0.1, 2048, "vision_ocr_fallback"
        )
        text = response.content or ""
        # 兼容思考模式模型
        if not text.strip() and response.reasoning_content:
            text = response.reasoning_content
        text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()

        result = _parse_json_response(text)
        # 标记为 OCR 降级结果
        if "notes" in result:
            result["notes"] = f"[OCR降级] {result['notes']}"
        else:
            result["notes"] = "[OCR降级] 此结果基于 OCR 文字推断"
        return result
    except Exception as e:
        log.error("OCR 降级 LLM 分析失败: %s", e)
        return {
            "page_type": "unknown",
            "page_title": "",
            "visible_url": "",
            "features": [],
            "navigation": [],
            "notes": f"OCR 降级失败: {e}",
        }


async def _run_ocr(
    image_path: str | Path | None,
    image_base64: str | None,
) -> str:
    """执行 OCR 识别，返回提取的文字内容。

    优先使用 RapidOCR（轻量、中文效果好），
    如果未安装则尝试 EasyOCR，
    都没有则返回空字符串。
    """
    import tempfile

    # 确保有图片文件路径（OCR 库通常需要文件路径或 numpy 数组）
    temp_file = None
    if image_path:
        img_path = str(image_path)
    elif image_base64:
        # 将 base64 写入临时文件
        img_bytes = base64.b64decode(image_base64)
        temp_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        temp_file.write(img_bytes)
        temp_file.close()
        img_path = temp_file.name
    else:
        return ""

    try:
        ocr_text = await asyncio.to_thread(_do_ocr_sync, img_path)
        return ocr_text
    finally:
        # 清理临时文件
        if temp_file:
            try:
                Path(temp_file.name).unlink(missing_ok=True)
            except Exception as _e:
                log.debug("清理 OCR 临时文件失败: %s", _e)


def _do_ocr_sync(img_path: str) -> str:
    """同步执行 OCR（在线程中调用）。

    按优先级尝试不同的 OCR 引擎：
    1. RapidOCR（推荐：轻量、中文效果好、pip install rapidocr-onnxruntime）
    2. EasyOCR（备选：多语言支持好）
    3. 都没有则返回空字符串并提示安装
    """
    # 方案 1：RapidOCR
    try:
        from rapidocr_onnxruntime import RapidOCR
        ocr = RapidOCR()
        result, _ = ocr(img_path)
        if result:
            # result 格式: [[box, text, confidence], ...]
            # 按 y 坐标排序（从上到下），模拟阅读顺序
            lines = []
            for item in result:
                if len(item) >= 2:
                    text = item[1] if isinstance(item[1], str) else str(item[1])
                    if text.strip():
                        lines.append(text.strip())
            return "\n".join(lines)
        return ""
    except ImportError as _e:
        log.debug("RapidOCR 未安装: %s", _e)
    except Exception as e:
        log.warning("RapidOCR 执行失败: %s", e)

    # 方案 2：EasyOCR
    try:
        import easyocr
        reader = easyocr.Reader(['ch_sim', 'en'], gpu=False)
        results = reader.readtext(img_path)
        if results:
            lines = [item[1] for item in results if item[1].strip()]
            return "\n".join(lines)
        return ""
    except ImportError as _e:
        log.debug("EasyOCR 未安装: %s", _e)
    except Exception as e:
        log.warning("EasyOCR 执行失败: %s", e)

    # 都没有安装
    log.warning(
        "未安装 OCR 库，无法执行 OCR 降级。"
        "请安装: pip install rapidocr-onnxruntime"
    )
    return ""


# ============================================================
# 多模态 LLM 调用（兼容 OpenAI / Anthropic）
# ============================================================

async def _call_vision_llm(
    llm_client,
    system_prompt: str,
    image_base64: str,
    mime_type: str,
    user_text: str,
    caller: str = "vision",
) -> dict:
    """调用多模态 LLM 分析图片。

    兼容两种协议：
    - OpenAI: content 为 list[{type: "text"}, {type: "image_url"}]
    - Anthropic: content 为 list[{type: "text"}, {type: "image", source: {...}}]
    """
    provider = llm_client.config.provider

    if provider == "anthropic":
        result = await _call_anthropic_vision(
            llm_client, system_prompt, image_base64, mime_type, user_text, caller
        )
    else:
        result = await _call_openai_vision(
            llm_client, system_prompt, image_base64, mime_type, user_text, caller
        )

    return result


async def _call_openai_vision(
    llm_client, system_prompt, image_base64, mime_type, user_text, caller
) -> dict:
    """OpenAI vision API 调用。

    兼容多种 OpenAI 兼容 API：
    - 标准 OpenAI (gpt-4o 等): 支持 detail 参数
    - DashScope 通义千问 (qwen-vl-max 等): 不支持 detail 参数
    - DeepSeek: 纯文本模型不支持 image_url
    """
    import time
    from core.llm import LLMMonitor

    client = llm_client._get_openai_client()
    base_url = (llm_client.config.base_url or "").lower()
    model = (llm_client.config.model or "").lower()
    t0 = time.time()

    # 检测是否为已知不支持 vision 的模型。
    # ★ 改为「厂商 + 模型子串」检测，避免维护一长串硬编码模型名，
    # 当厂商发布新版本（如 deepseek-v5）时也能正确识别。
    _non_vision_patterns = [
        # (base_url 子串, 模型子串) —— 命中即不支持 vision
        ("deepseek.com", "deepseek-chat"),       # DeepSeek 文本模型，无视觉能力
        ("deepseek.com", "deepseek-reasoner"),   # DeepSeek 推理模型，无视觉能力
        ("deepseek.com", "deepseek-v"),          # 兜底：所有 deepseek-v* 历史错误名
        ("moonshot.cn", "kimi-k2"),              # Kimi K2 纯文本
        ("moonshot.cn", "moonshot-v1"),          # Moonshot v1 纯文本
        ("dashscope.aliyuncs.com", "qwen-max"),
        ("dashscope.aliyuncs.com", "qwen-turbo"),
        ("dashscope.aliyuncs.com", "qwen-plus"),
    ]
    for url_sub, model_sub in _non_vision_patterns:
        if url_sub in base_url and model_sub in model:
            raise ValueError(
                f"当前模型 {llm_client.config.model} 不支持图片输入（非多模态模型）。"
                f"请切换到支持 Vision 的模型（如 qwen-vl-max、gpt-4o、claude-3.5-sonnet）。"
            )

    # 构造 image_url 内容块（DashScope 不支持 detail 参数）
    is_dashscope = "dashscope" in base_url
    image_content = {
        "type": "image_url",
        "image_url": {
            "url": f"data:{mime_type};base64,{image_base64}",
        },
    }
    # 仅对标准 OpenAI API 添加 detail 参数
    if not is_dashscope:
        image_content["image_url"]["detail"] = "high"

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": user_text},
                image_content,
            ],
        },
    ]

    extra = {}
    if "localhost" in base_url or "127.0.0.1" in base_url:
        extra["extra_body"] = {"options": {"num_ctx": 32768}}

    try:
        resp = client.chat.completions.create(
            model=llm_client.config.model,
            messages=messages,
            max_tokens=4096,
            temperature=0.1,
            **extra,
        )
        elapsed = time.time() - t0
        from core.llm import _parse_sse_chat_payload
        resp = _parse_sse_chat_payload(resp)
        # 兼容思考模式模型（qwen3.x 等）：content 可能为空，实际内容在 reasoning_content
        content = resp.choices[0].message.content or ""
        if not content.strip():
            # 某些思考模式模型把内容放在 reasoning_content 中
            reasoning = getattr(resp.choices[0].message, "reasoning_content", None)
            if reasoning:
                content = reasoning
                log.info("Vision 响应 content 为空，使用 reasoning_content")

        # 监控埋点
        usage = getattr(resp, "usage", None)
        LLMMonitor().record(
            model=llm_client.config.model,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            elapsed=elapsed,
            caller=caller,
        )

        return _parse_json_response(content)
    except Exception as e:
        log.error("OpenAI vision 调用失败: %s", e)
        raise


async def _call_anthropic_vision(
    llm_client, system_prompt, image_base64, mime_type, user_text, caller
) -> dict:
    """Anthropic vision API 调用。"""
    import time
    from core.llm import LLMMonitor

    client = llm_client._get_anthropic_client()
    t0 = time.time()

    try:
        resp = client.messages.create(
            model=llm_client.config.model,
            max_tokens=4096,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime_type,
                                "data": image_base64,
                            },
                        },
                        {"type": "text", "text": user_text},
                    ],
                }
            ],
        )
        elapsed = time.time() - t0
        content = resp.content[0].text if resp.content else ""

        # 监控埋点
        LLMMonitor().record(
            model=llm_client.config.model,
            input_tokens=getattr(resp.usage, "input_tokens", 0) or 0,
            output_tokens=getattr(resp.usage, "output_tokens", 0) or 0,
            elapsed=elapsed,
            caller=caller,
        )

        return _parse_json_response(content)
    except Exception as e:
        log.error("Anthropic vision 调用失败: %s", e)
        raise


def _parse_json_response(text: str) -> dict:
    """从 LLM 响应中解析 JSON。
    
    兼容思考模式模型（qwen3.x 等）返回的 <think>...</think> 标签。
    """
    # 去掉 <think>...</think> 思考内容（贪婪匹配）
    cleaned = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
    # 如果清理后为空，用原始文本
    if not cleaned:
        cleaned = text

    # 尝试提取 JSON 对象
    json_match = re.search(r'\{[\s\S]*\}', cleaned)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError as _e:
            log.debug("JSON 解析失败 (清理后文本): %s", _e)

    # 再尝试从原始文本中提取（以防 think 标签去除影响了匹配）
    if cleaned != text:
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError as _e:
                log.debug("JSON 解析失败 (原始文本): %s", _e)

    # fallback: 返回原始文本作为 notes
    log.warning("无法从 vision LLM 响应中解析 JSON，返回原始文本")
    return {
        "page_type": "unknown",
        "page_title": "",
        "visible_url": "",
        "features": [],
        "navigation": [],
        "notes": cleaned[:500] if cleaned else text[:500],
    }
