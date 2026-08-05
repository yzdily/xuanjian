"""验证码自动识别模块。

支持的验证码类型：
- image_captcha: 图形验证码（扭曲文字、算术题等）
- slider_captcha: 简单滑块验证（缺口拖动）

不支持的类型（直接返回 False，走原有手动流程）：
- third_party_captcha: 第三方人机验证（极验/防水墙/reCAPTCHA 等）
- sms_code: 手机/邮箱验证码
- text_hint: 文本提示类

依赖（可选，未安装时静默跳过）：
- ddddocr: 验证码专用 OCR + 滑块缺口检测（pip install ddddocr）
- rapidocr-onnxruntime: 通用 OCR 降级方案（已有）

设计原则：
- 独立模块，不修改任何现有文件
- 所有异常内部消化，绝不向上抛出
- 识别失败 → return False → 走原有手动流程
"""

from __future__ import annotations

import asyncio
import io
import logging
import random
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page

log = logging.getLogger(__name__)

# ── OCR 引擎懒加载 ──────────────────────────────────────────

_ddddocr_cls = None  # ddddocr.DdddOcr 实例（验证码专用）
_ddddocr_slide = None  # ddddocr.DdddOcr slide 模式实例
_rapidocr_inst = None  # RapidOCR 实例（降级）


def _get_ddddocr():
    """懒加载 ddddocr（验证码识别）。"""
    global _ddddocr_cls
    if _ddddocr_cls is not None:
        return _ddddocr_cls
    try:
        import ddddocr
        _ddddocr_cls = ddddocr.DdddOcr(show_ad=False)
        log.info("ddddocr 加载成功（验证码识别模式）")
        return _ddddocr_cls
    except ImportError:
        log.debug("ddddocr 未安装，验证码自动识别不可用")
        return None
    except Exception as e:
        log.warning("ddddocr 加载失败: %s", e)
        return None


def _get_ddddocr_slide():
    """懒加载 ddddocr 滑块模式。"""
    global _ddddocr_slide
    if _ddddocr_slide is not None:
        return _ddddocr_slide
    try:
        import ddddocr
        _ddddocr_slide = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)
        log.info("ddddocr 滑块模式加载成功")
        return _ddddocr_slide
    except ImportError:
        return None
    except Exception as e:
        log.warning("ddddocr 滑块模式加载失败: %s", e)
        return None


def _get_rapidocr():
    """懒加载 RapidOCR（降级方案）。"""
    global _rapidocr_inst
    if _rapidocr_inst is not None:
        return _rapidocr_inst
    try:
        from rapidocr_onnxruntime import RapidOCR
        _rapidocr_inst = RapidOCR()
        log.info("RapidOCR 加载成功（验证码降级方案）")
        return _rapidocr_inst
    except ImportError:
        return None
    except Exception as e:
        log.warning("RapidOCR 加载失败: %s", e)
        return None


# ── 图形验证码识别 ──────────────────────────────────────────

# 验证码图片选择器（优先级从高到低）
_CAPTCHA_IMG_SELECTORS = [
    'img[src*="captcha" i]',
    'img[src*="verify" i]',
    'img[src*="vcode" i]',
    'img[src*="kaptcha" i]',
    'img[id*="captcha" i]',
    'img[class*="captcha" i]',
    'img[alt*="验证码"]',
    'canvas.captcha',
    'canvas[class*="captcha"]',
]

# 验证码输入框选择器
_CAPTCHA_INPUT_SELECTORS = [
    'input[placeholder*="验证码"]',
    'input[placeholder*="captcha" i]',
    'input[placeholder*="verify" i]',
    'input[placeholder*="vcode" i]',
    'input[name*="captcha" i]',
    'input[name*="verify" i]',
    'input[name*="vcode" i]',
    'input[id*="captcha" i]',
    'input[id*="verify" i]',
    'input[id*="vcode" i]',
    'input autocomplete="off"]:near(img[src*="captcha" i])',
]

# 刷新按钮选择器（识别失败时点击刷新验证码）
_CAPTCHA_REFRESH_SELECTORS = [
    'img[src*="captcha" i]',  # 点击图片本身通常可刷新
    'a:has-text("换一张")',
    'a:has-text("看不清")',
    'span:has-text("换一张")',
    'span:has-text("看不清")',
    'button:has-text("换一张")',
    '.captcha-refresh',
    '#captcha-refresh',
]


async def _recognize_image_captcha(img_bytes: bytes) -> str | None:
    """识别图形验证码图片中的文字。

    优先 ddddocr，失败则降级 RapidOCR。
    """
    # 方案 1: ddddocr（验证码专用，识别率最高）
    ocr = _get_ddddocr()
    if ocr is not None:
        try:
            result = await asyncio.to_thread(ocr.classification, img_bytes)
            if result and isinstance(result, str) and result.strip():
                text = result.strip()
                log.info("ddddocr 识别结果: %s", text)
                return text
        except Exception as e:
            log.warning("ddddocr 识别失败: %s", e)

    # 方案 2: RapidOCR 降级
    rapid = _get_rapidocr()
    if rapid is not None:
        try:
            result, _ = await asyncio.to_thread(rapid, img_bytes)
            if result:
                # RapidOCR 返回 [[text, confidence, bbox], ...]
                text = "".join(item[0] for item in result if item[0])
                text = text.strip()
                if text:
                    log.info("RapidOCR 降级识别结果: %s", text)
                    return text
        except Exception as e:
            log.warning("RapidOCR 降级识别失败: %s", e)

    return None


async def _find_captcha_input(page: Page) -> str | None:
    """找到验证码输入框的 selector。"""
    for sel in _CAPTCHA_INPUT_SELECTORS:
        try:
            cnt = await page.locator(sel).count()
            if cnt > 0:
                return sel
        except Exception:
            continue
    return None


async def _click_captcha_refresh(page: Page) -> bool:
    """点击刷新验证码图片。"""
    for sel in _CAPTCHA_REFRESH_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=500):
                await loc.click(timeout=1000)
                await asyncio.sleep(0.8)
                return True
        except Exception:
            continue
    return False


async def _extract_captcha_image(page: Page) -> bytes | None:
    """截取验证码图片元素。"""
    for sel in _CAPTCHA_IMG_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=500):
                img_bytes = await loc.screenshot()
                return img_bytes
        except Exception:
            continue

    # canvas 类型：用 JS 导出
    try:
        canvas_data = await page.evaluate("""() => {
            const canvas = document.querySelector('canvas.captcha, canvas[class*="captcha"]');
            if (!canvas) return null;
            return canvas.toDataURL('image/png').split(',')[1];
        }""")
        if canvas_data:
            import base64
            return base64.b64decode(canvas_data)
    except Exception:
        pass

    return None


async def solve_image_captcha(page: Page, max_retries: int = 2) -> bool:
    """自动识别图形验证码并填入。

    流程：
    1. 截取验证码图片
    2. OCR 识别
    3. 填入输入框
    4. 失败时刷新验证码重试

    返回 True=识别并填入成功，False=失败（应回退到手动流程）。
    """
    for attempt in range(max_retries):
        log.info("图形验证码识别尝试 %d/%d", attempt + 1, max_retries)

        # 1. 截取验证码图片
        img_bytes = await _extract_captcha_image(page)
        if not img_bytes:
            log.warning("未能截取到验证码图片")
            return False

        # 2. OCR 识别
        text = await _recognize_image_captcha(img_bytes)
        if not text:
            log.warning("OCR 未识别出文字，尝试刷新验证码")
            if attempt < max_retries - 1:
                await _click_captcha_refresh(page)
            continue

        # 过滤明显不合理的识别结果
        # 验证码通常 4-6 个字符，纯数字或字母或简单算术
        clean = text.replace(" ", "").replace("×", "*").replace("÷", "/")
        if len(clean) < 2 or len(clean) > 10:
            log.warning("识别结果长度异常: '%s'（长度 %d），跳过", clean, len(clean))
            if attempt < max_retries - 1:
                await _click_captcha_refresh(page)
            continue

        # 3. 简单算术验证码处理（如 "3+5=?" → 填 "8"）
        fill_value = _maybe_eval_arithmetic(clean)

        # 4. 找输入框并填入
        input_sel = await _find_captcha_input(page)
        if not input_sel:
            log.warning("未找到验证码输入框")
            return False

        try:
            await page.fill(input_sel, fill_value, timeout=2000)
            log.info("验证码填入成功: '%s' → %s", fill_value, input_sel)
            # 填入后等一下让前端校验
            await asyncio.sleep(0.5)
            return True
        except Exception as e:
            log.warning("验证码填入失败: %s", e)
            if attempt < max_retries - 1:
                await _click_captcha_refresh(page)
            continue

    return False


def _maybe_eval_arithmetic(text: str) -> str:
    """处理简单算术验证码，如 '3+5' → '8'。

    仅支持加减乘除，使用安全的栈式求值算法，不使用 eval。
    """
    import re
    # 只允许数字、运算符和括号
    if not re.match(r'^[\d+\-*/().]+$', text):
        return text
    if len(text) > 20:  # 限制长度
        return text
    
    try:
        # 使用 token 化 + 栈式求值，不支持 eval
        # 简化实现：仅支持整数加减乘除
        tokens = re.findall(r'\d+|[+\-*/()]', text)
        
        # 转换为后缀表达式（Shunting-yard 算法简化版）
        def to_postfix(tokens):
            prec = {'+': 1, '-': 1, '*': 2, '/': 2}
            output = []
            ops = []
            for t in tokens:
                if t.isdigit():
                    output.append(int(t))
                elif t in prec:
                    while ops and ops[-1] != '(' and prec.get(ops[-1], 0) >= prec[t]:
                        output.append(ops.pop())
                    ops.append(t)
                elif t == '(':
                    ops.append(t)
                elif t == ')':
                    while ops and ops[-1] != '(':
                        output.append(ops.pop())
                    if ops:
                        ops.pop()  # pop '('
            while ops:
                output.append(ops.pop())
            return output
        
        def eval_postfix(postfix):
            stack = []
            for t in postfix:
                if isinstance(t, int):
                    stack.append(t)
                else:
                    if len(stack) < 2:
                        return text
                    b, a = stack.pop(), stack.pop()
                    if t == '+':
                        stack.append(a + b)
                    elif t == '-':
                        stack.append(a - b)
                    elif t == '*':
                        stack.append(a * b)
                    elif t == '/':
                        if b == 0:
                            return text
                        stack.append(a // b)
            return str(stack[0]) if stack else text
        
        postfix = to_postfix(tokens)
        result = eval_postfix(postfix)
        return result
    except Exception:
        return text


# ── 滑块验证码识别 ──────────────────────────────────────────

# 滑块相关选择器
_SLIDER_SELECTORS = [
    # 极验
    '.geetest_slider_button',
    # 阿里 NoCaptcha
    '.nc_iconfont.btn_slide',
    '.nc-lang-cnt .btn_slide',
    # 网易易盾
    '.yidun_slider',
    # 通用
    'div[class*="slider"] button',
    'div[class*="slider"] span',
    'div[class*="drag"]',
    'span[class*="slider"]',
]


async def solve_slider_captcha(page: Page, max_retries: int = 2) -> bool:
    """自动识别滑块验证码并拖动。

    仅支持简单缺口滑块，不支持极验4代等高级行为验证。

    流程：
    1. 截取背景图和滑块图
    2. ddddocr.slide_match 计算缺口偏移
    3. 模拟人类拖动轨迹
    4. 检测是否通过

    返回 True=拖动成功，False=失败。
    """
    slide_ocr = _get_ddddocr_slide()
    if slide_ocr is None:
        log.info("ddddocr 滑块模式不可用，跳过滑块验证码")
        return False

    for attempt in range(max_retries):
        log.info("滑块验证码识别尝试 %d/%d", attempt + 1, max_retries)

        # 1. 尝试提取背景图和滑块图
        bg_bytes, fg_bytes = await _extract_slider_images(page)
        if not bg_bytes or not fg_bytes:
            log.warning("未能提取滑块背景图/前景图")
            return False

        # 2. 计算缺口偏移
        try:
            offset = await asyncio.to_thread(slide_ocr.slide_match, fg_bytes, bg_bytes)
            if isinstance(offset, dict):
                target_x = offset.get("target", [0, 0])[0]
            elif isinstance(offset, (list, tuple)) and len(offset) >= 1:
                target_x = offset[0] if isinstance(offset[0], (int, float)) else 0
            else:
                target_x = 0
        except Exception as e:
            log.warning("滑块缺口检测失败: %s", e)
            return False

        if target_x <= 0:
            log.warning("缺口偏移量异常: %s", target_x)
            if attempt < max_retries - 1:
                # 刷新重试
                await _try_reset_slider(page)
            continue

        # 3. 找到滑块元素并执行拖动
        slider_loc = await _find_slider_element(page)
        if not slider_loc:
            log.warning("未找到滑块元素")
            return False

        # 4. 模拟人类拖动
        try:
            await _human_like_drag(slider_loc, target_x)
            await asyncio.sleep(1.5)

            # 5. 检测是否通过
            if await _check_slider_success(page):
                log.info("滑块验证码通过")
                return True

            log.info("滑块验证未通过，可能偏移不准")
            if attempt < max_retries - 1:
                await _try_reset_slider(page)
        except Exception as e:
            log.warning("滑块拖动失败: %s", e)
            if attempt < max_retries - 1:
                await _try_reset_slider(page)
            continue

    return False


async def _extract_slider_images(page: Page) -> tuple[bytes | None, bytes | None]:
    """提取滑块验证码的背景图和前景图。"""
    bg_bytes = None
    fg_bytes = None

    # 尝试从 canvas/img 提取背景图
    try:
        bg_data = await page.evaluate("""() => {
            // 极验背景图
            const geetestBg = document.querySelector('.geetest_canvas_bg');
            if (geetestBg) return geetestBg.toDataURL('image/png').split(',')[1];
            // 通用 canvas 背景
            const canvasBg = document.querySelector('canvas[class*="bg"], canvas[class*="background"]');
            if (canvasBg) return canvasBg.toDataURL('image/png').split(',')[1];
            return null;
        }""")
        if bg_data:
            import base64
            bg_bytes = base64.b64decode(bg_data)
    except Exception:
        pass

    # 尝试提取前景图（滑块）
    try:
        fg_data = await page.evaluate("""() => {
            // 极验滑块
            const geetestSlice = document.querySelector('.geetest_canvas_slice');
            if (geetestSlice) return geetestSlice.toDataURL('image/png').split(',')[1];
            return null;
        }""")
        if fg_data:
            import base64
            fg_bytes = base64.b64decode(fg_data)
    except Exception:
        pass

    # 如果 canvas 提取失败，尝试截取整个验证区域作为背景
    if not bg_bytes:
        try:
            captcha_area = page.locator(
                '.geetest_panel, .nc_wrapper, .yidun_panel, '
                'div[class*="captcha"], div[class*="verify"]'
            ).first
            if await captcha_area.is_visible(timeout=500):
                bg_bytes = await captcha_area.screenshot()
        except Exception:
            pass

    return bg_bytes, fg_bytes


async def _find_slider_element(page: Page):
    """找到滑块可拖动元素。"""
    for sel in _SLIDER_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=500):
                return loc
        except Exception:
            continue
    return None


async def _human_like_drag(slider_loc, target_x: int) -> None:
    """模拟人类拖动轨迹：先快后慢 + 随机抖动。"""
    box = await slider_loc.bounding_box()
    if not box:
        raise RuntimeError("滑块元素无 bounding box")

    start_x = box["x"] + box["width"] / 2
    start_y = box["y"] + box["height"] / 2

    await slider_loc.page.mouse.move(start_x, start_y)
    await slider_loc.page.mouse.down()

    # 分段移动，模拟人类拖动曲线
    steps = random.randint(20, 35)
    current_x = start_x

    for i in range(steps):
        progress = (i + 1) / steps
        # 缓出曲线：前期快后期慢
        eased = 1 - (1 - progress) ** 2.5
        dest_x = start_x + target_x * eased

        # 添加微小的随机抖动（±1~2px）
        jitter_y = random.uniform(-1.5, 1.5)
        jitter_x = random.uniform(-0.5, 0.5) if progress < 0.8 else 0

        await slider_loc.page.mouse.move(
            dest_x + jitter_x,
            start_y + jitter_y,
        )
        current_x = dest_x

        # 随机微停顿，更像人类
        if random.random() < 0.1:
            await asyncio.sleep(random.uniform(0.02, 0.06))
        else:
            await asyncio.sleep(random.uniform(0.008, 0.025))

    # 最终精确定位
    await slider_loc.page.mouse.move(start_x + target_x, start_y)
    await asyncio.sleep(random.uniform(0.1, 0.3))
    await slider_loc.page.mouse.up()


async def _check_slider_success(page: Page) -> bool:
    """检测滑块是否通过验证。"""
    try:
        # 检测验证元素是否消失
        for sel in ['.geetest_panel', '.nc_wrapper', '.yidun_panel']:
            try:
                cnt = await page.locator(sel).count()
                if cnt > 0:
                    visible = await page.locator(sel).first.is_visible(timeout=300)
                    if visible:
                        return False
            except Exception:
                continue

        # 检测成功提示文字
        success_texts = ["验证成功", "验证通过", "success", "verified"]
        body_text = await page.evaluate("() => (document.body?.innerText || '').slice(0, 500)")
        if any(t in (body_text or "").lower() for t in success_texts):
            return True

        # 检测 URL 是否跳转（验证通过通常会跳转）
        current_url = page.url.lower()
        if not any(kw in current_url for kw in ["captcha", "verify", "slide"]):
            return True

    except Exception:
        pass
    return False


async def _try_reset_slider(page: Page) -> None:
    """重置滑块验证，准备重试。"""
    try:
        # 点击重试按钮
        for sel in [
            '.geetest_reset', '.geetest_refresh',
            'a:has-text("重试")', 'button:has-text("重试")',
            'span:has-text("重试")',
        ]:
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=500):
                    await loc.click(timeout=1000)
                    await asyncio.sleep(0.5)
                    return
            except Exception:
                continue
        # 兜底：刷新页面
        await page.reload(wait_until="domcontentloaded", timeout=5000)
        await asyncio.sleep(1)
    except Exception:
        pass


# ── 总入口 ──────────────────────────────────────────────────

async def auto_solve(page: Page, captcha_kind: str) -> bool:
    """验证码自动识别总入口。

    参数：
        page: Playwright Page 对象
        captcha_kind: _detect_captcha() 返回的验证码类型

    返回：
        True=识别并填入/操作成功，可以继续登录流程
        False=识别失败或不支持，应回退到手动流程

    不支持的类型直接返回 False，不影响现有流程。
    """
    if captcha_kind == "image_captcha":
        try:
            return await solve_image_captcha(page)
        except Exception as e:
            log.error("图形验证码自动识别异常: %s", e)
            return False

    if captcha_kind == "slider_captcha":
        try:
            return await solve_slider_captcha(page)
        except Exception as e:
            log.error("滑块验证码自动识别异常: %s", e)
            return False

    # 不支持的类型：third_party_captcha / sms_code / text_hint
    log.info("验证码类型 '%s' 不支持自动识别，需手动完成", captcha_kind)
    return False
