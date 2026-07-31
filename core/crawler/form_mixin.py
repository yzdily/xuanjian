"""
FormMixin — 表单智能填写与提交。

从 crawler_core.py 拆分出来的独立 mixin，负责：
- 根据字段名/类型/placeholder 智能推断填写值
- 自动填写并提交表单，捕获触发的请求
"""

from __future__ import annotations

import asyncio
from typing import Any

from .models import CrawledForm, FORM_FILL_RULES


class FormMixin:
    """表单填写与提交能力（Mixin，需配合 AutoCrawler 使用）。"""

    async def _fill_and_submit_form(self, page, url: str, form_info: dict, captured: list) -> CrawledForm | None:
        """智能填写并提交表单。"""
        form = CrawledForm(
            page_url=url,
            action=form_info.get("action", ""),
            method=form_info.get("method", "GET"),
            inputs=form_info.get("inputs", []),
            selector=form_info.get("selector", ""),
        )

        # 逐个字段填写
        for inp in form_info.get("inputs", []):
            name = inp.get("name", "").lower()
            input_type = inp.get("type", "").lower()
            selector_base = form_info.get("selector", "")

            # 跳过隐藏字段和提交按钮
            if input_type in ("hidden", "submit", "button", "image"):
                continue
            if input_type == "file":
                continue  # 文件上传 Phase 2 再测

            # 根据字段名匹配填写值
            fill_value = self._smart_fill_value(name, input_type, inp.get("placeholder", ""))
            if not fill_value:
                continue

            # 构建选择器
            if inp.get("id"):
                field_sel = f"#{inp['id']}"
            elif inp.get("name"):
                field_sel = f"{selector_base} [name='{inp['name']}']"
            else:
                continue

            try:
                if input_type == "checkbox" or input_type == "radio":
                    await page.check(field_sel, timeout=2000)
                elif input_type == "select":
                    # 选第一个非空 option
                    await page.select_option(field_sel, index=1, timeout=2000)
                else:
                    await page.fill(field_sel, fill_value, timeout=2000)
            except Exception:
                continue

        # 提交表单
        before = len(captured)
        try:
            submit_sel = f"{form_info.get('selector', '')} [type=submit]"
            try:
                await page.click(submit_sel, timeout=3000)
            except Exception:
                # 如果没有 submit 按钮，试 Enter
                try:
                    await page.keyboard.press("Enter")
                except Exception:
                    pass
            await asyncio.sleep(0.5)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

            form.submitted = True
            form.submit_requests = [dict(r) for r in captured[before:]]
        except Exception:
            pass

        # 回到原页面
        if page.url.split("?")[0] != url.split("?")[0]:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception:
                pass

        return form

    @staticmethod
    def _smart_fill_value(name: str, input_type: str, placeholder: str) -> str:
        """根据字段名/类型/placeholder 智能推断填写值。"""
        check_keys = [name] + name.split("_") + name.split("-") + [placeholder.lower()]

        for key in check_keys:
            for pattern, value in FORM_FILL_RULES.items():
                if pattern in key:
                    return value

        # 按 input type fallback
        type_defaults = {
            "text": "test",
            "email": "test@pentest-agent.local",
            "number": "1",
            "tel": "13800138000",
            "date": "2024-01-01",
            "datetime-local": "2024-01-01T12:00",
            "textarea": "Test content for penetration testing.",
        }
        return type_defaults.get(input_type, "test")
