"""回归钉（阶段 2 UI 接线）—— 固化"断线能力接线"，防回退。

为什么需要这些钉子
------------------
这一批改动的本质是**把后端早已实现、前端零调用的能力接上**。接线的特征就是：
两端各写一半、靠约定对齐。任何一端被单独改动（重构、回滚、误删），
都不会报错 —— 只会静默失效。所以必须钉住"两端都在、且协议一致"。

钉住四件事：
1. `/api/chat` 的 `file_paths` 分支仍在（且空消息校验已放宽为"三个都空才拒"）；
2. 前端 terminal 仍在组装 `file_paths` / `screenshot_paths` / `oob_callback_url`；
3. **协议一致性**：`/api/skills/save` 用 `{"status":"ok|error","message"}`，
   前端必须按 status 判断 —— 踩过的坑：照抄其他端点的 `data.error` 写法会让
   "名称非法 / 内容为空 / 内置技能不可改" 全部静默失败。
4. 上传端点挂在 server 上且**不在鉴权白名单**（附件含用户文件，必须走鉴权）。
"""
from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INDEX_HTML = PROJECT_ROOT / "web" / "index.html"


@pytest.fixture(scope="module")
def index_src() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


# ---------------------------------------------------------------- 后端侧

def test_chat_accepts_file_paths():
    import web.server as srv
    src = inspect.getsource(srv.chat)
    assert 'body.get("file_paths"' in src, "/api/chat 不再接收 file_paths，文档附件链路断裂"
    assert "build_attachment_block" in src, "附件抽取未接进 chat"
    # 放宽后的空消息校验：三者都空才拒绝（否则"只带附件不写字"会被拒）
    assert re.search(r"not user_message\.strip\(\)\s+and\s+not screenshot_paths\s+and\s+not file_paths", src)


def test_upload_routes_registered_and_authenticated():
    import web.server as srv

    paths: set[str] = set()

    def walk(routes):
        for r in routes:
            p = getattr(r, "path", None)
            if isinstance(p, str) and p:
                paths.add(p)
            for attr in ("router", "original_router"):
                sub = getattr(r, attr, None)
                if sub is not None and hasattr(sub, "routes"):
                    walk(sub.routes)

    walk(srv.app.routes)
    assert "/api/upload/attachment" in paths
    assert "/api/upload/allowed" in paths
    from web.server import _AUTH_WHITELIST
    assert not any("upload" in str(p) for p in _AUTH_WHITELIST), "上传端点不得免鉴权"


# ---------------------------------------------------------------- 前端侧

def test_frontend_builds_full_chat_payload(index_src):
    assert "function buildChatPayload" in index_src
    m = re.search(r"function buildChatPayload\(message\)\s*\{(.*?)\n\}", index_src, re.S)
    assert m, "buildChatPayload 结构被改坏"
    body = m.group(1)
    for field in ("scan_mode", "screenshot_paths", "file_paths", "oob_callback_url"):
        assert field in body, f"payload 丢失字段 {field}"


def test_terminal_no_longer_hardcodes_smart_mode(index_src):
    """终端发送曾硬编码 scan_mode:'smart'，用户选的模式无法生效。"""
    assert "JSON.stringify({ message: msg, task_id: currentTaskId, scan_mode: 'smart' })" not in index_src
    assert "JSON.stringify(buildChatPayload(msg))" in index_src


def test_frontend_dispatches_by_channel(index_src):
    """图片 → screenshot_paths，文档 → file_paths（按后端返回的 channel 分派）。"""
    assert "screenshot_paths'" in index_src and "file_paths'" in index_src
    assert "f.channel === 'screenshot_paths'" in index_src
    assert "f.channel === 'file_paths'" in index_src


def test_skills_save_protocol_used_correctly(index_src):
    """坑：/api/skills/save 用 status 协议，前端必须据此判断。"""
    m = re.search(r"async function termAddSkills[\s\S]*?\n\}", index_src)
    assert m, "termAddSkills 被删或改名"
    body = m.group(0)
    assert "data.status === 'error'" in body, "未按 status 协议判断 → 技能保存错误会被静默吞掉"
    assert "data.message" in body
    # 目录层级是 skills_my/<category>/<name>/，category 用默认 user 语义
    assert "category: 'user'" in body


def test_frontend_has_plus_menu_wiring(index_src):
    for token in ("termPlusBtn", "termPop", "termCtxChips", "termFileInput",
                  "termSkillInput", "toggleTermPop", "renderTermChips"):
        assert token in index_src, f"「＋」菜单缺少 {token}"


def test_frontend_clears_attachments_after_send(index_src):
    """附件/OOB 提交后必须清空（否则下一轮会被重复携带），模式要保留。"""
    m = re.search(r"function clearTermCtxAfterSend\(\)\s*\{(.*?)\n\}", index_src, re.S)
    assert m
    body = m.group(1)
    assert "termCtx.files = []" in body and "termCtx.oob = ''" in body
    assert "termCtx.mode" not in body, "扫描模式是「下个任务生效」，不应在发送后清空"


def test_no_native_prompt_in_terminal_ctx(index_src):
    """无障碍目标：不在终端上下文里用原生 prompt/confirm。"""
    m = re.search(r"// ============ 终端「＋」上下文[\s\S]*?async function sendTerminalMessage", index_src)
    assert m
    seg = m.group(0)
    assert "prompt(" not in seg, "终端上下文里用了原生 prompt（与无障碍基线冲突）"
