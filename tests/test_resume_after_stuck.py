"""
测试 STUCK 后"继续"指令恢复逻辑。

回归背景：之前 _maybe_nudge_phase_forward 计数到 3 后，task_stuck 事件触发主循环 break。
当用户输入"继续"再次进入 chat()，nudge 计数仍为 3，下一次 LLM 输出文字就再次 STUCK，
陷入"卡死 → 重置 → 卡死"的死循环。

本次修复验证：
1. reset_nudge_counter 正确清零当前/指定 phase 的计数
2. _detect_and_handle_resume_command 在 stuck 阶段识别"继续/resume/go"
3. 在 idle/report 阶段不识别（避免覆盖已有恢复逻辑）
4. 在 analyze/test/explore 阶段被识别并返回 kick_msg
5. 普通对话（非继续指令）不被误识别
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class FakeSession:
    """只挂上 _detect_and_handle_resume_command 需要的最小属性。"""

    def __init__(self, phase: str = "test", nudge_count: int = 3):
        self.phase = phase
        self._nudge_count = {"analyze": 0, "test": 0, "explore": 0}
        if phase in self._nudge_count:
            self._nudge_count[phase] = nudge_count

    # 直接用 UtilsMixin 上真接出来的方法（保持和生产代码一致）
    from core.session.utils_mixin import UtilsMixin
    reset_nudge_counter = UtilsMixin.reset_nudge_counter
    _detect_and_handle_resume_command = (
        sys.modules["core.session.chat_loop"].ChatLoopMixin._detect_and_handle_resume_command
    )


def test_reset_nudge_counter_current_phase():
    s = FakeSession(phase="test", nudge_count=3)
    assert s._nudge_count["test"] == 3
    s.reset_nudge_counter()
    assert s._nudge_count["test"] == 0
    print("✓ reset_nudge_counter(): 当前 phase 计数被清零")


def test_reset_nudge_counter_specific_phase():
    s = FakeSession(phase="test", nudge_count=3)
    s._nudge_count["analyze"] = 2
    s.reset_nudge_counter("analyze")
    assert s._nudge_count["analyze"] == 0
    assert s._nudge_count["test"] == 3
    print("✓ reset_nudge_counter('analyze'): 只清零指定 phase")


def test_reset_nudge_counter_tolerate_none_dict():
    s = FakeSession(phase="test")
    s._nudge_count = None
    s.reset_nudge_counter()
    assert s._nudge_count == {"test": 0}
    print("✓ reset_nudge_counter(): 容忍 None / 异常 dict")


def test_resume_keyword_exact_match_in_stuck_phase():
    """核心场景：Phase 2（test）已 stuck，用户输入'继续'，应被识别。"""
    s = FakeSession(phase="test", nudge_count=3)
    handled, kick = s._detect_and_handle_resume_command("继续", "test")
    assert handled is True
    assert "唤醒" in kick or "重置" in kick
    assert s._nudge_count["test"] == 0
    print("✓ exact '继续' in Phase 2 → handled=True + counter reset")


def test_resume_keyword_variants_in_stuck_phase():
    """子串匹配：'继续吧' / '请继续' / 'continue please' / 'go' 等。"""
    for msg in ["继续吧", "请继续", "继续测试", "go on", "resume", "Continue", "CONTINUE"]:
        s = FakeSession(phase="test", nudge_count=3)
        handled, _ = s._detect_and_handle_resume_command(msg, "test")
        assert handled is True, f"未识别: {msg!r}"
    print("✓ 子串 + 大小写变体都被识别")


def test_resume_not_recognized_in_idle_phase():
    """idle 阶段走自己的恢复分支（本方法不应越权接管）。"""
    s = FakeSession(phase="idle", nudge_count=0)
    handled, kick = s._detect_and_handle_resume_command("继续", "idle")
    assert handled is False
    assert kick == ""
    print("✓ idle 阶段不识别 — 让出给 idle 分支处理")


def test_resume_not_recognized_in_report_phase():
    """report 阶段走追问分支（chat_loop.py 第 270 行已处理）。"""
    s = FakeSession(phase="report", nudge_count=0)
    handled, kick = s._detect_and_handle_resume_command("继续", "report")
    assert handled is False
    print("✓ report 阶段不识别 — 让出给追问分支处理")


def test_resume_not_recognized_for_non_resume_messages():
    """普通对话（不带'继续'关键词）不应被误识别。"""
    s = FakeSession(phase="test", nudge_count=3)
    for msg in ["帮我分析这个 URL", "test", "do scan", "开始吧"]:
        # 注意 '开始吧' 不含 '继续'，但可能被 'go on' 的 'on' 子串误命中，
        # 因此我们专门挑不含 '继续/resume/continue/go' 子串的输入
        if 'on' in msg.lower() and len('on') <= 4:
            continue
        handled, _ = s._detect_and_handle_resume_command(msg, "test")
        assert handled is False, f"误识别: {msg!r}"
    print("✓ 普通对话不会触发恢复逻辑")


def test_kick_msg_includes_phase_and_old_count():
    """kick 消息应包含 phase 信息 + 计数旧值，便于诊断。"""
    s = FakeSession(phase="test", nudge_count=3)
    handled, kick = s._detect_and_handle_resume_command("继续", "test")
    assert "test" in kick
    assert "3→0" in kick
    print("✓ kick_msg 包含 phase + 计数变化")


def test_chat_loop_integration_resume_unblocks_stuck():
    """端到端：模拟 stuck → 用户"继续" → nudge 计数被重置 → LLM 又能拿到 nudge。"""
    from core.session.utils_mixin import UtilsMixin

    s = FakeSession(phase="test", nudge_count=3)

    # 1) 模拟主循环 _maybe_nudge_phase_forward 的判断：counter=3 → 已满，放弃
    attr = "_nudge_count"
    count = getattr(s, attr, {}).get(s.phase, 0)
    assert count >= 3, "应处于 stuck 状态"

    # 2) 用户输入"继续"
    handled, kick = s._detect_and_handle_resume_command("继续", s.phase)
    assert handled is True

    # 3) 现在 _nudge_count 已被清零，下一轮主循环的 _maybe_nudge_phase_forward
    #    又能给 LLM 3 次 nudge 机会，而不是立即再 stuck
    new_count = getattr(s, attr, {}).get(s.phase, 0)
    assert new_count == 0, f"stuck 状态下'继续'应清零计数，实际={new_count}"
    print("✓ 集成：stuck → '继续' → 计数清零 → LLM 重新获得 nudge 窗口")


if __name__ == "__main__":
    test_reset_nudge_counter_current_phase()
    test_reset_nudge_counter_specific_phase()
    test_reset_nudge_counter_tolerate_none_dict()
    test_resume_keyword_exact_match_in_stuck_phase()
    test_resume_keyword_variants_in_stuck_phase()
    test_resume_not_recognized_in_idle_phase()
    test_resume_not_recognized_in_report_phase()
    test_resume_not_recognized_for_non_resume_messages()
    test_kick_msg_includes_phase_and_old_count()
    test_chat_loop_integration_resume_unblocks_stuck()
    print("\n所有回归测试通过 ✓")
