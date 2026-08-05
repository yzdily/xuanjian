"""
Fuzz Base — 抽象基类与数据结构

定义所有 Fuzzer 的统一接口和输入/输出数据结构。

核心定位：
  fuzz 模块是 LLM 的"批量执行引擎"，负责需要大量请求的场景：
  - SQL 盲注 → 逐字符/逐位提取数据（几十~几百请求）
  - WAF 绕过 → 批量发送 payload 变体，找到能过防护的那个
  - 竞态条件 → 并发发送请求触发竞态

  设计原则：
  - LLM 负责策略（制定 payload 模板、分析结果）
  - Fuzz 负责执行（批量发送、检测差异、智能停止）
  - 像 Burp Intruder 一样：发现响应差异就停止
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


# ============================================================
# 共享 HTTP 客户端（连接池复用）
# ============================================================
_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    """获取共享的 HTTP 客户端（连接池复用）。"""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _http_client


class FuzzResult(Enum):
    """Fuzz 结果枚举"""
    CONFIRMED = "confirmed"       # 确认成功（找到有效 payload / 提取到数据）
    LIKELY = "likely"             # 高度疑似（有差异但不够确定）
    NOT_VULN = "not_vuln"         # 确认失败（所有 payload 均无效）
    INCONCLUSIVE = "inconclusive" # 无法判断（目标无响应/WAF全拦截等）
    ERROR = "error"               # 执行过程出错
    TIMEOUT = "timeout"           # 超时


@dataclass
class FuzzTask:
    """Fuzz 任务输入 — 描述"要 fuzz 什么"

    由 LLM 构造，传给 Fuzzer 执行。
    """
    # 必填
    vuln_type: str                       # 漏洞类型（中文标准名，如"SQL注入"、"WAF绕过"）
    target_url: str                      # 目标 URL（完整，含 path + query）

    # 请求信息
    method: str = "GET"                  # HTTP 方法
    param_name: str = ""                 # 可疑参数名（如 "id"、"user_id"）
    original_value: str = ""             # 参数原始值（如 "123"）
    headers: dict[str, str] = field(default_factory=dict)   # 请求头（含 Cookie/Auth）
    body: str = ""                       # 请求体（POST 场景）
    content_type: str = ""               # Content-Type

    # ★ LLM 传入的已验证 payload 模板（核心新增）
    working_payload_template: str = ""   # 已验证可用的 payload 模板
    # 示例：
    #   SQL盲注: "1' AND IF(ASCII(SUBSTR(({expr}),{pos},1))>{mid},SLEEP(3),0)-- -"
    #   WAF绕过: "{original}' /*!50000AND*/ {payload}-- -"
    injection_type: str = ""             # 注入类型提示（error_based/union/blind_time/blind_bool）
    bypass_notes: str = ""               # WAF 绕过方式说明

    # ★ WAF fuzz 专用：payload 字典
    payload_list: list[str] = field(default_factory=list)  # LLM 生成的 payload 变体列表

    # 上下文
    baseline_response: str = ""          # 正常响应内容（用于 diff 对比）
    baseline_status: int = 0             # 正常响应状态码
    baseline_body_length: int = 0        # 正常响应 body 长度（用于差异检测）
    hints: list[str] = field(default_factory=list)  # LLM 给的提示

    # ★ 智能停止配置
    stop_on_diff: bool = True            # 发现响应差异时是否立即停止
    diff_threshold: float = 0.3          # body 长度差异超过此比例视为"不同"
    max_success_count: int = 3           # 找到 N 个成功 payload 后停止

    # 额外配置
    timeout: float = 30.0                # 单次请求超时
    max_requests: int = 100              # 最大请求数限制
    proxy_url: str = ""                  # 代理地址


@dataclass
class FuzzEvidence:
    """Fuzz 产出的结构化证据 — 描述"fuzz 结果是什么"

    由 Fuzzer 填充，返回给 LLM 做后续利用。
    """
    # 核心结论
    result: FuzzResult                   # fuzz 结果
    confidence: float = 0.0              # 置信度 0.0 ~ 1.0
    summary: str = ""                    # 一句话结论（人类可读）
    fuzzer_name: str = ""                # 使用的 fuzzer 名称

    # 执行统计
    requests_sent: int = 0               # 总共发了多少个请求
    elapsed_seconds: float = 0.0         # 耗时（秒）

    # ★ fuzz 核心产出
    working_payloads: list[str] = field(default_factory=list)  # 成功的 payload 列表
    extracted_data: dict[str, Any] = field(default_factory=dict)  # 提取到的数据
    # 示例：
    # SQL盲注: {"db_version": "MySQL 5.7.38", "current_user": "root@localhost",
    #            "current_db": "app_db", "tables": ["users", "orders"]}
    # WAF绕过: {"bypass_payload": "' /*!50000AND*/ 1=1-- -", "waf_type": "ModSecurity"}
    # 竞态:    {"success_count": 5, "expected_max": 1}

    # 证据详情
    poc_curl: str = ""                   # 可复现的 PoC（curl 命令）
    data_leaked: str = ""                # 泄露的数据样例
    impact_scope: str = ""               # 影响范围描述
    diff_highlight: str = ""             # 关键差异

    # 响应差异记录
    response_diffs: list[dict[str, Any]] = field(default_factory=list)
    # 每个元素: {"payload": "...", "status": 200, "body_len": 1234, "is_different": True}

    # 辅助信息
    key_request: str = ""                # 关键攻击请求包
    key_response: str = ""               # 关键响应包
    timeline: list[dict[str, Any]] = field(default_factory=list)
    waf_detected: bool = False
    error_message: str = ""
    stop_reason: str = ""                # 停止原因（diff_detected/max_requests/all_done/timeout）

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。"""
        return {
            "result": self.result.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "fuzzer_name": self.fuzzer_name,
            "requests_sent": self.requests_sent,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "working_payloads": self.working_payloads[:10],
            "extracted_data": self.extracted_data,
            "poc_curl": self.poc_curl,
            "data_leaked": self.data_leaked[:500],
            "impact_scope": self.impact_scope,
            "diff_highlight": self.diff_highlight[:1000],
            "response_diffs": self.response_diffs[-20:],
            "waf_detected": self.waf_detected,
            "stop_reason": self.stop_reason,
            "error_message": self.error_message,
        }

    def to_prompt(self) -> str:
        """格式化为可注入 LLM prompt 的文本摘要。"""
        lines = [f"## Fuzz 结果: {self.result.value} (置信度 {self.confidence:.0%})"]
        lines.append(f"Fuzzer: {self.fuzzer_name} | 请求数: {self.requests_sent} | 耗时: {self.elapsed_seconds:.1f}s")
        if self.stop_reason:
            lines.append(f"停止原因: {self.stop_reason}")
        if self.summary:
            lines.append(f"结论: {self.summary}")
        if self.working_payloads:
            lines.append("### 成功的 Payload:")
            for p in self.working_payloads[:5]:
                lines.append(f"  - `{p}`")
        if self.extracted_data:
            lines.append("### 提取到的数据:")
            for k, v in self.extracted_data.items():
                lines.append(f"  - {k}: {str(v)[:150]}")
        if self.data_leaked:
            lines.append(f"泄露数据样例: {self.data_leaked[:200]}")
        if self.impact_scope:
            lines.append(f"影响范围: {self.impact_scope}")
        if self.diff_highlight:
            lines.append(f"关键差异:\n```\n{self.diff_highlight[:500]}\n```")
        if self.poc_curl:
            lines.append(f"PoC:\n```bash\n{self.poc_curl}\n```")
        if self.waf_detected:
            lines.append("⚠️ 检测到 WAF 拦截")
        if self.error_message:
            lines.append(f"❌ 错误: {self.error_message}")
        return "\n".join(lines)


class BaseFuzzer:
    """Fuzzer 抽象基类

    所有专项 Fuzzer 继承此类，实现 fuzz() 方法。

    设计原则：
    - fuzz() 内部可以发送大量请求（不受 LLM 轮次限制）
    - Fuzzer 自己决定 fuzz 策略（不需要 LLM 逐步指导）
    - 输出结构化的 FuzzEvidence（LLM 拿到结果继续利用）
    - ★ 核心机制：响应差异检测 → 自动停止（像 Burp Intruder）
    """

    # 子类声明自己能处理的漏洞类型
    VULN_TYPES: list[str] = []
    NAME: str = "base"
    PRIORITY: int = 5

    def __init__(self, proxy_url: str = "", default_timeout: float = 30.0):
        self.proxy_url = proxy_url
        self.default_timeout = default_timeout

    async def fuzz(self, task: FuzzTask) -> FuzzEvidence:
        """执行 fuzz，返回结构化证据。子类必须实现。"""
        raise NotImplementedError(f"{self.__class__.__name__} 未实现 fuzz()")

    def can_handle(self, vuln_type: str) -> bool:
        """判断本 Fuzzer 是否能处理该漏洞类型。"""
        if not vuln_type:
            return False
        vt_lower = vuln_type.lower().strip()
        for supported in self.VULN_TYPES:
            if supported.lower() in vt_lower or vt_lower in supported.lower():
                return True
        return False

    # ============================================================
    # 工具方法（子类可复用）
    # ============================================================

    async def _send_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str = "",
        timeout: float = 0,
    ) -> dict[str, Any]:
        """发送 HTTP 请求，返回 {status, headers, body, elapsed, error}。"""
        timeout = timeout or self.default_timeout
        kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "headers": headers or {},
            "timeout": timeout,
            "follow_redirects": True,
        }
        if self.proxy_url:
            kwargs["proxy"] = self.proxy_url
        if body:
            kwargs["content"] = body.encode("utf-8", errors="replace")

        t0 = time.time()
        try:
            client = await get_http_client()
            resp = await client.request(**kwargs)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10000],
                "body_length": len(resp.text),
                "elapsed": time.time() - t0,
                "error": None,
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "body_length": 0,
                "elapsed": time.time() - t0,
                "error": f"{type(e).__name__}: {e}",
            }

    def _is_response_different(
        self,
        baseline_status: int,
        baseline_body_length: int,
        resp_status: int,
        resp_body_length: int,
        threshold: float = 0.3,
    ) -> bool:
        """判断响应是否与基线有显著差异（Burp Intruder 式判断）。

        差异标准：
        1. 状态码不同
        2. body 长度差异超过阈值
        """
        # 状态码变化
        if resp_status != baseline_status:
            return True
        # body 长度差异
        if baseline_body_length > 0:
            diff_ratio = abs(resp_body_length - baseline_body_length) / baseline_body_length
            if diff_ratio > threshold:
                return True
        return False

    def _detect_waf(self, status: int, body: str, headers: dict) -> bool:
        """简单的 WAF 检测。"""
        if status in (403, 406, 429, 503):
            waf_keywords = [
                "blocked", "forbidden", "waf", "firewall", "security",
                "access denied", "请求被拦截", "安全拦截",
            ]
            body_lower = body.lower()
            if any(kw in body_lower for kw in waf_keywords):
                return True
        waf_headers = ["x-waf", "x-sucuri", "x-cdn", "cf-ray", "x-powered-by-anquanbao"]
        for h in waf_headers:
            if h in {k.lower() for k in headers}:
                return True
        return False

    def _build_curl(self, method: str, url: str, headers: dict | None = None, body: str = "") -> str:
        """构造 curl 命令。"""
        parts = [f"curl -X {method.upper()}"]
        if headers:
            for k, v in headers.items():
                if k.lower() in ("host", "content-length", "accept-encoding"):
                    continue
                parts.append(f"  -H '{k}: {v}'")
        if body:
            parts.append(f"  -d '{body}'")
        parts.append(f"  '{url}'")
        return " \\\n".join(parts)

    def _make_error_evidence(self, error: str) -> FuzzEvidence:
        """快速构造一个错误结果。"""
        return FuzzEvidence(
            result=FuzzResult.ERROR,
            confidence=0.0,
            summary=f"Fuzz 失败: {error}",
            fuzzer_name=self.NAME,
            error_message=error,
        )
