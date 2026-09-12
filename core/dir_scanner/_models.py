"""DirectoryScanner 数据模型 — 从 core/dir_scanner.py 抽取，行为不变。"""

from __future__ import annotations

from dataclasses import dataclass, field


# ============================================================
# 数据模型
# ============================================================

@dataclass
class DirEntry:
    """单个目录/文件探测结果。"""
    path: str               # 相对路径，如 "/admin" 或 "/actuator/env"
    url: str                # 完整 URL
    status: int             # HTTP 状态码
    length: int             # 响应体字节数
    content_type: str       # Content-Type
    redirect: str           # Location 头（无则空）
    is_directory: bool      # 推测是否为目录
    title: str              # 从 HTML <title> 提取的标题（无则空）
    body_hash: str          # 响应体哈希（用于通配符对比）
    body_text: str = ""     # 响应体文本截断（用于相似度对比，可选）


@dataclass
class DirFinding:
    """目录扫描产出的漏洞/信息泄露发现。"""
    vuln_type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""


@dataclass
class DirScanResult:
    """目录扫描汇总结果。"""
    target: str
    entries: list[DirEntry] = field(default_factory=list)
    findings: list[DirFinding] = field(default_factory=list)
    total_requests: int = 0
    elapsed: float = 0.0
    host_unreachable: bool = False
    wildcard_detected: bool = False
    waf_blocked: bool = False
    timeout_blocked: bool = False
    recursed_dirs: int = 0
    # ★ OPT5: catch-all 路由检测 — 多个不同路径返回相同 body_hash
    catch_all_detected: bool = False
    catch_all_hash: str = ""
    catch_all_rate: float = 0.0
    # ★ catch-all 响应体（用于相似度对比，过滤近似重复）
    catch_all_body: str = ""
    # ★ 早期 catch-all 中止：首批 API 路径扫描后检测到 catch-all，
    #   跳过后续非 API 路径，减少噪音
    early_abort_count: int = 0
    # ★ 技术栈感知诊断
    tech_stack_detected: str = ""
    is_spa_detected: bool = False
    wordlist_size: int = 0
    # ★ 诊断字段：连接失败 / 超时次数（供前端判断"为什么 0 请求"）
    connect_errors: int = 0
    timeout_errors: int = 0
    # ★ 标记是否走了"关键路径兜底"（基线失败后仍 best-effort 探测高频路径）
    critical_path_fallback: bool = False

    @property
    def discovered_count(self) -> int:
        return len(self.entries)

    @property
    def sensitive_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "host_unreachable": self.host_unreachable,
            "wildcard_detected": self.wildcard_detected,
            "catch_all_detected": self.catch_all_detected,
            "catch_all_rate": self.catch_all_rate,
            "early_abort_count": self.early_abort_count,
            "tech_stack_detected": self.tech_stack_detected,
            "is_spa_detected": self.is_spa_detected,
            "wordlist_size": self.wordlist_size,
            "total_requests": self.total_requests,
            "elapsed": round(self.elapsed, 2),
            "discovered_count": self.discovered_count,
            "sensitive_count": self.sensitive_count,
            "recursed_dirs": self.recursed_dirs,
            "connect_errors": self.connect_errors,
            "timeout_errors": self.timeout_errors,
            "critical_path_fallback": self.critical_path_fallback,
            "entries": [
                {
                    "path": e.path, "url": e.url, "status": e.status,
                    "length": e.length, "content_type": e.content_type,
                    "redirect": e.redirect, "title": e.title,
                }
                for e in self.entries
            ],
            "findings": [
                {
                    "vuln_type": f.vuln_type, "severity": f.severity,
                    "url": f.url, "detail": f.detail, "evidence": f.evidence[:300],
                }
                for f in self.findings
            ],
        }

