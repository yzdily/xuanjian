"""F5 — 框架级端点专项扫描模块。

jingtaituoming 全部 Critical 来自 Actuator/Shiro/heapdump/Swagger。
玄鉴 dir_scanner 仅有通用字典扫描，无 Spring Boot Actuator 矩阵。
"""
from __future__ import annotations

from typing import Any

FRAMEWORK_ENDPOINTS: dict[str, list[str]] = {
    "spring_boot_actuator": [
        "/actuator",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/heapdump",
        "/actuator/health",
        "/actuator/threaddump",
        "/actuator/loggers",
        "/actuator/configprops",
        "/actuator/conditions",
        "/actuator/metrics",
        "/actuator/scheduledtasks",
    ],
    "swagger": [
        "/swagger-ui.html",
        "/swagger-ui/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger.json",
        "/openapi.json",
        "/swagger-resources",
        "/api/swagger.json",
    ],
    "shiro_check": [
        "__detect_rememberme__",
    ],
    "common_files": [
        "/.env",
        "/.git/config",
        "/phpinfo.php",
        "/debug",
        "/health",
        "/.htpasswd",
        "/server-status",
        "/info.php",
    ],
}

EXPOSED_STATUS_CODES = {200, 302, 401}


class FrameworkScanner:
    """框架级端点扫描器。"""

    def __init__(
        self,
        request_fn: Any | None = None,
        concurrency: int = 1,
        interval_ms: int = 500,
    ) -> None:
        self._request = request_fn
        self._concurrency = concurrency
        self._interval_ms = interval_ms

    def endpoints_for(self, framework: str) -> list[str]:
        return FRAMEWORK_ENDPOINTS.get(framework, [])

    async def scan(
        self, base_url: str, frameworks: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """扫描指定框架的端点，返回暴露的端点列表。"""
        results: list[dict[str, Any]] = []
        targets = frameworks or list(FRAMEWORK_ENDPOINTS.keys())
        for fw in targets:
            for endpoint in self.endpoints_for(fw):
                if endpoint == "__detect_rememberme__":
                    results.append({
                        "framework": fw,
                        "endpoint": "(shiro probe)",
                        "status": "pending_shiro_detect",
                    })
                    continue
                url = base_url.rstrip("/") + endpoint
                entry = {"framework": fw, "endpoint": endpoint, "url": url}
                if self._request:
                    try:
                        resp = await self._request("GET", url)
                        status = getattr(resp, "status", 200)
                        if status in EXPOSED_STATUS_CODES:
                            entry["status"] = status
                            entry["exposed"] = True
                            results.append(entry)
                    except Exception as exc:
                        entry["status"] = -1
                        entry["error"] = str(exc)
                        results.append(entry)
                else:
                    entry["status"] = "not_scanned"
                    results.append(entry)
        return results

    def classify_finding(self, framework: str, endpoint: str, status: int) -> dict[str, Any]:
        """分类框架级漏洞。"""
        severity_map = {
            "/actuator/env": "Critical",
            "/actuator/heapdump": "Critical",
            "/actuator/beans": "High",
            "/actuator/configprops": "High",
            "/actuator/mappings": "Medium",
            "/actuator/loggers": "Medium",
            "/actuator/threaddump": "Medium",
            "/.env": "Critical",
            "/.git/config": "Critical",
        }
        return {
            "vuln_type": "FrameworkExposure",
            "framework": framework,
            "endpoint": endpoint,
            "severity": severity_map.get(endpoint, "Low"),
            "status": status,
        }


__all__ = ["FrameworkScanner", "FRAMEWORK_ENDPOINTS"]
