"""
端口扫描模块 — 端口扫描、协议识别、Web 指纹

借鉴 Venom 的端口扫描联动设计，支持批量目标导入、端口策略预设、
协议识别和 Web 指纹探测，结果可直接发送到漏洞扫描模块。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.log import get_logger

log = get_logger("port_scanner")


class PortStrategy(str, Enum):
    """端口扫描策略"""
    WEB_COMMON = "web_common"      # Web 常用端口
    TOP_100 = "top_100"            # Top 100 端口
    TOP_1000 = "top_1000"          # Top 1000 端口
    RCE = "rce"                    # RCE 相关端口
    FULL = "full"                  # 全端口


# 预设端口列表
PORT_STRATEGIES = {
    PortStrategy.WEB_COMMON: [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9443],
    PortStrategy.TOP_100: [
        80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 993, 995,
        587, 3306, 1433, 1521, 5432, 6379, 27017, 23, 465, 993,
        995, 3306, 5432, 6379, 8080, 8443, 8888, 9000, 10000,
        # ... more
    ],
    PortStrategy.RCE: [
        22, 23, 135, 139, 445, 593, 1099, 1433, 1521, 2049,
        3306, 3389, 4444, 5432, 5900, 5985, 6379, 7001, 8080,
        8443, 8888, 9000, 9200, 27017, 50000,
    ],
    PortStrategy.FULL: list(range(1, 65536)),
}


@dataclass
class ServiceInfo:
    """服务信息"""
    host: str
    port: int
    protocol: str = ""
    version: str = ""
    service: str = ""
    banner: str = ""
    http_status: int = 0
    http_title: str = ""
    http_server: str = ""
    web_fingerprint: list[str] = field(default_factory=list)
    is_web: bool = False


@dataclass
class ScanResult:
    """扫描结果"""
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    scan_time: float = 0.0


class PortScanner:
    """端口扫描器"""
    
    def __init__(
        self,
        strategy: PortStrategy = PortStrategy.TOP_100,
        custom_ports: list[int] | None = None,
        timeout: float = 3.0,
        max_concurrent: int = 100,
    ):
        self.strategy = strategy
        self.custom_ports = custom_ports or []
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore: asyncio.Semaphore | None = None
    
    async def scan(self, targets: list[str]) -> list[ScanResult]:
        """扫描多个目标
        
        Args:
            targets: 目标主机列表（IP 或域名）
            
        Returns:
            扫描结果列表
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        ports = self._get_ports()
        log.info(f"开始扫描 {len(targets)} 个目标，端口数: {len(ports)}")
        
        results = []
        for target in targets:
            result = await self._scan_host(target, ports)
            results.append(result)
        
        return results
    
    def _get_ports(self) -> list[int]:
        """获取要扫描的端口列表"""
        if self.custom_ports:
            return self.custom_ports
        return PORT_STRATEGIES.get(self.strategy, PORT_STRATEGIES[PortStrategy.TOP_100])
    
    async def _scan_host(self, host: str, ports: list[int]) -> ScanResult:
        """扫描单个主机"""
        import time
        t0 = time.time()
        
        # 并发扫描端口
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        services = []
        
        for port, result in zip(ports, results):
            if isinstance(result, ServiceInfo):
                open_ports.append(port)
                services.append(result)
        
        return ScanResult(
            host=host,
            open_ports=open_ports,
            services=services,
            scan_time=time.time() - t0,
        )
    
    async def _scan_port(self, host: str, port: int) -> ServiceInfo | None:
        """扫描单个端口"""
        async with self._semaphore:
            try:
                # TCP connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                
                # Port is open, try to identify service
                service_info = await self._identify_service(host, port)
                return service_info
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
    
    async def _identify_service(self, host: str, port: int) -> ServiceInfo:
        """识别服务"""
        info = ServiceInfo(host=host, port=port)
        
        # Common service ports
        SERVICE_MAP = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
        }
        
        info.service = SERVICE_MAP.get(port, "unknown")
        
        # Try HTTP request for web ports
        if port in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000):
            web_info = await self._fingerprint_web(host, port)
            if web_info:
                info.is_web = True
                info.http_status = web_info.get("status", 0)
                info.http_title = web_info.get("title", "")
                info.http_server = web_info.get("server", "")
                info.web_fingerprint = web_info.get("fingerprint", [])
        
        return info
    
    async def _fingerprint_web(self, host: str, port: int) -> dict | None:
        """Web 指纹识别"""
        import httpx
        
        protocol = "https" if port in (443, 8443) else "http"
        url = f"{protocol}://{host}:{port}/"
        
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                verify=False,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                
                title = ""
                title_match = re.search(r"<title>([^<]+)</title>", resp.text, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                
                server = resp.headers.get("Server", "")
                
                # Web fingerprint
                fingerprint = []
                
                # Check common frameworks
                if "X-Powered-By" in resp.headers:
                    fingerprint.append(f"powered-by:{resp.headers['X-Powered-By']}")
                
                if "asp.net" in resp.text.lower():
                    fingerprint.append("ASP.NET")
                if "php" in resp.text.lower():
                    fingerprint.append("PHP")
                if "jsp" in resp.text.lower():
                    fingerprint.append("JSP")
                
                return {
                    "status": resp.status_code,
                    "title": title[:100],
                    "server": server,
                    "fingerprint": fingerprint,
                }
                
        except Exception as e:
            log.debug(f"Web 指纹识别失败 {url}: {e}")
            return None


async def scan_targets(
    targets: list[str],
    strategy: str = "top_100",
    custom_ports: list[int] | None = None,
) -> list[ScanResult]:
    """便捷函数：扫描目标"""
    scanner = PortScanner(
        strategy=PortStrategy(strategy),
        custom_ports=custom_ports,
    )
    return await scanner.scan(targets)


def to_scan_urls(results: list[ScanResult]) -> list[str]:
    """将扫描结果转换为扫描 URL 列表"""
    urls = []
    for result in results:
        for service in result.services:
            if service.is_web:
                protocol = "https" if service.port in (443, 8443) else "http"
                urls.append(f"{protocol}://{service.host}:{service.port}/")
    return urls