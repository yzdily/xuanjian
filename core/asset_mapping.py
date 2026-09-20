"""
资产测绘模块 — 空间测绘联动

借鉴 Venom 的测绘联动设计,聚合 FOFA/Hunter/DayDayMap 等外部测绘结果,
收敛攻击面后直接发送到端口扫描或漏洞扫描模块。
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx

from core.log import get_logger
from core.di import register_resetter

log = get_logger("asset_mapping")


class MappingService(str, Enum):
    """测绘服务类型"""
    FOFA = "fofa"
    HUNTER = "hunter"
    DAYDAYMAP = "daydaymap"


@dataclass
class Asset:
    """资产信息"""
    host: str
    port: int = 80
    protocol: str = "http"
    title: str = ""
    domain: str = ""
    ip: str = ""
    country: str = ""
    city: str = ""
    service: str = ""
    banner: str = ""
    source: str = ""  # 来源服务
    raw: dict = field(default_factory=dict)


@dataclass
class MappingResult:
    """测绘结果"""
    service: MappingService
    query: str
    total: int = 0
    assets: list[Asset] = field(default_factory=list)
    error: str = ""


class AssetMappingClient:
    """资产测绘客户端"""

    def __init__(self):
        self._config = {
            MappingService.FOFA: {
                "api_url": "https://api.fofa.info/v1/api/search",
                "email": os.getenv("FOFA_EMAIL", ""),
                "api_key": os.getenv("FOFA_API_KEY", ""),
            },
            MappingService.HUNTER: {
                "api_url": "https://api.hunter.io/v2/search",
                "api_key": os.getenv("HUNTER_API_KEY", ""),
            },
            MappingService.DAYDAYMAP: {
                "api_url": "https://api.daydaymap.com/api/v1/search",
                "api_key": os.getenv("DAYDAYMAP_API_KEY", ""),
            },
        }

        self._timeout = httpx.Timeout(30.0, connect=10.0)

    async def query(
        self,
        service: MappingService,
        query: str,
        page: int = 1,
        size: int = 100,
    ) -> MappingResult:
        """执行测绘查询

        Args:
            service: 测绘服务
            query: 查询语法
            page: 页码
            size: 每页数量

        Returns:
            测绘结果
        """
        if service == MappingService.FOFA:
            return await self._query_fofa(query, page, size)
        elif service == MappingService.HUNTER:
            return await self._query_hunter(query, page, size)
        elif service == MappingService.DAYDAYMAP:
            return await self._query_daydaymap(query, page, size)
        else:
            return MappingResult(service=service, query=query, error="不支持的测绘服务")

    async def _query_fofa(self, query: str, page: int, size: int) -> MappingResult:
        """FOFA 查询"""
        config = self._config[MappingService.FOFA]

        if not config["email"] or not config["api_key"]:
            return MappingResult(
                service=MappingService.FOFA,
                query=query,
                error="FOFA API 未配置,请设置 FOFA_EMAIL 和 FOFA_API_KEY 环境变量"
            )

        params = {
            "email": config["email"],
            "key": config["api_key"],
            "qbase64": quote(query),
            "page": page,
            "size": size,
            "fields": "host,port,protocol,title,domain,ip,country,city",
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                resp = await client.get(config["api_url"], params=params)
                resp.raise_for_status()
                data = resp.json()

            if data.get("error"):
                return MappingResult(
                    service=MappingService.FOFA,
                    query=query,
                    error=data.get("errmsg", "未知错误")
                )

            assets = []
            for item in data.get("results", []):
                asset = Asset(
                    host=item.get("host", ""),
                    port=item.get("port", 80),
                    protocol=item.get("protocol", "http"),
                    title=item.get("title", ""),
                    domain=item.get("domain", ""),
                    ip=item.get("ip", ""),
                    country=item.get("country", ""),
                    city=item.get("city", ""),
                    source="fofa",
                    raw=item,
                )
                assets.append(asset)

            return MappingResult(
                service=MappingService.FOFA,
                query=query,
                total=data.get("size", 0),
                assets=assets,
            )

        except Exception as e:
            log.error(f"FOFA 查询失败: {e}")
            return MappingResult(service=MappingService.FOFA, query=query, error=str(e))

    async def _query_hunter(self, query: str, page: int, size: int) -> MappingResult:
        """Hunter 查询"""
        config = self._config[MappingService.HUNTER]

        if not config["api_key"]:
            return MappingResult(
                service=MappingService.HUNTER,
                query=query,
                error="Hunter API 未配置,请设置 HUNTER_API_KEY 环境变量"
            )

        params = {
            "api-key": config["api_key"],
            "query": query,
            "page": page,
            "page_size": size,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                resp = await client.get(config["api_url"], params=params)
                resp.raise_for_status()
                data = resp.json()

            if data.get("code") != 200:
                return MappingResult(
                    service=MappingService.HUNTER,
                    query=query,
                    error=data.get("message", "未知错误")
                )

            assets = []
            for item in data.get("data", {}).get("arr", []):
                asset = Asset(
                    host=item.get("host", ""),
                    port=item.get("port", 80),
                    protocol=item.get("protocol", "http"),
                    title=item.get("web_title", ""),
                    domain=item.get("domain", ""),
                    ip=item.get("ip", ""),
                    country=item.get("country", ""),
                    service=item.get("service", ""),
                    banner=item.get("banner", ""),
                    source="hunter",
                    raw=item,
                )
                assets.append(asset)

            return MappingResult(
                service=MappingService.HUNTER,
                query=query,
                total=data.get("data", {}).get("total", 0),
                assets=assets,
            )

        except Exception as e:
            log.error(f"Hunter 查询失败: {e}")
            return MappingResult(service=MappingService.HUNTER, query=query, error=str(e))

    async def _query_daydaymap(self, query: str, page: int, size: int) -> MappingResult:
        """DayDayMap 查询"""
        config = self._config[MappingService.DAYDAYMAP]

        if not config["api_key"]:
            return MappingResult(
                service=MappingService.DAYDAYMAP,
                query=query,
                error="DayDayMap API 未配置,请设置 DAYDAYMAP_API_KEY 环境变量"
            )

        # Similar implementation to FOFA
        params = {
            "apikey": config["api_key"],
            "query": query,
            "page": page,
            "size": size,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                resp = await client.get(config["api_url"], params=params)
                resp.raise_for_status()
                data = resp.json()

            assets = []
            for item in data.get("data", []):
                asset = Asset(
                    host=item.get("host", ""),
                    port=item.get("port", 80),
                    title=item.get("title", ""),
                    source="daydaymap",
                    raw=item,
                )
                assets.append(asset)

            return MappingResult(
                service=MappingService.DAYDAYMAP,
                query=query,
                total=data.get("total", 0),
                assets=assets,
            )

        except Exception as e:
            log.error(f"DayDayMap 查询失败: {e}")
            return MappingResult(service=MappingService.DAYDAYMAP, query=query, error=str(e))

    def to_targets(self, result: MappingResult) -> list[str]:
        """将测绘结果转换为目标列表

        Returns:
            目标 URL 列表
        """
        targets = []
        for asset in result.assets:
            if asset.protocol:
                url = f"{asset.protocol}://{asset.host}:{asset.port}"
            else:
                url = f"http://{asset.host}:{asset.port}"
            targets.append(url)
        return targets


# 全局客户端实例（D7 holder 化：global → _state 属性，零行为变更）
@dataclass
class _AssetMappingState:
    client: AssetMappingClient | None = None

_state = _AssetMappingState()


def get_mapping_client() -> AssetMappingClient:
    """获取测绘客户端实例"""
    if _state.client is None:
        _state.client = AssetMappingClient()
    return _state.client


async def query_assets(service: str, query: str) -> MappingResult:
    """便捷函数：查询资产"""
    client = get_mapping_client()
    service_enum = MappingService(service.lower())
    return await client.query(service_enum, query)


# ★ DI 收敛（D7/A4）：注册单例重置钩子，供 reset_singletons() 在测试间统一重置
def _reset_core_asset_mapping__client() -> None:
    _state.client = None

register_resetter("core_asset_mapping__client", _reset_core_asset_mapping__client)
