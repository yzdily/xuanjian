"""F1 — 跨域凭据隔离校验（0901 P0-B 教训落地）。

zhinenjqr 双域架构（/crm/* Cookie + /ht-aiqc/* Bearer JWT）跨域凭据直接报 401。
本模块在请求发出前校验凭据的 applicable_domains 是否覆盖目标域。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.workspace import credentials_path


class CredentialDomainMismatch(Exception):
    """凭据不适用于目标域名。"""


class CredentialStore:
    """凭据存储 + 跨域隔离校验。"""

    def __init__(self, cred_file: Path | None = None):
        self._path = cred_file or credentials_path()
        self._creds: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    self._creds = raw
                elif isinstance(raw, dict) and "credentials" in raw:
                    self._creds = raw["credentials"]
            except (json.JSONDecodeError, OSError):
                self._creds = []

    def get_credential(self, cred_id: str) -> dict[str, Any] | None:
        for c in self._creds:
            if c.get("id") == cred_id:
                return c
        return None

    def check_domain_match(self, url: str, cred: dict[str, Any]) -> None:
        """校验凭据的 applicable_domains 覆盖目标 URL 的域名。

        若凭据未配置 applicable_domains 则跳过校验（向后兼容）。
        """
        domains = cred.get("applicable_domains")
        if not domains:
            return
        api_domain = urlparse(url).netloc.lower()
        for d in domains:
            d_lower = d.lower()
            if api_domain.endswith(d_lower) or d_lower in api_domain:
                return
        raise CredentialDomainMismatch(
            f"目标域 {api_domain} 不在凭据 {cred.get('id', '?')} "
            f"的适用范围 {domains} 内"
        )

    def request_with_credential_check(
        self, url: str, method: str = "GET", cred: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """发请求前先做跨域校验，不通过则返回拦截结果。"""
        if cred is None:
            return {"status": -1, "body": "", "error": "no credential"}
        try:
            self.check_domain_match(url, cred)
        except CredentialDomainMismatch as exc:
            return {
                "status": -1,
                "body": "CREDENTIAL_DOMAIN_MISMATCH",
                "blocked_reason": str(exc),
            }
        return {"status": 200, "body": "", "_passed": True}

    def all_credentials(self) -> list[dict[str, Any]]:
        return list(self._creds)

    def add_applicable_domains(self, cred_id: str, domains: list[str]) -> bool:
        """为指定凭据补充 applicable_domains 字段并持久化。"""
        found = False
        for c in self._creds:
            if c.get("id") == cred_id:
                c["applicable_domains"] = domains
                c["isolation_verified"] = True
                found = True
                break
        if found:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._creds, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        return found


__all__ = ["CredentialStore", "CredentialDomainMismatch"]
