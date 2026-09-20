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
    """凭据存储 + 跨域隔离校验 + F3 完整 Cookie 集注册表。

    ★ F3（0918 §1.4 / auth_matrix）落地说明：
      `credential_injector._wait_for_login_result` 与 `login_judge.attempt_login`
      早已有 `required_cookies` 参数，但**全仓零生产实参**（参数存在、没人传），
      且本存储无对应字段 → "登录态判定只看单个 auth cookie" 的漏报面没被堵上。
      本类补：①凭据级 `required_cookies` 字段 ②租户级注册表
      ③`required_cookies_for()` 统一解析（供注入器/判定器喂入）。
    """

    def __init__(self, cred_file: Path | None = None, tenant_id: str | None = None):
        self._path = cred_file or credentials_path(tenant_id)
        self._creds: list[dict[str, Any]] = []
        # 租户 → 完整 Cookie 名集（per-tenant 注册表）
        self._tenant_required: dict[str, list[str]] = {}
        # 原文件容器形态：dict 形态要保形回写，否则会把兄弟字段写丢
        self._raw_is_dict = False
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    self._creds = raw
                elif isinstance(raw, dict):
                    self._raw_is_dict = True
                    self._creds = raw.get("credentials") or []
                    treg = raw.get("tenant_required_cookies")
                    if isinstance(treg, dict):
                        self._tenant_required = {
                            str(k): [str(x) for x in (v or [])]
                            for k, v in treg.items()
                            if isinstance(v, (list, tuple, set))
                        }
            except (json.JSONDecodeError, OSError):
                self._creds = []

    def _save(self) -> None:
        """回写凭据文件，**保留原容器形态**（dict 形态下兄弟字段不被写丢）。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload: Any = (
            {"credentials": self._creds, "tenant_required_cookies": self._tenant_required}
            if self._raw_is_dict
            else self._creds
        )
        self._path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def get_credential(self, cred_id: str) -> dict[str, Any] | None:
        for c in self._creds:
            if c.get("id") == cred_id:
                return c
        return None

    # ------------------------------------------------------------------
    # F3：完整 Cookie 集
    # ------------------------------------------------------------------
    def get_required_cookies(self, cred_id: str) -> set[str]:
        """凭据声明的"必须全命中"Cookie 名集（未配置 → 空集，表示不启用该判定）。"""
        c = self.get_credential(cred_id) or {}
        v = c.get("required_cookies")
        if isinstance(v, (list, tuple, set)):
            return {str(x).strip() for x in v if str(x).strip()}
        return set()

    def set_required_cookies(self, cred_id: str, cookies: Any) -> bool:
        """为指定凭据写入 `required_cookies` 并持久化。"""
        names = [str(x).strip() for x in (cookies or []) if str(x).strip()]
        for c in self._creds:
            if c.get("id") == cred_id:
                c["required_cookies"] = names
                self._save()
                return True
        return False

    def register_tenant_required_cookies(self, tenant: str, cookies: Any) -> None:
        """注册/更新租户级完整 Cookie 集（per-tenant 注册表）。"""
        self._tenant_required[str(tenant)] = [
            str(x).strip() for x in (cookies or []) if str(x).strip()
        ]
        self._save()

    def tenant_required_cookies(self) -> dict[str, list[str]]:
        return {k: list(v) for k, v in self._tenant_required.items()}

    def required_cookies_for(self, *, tenant: str = "", url: str = "") -> set[str]:
        """解析某次登录应使用的完整 Cookie 集。

        优先级：租户注册表（显式最强） → 按域名匹配到的凭据配置 → 空集（不启用判定）。
        空集是**安全默认**：行为与改造前一致（仅看 auth cookie 是否出现）。
        """
        if tenant:
            registered = self._tenant_required.get(str(tenant))
            if registered:
                return {str(x) for x in registered}
        if url:
            for c in self._creds:
                if not self.matches_url(url, c):
                    continue
                rc = self.get_required_cookies(str(c.get("id") or ""))
                if rc:
                    return rc
        return set()

    def matches_url(self, url: str, cred: dict[str, Any]) -> bool:
        """域匹配判定（不抛异常版，供解析用）。"""
        try:
            self.check_domain_match(url, cred)
            return True
        except CredentialDomainMismatch:
            return False

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
            # 走 _save 以保留原容器形态（原实现无条件写成 list，
            # dict 形态文件的兄弟字段 tenant_required_cookies 会被写丢）
            self._save()
        return found


__all__ = ["CredentialStore", "CredentialDomainMismatch"]
