"""F1 跨域凭据隔离单元测试。"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.credential_store import CredentialStore, CredentialDomainMismatch


class TestCredentialDomainMatch:
    def test_same_domain_passes(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["target.com"]}
        store.check_domain_match("http://api.target.com/v1/users", cred)

    def test_cross_domain_blocked(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["target.com"]}
        with pytest.raises(CredentialDomainMismatch):
            store.check_domain_match("http://other.com/v1/users", cred)

    def test_subdomain_matches(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["example.com"]}
        store.check_domain_match("http://api.example.com/users", cred)

    def test_no_applicable_domains_skips(self):
        store = CredentialStore()
        cred = {"id": "c1"}  # no applicable_domains
        store.check_domain_match("http://anything.com/users", cred)

    def test_multiple_domains(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["crm.com", "aiqc.com"]}
        store.check_domain_match("http://api.crm.com/users", cred)
        store.check_domain_match("http://api.aiqc.com/users", cred)
        with pytest.raises(CredentialDomainMismatch):
            store.check_domain_match("http://other.com/users", cred)


class TestRequestWithCredentialCheck:
    def test_blocked_returns_mismatch(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["target.com"]}
        result = store.request_with_credential_check(
            "http://other.com/api", "GET", cred,
        )
        assert result["status"] == -1
        assert result["body"] == "CREDENTIAL_DOMAIN_MISMATCH"

    def test_no_credential_returns_error(self):
        store = CredentialStore()
        result = store.request_with_credential_check("http://t.com/api", "GET", None)
        assert result["status"] == -1

    def test_passing_domain_returns_ok(self):
        store = CredentialStore()
        cred = {"id": "c1", "applicable_domains": ["target.com"]}
        result = store.request_with_credential_check(
            "http://api.target.com/api", "GET", cred,
        )
        assert result["status"] == 200
        assert result.get("_passed") is True


class TestCredentialStoreFile:
    def test_load_from_file(self, tmp_path):
        creds = [
            {"id": "c1", "applicable_domains": ["target.com"]},
            {"id": "c2", "applicable_domains": ["other.com"]},
        ]
        cred_file = tmp_path / "auth_credentials.json"
        cred_file.write_text(json.dumps(creds))
        store = CredentialStore(cred_file=cred_file)
        assert store.get_credential("c1") is not None
        assert store.get_credential("c2") is not None
        assert store.get_credential("c3") is None

    def test_add_applicable_domains(self, tmp_path):
        creds = [{"id": "c1"}]
        cred_file = tmp_path / "auth_credentials.json"
        cred_file.write_text(json.dumps(creds))
        store = CredentialStore(cred_file=cred_file)
        store.add_applicable_domains("c1", ["target.com"])
        # Reload and check
        store2 = CredentialStore(cred_file=cred_file)
        cred = store2.get_credential("c1")
        assert cred["applicable_domains"] == ["target.com"]
        assert cred["isolation_verified"] is True
