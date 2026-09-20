"""§3.2：跨域链路只计一次。"""
from __future__ import annotations

from core.loops.chained_finding import (
    CHAIN_REGISTRY,
    attach_domain_ref,
    count_unique_chains,
    domains_of,
    register_chain,
    reset_registry,
)


def setup_function():
    reset_registry()


def test_register_chain_idempotent():
    cid1 = register_chain({"steps": ["upload", "download", "xss"]})
    cid2 = register_chain({"steps": ["upload", "download", "xss"]})
    assert cid1 == cid2
    assert count_unique_chains() == 1


def test_different_chains_counted_separately():
    register_chain({"steps": ["upload", "xss"]})
    register_chain({"steps": ["ssrf", "rce"]})
    assert count_unique_chains() == 2


def test_multi_domain_refs_count_once():
    cid = register_chain({"steps": ["upload", "download", "xss"]})
    attach_domain_ref(cid, "upload", {"id": "f1"})
    attach_domain_ref(cid, "xss", {"id": "f2"})
    # 两个域挂引用，但链仍只计一次
    assert count_unique_chains() == 1
    assert sorted(domains_of(cid)) == ["upload", "xss"]
    assert len(CHAIN_REGISTRY[cid]["finding_refs"]) == 2


def test_attach_to_unknown_chain_returns_false():
    assert attach_domain_ref("chain-nonexistent", "upload") is False


def test_duplicate_domain_ref_not_repeated():
    cid = register_chain({"steps": ["a", "b"]})
    attach_domain_ref(cid, "upload")
    attach_domain_ref(cid, "upload")
    assert domains_of(cid) == ["upload"]


def test_steps_stored():
    cid = register_chain({"steps": ["p1", "p2"]})
    assert CHAIN_REGISTRY[cid]["steps"] == ["p1", "p2"]
