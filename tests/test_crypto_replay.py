"""
test_crypto_replay.py — core/crypto_replay 模块完整单测
"""

from __future__ import annotations

import pytest

from core.events import Events, bus
from core.crypto_replay import (
    AlgorithmType,
    CryptoTemplate,
    EncryptedField,
    apply_template,
    delete_template,
    encrypt_field,
    has_template,
    learn_from_capture,
    list_templates,
    load_template,
    save_template,
)


@pytest.fixture()
def isolated_crypto(tmp_path, monkeypatch):
    from core.crypto_replay import store as store_mod
    monkeypatch.setattr(store_mod, "TEMPLATE_ROOT", tmp_path / "data" / "crypto_templates")
    monkeypatch.chdir(tmp_path)
    yield tmp_path


# ============================================================
# Models
# ============================================================

class TestModels:
    def test_field_roundtrip(self):
        ef = EncryptedField(name="password", algorithm=AlgorithmType.SM4,
                            mode="CBC", key="abc123", iv="iviv")
        d = ef.to_dict()
        assert d["algorithm"] == "sm4"
        ef2 = EncryptedField.from_dict(d)
        assert ef2.algorithm == AlgorithmType.SM4
        assert ef2.key == "abc123"

    def test_field_unknown_algo_falls_back(self):
        ef = EncryptedField.from_dict({"name": "x", "algorithm": "elgamal_xyz"})
        assert ef.algorithm == AlgorithmType.UNKNOWN

    def test_template_upsert(self):
        t = CryptoTemplate(host="x.com")
        t.upsert_field(EncryptedField(name="a", algorithm=AlgorithmType.AES))
        t.upsert_field(EncryptedField(name="b", algorithm=AlgorithmType.SM4))
        assert len(t.fields) == 2
        # 同名覆盖
        t.upsert_field(EncryptedField(name="a", algorithm=AlgorithmType.SM4))
        assert len(t.fields) == 2
        assert t.get_field("a").algorithm == AlgorithmType.SM4

    def test_template_roundtrip(self):
        t = CryptoTemplate(host="x.com", note="test")
        t.upsert_field(EncryptedField(name="p", algorithm=AlgorithmType.AES, key="k"))
        d = t.to_dict()
        t2 = CryptoTemplate.from_dict(d)
        assert t2.host == "x.com"
        assert t2.fields[0].name == "p"
        assert t2.fields[0].algorithm == AlgorithmType.AES


# ============================================================
# Store
# ============================================================

class TestStore:
    def test_save_and_load(self, isolated_crypto):
        t = CryptoTemplate(host="example.com")
        t.upsert_field(EncryptedField(name="data", algorithm=AlgorithmType.SM4, key="k"))
        assert save_template(t) is True
        loaded = load_template("example.com")
        assert loaded is not None
        assert loaded.fields[0].name == "data"

    def test_load_missing_returns_none(self, isolated_crypto):
        assert load_template("nope.com") is None

    def test_save_no_host_returns_false(self, isolated_crypto):
        assert save_template(CryptoTemplate(host="")) is False

    def test_list_sorted(self, isolated_crypto):
        save_template(CryptoTemplate(host="a.com"))
        save_template(CryptoTemplate(host="b.com"))
        items = list_templates()
        assert len(items) == 2
        # 验证两个 host 都在结果中（不依赖排序顺序）
        hosts = {item["host"] for item in items}
        assert hosts == {"a.com", "b.com"}

    def test_delete(self, isolated_crypto):
        save_template(CryptoTemplate(host="x.com"))
        assert delete_template("x.com") is True
        assert delete_template("x.com") is False

    def test_safe_host_strips_path_separators(self, isolated_crypto):
        # 不应能用恶意 host 写到任意路径
        save_template(CryptoTemplate(host="../etc/passwd"))
        from core.crypto_replay import store as store_mod
        # 没有任何文件被写到 root
        assert not (store_mod.TEMPLATE_ROOT.parent / "passwd.json").exists()


# ============================================================
# Learner
# ============================================================

class TestLearner:
    def test_learn_basic(self, isolated_crypto):
        ok = learn_from_capture({
            "host": "example.com",
            "url": "https://example.com/api/login",
            "field": "password",
            "algorithm": "sm4",
            "mode": "CBC",
            "key": "0123456789abcdef",
        })
        assert ok is True
        tpl = load_template("example.com")
        assert tpl is not None
        assert tpl.has_field("password")
        assert tpl.get_field("password").algorithm == AlgorithmType.SM4
        assert tpl.sample_url == "https://example.com/api/login"

    def test_learn_missing_host_or_field(self, isolated_crypto):
        assert learn_from_capture({"field": "x", "algorithm": "aes"}) is False
        assert learn_from_capture({"host": "x.com", "algorithm": "aes"}) is False

    def test_learn_upserts(self, isolated_crypto):
        learn_from_capture({"host": "x.com", "field": "a", "algorithm": "aes", "key": "k1"})
        learn_from_capture({"host": "x.com", "field": "a", "algorithm": "sm4", "key": "k2"})
        learn_from_capture({"host": "x.com", "field": "b", "algorithm": "aes"})
        tpl = load_template("x.com")
        assert len(tpl.fields) == 2
        assert tpl.get_field("a").algorithm == AlgorithmType.SM4
        assert tpl.get_field("a").key == "k2"

    def test_learn_unknown_algo_safe(self, isolated_crypto):
        ok = learn_from_capture({"host": "x.com", "field": "a", "algorithm": "weird_x"})
        assert ok is True  # 仍然保存，但算法标为 unknown
        assert load_template("x.com").get_field("a").algorithm == AlgorithmType.UNKNOWN


# ============================================================
# Applier
# ============================================================

class TestApplier:
    def test_has_template(self, isolated_crypto):
        assert has_template("nope.com") is False
        save_template(CryptoTemplate(host="x.com"))
        assert has_template("x.com") is True

    def test_encrypt_field_no_template_returns_plaintext(self, isolated_crypto):
        assert encrypt_field("nope.com", "password", "secret") == "secret"

    def test_encrypt_field_no_field_returns_plaintext(self, isolated_crypto):
        save_template(CryptoTemplate(host="x.com"))
        assert encrypt_field("x.com", "missing", "hi") == "hi"

    def test_encrypt_field_unknown_algo_returns_plaintext(self, isolated_crypto):
        t = CryptoTemplate(host="x.com")
        t.upsert_field(EncryptedField(name="p", algorithm=AlgorithmType.UNKNOWN))
        save_template(t)
        assert encrypt_field("x.com", "p", "hi") == "hi"

    def test_encrypt_field_with_engine_mock(self, isolated_crypto, monkeypatch):
        """模拟 crypto_engine.encrypt_aes 可用，验证 applier 能调通。"""
        import core.crypto_engine as ce

        def fake_encrypt_aes(plaintext, key, iv, mode):
            return f"AES({plaintext})"

        # 注意：使用 monkeypatch.setattr 时 raising=False 允许新增属性
        monkeypatch.setattr(ce, "encrypt_aes", fake_encrypt_aes, raising=False)

        t = CryptoTemplate(host="x.com")
        t.upsert_field(EncryptedField(
            name="password", algorithm=AlgorithmType.AES, mode="CBC",
            key="0123456789abcdef", iv="ivivivivivivivix",
        ))
        save_template(t)

        result = encrypt_field("x.com", "password", "hello")
        assert result == "AES(hello)"

    def test_apply_template_dict(self, isolated_crypto, monkeypatch):
        import core.crypto_engine as ce
        monkeypatch.setattr(ce, "encrypt_aes",
                            lambda plaintext, key, iv, mode: f"E({plaintext})", raising=False)

        t = CryptoTemplate(host="x.com")
        t.upsert_field(EncryptedField(name="password", algorithm=AlgorithmType.AES))
        save_template(t)

        out = apply_template("x.com", {"username": "admin", "password": "p@ss", "extra": 1})
        # 模板里没规定 username，原样保留
        assert out["username"] == "admin"
        # password 被加密
        assert out["password"] == "E(p@ss)"
        # 非字符串/字节字段原样
        assert out["extra"] == 1

    def test_apply_template_no_template_returns_copy(self, isolated_crypto):
        original = {"a": 1}
        out = apply_template("nope.com", original)
        assert out == original
        assert out is not original  # 是新 dict


# ============================================================
# Register / 事件总线
# ============================================================

class TestRegister:
    def test_attach_idempotent(self, isolated_crypto):
        from core.crypto_replay import register as reg_mod
        reg_mod.detach()
        before = bus.stats().get(Events.CRYPTO_CAPTURED, 0)
        reg_mod.attach()
        reg_mod.attach()
        after = bus.stats().get(Events.CRYPTO_CAPTURED, 0)
        assert after == before + 1
        reg_mod.detach()

    def test_event_triggers_learner(self, isolated_crypto):
        from core.crypto_replay import register as reg_mod
        reg_mod.detach()
        reg_mod.attach()
        try:
            bus.emit(Events.CRYPTO_CAPTURED, {
                "host": "evt.com",
                "field": "data",
                "algorithm": "sm4",
                "key": "k1",
            })
            tpl = load_template("evt.com")
            assert tpl is not None
            assert tpl.has_field("data")
        finally:
            reg_mod.detach()
