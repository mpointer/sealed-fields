import base64
import hashlib
import hmac as hmac_mod
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sealed_fields import (
    KeyNotConfiguredError,
    SealedFieldsError,
    SystemicUnsealError,
    UnknownKeyVersionError,
    create_sealed_fields,
    generate_key,
    hash_token,
    is_sealed,
    sealed_fields_from_env,
)

KEY_A = generate_key()
KEY_B = generate_key()
VECTORS = json.loads((Path(__file__).parents[2] / "test" / "vectors.json").read_text())


def make_sf(**overrides):
    cfg = {"namespaces": {"PII": {"key": KEY_A}}}
    cfg.update(overrides)
    return create_sealed_fields(**cfg)


class TestSealUnseal:
    def test_round_trips_utf8(self):
        sf = make_sf()
        for text in ["hello", "héllo wörld — 你好 🚀", "a" * 10_000]:
            assert sf.unseal(sf.seal(text)) == text

    def test_canonical_format_and_is_sealed(self):
        token = make_sf().seal("secret")
        assert token.startswith("v1:")
        assert is_sealed(token)

    def test_random_nonce(self):
        sf = make_sf()
        assert sf.seal("same") != sf.seal("same")

    def test_plaintext_passthrough(self):
        sf = make_sf()
        assert sf.unseal("just some text") == "just some text"
        assert sf.unseal("colon:separated:text") == "colon:separated:text"

    def test_sealed_empty_string_round_trips_and_is_recognized(self):
        sf = make_sf()
        token = sf.seal("")
        assert is_sealed(token)  # nonce+tag, zero ciphertext bytes — valid GCM
        assert sf.unseal(token) == ""

    def test_aad_binding_rejects_version_reattribution(self):
        sf = create_sealed_fields(
            namespaces={"PII": {"key": KEY_A, "version": "v2", "retired": {"v1": KEY_A}}}
        )
        token = sf.seal("secret")
        forged = "v1:" + token.split(":", 1)[1]
        with pytest.raises(Exception):
            sf.unseal(forged)

    def test_tampered_ciphertext_raises(self):
        sf = make_sf()
        token = sf.seal("secret")
        corrupted = token[:-4] + "AAAA"
        with pytest.raises(Exception):
            sf.unseal(corrupted)

    def test_key_encodings_equivalent(self):
        raw = base64.urlsafe_b64decode(KEY_A + "=" * (-len(KEY_A) % 4))
        for key in [raw.hex(), base64.b64encode(raw).decode(), KEY_A, raw]:
            token = create_sealed_fields(namespaces={"PII": {"key": key}}).seal("x")
            assert make_sf().unseal(token) == "x"

    def test_malformed_key_rejected(self):
        with pytest.raises(KeyNotConfiguredError):
            create_sealed_fields(namespaces={"PII": {"key": "tooshort"}})
        for lenient in [
            "A" * 20 + " " + "A" * 23,
            "A" * 21 + "!" + "A" * 22,
        ]:
            with pytest.raises(KeyNotConfiguredError):
                create_sealed_fields(namespaces={"PII": {"key": lenient}})

    def test_padded_standard_base64_key_accepted(self):
        padded = base64.b64encode(base64.urlsafe_b64decode(KEY_A + "=")).decode()
        assert len(padded) == 44
        a = make_sf()
        b = create_sealed_fields(namespaces={"PII": {"key": padded}})
        assert b.unseal(a.seal("x")) == "x"


class TestRotation:
    def test_retired_keys_read_active_key_writes(self):
        old_token = make_sf().seal("legacy row")
        rotated = create_sealed_fields(
            namespaces={"PII": {"key": KEY_B, "version": "v2", "retired": {"v1": KEY_A}}}
        )
        assert rotated.unseal(old_token) == "legacy row"
        assert rotated.seal("new row").startswith("v2:")

    def test_unknown_version_raises_by_default(self):
        token = create_sealed_fields(namespaces={"PII": {"key": KEY_A, "version": "v9"}}).seal("x")
        with pytest.raises(UnknownKeyVersionError):
            make_sf().unseal(token)

    def test_unknown_version_passthrough_when_configured(self):
        token = create_sealed_fields(namespaces={"PII": {"key": KEY_A, "version": "v9"}}).seal("x")
        migrating = make_sf(on_unknown_version="passthrough")
        assert migrating.unseal(token) == token

    def test_retired_version_collision_rejected(self):
        with pytest.raises(SealedFieldsError):
            create_sealed_fields(
                namespaces={"PII": {"key": KEY_A, "version": "v1", "retired": {"v1": KEY_B}}}
            )


class TestNamespaces:
    def test_cryptographic_separation(self):
        sf = create_sealed_fields(namespaces={"PII": {"key": KEY_A}, "TOTP": {"key": KEY_B}})
        token = sf.seal("secret", "PII")
        assert sf.unseal(token, "PII") == "secret"
        with pytest.raises(Exception):
            sf.unseal(token, "TOTP")

    def test_explicit_namespace_required_without_default(self):
        sf = create_sealed_fields(namespaces={"PII": {"key": KEY_A}, "TOTP": {"key": KEY_B}})
        with pytest.raises(SealedFieldsError):
            sf.seal("x")


class TestModes:
    def test_strict_raises_without_key(self):
        sf = create_sealed_fields(namespaces={"PII": {}})
        with pytest.raises(KeyNotConfiguredError):
            sf.seal("x")
        assert not sf.is_configured()

    def test_dormant_passthrough_warns_once(self):
        warnings = []
        sf = create_sealed_fields(
            namespaces={"PII": {}}, mode="dormant", logger=warnings.append
        )
        assert sf.seal("x") == "x"
        assert sf.seal("y") == "y"
        assert len(warnings) == 1
        assert "PLAINTEXT" in warnings[0]

    def test_dormant_refuses_token_shaped_input(self):
        # Regression: stored as-is, these failed auth once a key was
        # provisioned and enough of them on one page tripped SystemicUnsealError.
        sf = create_sealed_fields(
            namespaces={"PII": {}}, mode="dormant", logger=lambda _m: None
        )
        with pytest.raises(SealedFieldsError):
            sf.seal(make_sf().seal("x"))
        with pytest.raises(SealedFieldsError):
            sf.seal("v1:AAAA")
        with pytest.raises(SealedFieldsError):
            sf.seal_row({"name": "v9:abc"}, ["name"])
        assert sf.seal("v1 not a token") == "v1 not a token"

    def test_dormant_warns_once_per_namespace(self):
        warnings = []
        sf = create_sealed_fields(
            namespaces={"A": {}, "B": {}}, mode="dormant", logger=warnings.append
        )
        sf.seal("x", "A")
        sf.seal("y", "B")
        sf.seal("z", "B")
        assert len(warnings) == 2
        assert '"B"' in warnings[1]


class TestRows:
    FIELDS = ["name", "notes"]

    def test_seal_row_skips_and_copies(self):
        sf = make_sf()
        row = {"id": 7, "name": "Ada", "notes": "", "extra": "untouched"}
        out = sf.seal_row(row, self.FIELDS)
        assert is_sealed(out["name"])
        assert out["notes"] == ""
        assert out["extra"] == "untouched"
        assert row["name"] == "Ada"

    def test_token_shaped_input_is_sealed_not_trusted(self):
        # Regression: seal_row used to skip values that looked sealed, storing
        # attacker-chosen "tokens" unencrypted and tripping SystemicUnsealError.
        sf = make_sf()
        evil = "v1:" + base64.urlsafe_b64encode(os.urandom(30)).decode().rstrip("=")
        assert is_sealed(evil)
        out = sf.seal_row({"name": evil}, self.FIELDS)
        assert out["name"] != evil
        assert sf.unseal_row(out, self.FIELDS)["name"] == evil
        rows = [
            sf.seal_row({"name": "v1:" + base64.urlsafe_b64encode(os.urandom(30)).decode()}, self.FIELDS)
            for _ in range(5)
        ]
        sf.unseal_rows(rows, self.FIELDS)  # must not raise

    def test_mixed_plaintext_rows_mid_migration(self):
        sf = make_sf()
        rows = sf.unseal_rows(
            [sf.seal_row({"name": "Ada"}, self.FIELDS), {"name": "Grace"}], self.FIELDS
        )
        assert [r["name"] for r in rows] == ["Ada", "Grace"]

    def test_isolated_failure_nulls_field(self):
        writer = make_sf()
        reader = create_sealed_fields(
            namespaces={"PII": {"key": KEY_B}}, logger=lambda m: None
        )
        out = reader.unseal_row(writer.seal_row({"name": "Ada"}, self.FIELDS), self.FIELDS)
        assert out["name"] is None

    def test_systemic_failure_raises(self):
        writer = make_sf()
        reader = create_sealed_fields(
            namespaces={"PII": {"key": KEY_B}}, logger=lambda m: None
        )
        rows = [writer.seal_row({"name": f"p{i}"}, self.FIELDS) for i in range(5)]
        with pytest.raises(SystemicUnsealError):
            reader.unseal_rows(rows, self.FIELDS)

    def test_plaintext_does_not_dilute_failure_rate(self):
        writer = make_sf()
        reader = create_sealed_fields(
            namespaces={"PII": {"key": KEY_B}}, logger=lambda m: None
        )
        rows = [writer.seal_row({"name": f"p{i}"}, self.FIELDS) for i in range(5)]
        rows += [{"name": f"plain{i}"} for i in range(20)]
        with pytest.raises(SystemicUnsealError):
            reader.unseal_rows(rows, self.FIELDS)

    def test_json_fields_true_inverses(self):
        sf = make_sf()
        spec = {"fields": ["name"], "json_fields": ["snapshot"]}
        obj_row = sf.unseal_row(sf.seal_row({"name": "Ada", "snapshot": {"a": 1}}, spec), spec)
        assert obj_row["snapshot"] == {"a": 1}
        # The regression this pins: string values must survive as strings.
        str_row = sf.unseal_row(sf.seal_row({"name": "Ada", "snapshot": "free text"}, spec), spec)
        assert str_row["snapshot"] == "free text"


class TestLegacy:
    @staticmethod
    def _iv_ct_tag(plaintext: str, key: bytes) -> str:
        nonce = os.urandom(12)
        ct_tag = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        ct, tag = ct_tag[:-16], ct_tag[-16:]
        b64 = lambda b: base64.b64encode(b).decode()
        return f"{b64(nonce)}:{b64(ct)}:{b64(tag)}"

    @staticmethod
    def _v1_iv_tag_ct(plaintext: str, key: bytes) -> str:
        nonce = os.urandom(12)
        ct_tag = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        ct, tag = ct_tag[:-16], ct_tag[-16:]
        b64 = lambda b: base64.b64encode(b).decode()
        return f"v1:{b64(nonce)}:{b64(tag)}:{b64(ct)}"

    def _key_bytes(self, key_str):
        return base64.urlsafe_b64decode(key_str + "=" * (-len(key_str) % 4))

    def test_dormant_refuses_legacy_shaped_input(self):
        sf = create_sealed_fields(
            namespaces={"PII": {}}, mode="dormant", legacy=["iv-ct-tag"], logger=lambda _m: None
        )
        with pytest.raises(SealedFieldsError):
            sf.seal(self._iv_ct_tag("x", self._key_bytes(KEY_A)))
        assert sf.seal("plain") == "plain"

    def test_iv_ct_tag_decodes(self):
        sf = make_sf(legacy=["iv-ct-tag"])
        assert sf.unseal(self._iv_ct_tag("legacy value", self._key_bytes(KEY_A))) == "legacy value"

    def test_v1_iv_tag_ct_decodes_despite_prefix(self):
        sf = make_sf(legacy=["v1-iv-tag-ct"])
        token = self._v1_iv_tag_ct("older value", self._key_bytes(KEY_A))
        assert not is_sealed(token)
        assert sf.unseal(token) == "older value"

    def test_unauthenticated_legacy_raises(self):
        sf = make_sf(legacy=["iv-ct-tag"])
        foreign = self._iv_ct_tag("data", self._key_bytes(KEY_B))
        with pytest.raises(Exception):
            sf.unseal(foreign)

    def test_disabled_formats_pass_through(self):
        sf = make_sf()
        token = self._iv_ct_tag("x", self._key_bytes(KEY_A))
        assert sf.unseal(token) == token

    def test_row_helpers_decode_legacy_tokens(self):
        sf = make_sf(legacy=["iv-ct-tag", "v1-iv-tag-ct"], logger=lambda m: None)
        k = self._key_bytes(KEY_A)
        row = {"a": self._iv_ct_tag("one", k), "b": self._v1_iv_tag_ct("two", k)}
        assert sf.unseal_row(row, ["a", "b"]) == {"a": "one", "b": "two"}

    def test_row_helper_legacy_failures_count_as_systemic(self):
        sf = make_sf(legacy=["iv-ct-tag"], logger=lambda m: None)
        rows = [{"a": self._iv_ct_tag(f"p{i}", self._key_bytes(KEY_B))} for i in range(5)]
        assert sf.unseal_row(rows[0], ["a"])["a"] is None
        with pytest.raises(SystemicUnsealError):
            sf.unseal_rows(rows, ["a"])

    def test_ordinary_colon_text_not_mistaken(self):
        sf = make_sf(legacy=["iv-ct-tag", "v1-iv-tag-ct"])
        for s in ["a:b:c", "12:30:45", "v1:looks:like:legacy"]:
            assert sf.unseal(s) == s


class TestBlindIndexAndUtils:
    def test_blind_index_deterministic_and_normalized(self):
        sf = make_sf(blind_index_key=KEY_A)
        assert sf.blind_index("alice@example.com") == sf.blind_index("  Alice@Example.COM ")
        assert sf.blind_index("Alice", normalize=False) != sf.blind_index("alice", normalize=False)

    def test_blind_index_reference(self):
        sf = make_sf(blind_index_key=KEY_A)
        raw = base64.urlsafe_b64decode(KEY_A + "=" * (-len(KEY_A) % 4))
        expected = hmac_mod.new(raw, b"alice@example.com", hashlib.sha256).hexdigest()
        assert sf.blind_index("alice@example.com") == expected

    def test_blind_index_custom_normalizer(self):
        sf = make_sf(blind_index_key=KEY_A)
        casefold = lambda s: s.strip().casefold()
        # "ß".casefold() is "ss" while lower() leaves it alone, so the two
        # policies produce different tokens for the same input.
        assert sf.blind_index(" Straße ", normalize=casefold) == sf.blind_index(
            "strasse", normalize=False
        )
        assert sf.blind_index("Straße", normalize=casefold) != sf.blind_index("Straße")

    def test_blind_index_requires_key(self):
        with pytest.raises(KeyNotConfiguredError):
            make_sf().blind_index("x")

    def test_generate_key_and_hash_token(self):
        key = generate_key()
        assert len(base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))) == 32
        assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()
        with pytest.raises(SealedFieldsError):
            hash_token("")

    def test_is_sealed_rejects_lookalikes(self):
        assert not is_sealed("v1:not-base64!!!")
        assert not is_sealed("v1:aGk")
        assert not is_sealed("plain text")
        assert not is_sealed(None)
        assert not is_sealed(42)


class TestFromEnv:
    def test_builds_from_env_mapping(self):
        env = {
            "SEALED_KEY_PII": KEY_B,
            "SEALED_KEY_PII_VERSION": "v2",
            "SEALED_KEY_PII_RETIRED": f"v1:{KEY_A}",
            "SEALED_BLIND_INDEX_KEY": KEY_A,
        }
        sf = sealed_fields_from_env(["PII"], env=env)
        token = sf.seal("x")
        assert token.startswith("v2:")
        assert sf.unseal(token) == "x"
        old = sealed_fields_from_env(["PII"], env={"SEALED_KEY_PII": KEY_A})
        assert sf.unseal(old.seal("old")) == "old"

    def test_malformed_retired_entry_rejected(self):
        with pytest.raises(SealedFieldsError):
            sealed_fields_from_env(
                ["PII"], env={"SEALED_KEY_PII": KEY_A, "SEALED_KEY_PII_RETIRED": "nocolon"}
            )


class TestCrossLanguage:
    def test_decodes_every_shared_vector(self):
        sf = create_sealed_fields(
            namespaces={"PII": {"key": VECTORS["key"]}},
            blind_index_key=VECTORS["blindIndex"]["key"],
        )
        for name, token in VECTORS["tokens"].items():
            assert sf.unseal(token) == VECTORS["plaintext"], name
        assert sf.blind_index(VECTORS["blindIndex"]["value"]) == VECTORS["blindIndex"]["hex"]
        ctx = VECTORS["blindIndexContext"]
        assert sf.blind_index(ctx["value"], context=ctx["context"]) == ctx["hex"]
        trim = VECTORS["blindIndexTrim"]
        assert sf.blind_index(trim["value"]) == trim["hex"]
        bound = VECTORS["contextTokens"]
        for name, token in bound["tokens"].items():
            assert sf.unseal(token, context=bound["context"]) == VECTORS["plaintext"], name
            with pytest.raises(Exception):
                sf.unseal(token)


def test_short_canonical_token_rejected():
    sf = make_sf()
    for t in ["v1:AAAAAA", "v1:AAAAAAAAAAA", "v1:" + "A" * 36]:
        with pytest.raises(SealedFieldsError, match="too short"):
            sf.unseal(t)


def test_blind_index_context_separates_columns():
    sf = make_sf(blind_index_key=KEY_A)
    plain = sf.blind_index("alice@example.com")
    users = sf.blind_index("alice@example.com", context="users.email")
    contacts = sf.blind_index("alice@example.com", context="contacts.email")
    assert len({plain, users, contacts}) == 3
    assert sf.blind_index("alice@example.com", context="") == plain
    with pytest.raises(SealedFieldsError):
        sf.blind_index("x", context="a\0b")


def test_trailing_newline_is_not_a_token():
    token = make_sf().seal("x")
    assert not is_sealed(token + "\n")
    assert make_sf().unseal(token + "\n") == token + "\n"


def test_empty_namespace_is_not_the_default():
    with pytest.raises(SealedFieldsError, match="unknown namespace"):
        make_sf().seal("x", "")


class TestPlaintextReject:
    def make(self):
        return make_sf(plaintext="reject", logger=lambda m: None)

    def test_unseal_throws_on_plaintext_and_decodes_tokens(self):
        sf = self.make()
        with pytest.raises(SealedFieldsError, match="not a sealed token"):
            sf.unseal("plain")
        assert sf.unseal(sf.seal("x")) == "x"

    def test_row_helpers_null_and_count_plaintext(self):
        sf = self.make()
        assert sf.unseal_row({"a": "plain", "b": sf.seal("ok")}, ["a", "b"]) == {"a": None, "b": "ok"}
        with pytest.raises(SystemicUnsealError):
            sf.unseal_rows([{"a": "plain"}] * 5, ["a"])

    def test_rejects_invalid_values_and_dormant_combination(self):
        with pytest.raises(SealedFieldsError, match="plaintext must be"):
            make_sf(plaintext="deny")
        with pytest.raises(SealedFieldsError, match="dormant"):
            create_sealed_fields(namespaces={"PII": {}}, mode="dormant", plaintext="reject")


class TestContextBinding:
    def collect(self, **kw):
        warnings: list[str] = []
        return make_sf(logger=warnings.append, **kw), warnings

    def test_round_trip_and_string_equals_one_part(self):
        sf = make_sf()
        assert sf.unseal(sf.seal("x", context=["users", "email"]), context=["users", "email"]) == "x"
        assert sf.unseal(sf.seal("x", context="users.email"), context=["users.email"]) == "x"

    def test_moved_or_downgraded_token_fails(self):
        sf = make_sf()
        token = sf.seal("x", context=["users", "email"])
        for bad in (["users", "notes"], None, ["users.email"]):
            with pytest.raises(Exception):
                sf.unseal(token, context=bad)
        with pytest.raises(Exception):
            sf.unseal(sf.seal("x", context=["a.b", "c"]), context=["a", "b.c"])

    def test_unbound_with_context_fails_without_fallback(self):
        sf = make_sf()
        with pytest.raises(Exception):
            sf.unseal(sf.seal("x"), context="users.email")

    def test_empty_context_and_bad_parts(self):
        sf = make_sf()
        plain = sf.seal("x")
        assert sf.unseal(plain, context="") == "x"
        assert sf.unseal(plain, context=[]) == "x"
        with pytest.raises(SealedFieldsError):
            sf.seal("x", context=["users", ""])
        with pytest.raises(SealedFieldsError):
            sf.seal("x", context="a\0b")

    def test_rejects_non_boolean_fallback(self):
        with pytest.raises(SealedFieldsError, match="boolean"):
            make_sf(context_fallback="yes")

    def test_fallback_counts_and_warns_once(self):
        sf, warnings = self.collect(context_fallback=True)
        unbound = sf.seal("x")
        assert sf.unseal(unbound, context="users.email") == "x"
        assert sf.unseal(unbound, context="users.email") == "x"
        assert sf.unseal(sf.seal("y", context="users.email"), context="users.email") == "y"
        assert sf.unseal(unbound) == "x"
        assert sf.stats() == {"unbound_reads": 2}
        assert len(warnings) == 1

    def test_fallback_does_not_let_a_bound_token_move(self):
        sf = make_sf(context_fallback=True)
        token = sf.seal("x", context="users.email")
        with pytest.raises(Exception):
            sf.unseal(token, context="users.notes")
        assert sf.stats()["unbound_reads"] == 0

    def test_row_helpers(self):
        spec = {"fields": ["email"], "context": lambda field, row: ["users", field, str(row["id"])]}
        sf = make_sf(logger=lambda m: None)
        a = sf.seal_row({"id": 1, "email": "a@x"}, spec)
        b = sf.seal_row({"id": 2, "email": "b@x"}, spec)
        assert sf.unseal_row(a, spec) == {"id": 1, "email": "a@x"}
        assert sf.unseal_row({**b, "email": a["email"]}, spec) == {"id": 2, "email": None}
        migrating = make_sf(context_fallback=True, logger=lambda m: None)
        old = [{"id": i, "email": migrating.seal("e")} for i in range(5)]
        migrating.unseal_rows(old, spec)
        assert migrating.stats()["unbound_reads"] == 5

    def test_legacy_needs_fallback_with_context(self):
        key = base64.urlsafe_b64decode(KEY_A + "=" * (-len(KEY_A) % 4))
        token = TestLegacy._iv_ct_tag("old", key)
        strict = make_sf(legacy=["iv-ct-tag"])
        with pytest.raises(SealedFieldsError, match="legacy"):
            strict.unseal(token, context="t.c")
        assert strict.unseal(token) == "old"
        migrating = make_sf(legacy=["iv-ct-tag"], context_fallback=True, logger=lambda m: None)
        assert migrating.unseal(token, context="t.c") == "old"
        assert migrating.stats()["unbound_reads"] == 1
