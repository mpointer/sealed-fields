"""sealed-fields: field-level encryption for PII at rest.

Python twin of the sealed-fields npm package. Wire format, semantics, and
API shape are kept deliberately identical; the two implementations share
cross-language test vectors and data sealed by either unseals in the other.

Canonical wire format:

    v<N>:<base64url(nonce | ciphertext | tag)>

AES-256-GCM, random 12-byte nonce per value, 16-byte tag, key version label
bound as additional authenticated data (AAD). Tokens are emitted as unpadded
base64url; padded and standard-alphabet blobs are accepted on read.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as hmac_mod
import json
import re
import secrets
from typing import Any, Callable, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "SealedFields",
    "create_sealed_fields",
    "sealed_fields_from_env",
    "is_sealed",
    "generate_key",
    "hash_token",
    "SealedFieldsError",
    "KeyNotConfiguredError",
    "UnknownKeyVersionError",
    "SystemicUnsealError",
]

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16

_TOKEN_RE = re.compile(r"^(v\d+):([A-Za-z0-9_-]+={0,2})$")
_VERSION_RE = re.compile(r"^v\d+$")


class SealedFieldsError(Exception):
    """Base class for every error this library raises deliberately."""


class KeyNotConfiguredError(SealedFieldsError):
    """An operation needed a key that is not configured (strict mode)."""


class UnknownKeyVersionError(SealedFieldsError):
    """A token names a key version that is not in the namespace's keyring."""

    def __init__(self, version: str, namespace: str) -> None:
        super().__init__(
            f'unseal: token names key version "{version}" which is not in the '
            f'"{namespace}" keyring. Add it to retired keys, or set '
            f'on_unknown_version="passthrough" during an active migration.'
        )
        self.version = version


class SystemicUnsealError(SealedFieldsError):
    """More than half of attempted unseals across a batch failed."""

    def __init__(self, failures: int, attempts: int) -> None:
        super().__init__(
            f"systemic unseal failure: {failures}/{attempts} attempted unseals "
            f"failed. This usually means the wrong key is configured for this namespace."
        )
        self.failures = failures
        self.attempts = attempts


def _parse_key(raw: str | bytes, label: str) -> bytes:
    """Accept a 64-char hex, base64, base64url, or raw 32-byte key."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) != KEY_BYTES:
            raise KeyNotConfiguredError(f"{label} must be {KEY_BYTES} bytes (got {len(raw)}).")
        return bytes(raw)
    s = raw.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return bytes.fromhex(s)
    # 32 bytes encode to exactly 43 base64 chars plus optional "=". Check the
    # shape strictly so typos and arbitrary strings are never accepted as keys.
    if re.fullmatch(r"[A-Za-z0-9+/_-]{43}=?", s):
        normalized = s.rstrip("=").replace("-", "+").replace("_", "/")
        return base64.b64decode(normalized + "=")
    raise KeyNotConfiguredError(
        f"{label} must be a {KEY_BYTES}-byte key as 64-char hex or 43-char "
        f"base64/base64url. Keys must be random; a passphrase is not a key. "
        f"Generate one with generate_key()."
    )


def _decode_blob(blob: str) -> bytes:
    normalized = blob.replace("-", "+").replace("_", "/").rstrip("=")
    return base64.b64decode(normalized + "=" * (-len(normalized) % 4))


def is_sealed(value: Any) -> bool:
    """True when a value structurally matches the canonical sealed format."""
    if not isinstance(value, str):
        return False
    m = _TOKEN_RE.fullmatch(value)
    if not m:
        return False
    try:
        raw = _decode_blob(m.group(2))
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= NONCE_BYTES + TAG_BYTES  # empty plaintext is valid GCM


def _encode_context(context: str | Sequence[str] | None) -> str | None:
    """Parts joined with NUL; "" and [] mean no context. Matches the npm package."""
    if context is None:
        return None
    parts = [context] if isinstance(context, str) else list(context)
    if not parts or parts == [""]:
        return None
    for p in parts:
        if not isinstance(p, str) or p == "" or "\0" in p:
            raise SealedFieldsError("context parts must be non-empty strings without NUL.")
    return "\0".join(parts)


def _build_aad(version: str, context: str | None) -> bytes:
    """GCM AAD: the version label, plus ``0x00 || context`` when bound."""
    v = version.encode("ascii")
    return v if context is None else v + b"\0" + context.encode("utf-8")


# String.prototype.trim()'s set. str.strip() differs (it also strips
# \x1c-\x1f and \x85, and keeps \ufeff), which would split blind-index tokens.
_JS_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def generate_key() -> str:
    """Fresh 32-byte key, base64url without padding. Suitable for any key slot."""
    return base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii").rstrip("=")


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a one-time token for safe storage."""
    if not isinstance(token, str) or not token:
        raise SealedFieldsError("hash_token requires a non-empty string.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _Keyring:
    def __init__(self, active_version: str, keys: dict[str, bytes]) -> None:
        self.active_version = active_version
        self.keys = keys


def _build_keyring(cfg: Mapping[str, Any], namespace: str) -> _Keyring | None:
    raw_key = cfg.get("key")
    if raw_key is None or (isinstance(raw_key, str) and raw_key.strip() == ""):
        return None
    active_version = (cfg.get("version") or "v1").strip() or "v1"
    if not _VERSION_RE.fullmatch(active_version):
        raise SealedFieldsError(
            f'namespace "{namespace}": version must look like "v1", "v2", ... (got "{active_version}").'
        )
    keys = {active_version: _parse_key(raw_key, f'namespace "{namespace}" key')}
    for ver, raw in (cfg.get("retired") or {}).items():
        if not _VERSION_RE.fullmatch(ver):
            raise SealedFieldsError(
                f'namespace "{namespace}": retired key version "{ver}" must look like "v1", "v2", ...'
            )
        if ver == active_version:
            raise SealedFieldsError(
                f'namespace "{namespace}": retired key version "{ver}" collides with the active version.'
            )
        keys[ver] = _parse_key(raw, f'namespace "{namespace}" retired key {ver}')
    return _Keyring(active_version, keys)


# Legacy wire formats (read-only migration aids), matching the npm package:
#   "iv-ct-tag"    -> <b64 iv>:<b64 ciphertext>:<b64 tag>       (no AAD)
#   "v1-iv-tag-ct" -> v1:<b64 iv>:<b64 tag>:<b64 ciphertext>    (no AAD)
_LEGACY_FORMATS = ("iv-ct-tag", "v1-iv-tag-ct")


def _match_legacy(token: str, fmt: str) -> tuple[bytes, bytes, bytes] | None:
    parts = token.split(":")
    try:
        if fmt == "iv-ct-tag":
            if len(parts) != 3:
                return None
            iv, ct, tag = (base64.b64decode(p, validate=False) for p in parts)
        elif fmt == "v1-iv-tag-ct":
            if len(parts) != 4 or parts[0] != "v1":
                return None
            iv, tag, ct = (base64.b64decode(p, validate=False) for p in parts[1:])
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    if len(iv) != NONCE_BYTES or len(tag) != TAG_BYTES or len(ct) == 0:
        return None
    return iv, ct, tag


class SealedFields:
    def __init__(
        self,
        namespaces: Mapping[str, Mapping[str, Any]],
        *,
        default_namespace: str | None = None,
        blind_index_key: str | bytes | None = None,
        mode: str = "strict",
        legacy: Sequence[str] = (),
        on_unknown_version: str = "throw",
        plaintext: str = "passthrough",
        context_fallback: bool = False,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        if not namespaces:
            raise SealedFieldsError("at least one namespace must be configured.")
        self._rings: dict[str, _Keyring | None] = {
            name: _build_keyring(cfg, name) for name, cfg in namespaces.items()
        }
        if default_namespace is not None and default_namespace not in self._rings:
            raise SealedFieldsError(
                f'default_namespace "{default_namespace}" is not a configured namespace.'
            )
        self._default_ns = default_namespace or (
            next(iter(self._rings)) if len(self._rings) == 1 else None
        )
        if blind_index_key is not None and not (
            isinstance(blind_index_key, str) and blind_index_key.strip() == ""
        ):
            self._index_key: bytes | None = _parse_key(blind_index_key, "blind_index_key")
        else:
            self._index_key = None
        if mode not in ("strict", "dormant"):
            raise SealedFieldsError('mode must be "strict" or "dormant".')
        self._mode = mode
        for fmt in legacy:
            if fmt not in _LEGACY_FORMATS:
                raise SealedFieldsError(f'unknown legacy format "{fmt}".')
        self._legacy = tuple(legacy)
        if on_unknown_version not in ("throw", "passthrough"):
            raise SealedFieldsError('on_unknown_version must be "throw" or "passthrough".')
        self._on_unknown_version = on_unknown_version
        if plaintext not in ("passthrough", "reject"):
            raise SealedFieldsError('plaintext must be "passthrough" or "reject".')
        if plaintext == "reject" and mode == "dormant":
            raise SealedFieldsError(
                'plaintext "reject" cannot be combined with mode "dormant", which writes plaintext.'
            )
        self._plaintext = plaintext
        if not isinstance(context_fallback, bool):
            raise SealedFieldsError("context_fallback must be a boolean.")
        self._context_fallback = context_fallback
        self._warned_fallback: set[str] = set()
        self._unbound_reads = 0
        self._warn = logger or (lambda m: print(m))
        self._warned_dormant: set[str] = set()

    # -- internals ---------------------------------------------------------

    def _resolve_ns(self, namespace: str | None) -> str:
        ns = namespace if namespace is not None else self._default_ns
        if ns is None:
            raise SealedFieldsError(
                "no namespace given and no default_namespace configured (multiple namespaces exist)."
            )
        if ns not in self._rings:
            raise SealedFieldsError(f'unknown namespace "{ns}".')
        return ns

    def _warn_dormant_once(self, ns: str) -> None:
        if ns in self._warned_dormant:
            return
        self._warned_dormant.add(ns)
        self._warn(
            f'[sealed-fields] SECURITY: namespace "{ns}" has no key configured — sealed '
            f'columns are being written in PLAINTEXT (mode: "dormant"). '
            f"Provision a key before production traffic."
        )

    def _try_legacy(self, token: str, ring: _Keyring) -> str | None:
        matched = False
        last_error: Exception | None = None
        for fmt in self._legacy:
            parts = _match_legacy(token, fmt)
            if parts is None:
                continue
            matched = True
            iv, ct, tag = parts
            ordered = [ring.keys[ring.active_version]] + [
                k for v, k in ring.keys.items() if v != ring.active_version
            ]
            for key in ordered:
                try:
                    return AESGCM(key).decrypt(iv, ct + tag, None).decode("utf-8")
                except Exception as err:  # InvalidTag
                    last_error = err
        if matched:
            assert last_error is not None
            raise last_error
        return None

    # -- public API --------------------------------------------------------

    def is_configured(self, namespace: str | None = None) -> bool:
        return self._rings[self._resolve_ns(namespace)] is not None

    def seal(
        self,
        plaintext: str,
        namespace: str | None = None,
        *,
        context: str | Sequence[str] | None = None,
    ) -> str:
        """Encrypt under the namespace's active key, bound to ``context`` if
        given (see ``unseal``)."""
        aad_context = _encode_context(context)
        ns = self._resolve_ns(namespace)
        ring = self._rings[ns]
        if ring is None:
            if self._mode == "strict":
                raise KeyNotConfiguredError(
                    f'namespace "{ns}" has no key configured; cannot seal (mode: "strict").'
                )
            # Stored as-is, a token-shaped value would fail auth once a key is
            # on and count toward SystemicUnsealError. Refuse it instead.
            if _TOKEN_RE.fullmatch(plaintext) or any(
                _match_legacy(plaintext, f) for f in self._legacy
            ):
                raise SealedFieldsError(
                    'seal: refusing to store a token-shaped value as plaintext (mode: "dormant").'
                )
            self._warn_dormant_once(ns)
            return plaintext
        nonce = secrets.token_bytes(NONCE_BYTES)
        aes = AESGCM(ring.keys[ring.active_version])
        ct = aes.encrypt(
            nonce, plaintext.encode("utf-8"), _build_aad(ring.active_version, aad_context)
        )
        blob = base64.urlsafe_b64encode(nonce + ct).decode("ascii").rstrip("=")
        return f"{ring.active_version}:{blob}"

    def unseal(
        self,
        value: str,
        namespace: str | None = None,
        *,
        context: str | Sequence[str] | None = None,
    ) -> str:
        """Decrypt a token. ``context`` must match the one it was sealed with:
        a string or parts such as ``["users", "email"]``, joined with NUL.
        With ``context_fallback=True`` a token sealed without a context still
        reads, and is counted in ``stats()["unbound_reads"]``."""
        aad_context = _encode_context(context)
        ns = self._resolve_ns(namespace)
        ring = self._rings[ns]
        m = _TOKEN_RE.fullmatch(value)
        if m:
            if ring is None:
                if self._mode == "strict":
                    raise KeyNotConfiguredError(
                        f'namespace "{ns}" has no key configured; cannot unseal a sealed value.'
                    )
                self._warn_dormant_once(ns)
                return value
            version = m.group(1)
            key = ring.keys.get(version)
            if key is None:
                if self._on_unknown_version == "passthrough":
                    return value
                raise UnknownKeyVersionError(version, ns)
            raw = _decode_blob(m.group(2))
            if len(raw) < NONCE_BYTES + TAG_BYTES:
                raise SealedFieldsError("unseal: token is too short to be a sealed value.")
            nonce, ct = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
            aes = AESGCM(key)
            try:
                return aes.decrypt(nonce, ct, _build_aad(version, aad_context)).decode("utf-8")
            except InvalidTag as err:
                # Only an auth failure can mean "sealed before binding".
                if aad_context is None or not self._context_fallback:
                    raise
                try:
                    out = aes.decrypt(nonce, ct, _build_aad(version, None)).decode("utf-8")
                except InvalidTag:
                    raise err from None
                self._note_unbound_read(ns)
                return out
        if (
            ring is not None
            and self._legacy
            and any(_match_legacy(value, f) for f in self._legacy)
        ):
            # Legacy formats have no AAD, so they cannot carry a binding.
            if aad_context is not None and not self._context_fallback:
                raise SealedFieldsError(
                    "unseal: legacy token cannot be bound to a context "
                    "(enable context_fallback to migrate)."
                )
            decoded = self._try_legacy(value, ring)
            if decoded is not None:
                if aad_context is not None:
                    self._note_unbound_read(ns)
                return decoded
        if self._plaintext == "reject":
            raise SealedFieldsError('unseal: value is not a sealed token (plaintext: "reject").')
        return value  # plaintext passthrough

    def _note_unbound_read(self, ns: str) -> None:
        self._unbound_reads += 1
        if ns in self._warned_fallback:
            return
        self._warned_fallback.add(ns)
        self._warn(
            f'[sealed-fields] namespace "{ns}": read a token with no context binding via '
            f'context_fallback. Re-encrypt to bind it; stats()["unbound_reads"] counts these reads.'
        )

    def stats(self) -> dict[str, int]:
        """Counters since this instance was created. ``unbound_reads`` is the
        number of reads that needed context_fallback; it should stay at zero
        before fallback is turned off. Per instance and per process."""
        return {"unbound_reads": self._unbound_reads}

    def maybe_seal(
        self,
        value: str | None,
        namespace: str | None = None,
        *,
        context: str | Sequence[str] | None = None,
    ) -> str | None:
        if value is None or value == "":
            return None
        return self.seal(value, namespace, context=context)

    def maybe_unseal(
        self,
        value: str | None,
        namespace: str | None = None,
        *,
        context: str | Sequence[str] | None = None,
    ) -> str | None:
        if value is None or value == "":
            return None
        return self.unseal(value, namespace, context=context)

    def blind_index(
        self,
        value: str,
        *,
        normalize: bool | Callable[[str], str] = True,
        context: str | None = None,
    ) -> str:
        """Deterministic HMAC-SHA256 lookup token for an equality query on an
        otherwise-sealed column. ONLY for high-entropy values (email, username,
        phone). Never index a low-entropy field: a deterministic MAC over a
        small domain is trivially dictionary-attacked.

        Normalization (default on) is trim + lowercase, matching the npm
        package's String.prototype.toLowerCase for cross-language equality.
        Pass a callable to normalize differently, for example
        ``lambda s: s.strip().casefold()`` when existing index tokens were
        built with casefold. Whatever you pick, every writer and every reader
        of a column must use the same normalization, or lookups silently miss.
        No Unicode normalization is applied; pass
        ``lambda s: unicodedata.normalize("NFC", s).strip().lower()`` if inputs
        may arrive as NFD.

        ``context`` (opt-in) separates columns: the MAC input becomes
        ``context || 0x00 || value``, so the same email indexed under
        "users.email" and "contacts.email" cannot be joined on equality.
        Omitting it keeps pre-0.5 tokens unchanged.
        """
        if self._index_key is None:
            raise KeyNotConfiguredError(
                "blind_index_key is not configured; cannot build a blind index."
            )
        if callable(normalize):
            normalized = normalize(value)
        elif normalize:
            normalized = value.strip(_JS_WHITESPACE).lower()
        else:
            normalized = value
        mac = hmac_mod.new(self._index_key, digestmod=hashlib.sha256)
        if context:
            if "\0" in context:
                raise SealedFieldsError("blind_index context must not contain NUL.")
            mac.update(context.encode("utf-8") + b"\0")
        mac.update(normalized.encode("utf-8"))
        return mac.hexdigest()

    # -- row helpers ---------------------------------------------------------

    @staticmethod
    def _normalize_spec(spec: Any) -> tuple[tuple[str, ...], tuple[str, ...], Any]:
        # A Mapping spec may carry "context": a callable (field, row) -> context.
        if isinstance(spec, Mapping):
            return (
                tuple(spec.get("fields") or ()),
                tuple(spec.get("json_fields") or ()),
                spec.get("context"),
            )
        return tuple(spec), (), None

    def seal_row(
        self, row: Mapping[str, Any], spec: Any, namespace: str | None = None
    ) -> dict[str, Any]:
        fields, json_fields, ctx = self._normalize_spec(spec)
        out = dict(row)
        for field in json_fields:
            v = out.get(field)
            if v is not None:
                out[field] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        for field in (*fields, *json_fields):
            v = out.get(field)
            if not isinstance(v, str) or v == "":
                continue
            # Seal unconditionally: a value that merely looks like a token is
            # untrusted input, not ciphertext. Call seal_row once per write.
            out[field] = self.seal(v, namespace, context=ctx(field, row) if ctx else None)
        return out

    def _unseal_row_internal(
        self, row: Mapping[str, Any], spec: Any, namespace: str | None
    ) -> tuple[dict[str, Any], int, int]:
        fields, json_fields, ctx = self._normalize_spec(spec)
        out = dict(row)
        failures = 0
        attempts = 0
        for field in (*fields, *json_fields):
            v = out.get(field)
            if not isinstance(v, str) or v == "":
                continue
            if self._plaintext == "passthrough" and not (
                is_sealed(v) or any(_match_legacy(v, f) for f in self._legacy)
            ):
                continue
            attempts += 1
            try:
                out[field] = self.unseal(v, namespace, context=ctx(field, row) if ctx else None)
            except Exception as err:
                # Never hand raw ciphertext to a caller; None is a safe sentinel.
                self._warn(f'[sealed-fields] unseal failed for field "{field}": {err}')
                out[field] = None
                failures += 1
        for field in json_fields:
            v = out.get(field)
            if isinstance(v, str) and v:
                try:
                    out[field] = json.loads(v)
                except ValueError:
                    pass  # leave as-is; never null data that decrypted fine
        return out, failures, attempts

    def unseal_row(
        self, row: Mapping[str, Any], spec: Any, namespace: str | None = None
    ) -> dict[str, Any]:
        return self._unseal_row_internal(row, spec, namespace)[0]

    def unseal_rows(
        self, rows: Iterable[Mapping[str, Any]], spec: Any, namespace: str | None = None
    ) -> list[dict[str, Any]]:
        total_failures = 0
        total_attempts = 0
        result = []
        for row in rows:
            out, failures, attempts = self._unseal_row_internal(row, spec, namespace)
            total_failures += failures
            total_attempts += attempts
            result.append(out)
        if total_attempts >= 5 and total_failures / total_attempts > 0.5:
            raise SystemicUnsealError(total_failures, total_attempts)
        return result


def create_sealed_fields(**kwargs: Any) -> SealedFields:
    return SealedFields(kwargs.pop("namespaces"), **kwargs)


def sealed_fields_from_env(
    namespaces: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    **options: Any,
) -> SealedFields:
    """Build a SealedFields from environment variables, by convention:

        SEALED_KEY_<NS>            active key for namespace <NS>
        SEALED_KEY_<NS>_VERSION    active key version label (default "v1")
        SEALED_KEY_<NS>_RETIRED    comma-separated "v1:<key>,v2:<key>"
        SEALED_BLIND_INDEX_KEY     blind index HMAC key

    Namespaces are listed explicitly; the environment is never scanned.
    """
    import os

    e = env if env is not None else os.environ
    ns_config: dict[str, dict[str, Any]] = {}
    for ns in namespaces:
        retired: dict[str, str] = {}
        retired_raw = (e.get(f"SEALED_KEY_{ns}_RETIRED") or "").strip()
        if retired_raw:
            for pair in retired_raw.split(","):
                pair = pair.strip()
                if not pair:
                    continue
                ver, sep, key = pair.partition(":")
                if not sep or not ver.strip() or not key.strip():
                    raise SealedFieldsError(
                        f'SEALED_KEY_{ns}_RETIRED entries must look like "v1:<key>" (got "{pair}").'
                    )
                retired[ver.strip()] = key.strip()
        ns_config[ns] = {
            "key": e.get(f"SEALED_KEY_{ns}"),
            "version": e.get(f"SEALED_KEY_{ns}_VERSION"),
            "retired": retired,
        }
    blind = e.get("SEALED_BLIND_INDEX_KEY")
    if blind is not None:
        options.setdefault("blind_index_key", blind)
    return SealedFields(ns_config, **options)
