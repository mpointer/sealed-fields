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
    try:
        normalized = s.replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=False)
        if len(decoded) == KEY_BYTES:
            return decoded
    except (binascii.Error, ValueError):
        pass
    raise KeyNotConfiguredError(
        f"{label} must be a {KEY_BYTES}-byte key as 64-char hex, base64, or "
        f"base64url. Generate one with generate_key()."
    )


def _decode_blob(blob: str) -> bytes:
    normalized = blob.replace("-", "+").replace("_", "/").rstrip("=")
    return base64.b64decode(normalized + "=" * (-len(normalized) % 4))


def is_sealed(value: Any) -> bool:
    """True when a value structurally matches the canonical sealed format."""
    if not isinstance(value, str):
        return False
    m = _TOKEN_RE.match(value)
    if not m:
        return False
    try:
        raw = _decode_blob(m.group(2))
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= NONCE_BYTES + TAG_BYTES  # empty plaintext is valid GCM


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
    if not _VERSION_RE.match(active_version):
        raise SealedFieldsError(
            f'namespace "{namespace}": version must look like "v1", "v2", ... (got "{active_version}").'
        )
    keys = {active_version: _parse_key(raw_key, f'namespace "{namespace}" key')}
    for ver, raw in (cfg.get("retired") or {}).items():
        if not _VERSION_RE.match(ver):
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
        self._warn = logger or (lambda m: print(m))
        self._warned_dormant = False

    # -- internals ---------------------------------------------------------

    def _resolve_ns(self, namespace: str | None) -> str:
        ns = namespace or self._default_ns
        if ns is None:
            raise SealedFieldsError(
                "no namespace given and no default_namespace configured (multiple namespaces exist)."
            )
        if ns not in self._rings:
            raise SealedFieldsError(f'unknown namespace "{ns}".')
        return ns

    def _warn_dormant_once(self, ns: str) -> None:
        if self._warned_dormant:
            return
        self._warned_dormant = True
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

    def seal(self, plaintext: str, namespace: str | None = None) -> str:
        ns = self._resolve_ns(namespace)
        ring = self._rings[ns]
        if ring is None:
            if self._mode == "strict":
                raise KeyNotConfiguredError(
                    f'namespace "{ns}" has no key configured; cannot seal (mode: "strict").'
                )
            self._warn_dormant_once(ns)
            return plaintext
        nonce = secrets.token_bytes(NONCE_BYTES)
        aes = AESGCM(ring.keys[ring.active_version])
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), ring.active_version.encode("ascii"))
        blob = base64.urlsafe_b64encode(nonce + ct).decode("ascii").rstrip("=")
        return f"{ring.active_version}:{blob}"

    def unseal(self, value: str, namespace: str | None = None) -> str:
        ns = self._resolve_ns(namespace)
        ring = self._rings[ns]
        m = _TOKEN_RE.match(value)
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
            nonce, ct = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
            return AESGCM(key).decrypt(nonce, ct, version.encode("ascii")).decode("utf-8")
        if ring is not None and self._legacy:
            decoded = self._try_legacy(value, ring)
            if decoded is not None:
                return decoded
        return value  # plaintext passthrough

    def maybe_seal(self, value: str | None, namespace: str | None = None) -> str | None:
        if value is None or value == "":
            return None
        return self.seal(value, namespace)

    def maybe_unseal(self, value: str | None, namespace: str | None = None) -> str | None:
        if value is None or value == "":
            return None
        return self.unseal(value, namespace)

    def blind_index(self, value: str, *, normalize: bool = True) -> str:
        """Deterministic HMAC-SHA256 lookup token for an equality query on an
        otherwise-sealed column. ONLY for high-entropy values (email, username,
        phone). Never index a low-entropy field: a deterministic MAC over a
        small domain is trivially dictionary-attacked.

        Normalization (default on) is trim + lowercase, matching the npm
        package's String.prototype.toLowerCase for cross-language equality.
        """
        if self._index_key is None:
            raise KeyNotConfiguredError(
                "blind_index_key is not configured; cannot build a blind index."
            )
        normalized = value.strip().lower() if normalize else value
        return hmac_mod.new(self._index_key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()

    # -- row helpers ---------------------------------------------------------

    @staticmethod
    def _normalize_spec(spec: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if isinstance(spec, Mapping):
            return tuple(spec.get("fields") or ()), tuple(spec.get("json_fields") or ())
        return tuple(spec), ()

    def seal_row(
        self, row: Mapping[str, Any], spec: Any, namespace: str | None = None
    ) -> dict[str, Any]:
        fields, json_fields = self._normalize_spec(spec)
        out = dict(row)
        for field in json_fields:
            v = out.get(field)
            if v is not None:
                out[field] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        for field in (*fields, *json_fields):
            v = out.get(field)
            if not isinstance(v, str) or v == "":
                continue
            if is_sealed(v):
                continue
            out[field] = self.seal(v, namespace)
        return out

    def _unseal_row_internal(
        self, row: Mapping[str, Any], spec: Any, namespace: str | None
    ) -> tuple[dict[str, Any], int, int]:
        fields, json_fields = self._normalize_spec(spec)
        out = dict(row)
        failures = 0
        attempts = 0
        for field in (*fields, *json_fields):
            v = out.get(field)
            if not isinstance(v, str) or v == "" or not is_sealed(v):
                continue
            attempts += 1
            try:
                out[field] = self.unseal(v, namespace)
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
