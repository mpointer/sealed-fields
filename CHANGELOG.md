# Changelog

Both packages share one version number and one `v*` tag.

## 0.6.0 (2026-10-28)

Both packages:

- Context binding. `seal` / `unseal` take an optional `context` (a string or
  parts such as `["users", "email"]`), bound into the GCM AAD as
  `version || 0x00 || context`. A token copied to another column or row
  fails authentication. The token format is unchanged, and tokens sealed
  without a context read exactly as before. Shared vectors added.
- TS: the second argument of `seal`, `unseal`, `maybeSeal` and `maybeUnseal`
  is a namespace string or `{ namespace, context }`. Python takes
  `context=` as a keyword.
- Row helpers accept a `context(field, row)` function in the spec.
- `contextFallback` / `context_fallback` for migrating existing rows: a
  read that fails under the context is retried without it, logged once per
  namespace, and counted in `stats().unboundReads` (Python
  `stats()["unbound_reads"]`). Legacy-format tokens read with a context
  only under fallback.
- Python: `SealedText`, `SealedString` and `SealedJSON` take `context`
  (column-level), included in the SQLAlchemy cache key.
- CI reports coverage and fails below set thresholds.
- New `plaintext: "reject"` / `plaintext="reject"` option for fully migrated
  columns. `unseal` throws on a non-token value instead of passing it
  through, and the row helpers null it and count it toward
  `SystemicUnsealError`. Default stays `"passthrough"`. Rejected with
  `mode: "dormant"`.

## 0.5.0 (2026-10-28)

Both packages:

- `blindIndex` / `blind_index` take an opt-in `context` for separating
  columns. The MAC input becomes `context || 0x00 || value`. Without a
  context, tokens are unchanged. Shared vector added.
- Key parsing is strict: 64-char hex or 43-char base64/base64url with an
  optional trailing `=`. TS used to skip invalid characters while decoding,
  so typo'd strings could be accepted as keys.
- Dormant mode warns once per namespace instead of once per instance.
- Docs: blind indexes apply no Unicode normalization; README shows an NFC
  normalizer.

Python:

- Tokens and version labels use `fullmatch`, so `"v1:...\n"` is no longer
  treated as sealed (TS already rejected it).
- `namespace=""` is an unknown namespace, as in TS, not the default.
- **Token change:** the default `blind_index` trim now strips exactly the
  characters JS `String.prototype.trim()` strips. Before, a value starting
  or ending with `\x1c`-`\x1f`, `\x85` or `\ufeff` got a different token in
  Python than in TS. Python-written index rows for such values need
  recomputing; all other tokens are unchanged. Shared vector added.

## 0.4.0 (2026-10-28)

Both packages. **Breaking:** `sealRow` / `seal_row` now seal every listed
string, so call them exactly once per write.

- `sealRow` no longer skips values that look sealed. Token-shaped user input
  was stored unencrypted, nulled on read, and five on one page tripped
  `SystemicUnsealError` for every viewer. This also fixes `jsonFields` being
  double-sealed when a sealed row was passed in again. Read-modify-write
  paths that re-pass rows read from the database will now double-seal.
- `unsealRow` / `unsealRows` decode enabled legacy formats instead of
  returning raw legacy ciphertext, and count legacy failures toward
  systemic detection.
- TS: the constructor validates `mode`, `legacy` and `onUnknownVersion`. An
  unrecognized `mode` (for example `"STRICT"`) used to write plaintext.
- `unseal` rejects tokens shorter than nonce + tag. TS pins
  `authTagLength: 16`, because Node 20/22 otherwise accept truncated GCM tags.
- README: audit existing plaintext for token-shaped values before enabling
  a key or legacy decoder.

## 0.3.0 (2026-10-19)

Both packages:

- `blindIndex` / `blind_index` accept a custom normalizer function in place
  of the boolean. The default (trim + lowercase) is unchanged.

Python:

- New `sealed_fields.sqlalchemy` module, installed with
  `pip install "sealed-fields[sqlalchemy]"`: `SealedText`, `SealedString`
  and `SealedJSON` TypeDecorators. Each takes a `SealedFields` instance or a
  zero-argument callable returning one, plus an optional namespace; both are
  part of the SQLAlchemy cache key. `None` stays `NULL`, an empty string is
  sealed, plaintext rows read through, the keyring's mode decides what a
  key-less write does, and a bad token raises on read.
- CI runs the suite against SQLAlchemy 1.4 and 2.x and verifies the
  sdist and wheel build.
- The release workflow publishes to PyPI by trusted publishing (OIDC) on
  the same tag that publishes to npm. The PyPI project must have the
  GitHub publisher configured once (owner `mpointer`, repository
  `sealed-fields`, workflow `release.yml`).

## 0.2.0 (2026-07-25)

- Python package (`sealed-fields` on PyPI) with the identical wire format
  and API surface. Both suites decode the shared vectors in
  `test/vectors.json`.
- `isSealed` recognizes a sealed empty string (nonce plus tag, zero
  ciphertext bytes).

## 0.1.0 (2026-07-25)

- TypeScript core: AES-256-GCM wire format with AAD-bound key versions, key
  namespaces, retired-key rotation, blind indexes, row helpers with
  systemic-failure detection, legacy-format decoders.
