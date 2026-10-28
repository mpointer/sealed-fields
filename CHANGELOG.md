# Changelog

Both packages share one version number and one `v*` tag.

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
