# Roadmap

v0.1.0 shipped the TypeScript core: canonical AES-256-GCM wire format with
AAD-bound key versions, key namespaces, retired-key rotation, blind indexes,
row helpers with systemic-failure detection, and legacy-format decoders.

## v0.2

- [x] Python package (`sealed-fields` on PyPI) in `python/`: identical wire
      format and API surface. Shared vectors in `test/vectors.json` are
      decoded by both suites in CI; data sealed by either implementation
      unseals in the other.
- [x] `isSealed` recognizes a sealed empty string (nonce+tag, zero
      ciphertext bytes) — harvest from the first production adopter, whose
      shim had to carry its own structural check.

## v0.3

- [x] SQLAlchemy column types in the Python package, as the `sqlalchemy`
      extra: `SealedText`, `SealedString`, `SealedJSON` TypeDecorators with
      a provider (instance or lazy callable) and a namespace, both part of
      the SQLAlchemy cache key. Harvested from the first production
      adopter's own TypeDecorators, keeping its boundary rules (NULL both
      ways, sealed empty string, plaintext passthrough mid-migration, mode
      decides key-less writes, bad tokens raise). Tested on SQLAlchemy 1.4
      and 2.x.
- [x] `blindIndex` / `blind_index` accept a custom normalizer function, for
      index columns whose stored tokens were built under a rule other than
      trim + lowercase (the adopter above used casefold).
- [x] Release workflow publishes the Python package to PyPI by trusted
      publishing on the same `v*` tag as npm.

## v0.4 candidates
- [ ] Drizzle column helpers: a `sealedText()` / `sealedJson()` custom type
      so schema declarations carry the sealing, mirroring the SQLAlchemy
      TypeDecorator pattern in the Python reference.
- [ ] Backfill script template: cursor-paginated re-encrypt for plaintext
      rows and for retired-key rows, with dry-run counts and progress
      checkpoints.
- [ ] Key-audit helper: scan a table and report rows by state (plaintext,
      active version, each retired version, unknown version) so "is the
      rotation done" is a query, not a guess.

## Later / on demand

- [ ] Additional legacy decoders if adopters bring other common formats
      (for example the compact binary `base64(iv|tag|ct)` shape).
- [ ] scrypt/HKDF key-derivation helper for teams that manage passphrase
      secrets instead of raw 32-byte keys.

## Non-goals

- Envelope encryption / KMS integration. This library holds raw data keys;
  wrap them with your KMS upstream if you need that layer.
- Searchable encryption beyond blind-index equality. Range queries and
  full-text search over ciphertext are research-grade machinery, not a
  weekend dependency.
- Key storage or key management. Keys come from your environment or secret
  manager; this library never persists them.
