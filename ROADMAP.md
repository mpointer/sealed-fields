# Roadmap

v0.1.0 ships the TypeScript core: canonical AES-256-GCM wire format with
AAD-bound key versions, key namespaces, retired-key rotation, blind indexes,
row helpers with systemic-failure detection, legacy-format decoders, and a
Python cross-language fixture in the test suite.

## v0.2 candidates

- [ ] Python package (`sealed-fields` on PyPI) with the identical wire format
      and API surface, ported from the production Python reference
      implementation. Shared test vectors prove cross-language compatibility
      in both CI pipelines.
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

- [ ] SQLAlchemy TypeDecorators in the Python package (EncryptedText,
      EncryptedJSON) once the core port lands.
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
