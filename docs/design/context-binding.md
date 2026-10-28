# Design note: binding sealed values to their row and column

Status: accepted, not implemented. Target: 0.6.0.

## Problem

A token authenticates its key version and nothing else. Someone with write
access to the database but no key can move ciphertext around, and it still
decrypts:

- **Cross-row swap.** Copy user A's sealed SSN into user B's row. The app now
  shows A's SSN on B's account, or sends it to B's email.
- **Cross-column swap.** Copy a sealed `notes` value into `email`. Password
  reset mail goes wherever the attacker chose, if they can get a token that
  decrypts to their own address into the right place (for example, by
  signing up and copying their own sealed email over the victim's).

Both are realistic for the threat model this library targets: leaked DB
credentials, a compromised replica, a SQL injection with write access, a
rogue admin with a SQL console.

## Proposal

Add an opt-in `context` to seal and unseal. It goes into the GCM additional
authenticated data next to the version label:

```
AAD = version                          (no context, today)
AAD = version || 0x00 || context       (with context)
```

The token format does not change: still `v1:<base64url(nonce|ct|tag)>`.
Decrypting with the wrong context fails authentication exactly like a
tampered token.

### API

```ts
sf.seal(ssn, { namespace: "PII", context: ["users", "ssn"] });
sf.unseal(token, { namespace: "PII", context: ["users", "ssn"] });
```

- The second argument becomes `string | { namespace?, context? }`. A string
  is still the namespace, so existing calls keep compiling.
- `context` is `string | readonly string[]`. Arrays are joined with `0x00`,
  and any part containing NUL is rejected. That keeps the encoding
  injective: `["a.b", "c"]` and `["a", "b.c"]` cannot collide, which a
  caller-built `"a.b.c"` string could. Same NUL rule as the blind-index
  `context` from 0.5.0, and the same name.
- Row helpers take a function, because the context usually depends on the
  row: `sealRow(row, { fields: ["ssn"], context: (field, row) => ["users", field, row.id] })`.
  `unsealRow` and `unsealRows` take the same spec, so one constant serves
  both directions.
- Python mirrors it: `seal(v, namespace=..., context=...)`, and the
  SQLAlchemy types take `context="users.ssn"` (column-level only, see below).
- Shared vectors in `test/vectors.json` for a bound token, both suites.

### What to bind

- **Table and column: the documented default.** Known at every call site, never changes,
  stops cross-column swaps and copying between tables.
- **Row id: an opt-in upgrade, not the default.** It stops cross-row
  swaps, which is the bigger risk. But a database-generated id
  (`SERIAL`, auto-increment) does not exist until after the `INSERT`. Then
  the choice is insert-then-update, or binding table and column only.
  Insert-then-update is easy to get wrong, so the README will not
  recommend row ids by default. It will present them as the upgrade for
  tables with client-generated ids (UUIDs), where binding them is free.
- A row id in the context means the value must be resealed if the id ever
  changes (merges, re-keys). Rare, but worth a line in the docs.

The SQLAlchemy `TypeDecorator` hooks see the value but not the row, so the
column types can bind table and column only. Row-level binding there needs
the row helpers or an ORM event hook. I'd leave that out of scope for 0.6.

## Migration

Existing rows were sealed without a context. Turning binding on must not
break them on day one.

- New instance option `contextFallback: true` (Python `context_fallback=True`).
  When a context is supplied and decryption under it fails, retry with the
  plain version AAD. If that succeeds, return the value and log once per
  namespace that unbound tokens are still being read, and increment a
  counter (below).
- Writes always bind. A normal re-encrypt backfill (read with fallback,
  write bound) migrates the table.
- `sf.stats()` (Python `sf.stats()`) returns `{ unboundReads }`, the number
  of fallback decrypts since the instance was created. A backfill job or a
  health check can confirm it stays at zero over a full read cycle before
  fallback is turned off. The counter is per instance and per process, so
  read it on every instance, or ship it to your metrics.
- After the backfill, remove `contextFallback`. From then on an unbound or
  moved token fails like any tampered value. The row helpers null it and
  count it toward `SystemicUnsealError`.

While fallback is on, an attacker can still move an old *unbound* token,
which is no worse than today. They cannot move a bound token, and they
cannot turn a bound token into an unbound one, because both AADs are
authenticated.

### Alternatives considered

- **A marker in the token, such as a `v1b:` prefix.** It lets a reader tell
  bound and unbound tokens apart without a second decrypt. Rejected
  because readers older than 0.6 don't recognize it as a token and would
  pass the ciphertext through as if it were plaintext. With no marker, an
  old reader tries the token, fails authentication and throws, which fails
  closed.
- **A marker byte inside the blob.** It fails closed in old readers, but
  it changes the byte layout every implementation has to parse. That's a
  real format change for almost no gain over the fallback.
- **Always bind, no option.** Every existing row would break on upgrade.

The fallback costs a second GCM decrypt, and only on unbound rows during
the migration window. That's microseconds per value.

## Not covered

- **Rollback and replay.** Writing an *older* token for the same row and
  column back into place still authenticates. Stopping it needs a version
  counter in the context, which means application-level state. Document it
  and leave it out.
- **Blind indexes.** They already have their own `context`. This change
  doesn't touch them.
- **Key rotation.** The version is still the first part of the AAD, so
  rotation works as it does today.

## Effort

About a day for both languages: options plumbing, the AAD change in
`seal.ts` and Python `seal`/`unseal`, fallback, row-helper spec, shared
vectors, tests that a moved token fails, and docs. No change to the wire
format or `isSealed`.

## Decisions

1. The README recommends table and column binding by default. Row ids are
   documented as an opt-in upgrade for client-generated ids.
2. The fallback logs once per namespace and also exposes the
   `stats().unboundReads` counter.
