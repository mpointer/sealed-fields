# sealed-fields

Field-level encryption for PII at rest, extracted from three production applications. AES-256-GCM with versioned key rotation, key namespaces, blind indexes for equality lookups on encrypted columns, and row helpers that detect systemic key failures. Zero dependencies. Bring your own database.

```
npm install sealed-fields
```

## What problem this solves

Your database holds columns that are radioactive in a leaked backup: free-text notes about people, emails, phone numbers, OAuth refresh tokens, TOTP secrets. Full-disk encryption does not help when the attacker has valid database credentials or a copy of the dump. Application-layer field encryption does: the column stores ciphertext, and only the application holding the key can read it.

This library is the shared core of that pattern, extracted after building it three separate times in production. It does not defend against a fully compromised application server, because the app must hold the key to function. That is a different threat model with different tools.

## Quick start

```ts
import { createSealedFields, generateKey } from "sealed-fields";

// One-time setup: node -e "console.log(require('sealed-fields').generateKey())"
const sf = createSealedFields({
  namespaces: {
    PII: { key: process.env.SEALED_KEY_PII },
  },
  blindIndexKey: process.env.SEALED_BLIND_INDEX_KEY,
});

const token = sf.seal("free-text note about a real person");
// "v1:bxLki3..." goes in the database

sf.unseal(token); // the plaintext
sf.unseal("legacy plaintext row"); // passes through unchanged (see Migration)
```

Wire format: `v1:<base64url(nonce | ciphertext | tag)>`. The key version label is bound as additional authenticated data, so a token cannot be re-attributed to a different key version. Tampering with the prefix fails authentication.

## Key rotation without a flag day

Every token names the key version that wrote it. Rotation is three steps and no downtime:

```ts
const sf = createSealedFields({
  namespaces: {
    PII: {
      key: process.env.SEALED_KEY_PII, // the NEW key
      version: "v2",
      retired: { v1: process.env.SEALED_KEY_PII_OLD }, // decrypt-only
    },
  },
});
```

New writes seal under v2. Old rows keep reading under v1. Re-encrypt at your leisure with a backfill script, then drop the retired key. If a token names a version you no longer hold, `unseal` throws instead of returning ciphertext. The `onUnknownVersion: "passthrough"` option exists for the migration window only.

## Key namespaces limit rotation blast radius

Rotating your PII key after an incident should not also invalidate every stored TOTP secret, and vice versa. Namespaces are separate keyrings under one instance:

```ts
const sf = createSealedFields({
  namespaces: {
    PII: { key: process.env.SEALED_KEY_PII },
    TOTP: { key: process.env.SEALED_KEY_TOTP },
  },
});

sf.seal(totpSecret, "TOTP");
```

A value sealed in one namespace fails authentication in another. That is enforced by the key, not by convention.

## Blind indexes: equality lookups on encrypted columns

Encrypted columns cannot be queried. A blind index is a deterministic HMAC-SHA256 of the normalized value, stored in a sibling column, so `WHERE email_idx = ?` works while the email itself stays sealed:

```ts
await db.insert(users).values({
  email: sf.seal(email),
  emailIdx: sf.blindIndex(email), // trim + lowercase, then HMAC
});

const row = await db.query.users.findFirst({
  where: eq(users.emailIdx, sf.blindIndex(inputEmail)),
});
```

Only index high-entropy values: emails, usernames, phone numbers. Never index a low-entropy field like state, zip code, or birth year. A deterministic MAC over a small domain is trivially dictionary-attacked.

## Row helpers

Declare which fields on a table are sealed, once, and use the row helpers at the write and read boundaries:

```ts
const NOTE_FIELDS = { fields: ["content", "authorEmail"], jsonFields: ["snapshot"] };

await db.insert(notes).values(sf.sealRow(values, NOTE_FIELDS));
const rows = sf.unsealRows(await db.select().from(notes), NOTE_FIELDS);
```

The helpers carry three production lessons:

1. A failed unseal nulls the field instead of handing raw ciphertext to your UI.
2. If more than half of attempted unseals across a batch fail (minimum 5), `unsealRows` throws `SystemicUnsealError`. That pattern means the wrong key is configured, and a page of silent nulls is worse than an error page. Plaintext rows mid-migration do not dilute the rate; only genuinely sealed values count as attempts.
3. `jsonFields` are stringified before sealing and parsed after unsealing, unconditionally in both directions. A conditional version of this (stringify only objects, parse everything) shipped a real bug: every string-valued row came back null. Seal and unseal must be true inverses.

## Migration from plaintext, and from other wire formats

`unseal` passes non-token strings through unchanged, so a column can be read transparently while it still holds plaintext rows. Swap the write path first, then backfill whenever convenient.

If you already have encrypted data in one of these common shapes, enable its decoder and adopt without a stop-the-world re-encrypt:

```ts
const sf = createSealedFields({
  namespaces: { PII: { key } },
  legacy: ["iv-ct-tag"],      // <b64 iv>:<b64 ciphertext>:<b64 tag>
  // legacy: ["v1-iv-tag-ct"] // v1:<b64 iv>:<b64 tag>:<b64 ciphertext>
});
```

Reads understand the old tokens. Every write produces the canonical format. A legacy-shaped token that no key can authenticate throws, because that is an integrity problem, not plaintext.

## Fail closed by default

With no key configured, `seal` throws. If you need the deploy window where code ships before keys are provisioned, opt in explicitly:

```ts
createSealedFields({ namespaces: { PII: {} }, mode: "dormant" });
```

Dormant mode writes plaintext and logs one loud warning per process. It exists because a silent fail-open version of this exact behavior is how PII ends up unencrypted in production for months. The warning is the point.

## Environment convention

```ts
import { sealedFieldsFromEnv } from "sealed-fields";

// Reads SEALED_KEY_PII, SEALED_KEY_PII_VERSION, SEALED_KEY_PII_RETIRED,
// SEALED_KEY_TOTP, ..., and SEALED_BLIND_INDEX_KEY.
const sf = sealedFieldsFromEnv(["PII", "TOTP"]);
```

Namespaces are listed explicitly. The helper never scans the environment, so a typo cannot silently create a keyless namespace.

## Utilities

`generateKey()` returns a fresh 32-byte key as base64url. `hashToken(t)` is a SHA-256 hex digest for one-time tokens (magic links, verification codes): store the hash, send the plaintext, and a leaked database cannot consume pending tokens. `isSealed(v)` is a structural check for the canonical format.

## Cross-language

The wire format is deliberately simple and language-neutral: AES-256-GCM, `nonce || ciphertext || tag`, urlsafe base64, key version as AAD. The test suite includes a fixture generated by the Python reference implementation (`cryptography`'s AESGCM), and a Python package with the same API is on the [roadmap](./ROADMAP.md).

## What this is not

Not envelope encryption with a KMS, not searchable encryption beyond equality, not order-preserving anything, and not a defense against an attacker who owns your application server. For range queries or full-text search over encrypted data you need different (and heavier) machinery.

## License

MIT
