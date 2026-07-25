import { createDecipheriv } from "node:crypto";
import { NONCE_BYTES, TAG_BYTES, type Keyring } from "./keyring.js";

// Read-only decoders for pre-existing wire formats, so an application can
// adopt sealed-fields without a stop-the-world re-encrypt backfill: reads
// understand the old tokens, and every write produces the canonical format.
// Rows migrate lazily, or via a one-time backfill script at your leisure.
//
//   "iv-ct-tag"    →  <b64 iv>:<b64 ciphertext>:<b64 tag>
//                     (versionless AES-256-GCM, no AAD)
//   "v1-iv-tag-ct" →  v1:<b64 iv>:<b64 tag>:<b64 ciphertext>
//                     (version-prefixed AES-256-GCM, no AAD)
//
// Both are tried with the active key first, then every retired key, because
// versionless formats cannot say which key wrote them.

export type LegacyFormat = "iv-ct-tag" | "v1-iv-tag-ct";

interface LegacyParts {
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

function b64(s: string): Buffer {
  return Buffer.from(s, "base64");
}

/** Structurally match a legacy token. Returns null when the shape is wrong. */
export function matchLegacy(token: string, format: LegacyFormat): LegacyParts | null {
  const parts = token.split(":");
  if (format === "iv-ct-tag") {
    if (parts.length !== 3) return null;
    const [iv, ciphertext, tag] = [b64(parts[0]!), b64(parts[1]!), b64(parts[2]!)];
    if (iv.length !== NONCE_BYTES || tag.length !== TAG_BYTES || ciphertext.length === 0) return null;
    return { iv, ciphertext, tag };
  }
  // "v1-iv-tag-ct"
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  const [iv, tag, ciphertext] = [b64(parts[1]!), b64(parts[2]!), b64(parts[3]!)];
  if (iv.length !== NONCE_BYTES || tag.length !== TAG_BYTES || ciphertext.length === 0) return null;
  return { iv, ciphertext, tag };
}

function decryptParts(parts: LegacyParts, key: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, parts.iv);
  decipher.setAuthTag(parts.tag);
  return Buffer.concat([decipher.update(parts.ciphertext), decipher.final()]).toString("utf8");
}

/**
 * Attempt every enabled legacy format against every key in the ring.
 *
 * Returns the plaintext on success, null when the token doesn't structurally
 * match any enabled format (treat as plaintext passthrough upstream), and
 * throws when a token matched a format but no key could authenticate it —
 * that is an integrity/key problem, not plaintext.
 */
export function tryLegacyFormats(
  token: string,
  formats: readonly LegacyFormat[],
  ring: Keyring,
): string | null {
  let matchedAny = false;
  let lastError: unknown;
  for (const format of formats) {
    const parts = matchLegacy(token, format);
    if (!parts) continue;
    matchedAny = true;
    for (const key of orderedKeys(ring)) {
      try {
        return decryptParts(parts, key);
      } catch (err) {
        lastError = err;
      }
    }
  }
  if (matchedAny) throw lastError;
  return null;
}

function orderedKeys(ring: Keyring): Buffer[] {
  const active = ring.keys.get(ring.activeVersion)!;
  const rest = [...ring.keys.entries()]
    .filter(([v]) => v !== ring.activeVersion)
    .map(([, k]) => k);
  return [active, ...rest];
}
