import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { NONCE_BYTES, TAG_BYTES, type Keyring } from "./keyring.js";
import { UnknownKeyVersionError } from "./errors.js";

// Canonical wire format:
//
//   v<N>:<base64url(nonce | ciphertext | tag)>
//
// AES-256-GCM, random 12-byte nonce per value, 16-byte tag. The key version
// label is bound as additional authenticated data (AAD), so a token cannot be
// silently re-attributed to a different key version: tampering with the
// prefix fails authentication.
//
// This is byte-compatible with the Python reference implementation, which
// uses AESGCM(nonce, plaintext, aad=version) via the `cryptography` package
// and emits urlsafe-base64. Data written by either implementation unseals in
// the other. See test/cross-language.test.ts for the shared fixture.

const TOKEN_RE = /^(v\d+):([A-Za-z0-9_-]+={0,2})$/;

/** True when a value structurally matches the canonical sealed format.
 *  Minimum blob length is nonce+tag with ZERO ciphertext bytes: a sealed
 *  empty string is valid GCM and must be recognized (found by the first
 *  production adopter, which had to work around the earlier +1 minimum). */
export function looksSealed(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const m = TOKEN_RE.exec(value);
  if (!m) return false;
  const raw = decodeBlob(m[2]!);
  return raw.length >= NONCE_BYTES + TAG_BYTES;
}

export function parseToken(token: string): { version: string; blob: string } | null {
  const m = TOKEN_RE.exec(token);
  return m ? { version: m[1]!, blob: m[2]! } : null;
}

function decodeBlob(blob: string): Buffer {
  // Accept padded and unpadded, standard and url-safe alphabets. The Python
  // reference emits padded urlsafe base64; we emit unpadded base64url.
  return Buffer.from(blob.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function sealWithKeyring(plaintext: string, ring: Keyring): string {
  const key = ring.keys.get(ring.activeVersion)!;
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(ring.activeVersion, "ascii"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([nonce, ciphertext, tag]).toString("base64url");
  return `${ring.activeVersion}:${blob}`;
}

/**
 * Unseal a canonical token against a keyring.
 *
 * Throws UnknownKeyVersionError when the token names a version the keyring
 * does not hold (unless `onUnknownVersion` is "passthrough", for use only
 * during an active key rotation). Throws the underlying OpenSSL error on a
 * tampered or wrong-key token: an authentication failure is a real integrity
 * problem and is never swallowed here.
 */
export function unsealWithKeyring(
  token: string,
  ring: Keyring,
  namespace: string,
  onUnknownVersion: "throw" | "passthrough",
): string {
  const parsed = parseToken(token)!;
  const key = ring.keys.get(parsed.version);
  if (!key) {
    if (onUnknownVersion === "passthrough") return token;
    throw new UnknownKeyVersionError(parsed.version, namespace);
  }
  const raw = decodeBlob(parsed.blob);
  const nonce = raw.subarray(0, NONCE_BYTES);
  const ciphertext = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.from(parsed.version, "ascii"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
