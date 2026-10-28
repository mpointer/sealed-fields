import { KeyNotConfiguredError, SealedFieldsError } from "./errors.js";

export const KEY_BYTES = 32; // AES-256
export const NONCE_BYTES = 12; // GCM standard nonce
export const TAG_BYTES = 16; // GCM auth tag

const VERSION_RE = /^v\d+$/;

/** Per-namespace key material. `key` may be omitted or empty to leave the
 *  namespace dormant (see `mode` on the config). */
export interface NamespaceConfig {
  /** Active key: 64-char hex, base64, base64url, or a 32-byte Buffer. */
  key?: string | Buffer;
  /** Label for the active key. Default "v1". Must match /^v\d+$/. */
  version?: string;
  /** Retired keys kept for UNSEALING only, by version label. */
  retired?: Record<string, string | Buffer>;
}

export interface Keyring {
  activeVersion: string;
  keys: Map<string, Buffer>;
}

/** Accept a 64-char hex, base64, base64url, or raw 32-byte Buffer key. */
export function parseKey(raw: string | Buffer, label: string): Buffer {
  if (Buffer.isBuffer(raw)) {
    if (raw.length !== KEY_BYTES) {
      throw new KeyNotConfiguredError(`${label} must be ${KEY_BYTES} bytes (got ${raw.length}).`);
    }
    return Buffer.from(raw);
  }
  const s = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
  // 32 bytes encode to exactly 43 base64 chars plus optional "=". Check the
  // shape strictly: Node's decoder silently skips invalid characters, so a
  // lenient check would accept typos and arbitrary strings as keys.
  if (/^[A-Za-z0-9+/_-]{43}=?$/.test(s)) {
    return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  }
  throw new KeyNotConfiguredError(
    `${label} must be a ${KEY_BYTES}-byte key as 64-char hex or 43-char base64/base64url. ` +
      `Keys must be random; a passphrase is not a key. Generate one with generateKey().`,
  );
}

/** Build a keyring for one namespace, or null when the namespace is dormant. */
export function buildKeyring(cfg: NamespaceConfig, namespace: string): Keyring | null {
  const rawKey = cfg.key;
  const isEmpty =
    rawKey == null || (typeof rawKey === "string" && rawKey.trim() === "");
  if (isEmpty) return null;

  const activeVersion = cfg.version?.trim() || "v1";
  if (!VERSION_RE.test(activeVersion)) {
    throw new SealedFieldsError(
      `namespace "${namespace}": version must look like "v1", "v2", ... (got "${activeVersion}").`,
    );
  }
  const keys = new Map<string, Buffer>();
  keys.set(activeVersion, parseKey(rawKey, `namespace "${namespace}" key`));
  for (const [ver, raw] of Object.entries(cfg.retired ?? {})) {
    if (!VERSION_RE.test(ver)) {
      throw new SealedFieldsError(
        `namespace "${namespace}": retired key version "${ver}" must look like "v1", "v2", ...`,
      );
    }
    if (ver === activeVersion) {
      throw new SealedFieldsError(
        `namespace "${namespace}": retired key version "${ver}" collides with the active version.`,
      );
    }
    keys.set(ver, parseKey(raw, `namespace "${namespace}" retired key ${ver}`));
  }
  return { activeVersion, keys };
}
