import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  KEY_BYTES,
  buildKeyring,
  parseKey,
  type Keyring,
  type NamespaceConfig,
} from "./keyring.js";
import { looksSealed, parseToken, sealWithKeyring, unsealWithKeyring } from "./seal.js";
import { tryLegacyFormats, type LegacyFormat } from "./legacy.js";
import {
  KeyNotConfiguredError,
  SealedFieldsError,
  SystemicUnsealError,
  UnknownKeyVersionError,
} from "./errors.js";

export { KeyNotConfiguredError, SealedFieldsError, SystemicUnsealError, UnknownKeyVersionError };
export type { LegacyFormat, NamespaceConfig };
export { looksSealed as isSealed };

export interface SealedFieldsLogger {
  warn(message: string): void;
}

export interface SealedFieldsConfig {
  /**
   * Key namespaces. Separate namespaces limit rotation blast radius: rotating
   * a PII key after an incident should not also invalidate, say, every stored
   * TOTP secret. A namespace whose key is empty/undefined is DORMANT (see mode).
   */
  namespaces: Record<string, NamespaceConfig>;
  /** Namespace used when a call doesn't name one. Default: sole namespace if exactly one is configured. */
  defaultNamespace?: string;
  /** HMAC-SHA256 key for blind indexes. Same accepted encodings as namespace keys. */
  blindIndexKey?: string | Buffer;
  /**
   * "strict" (default): sealing in a dormant namespace throws. Fail closed.
   * "dormant": sealing in a dormant namespace returns plaintext and logs one
   * loud warning per process — for the deploy window before keys are
   * provisioned. Never run production PII in dormant mode on purpose.
   */
  mode?: "strict" | "dormant";
  /** Legacy wire formats to accept when unsealing (read-only migration aid). */
  legacy?: readonly LegacyFormat[];
  /**
   * What to do when a token names a key version the keyring doesn't hold.
   * "throw" (default) fails closed. "passthrough" returns the token unchanged
   * and is only for the window of an active key rotation.
   */
  onUnknownVersion?: "throw" | "passthrough";
  logger?: SealedFieldsLogger;
}

/** Field spec for row helpers. Plain array = string fields. jsonFields are
 *  JSON.stringify-ed before sealing and JSON.parse-d after unsealing —
 *  unconditionally in both directions, so the two operations are true
 *  inverses regardless of whether the value was an object or a string. */
export type FieldSpec =
  | readonly string[]
  | { fields?: readonly string[]; jsonFields?: readonly string[] };

function normalizeSpec(spec: FieldSpec): { fields: readonly string[]; jsonFields: readonly string[] } {
  if (Array.isArray(spec)) return { fields: spec, jsonFields: [] };
  const s = spec as { fields?: readonly string[]; jsonFields?: readonly string[] };
  return { fields: s.fields ?? [], jsonFields: s.jsonFields ?? [] };
}

export class SealedFields {
  private readonly rings = new Map<string, Keyring | null>();
  private readonly defaultNs: string | null;
  private readonly indexKey: Buffer | null;
  private readonly mode: "strict" | "dormant";
  private readonly legacy: readonly LegacyFormat[];
  private readonly onUnknownVersion: "throw" | "passthrough";
  private readonly logger: SealedFieldsLogger;
  private warnedDormant = false;

  constructor(config: SealedFieldsConfig) {
    const names = Object.keys(config.namespaces);
    if (names.length === 0) {
      throw new SealedFieldsError("at least one namespace must be configured.");
    }
    for (const name of names) {
      this.rings.set(name, buildKeyring(config.namespaces[name]!, name));
    }
    if (config.defaultNamespace && !this.rings.has(config.defaultNamespace)) {
      throw new SealedFieldsError(
        `defaultNamespace "${config.defaultNamespace}" is not a configured namespace.`,
      );
    }
    this.defaultNs = config.defaultNamespace ?? (names.length === 1 ? names[0]! : null);
    this.indexKey =
      config.blindIndexKey != null &&
      !(typeof config.blindIndexKey === "string" && config.blindIndexKey.trim() === "")
        ? parseKey(config.blindIndexKey, "blindIndexKey")
        : null;
    this.mode = config.mode ?? "strict";
    this.legacy = config.legacy ?? [];
    this.onUnknownVersion = config.onUnknownVersion ?? "throw";
    this.logger = config.logger ?? console;
  }

  private resolveNs(namespace?: string): string {
    const ns = namespace ?? this.defaultNs;
    if (!ns) {
      throw new SealedFieldsError(
        "no namespace given and no defaultNamespace configured (multiple namespaces exist).",
      );
    }
    if (!this.rings.has(ns)) throw new SealedFieldsError(`unknown namespace "${ns}".`);
    return ns;
  }

  private warnDormantOnce(ns: string): void {
    if (this.warnedDormant) return;
    this.warnedDormant = true;
    this.logger.warn(
      `[sealed-fields] SECURITY: namespace "${ns}" has no key configured — sealed columns are ` +
        `being written in PLAINTEXT (mode: "dormant"). Provision a key before production traffic.`,
    );
  }

  /** True when this namespace has a usable keyring. */
  isConfigured(namespace?: string): boolean {
    return this.rings.get(this.resolveNs(namespace)) != null;
  }

  /** Encrypt a UTF-8 string under the namespace's active key. */
  seal(plaintext: string, namespace?: string): string {
    const ns = this.resolveNs(namespace);
    const ring = this.rings.get(ns);
    if (!ring) {
      if (this.mode === "strict") {
        throw new KeyNotConfiguredError(
          `namespace "${ns}" has no key configured; cannot seal (mode: "strict").`,
        );
      }
      this.warnDormantOnce(ns);
      return plaintext;
    }
    return sealWithKeyring(plaintext, ring);
  }

  /**
   * Decrypt a value. Non-token strings pass through unchanged (legacy
   * plaintext, pre-migration rows). Tokens that structurally match the
   * canonical format or an enabled legacy format are decrypted; an
   * authentication failure on a matching token throws — it is an integrity
   * problem, never plaintext.
   */
  unseal(value: string, namespace?: string): string {
    const ns = this.resolveNs(namespace);
    const ring = this.rings.get(ns);
    if (parseToken(value)) {
      if (!ring) {
        if (this.mode === "strict") {
          throw new KeyNotConfiguredError(
            `namespace "${ns}" has no key configured; cannot unseal a sealed value.`,
          );
        }
        this.warnDormantOnce(ns);
        return value;
      }
      return unsealWithKeyring(value, ring, ns, this.onUnknownVersion);
    }
    if (ring && this.legacy.length > 0) {
      const legacy = tryLegacyFormats(value, this.legacy, ring);
      if (legacy !== null) return legacy;
    }
    return value; // plaintext passthrough
  }

  /** Seal only when a value is present. Convenience for nullable columns. */
  maybeSeal(value: string | null | undefined, namespace?: string): string | null {
    if (value == null || value === "") return null;
    return this.seal(value, namespace);
  }

  /** Unseal only when a value is present. */
  maybeUnseal(value: string | null | undefined, namespace?: string): string | null {
    if (value == null || value === "") return null;
    return this.unseal(value, namespace);
  }

  /**
   * Deterministic HMAC-SHA256 lookup token for equality queries on an
   * otherwise-sealed column. ONLY for high-entropy values (email, username,
   * phone). Never index a low-entropy field (state, zip code, birth year): a
   * deterministic MAC over a small domain is trivially dictionary-attacked.
   *
   * Normalization (default on): trim + Unicode-aware lowercase, so
   * "Alice@Example.com " and "alice@example.com" index identically.
   */
  blindIndex(value: string, options?: { normalize?: boolean }): string {
    if (!this.indexKey) {
      throw new KeyNotConfiguredError("blindIndexKey is not configured; cannot build a blind index.");
    }
    const normalized = options?.normalize === false ? value : value.trim().toLowerCase();
    return createHmac("sha256", this.indexKey).update(normalized, "utf8").digest("hex");
  }

  /** Seal the listed fields on a row (insert/update payload). Returns a
   *  shallow copy; null/empty/non-string/already-sealed values are skipped. */
  sealRow<T extends Record<string, unknown>>(row: T, spec: FieldSpec, namespace?: string): T {
    const { fields, jsonFields } = normalizeSpec(spec);
    const out: Record<string, unknown> = { ...row };
    for (const field of jsonFields) {
      const v = out[field];
      if (v != null) out[field] = JSON.stringify(v);
    }
    for (const field of [...fields, ...jsonFields]) {
      const v = out[field];
      if (typeof v !== "string" || v.length === 0) continue;
      if (looksSealed(v)) continue;
      out[field] = this.seal(v, namespace);
    }
    return out as T;
  }

  private unsealRowInternal<T extends Record<string, unknown>>(
    row: T,
    spec: FieldSpec,
    namespace?: string,
  ): { out: T; failures: number; attempts: number } {
    const { fields, jsonFields } = normalizeSpec(spec);
    const out: Record<string, unknown> = { ...row };
    let failures = 0;
    let attempts = 0;
    for (const field of [...fields, ...jsonFields]) {
      const v = out[field];
      if (typeof v !== "string" || v.length === 0) continue;
      if (!looksSealed(v)) continue;
      attempts++;
      try {
        out[field] = this.unseal(v, namespace);
      } catch (err) {
        // Never hand raw ciphertext to a caller: null is a safe sentinel the
        // UI renders as missing. unsealRows detects systemic failure below.
        this.logger.warn(`[sealed-fields] unseal failed for field "${field}": ${String(err)}`);
        out[field] = null;
        failures++;
      }
    }
    for (const field of jsonFields) {
      const v = out[field];
      if (typeof v === "string" && v.length > 0) {
        // Leave the raw string on a parse failure. Never null data that
        // decrypted successfully.
        try {
          out[field] = JSON.parse(v);
        } catch {
          /* leave as-is */
        }
      }
    }
    return { out: out as T, failures, attempts };
  }

  /** Unseal the listed fields on one row. Plaintext values pass through;
   *  a failed unseal nulls the field rather than exposing ciphertext. */
  unsealRow<T extends Record<string, unknown>>(row: T, spec: FieldSpec, namespace?: string): T {
    return this.unsealRowInternal(row, spec, namespace).out;
  }

  /**
   * Unseal fields across a batch of rows. If more than half of the ATTEMPTED
   * unseals fail (minimum 5 attempts), a systemic key error is assumed and
   * SystemicUnsealError is thrown so the caller can fail the page instead of
   * silently serving nulls. Attempts count only genuinely sealed values, so a
   * mixed plaintext/sealed table mid-migration cannot dilute the failure rate.
   */
  unsealRows<T extends Record<string, unknown>>(rows: readonly T[], spec: FieldSpec, namespace?: string): T[] {
    let totalFailures = 0;
    let totalAttempts = 0;
    const result = rows.map((row) => {
      const { out, failures, attempts } = this.unsealRowInternal(row, spec, namespace);
      totalFailures += failures;
      totalAttempts += attempts;
      return out;
    });
    if (totalAttempts >= 5 && totalFailures / totalAttempts > 0.5) {
      throw new SystemicUnsealError(totalFailures, totalAttempts);
    }
    return result;
  }
}

export function createSealedFields(config: SealedFieldsConfig): SealedFields {
  return new SealedFields(config);
}

/** Fresh 32-byte key, base64url without padding. Suitable for any key slot. */
export function generateKey(): string {
  return randomBytes(KEY_BYTES).toString("base64url");
}

/**
 * SHA-256 hex digest of a one-time token (magic link, verification code) for
 * safe storage. Store the hash, send the plaintext; verify by re-hashing. A
 * leaked database cannot be used to consume pending tokens.
 */
export function hashToken(token: string): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new SealedFieldsError("hashToken requires a non-empty string.");
  }
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Build a SealedFields from environment variables, by convention:
 *
 *   SEALED_KEY_<NS>            active key for namespace <NS>
 *   SEALED_KEY_<NS>_VERSION    active key version label (default "v1")
 *   SEALED_KEY_<NS>_RETIRED    comma-separated "v1:<key>,v2:<key>" retired keys
 *   SEALED_BLIND_INDEX_KEY     blind index HMAC key
 *
 * Namespaces must be listed explicitly — env scanning is deliberately not done,
 * so a typo'd variable can never silently create a keyless namespace.
 */
export function sealedFieldsFromEnv(
  namespaces: readonly string[],
  options?: Omit<SealedFieldsConfig, "namespaces" | "blindIndexKey"> & {
    env?: Record<string, string | undefined>;
  },
): SealedFields {
  const env = options?.env ?? process.env;
  const nsConfig: Record<string, NamespaceConfig> = {};
  for (const ns of namespaces) {
    const retiredRaw = env[`SEALED_KEY_${ns}_RETIRED`]?.trim();
    const retired: Record<string, string> = {};
    if (retiredRaw) {
      for (const pair of retiredRaw.split(",")) {
        const trimmed = pair.trim();
        if (!trimmed) continue;
        const idx = trimmed.indexOf(":");
        if (idx <= 0 || idx === trimmed.length - 1) {
          throw new SealedFieldsError(
            `SEALED_KEY_${ns}_RETIRED entries must look like "v1:<key>" (got "${trimmed}").`,
          );
        }
        retired[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
      }
    }
    const nsEntry: NamespaceConfig = { retired };
    const key = env[`SEALED_KEY_${ns}`];
    if (key != null) nsEntry.key = key;
    const version = env[`SEALED_KEY_${ns}_VERSION`];
    if (version != null) nsEntry.version = version;
    nsConfig[ns] = nsEntry;
  }
  const { env: _drop, ...rest } = options ?? {};
  const config: SealedFieldsConfig = { ...rest, namespaces: nsConfig };
  const blindIndexKey = env["SEALED_BLIND_INDEX_KEY"];
  if (blindIndexKey != null) config.blindIndexKey = blindIndexKey;
  return new SealedFields(config);
}
