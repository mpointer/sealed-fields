import { describe, expect, it } from "vitest";
import {
  KeyNotConfiguredError,
  SealedFieldsError,
  UnknownKeyVersionError,
  createSealedFields,
  generateKey,
  hashToken,
  isSealed,
} from "../src/index.js";

const KEY_A = generateKey();
const KEY_B = generateKey();

function makeSf(overrides: Record<string, unknown> = {}) {
  return createSealedFields({
    namespaces: { PII: { key: KEY_A } },
    ...overrides,
  });
}

describe("seal / unseal", () => {
  it("round-trips UTF-8 including multibyte", () => {
    const sf = makeSf();
    for (const text of ["hello", "", "héllo wörld — 你好 🚀", "a".repeat(10_000)]) {
      if (text === "") continue; // empty handled by maybeSeal
      expect(sf.unseal(sf.seal(text))).toBe(text);
    }
  });

  it("emits the canonical v-prefixed format", () => {
    const token = makeSf().seal("secret");
    expect(token).toMatch(/^v1:[A-Za-z0-9_-]+$/);
    expect(isSealed(token)).toBe(true);
  });

  it("produces a different token per call (random nonce)", () => {
    const sf = makeSf();
    expect(sf.seal("same")).not.toBe(sf.seal("same"));
  });

  it("passes plaintext through unseal unchanged", () => {
    const sf = makeSf();
    expect(sf.unseal("just some text")).toBe("just some text");
    expect(sf.unseal("colon:separated:text")).toBe("colon:separated:text");
  });

  it("accepts hex, base64, base64url, and Buffer keys equivalently", () => {
    const raw = Buffer.from(KEY_A.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const variants = [
      raw.toString("hex"),
      raw.toString("base64"),
      raw.toString("base64url"),
      raw,
    ];
    const tokens = variants.map((key) =>
      createSealedFields({ namespaces: { PII: { key } } }).seal("x"),
    );
    const reader = makeSf();
    for (const t of tokens) expect(reader.unseal(t)).toBe("x");
  });

  it("rejects malformed keys", () => {
    expect(() => createSealedFields({ namespaces: { PII: { key: "tooshort" } } })).toThrow(
      KeyNotConfiguredError,
    );
  });

  it("tampering with the version prefix fails authentication (AAD binding)", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY_A, version: "v2", retired: { v1: KEY_A } } },
    });
    const token = sf.seal("secret"); // sealed under v2, AAD "v2"
    const forged = token.replace(/^v2:/, "v1:"); // same key is present as v1
    expect(() => sf.unseal(forged)).toThrow(); // GCM auth failure, not silence
  });

  it("tampered ciphertext throws, never returns garbage", () => {
    const sf = makeSf();
    const token = sf.seal("secret");
    const [v, blob] = token.split(":") as [string, string];
    const corrupted = `${v}:${blob.slice(0, -4)}AAAA`;
    expect(() => sf.unseal(corrupted)).toThrow();
  });
});

describe("key rotation", () => {
  it("unseals old-version tokens via retired keys; writes use the active key", () => {
    const oldSf = makeSf(); // v1 under KEY_A
    const oldToken = oldSf.seal("legacy row");
    const rotated = createSealedFields({
      namespaces: { PII: { key: KEY_B, version: "v2", retired: { v1: KEY_A } } },
    });
    expect(rotated.unseal(oldToken)).toBe("legacy row");
    expect(rotated.seal("new row")).toMatch(/^v2:/);
  });

  it("unknown version throws by default", () => {
    const oldSf = createSealedFields({ namespaces: { PII: { key: KEY_A, version: "v9" } } });
    const token = oldSf.seal("x");
    expect(() => makeSf().unseal(token)).toThrow(UnknownKeyVersionError);
  });

  it("unknown version passes through when explicitly configured for migration", () => {
    const oldSf = createSealedFields({ namespaces: { PII: { key: KEY_A, version: "v9" } } });
    const token = oldSf.seal("x");
    const migrating = makeSf({ onUnknownVersion: "passthrough" });
    expect(migrating.unseal(token)).toBe(token);
  });

  it("rejects a retired version that collides with the active version", () => {
    expect(() =>
      createSealedFields({
        namespaces: { PII: { key: KEY_A, version: "v1", retired: { v1: KEY_B } } },
      }),
    ).toThrow(SealedFieldsError);
  });
});

describe("namespaces", () => {
  it("keeps namespaces cryptographically separate", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY_A }, TOTP: { key: KEY_B } },
    });
    const token = sf.seal("secret", "PII");
    expect(sf.unseal(token, "PII")).toBe("secret");
    expect(() => sf.unseal(token, "TOTP")).toThrow(); // wrong key = auth failure
  });

  it("requires an explicit namespace when several exist and no default is set", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY_A }, TOTP: { key: KEY_B } },
    });
    expect(() => sf.seal("x")).toThrow(SealedFieldsError);
  });

  it("honors defaultNamespace", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY_A }, TOTP: { key: KEY_B } },
      defaultNamespace: "PII",
    });
    expect(sf.unseal(sf.seal("x"))).toBe("x");
  });
});

describe("strict vs dormant mode", () => {
  it("strict (default): sealing without a key throws", () => {
    const sf = createSealedFields({ namespaces: { PII: {} } });
    expect(() => sf.seal("x")).toThrow(KeyNotConfiguredError);
    expect(sf.isConfigured()).toBe(false);
  });

  it("dormant: sealing without a key passes plaintext through and warns exactly once", () => {
    const warnings: string[] = [];
    const sf = createSealedFields({
      namespaces: { PII: {} },
      mode: "dormant",
      logger: { warn: (m) => warnings.push(m) },
    });
    expect(sf.seal("x")).toBe("x");
    expect(sf.seal("y")).toBe("y");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("PLAINTEXT");
  });
});

describe("maybeSeal / maybeUnseal", () => {
  it("maps null, undefined, and empty string to null", () => {
    const sf = makeSf();
    expect(sf.maybeSeal(null)).toBeNull();
    expect(sf.maybeSeal(undefined)).toBeNull();
    expect(sf.maybeSeal("")).toBeNull();
    expect(sf.maybeUnseal(null)).toBeNull();
    expect(sf.maybeUnseal(sf.maybeSeal("v")!)).toBe("v");
  });
});

describe("utilities", () => {
  it("generateKey returns a parseable 32-byte key", () => {
    const key = generateKey();
    expect(Buffer.from(key, "base64url")).toHaveLength(32);
  });

  it("hashToken is deterministic sha256 hex and rejects empty input", () => {
    expect(hashToken("abc")).toBe(hashToken("abc"));
    expect(hashToken("abc")).toMatch(/^[0-9a-f]{64}$/);
    expect(() => hashToken("")).toThrow();
  });

  it("isSealed rejects lookalikes", () => {
    expect(isSealed("v1:not-base64!!!")).toBe(false);
    expect(isSealed("v1:aGk")).toBe(false); // too short to hold nonce+tag
    expect(isSealed("plain text")).toBe(false);
    expect(isSealed(null)).toBe(false);
    expect(isSealed(42)).toBe(false);
  });
});
