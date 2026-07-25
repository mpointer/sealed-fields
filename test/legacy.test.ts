import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createSealedFields, generateKey, isSealed } from "../src/index.js";

const KEY = generateKey();
const KEY_BUF = Buffer.from(KEY, "base64url");
const OLD_KEY = generateKey();
const OLD_KEY_BUF = Buffer.from(OLD_KEY, "base64url");

// Reference encoders reproducing the two legacy production formats exactly.

/** Format "iv-ct-tag": <b64 iv>:<b64 ciphertext>:<b64 tag>, no AAD. */
function encodeIvCtTag(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${ct.toString("base64")}:${tag.toString("base64")}`;
}

/** Format "v1-iv-tag-ct": v1:<b64 iv>:<b64 tag>:<b64 ciphertext>, no AAD. */
function encodeV1IvTagCt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ct.toString("base64")}`;
}

describe("legacy decoders", () => {
  it("unseals the iv-ct-tag format when enabled", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY } },
      legacy: ["iv-ct-tag"],
    });
    expect(sf.unseal(encodeIvCtTag("legacy value", KEY_BUF))).toBe("legacy value");
  });

  it("unseals the v1-iv-tag-ct format when enabled, despite the v1 prefix", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY } },
      legacy: ["v1-iv-tag-ct"],
    });
    const token = encodeV1IvTagCt("older value", KEY_BUF);
    expect(isSealed(token)).toBe(false); // 4 colon parts, not canonical
    expect(sf.unseal(token)).toBe("older value");
  });

  it("tries retired keys for versionless legacy tokens", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY, version: "v2", retired: { v1: OLD_KEY } } },
      legacy: ["iv-ct-tag"],
    });
    expect(sf.unseal(encodeIvCtTag("pre-rotation", OLD_KEY_BUF))).toBe("pre-rotation");
  });

  it("throws when a structurally matching legacy token authenticates under no key", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY } },
      legacy: ["iv-ct-tag"],
    });
    const foreign = encodeIvCtTag("someone else's data", OLD_KEY_BUF);
    expect(() => sf.unseal(foreign)).toThrow();
  });

  it("ignores legacy formats that are not enabled", () => {
    const sf = createSealedFields({ namespaces: { PII: { key: KEY } } });
    const token = encodeIvCtTag("x", KEY_BUF);
    expect(sf.unseal(token)).toBe(token); // passthrough: treated as plaintext
  });

  it("does not mistake ordinary colon-y text for a legacy token", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY } },
      legacy: ["iv-ct-tag", "v1-iv-tag-ct"],
    });
    for (const s of ["a:b:c", "12:30:45", "v1:looks:like:legacy but is not base64 of the right lengths"]) {
      expect(sf.unseal(s)).toBe(s);
    }
  });

  it("re-sealing legacy data writes the canonical format", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: KEY } },
      legacy: ["iv-ct-tag"],
    });
    const plain = sf.unseal(encodeIvCtTag("migrate me", KEY_BUF));
    const modern = sf.seal(plain);
    expect(modern).toMatch(/^v1:[A-Za-z0-9_-]+$/);
    expect(sf.unseal(modern)).toBe("migrate me");
  });
});
