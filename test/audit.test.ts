import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { KeyNotConfiguredError, createSealedFields, generateKey } from "../src/index.js";

const OLD = generateKey();
const NEW = generateKey();
const CTX = ["users", "email"];

/** Legacy "iv-ct-tag": <b64 iv>:<b64 ciphertext>:<b64 tag>, no AAD. */
function ivCtTag(plaintext: string, key: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "base64url"), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return `${iv.toString("base64")}:${ct.toString("base64")}:${cipher.getAuthTag().toString("base64")}`;
}

describe("audit", () => {
  const before = createSealedFields({ namespaces: { PII: { key: OLD } } });
  const sf = createSealedFields({
    namespaces: { PII: { key: NEW, version: "v2", retired: { v1: OLD } } },
    legacy: ["iv-ct-tag"],
  });
  const stranger = createSealedFields({ namespaces: { PII: { key: generateKey() } } });

  it("classifies every state", () => {
    const cases: [string | null, string, string?][] = [
      [null, "empty"],
      ["", "empty"],
      ["alice@example.com", "plaintext"],
      [sf.seal("a", { context: CTX }), "sealed", "v2"],
      [before.seal("a", { context: CTX }), "sealed", "v1"],
      [sf.seal("a"), "unbound", "v2"],
      [ivCtTag("a", OLD), "legacy"],
      [ivCtTag("a", generateKey()), "invalid"],
      ["v9:" + "A".repeat(40), "unknown-version", "v9"],
      [stranger.seal("a", { context: CTX }).replace(/^v1/, "v2"), "invalid", "v2"],
      ["v2:AAAA", "invalid", "v2"],
      [sf.seal("a", { context: ["contacts", "email"] }), "invalid", "v2"],
    ];
    for (const [value, state, version] of cases) {
      expect(sf.classify(value, { context: CTX }), String(value)).toEqual(version ? { state, version } : { state });
    }
  });

  it("without a context, a bound token is invalid and an unbound one is sealed", () => {
    expect(sf.classify(sf.seal("a", { context: CTX })).state).toBe("invalid");
    expect(sf.classify(sf.seal("a"))).toEqual({ state: "sealed", version: "v2" });
  });

  it("counts a column, with readable tokens by version", () => {
    const column = [
      sf.seal("a", { context: CTX }),
      sf.seal("b", { context: CTX }),
      before.seal("c", { context: CTX }),
      sf.seal("d"),
      "plain",
      null,
      ivCtTag("e", OLD),
      "v2:AAAA",
    ];
    expect(sf.audit(column, { context: CTX })).toEqual({
      total: 8,
      activeVersion: "v2",
      empty: 1,
      plaintext: 1,
      legacy: 1,
      unbound: 1,
      unknownVersion: 0,
      invalid: 1,
      versions: { v2: 3, v1: 1 },
    });
  });

  it("refuses a dormant namespace, even for an empty column", () => {
    const dormant = createSealedFields({ namespaces: { PII: {} }, mode: "dormant", logger: { warn: () => {} } });
    expect(() => dormant.audit([])).toThrow(KeyNotConfiguredError);
    expect(() => dormant.classify("x")).toThrow(KeyNotConfiguredError);
  });
});
