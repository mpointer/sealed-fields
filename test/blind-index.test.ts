import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { KeyNotConfiguredError, createSealedFields, generateKey } from "../src/index.js";

const KEY = generateKey();
const INDEX_KEY = generateKey();

function makeSf() {
  return createSealedFields({
    namespaces: { PII: { key: KEY } },
    blindIndexKey: INDEX_KEY,
  });
}

describe("blindIndex", () => {
  it("is deterministic for equal values", () => {
    const sf = makeSf();
    expect(sf.blindIndex("alice@example.com")).toBe(sf.blindIndex("alice@example.com"));
  });

  it("normalizes trim + lowercase by default", () => {
    const sf = makeSf();
    expect(sf.blindIndex("  Alice@Example.COM ")).toBe(sf.blindIndex("alice@example.com"));
  });

  it("respects normalize: false", () => {
    const sf = makeSf();
    expect(sf.blindIndex("Alice", { normalize: false })).not.toBe(sf.blindIndex("alice", { normalize: false }));
  });

  it("matches a reference HMAC-SHA256 computation", () => {
    const sf = makeSf();
    const expected = createHmac("sha256", Buffer.from(INDEX_KEY, "base64url"))
      .update("alice@example.com", "utf8")
      .digest("hex");
    expect(sf.blindIndex("alice@example.com")).toBe(expected);
  });

  it("produces different tokens under different index keys", () => {
    const other = createSealedFields({
      namespaces: { PII: { key: KEY } },
      blindIndexKey: generateKey(),
    });
    expect(makeSf().blindIndex("v")).not.toBe(other.blindIndex("v"));
  });

  it("throws when no blind index key is configured", () => {
    const sf = createSealedFields({ namespaces: { PII: { key: KEY } } });
    expect(() => sf.blindIndex("x")).toThrow(KeyNotConfiguredError);
  });
});
