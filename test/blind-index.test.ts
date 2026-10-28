import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { KeyNotConfiguredError, SealedFieldsError, createSealedFields, generateKey } from "../src/index.js";

const KEY = generateKey();
const INDEX_KEY = generateKey();

function makeSf() {
  return createSealedFields({
    namespaces: { PII: { key: KEY } },
    blindIndexKey: INDEX_KEY,
  });
}

describe("blindIndex", () => {
  it("context separates columns and leaves context-free tokens unchanged", () => {
    const sf = makeSf();
    const plain = sf.blindIndex("alice@example.com");
    const users = sf.blindIndex("alice@example.com", { context: "users.email" });
    const contacts = sf.blindIndex("alice@example.com", { context: "contacts.email" });
    expect(new Set([plain, users, contacts]).size).toBe(3);
    expect(sf.blindIndex("alice@example.com", { context: "" })).toBe(plain);
    expect(() => sf.blindIndex("x", { context: "a\0b" })).toThrow(SealedFieldsError);
  });

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

  it("accepts a custom normalizer in place of the boolean", () => {
    const sf = makeSf();
    const upper = (v: string) => v.trim().toUpperCase();
    expect(sf.blindIndex("  alice ", { normalize: upper })).toBe(sf.blindIndex("ALICE", { normalize: false }));
    expect(sf.blindIndex("alice", { normalize: upper })).not.toBe(sf.blindIndex("alice"));
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
