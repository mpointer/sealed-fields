import { describe, expect, it } from "vitest";
import { SystemicUnsealError, createSealedFields, generateKey, isSealed } from "../src/index.js";

const KEY = generateKey();
const WRONG_KEY = generateKey();

const quiet = { warn: () => {} };

function makeSf(key = KEY) {
  return createSealedFields({ namespaces: { PII: { key } }, logger: quiet });
}

const FIELDS = ["name", "notes"] as const;

describe("sealRow", () => {
  it("seals listed string fields, skips null/empty/non-string, returns a copy", () => {
    const sf = makeSf();
    const row = { id: 7, name: "Ada", notes: "", tags: ["x"], extra: "untouched" };
    const out = sf.sealRow(row, FIELDS);
    expect(isSealed(out.name)).toBe(true);
    expect(out.notes).toBe("");
    expect(out.extra).toBe("untouched");
    expect(row.name).toBe("Ada"); // input not mutated
  });

  it("does not double-seal an already sealed value", () => {
    const sf = makeSf();
    const once = sf.sealRow({ name: "Ada" }, FIELDS);
    const twice = sf.sealRow(once, FIELDS);
    expect(twice.name).toBe(once.name);
    expect(sf.unsealRow(twice, FIELDS).name).toBe("Ada");
  });
});

describe("unsealRow / unsealRows", () => {
  it("round-trips and tolerates mixed plaintext rows mid-migration", () => {
    const sf = makeSf();
    const sealed = sf.sealRow({ name: "Ada", notes: "n1" }, FIELDS);
    const legacyPlain = { name: "Grace", notes: "n2" };
    const rows = sf.unsealRows([sealed, legacyPlain], FIELDS);
    expect(rows[0]).toMatchObject({ name: "Ada", notes: "n1" });
    expect(rows[1]).toMatchObject({ name: "Grace", notes: "n2" });
  });

  it("nulls a field on isolated unseal failure instead of exposing ciphertext", () => {
    const writer = makeSf();
    const reader = makeSf(WRONG_KEY);
    const sealed = writer.sealRow({ name: "Ada" }, FIELDS);
    const out = reader.unsealRow(sealed, FIELDS);
    expect(out.name).toBeNull();
  });

  it("throws SystemicUnsealError when most attempts fail (>=5 attempts, >50%)", () => {
    const writer = makeSf();
    const reader = makeSf(WRONG_KEY);
    const rows = Array.from({ length: 5 }, (_, i) => writer.sealRow({ name: `p${i}`, notes: null }, FIELDS));
    expect(() => reader.unsealRows(rows, FIELDS)).toThrow(SystemicUnsealError);
  });

  it("does not throw systemic error below the 5-attempt floor", () => {
    const writer = makeSf();
    const reader = makeSf(WRONG_KEY);
    const rows = Array.from({ length: 4 }, (_, i) => writer.sealRow({ name: `p${i}` }, FIELDS));
    const out = reader.unsealRows(rows, FIELDS);
    expect(out.every((r) => r.name === null)).toBe(true);
  });

  it("plaintext fields do not dilute the systemic failure rate", () => {
    const writer = makeSf();
    const reader = makeSf(WRONG_KEY);
    // 5 sealed (all will fail) + 20 plaintext rows. Raw slot math would say
    // 5/25 = 20% and stay silent; attempted math says 5/5 = 100% and throws.
    const rows = [
      ...Array.from({ length: 5 }, (_, i) => writer.sealRow({ name: `p${i}` }, FIELDS)),
      ...Array.from({ length: 20 }, (_, i) => ({ name: `plain${i}` })),
    ];
    expect(() => reader.unsealRows(rows, FIELDS)).toThrow(SystemicUnsealError);
  });
});

describe("jsonFields", () => {
  const SPEC = { fields: ["name"], jsonFields: ["snapshot"] } as const;

  it("stringify-all on seal and parse-all on unseal are true inverses for objects", () => {
    const sf = makeSf();
    const row = { name: "Ada", snapshot: { a: 1, list: [1, 2] } };
    const sealed = sf.sealRow(row, SPEC);
    expect(isSealed(sealed.snapshot as unknown as string)).toBe(true);
    const out = sf.unsealRow(sealed, SPEC);
    expect(out.snapshot).toEqual({ a: 1, list: [1, 2] });
  });

  it("plain strings in a jsonField survive the round trip as strings", () => {
    // The regression this guards: conditionally stringifying only objects
    // while unconditionally parsing on read returns null/garbage for every
    // string-valued row. Stringify-all / parse-all must be inverses.
    const sf = makeSf();
    const row = { name: "Ada", snapshot: "free text prompt" };
    const out = sf.unsealRow(sf.sealRow(row, SPEC), SPEC);
    expect(out.snapshot).toBe("free text prompt");
  });

  it("null jsonField values pass through", () => {
    const sf = makeSf();
    const out = sf.unsealRow(sf.sealRow({ name: "Ada", snapshot: null }, SPEC), SPEC);
    expect(out.snapshot).toBeNull();
  });
});
