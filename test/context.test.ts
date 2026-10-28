import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SealedFieldsError, SystemicUnsealError, createSealedFields, generateKey } from "../src/index.js";

const KEY = generateKey();

function makeSf(extra: Record<string, unknown> = {}) {
  const warnings: string[] = [];
  const sf = createSealedFields({
    namespaces: { PII: { key: KEY } },
    logger: { warn: (m) => warnings.push(m) },
    ...extra,
  });
  return { sf, warnings };
}

describe("context binding", () => {
  it("round-trips, and a string equals the one-part array", () => {
    const { sf } = makeSf();
    expect(sf.unseal(sf.seal("x", { context: ["users", "email"] }), { context: ["users", "email"] })).toBe("x");
    expect(sf.unseal(sf.seal("x", { context: "users.email" }), { context: ["users.email"] })).toBe("x");
  });

  it("a moved or downgraded token fails authentication", () => {
    const { sf } = makeSf();
    const token = sf.seal("x", { context: ["users", "email"] });
    expect(() => sf.unseal(token, { context: ["users", "notes"] })).toThrow();
    expect(() => sf.unseal(token)).toThrow();
    // Joining with NUL keeps parts unambiguous.
    const ab = sf.seal("x", { context: ["a.b", "c"] });
    expect(() => sf.unseal(ab, { context: ["a", "b.c"] })).toThrow();
  });

  it("an unbound token read with a context fails without fallback", () => {
    const { sf } = makeSf();
    expect(() => sf.unseal(sf.seal("x"), { context: ["users", "email"] })).toThrow();
  });

  it('"" and [] mean no context; empty or NUL parts are rejected', () => {
    const { sf } = makeSf();
    const plain = sf.seal("x");
    expect(sf.unseal(plain, { context: "" })).toBe("x");
    expect(sf.unseal(plain, { context: [] })).toBe("x");
    expect(() => sf.seal("x", { context: ["users", ""] })).toThrow(SealedFieldsError);
    expect(() => sf.seal("x", { context: "a\0b" })).toThrow(SealedFieldsError);
  });

  it("a namespace string still works as the second argument", () => {
    const { sf } = makeSf();
    expect(sf.unseal(sf.seal("x", "PII"), "PII")).toBe("x");
    expect(sf.maybeUnseal(sf.maybeSeal("x", { namespace: "PII", context: "t.c" }), { context: "t.c" })).toBe("x");
  });

  it("rejects a non-boolean contextFallback", () => {
    expect(() => makeSf({ contextFallback: "yes" })).toThrow(/boolean/);
  });
});

describe("contextFallback", () => {
  it("reads unbound tokens, counts them, and warns once per namespace", () => {
    const { sf, warnings } = makeSf({ contextFallback: true });
    const unbound = sf.seal("x");
    expect(sf.unseal(unbound, { context: "users.email" })).toBe("x");
    expect(sf.unseal(unbound, { context: "users.email" })).toBe("x");
    expect(sf.unseal(sf.seal("y", { context: "users.email" }), { context: "users.email" })).toBe("y");
    expect(sf.unseal(unbound)).toBe("x"); // no context: not an unbound read
    expect(sf.stats()).toEqual({ unboundReads: 2 });
    expect(warnings).toHaveLength(1);
  });

  it("does not let a bound token move: fallback only drops the context", () => {
    const { sf } = makeSf({ contextFallback: true });
    const token = sf.seal("x", { context: "users.email" });
    expect(() => sf.unseal(token, { context: "users.notes" })).toThrow();
    expect(sf.stats().unboundReads).toBe(0);
  });

  it("row helpers bind per field, null a moved value, and count fallback reads", () => {
    const spec = { fields: ["email"], context: (field: string, row: Record<string, unknown>) => ["users", field, String(row.id)] };
    const { sf } = makeSf();
    const a = sf.sealRow({ id: 1, email: "a@x" }, spec);
    const b = sf.sealRow({ id: 2, email: "b@x" }, spec);
    expect(sf.unsealRow(a, spec)).toEqual({ id: 1, email: "a@x" });
    expect(sf.unsealRow({ ...b, email: a.email }, spec)).toEqual({ id: 2, email: null });

    const { sf: migrating } = makeSf({ contextFallback: true });
    const old = Array.from({ length: 5 }, (_, i) => ({ id: i, email: migrating.seal("e") }));
    expect(() => migrating.unsealRows(old, spec)).not.toThrow(SystemicUnsealError);
    expect(migrating.stats().unboundReads).toBe(5);
  });

  it("legacy tokens need fallback when a context is given, and count as unbound", () => {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", Buffer.from(KEY, "base64url"), iv);
    const ct = Buffer.concat([c.update("old", "utf8"), c.final()]);
    const token = `${iv.toString("base64")}:${ct.toString("base64")}:${c.getAuthTag().toString("base64")}`;
    const { sf: strict } = makeSf({ legacy: ["iv-ct-tag"] });
    expect(() => strict.unseal(token, { context: "t.c" })).toThrow(/legacy/);
    expect(strict.unseal(token)).toBe("old");
    const { sf: migrating } = makeSf({ legacy: ["iv-ct-tag"], contextFallback: true });
    expect(migrating.unseal(token, { context: "t.c" })).toBe("old");
    expect(migrating.stats().unboundReads).toBe(1);
  });
});
