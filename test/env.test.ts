import { describe, expect, it } from "vitest";
import { SealedFieldsError, generateKey, sealedFieldsFromEnv } from "../src/index.js";

const K1 = generateKey();
const K2 = generateKey();
const IDX = generateKey();

describe("sealedFieldsFromEnv", () => {
  it("builds namespaces, versions, retired keys, and blind index from env", () => {
    const env = {
      SEALED_KEY_PII: K2,
      SEALED_KEY_PII_VERSION: "v2",
      SEALED_KEY_PII_RETIRED: `v1:${K1}`,
      SEALED_KEY_TOTP: K1,
      SEALED_BLIND_INDEX_KEY: IDX,
    };
    const sf = sealedFieldsFromEnv(["PII", "TOTP"], { env });
    const token = sf.seal("x", "PII");
    expect(token).toMatch(/^v2:/);
    expect(sf.unseal(token, "PII")).toBe("x");
    expect(sf.blindIndex("x")).toMatch(/^[0-9a-f]{64}$/);

    // v1 tokens written before the rotation still unseal
    const old = sealedFieldsFromEnv(["PII"], { env: { SEALED_KEY_PII: K1 } });
    expect(sf.unseal(old.seal("old", "PII"), "PII")).toBe("old");
  });

  it("leaves unset namespaces dormant instead of inventing keys", () => {
    const sf = sealedFieldsFromEnv(["PII"], { env: {}, mode: "dormant", logger: { warn: () => {} } });
    expect(sf.isConfigured("PII")).toBe(false);
    expect(sf.seal("x", "PII")).toBe("x");
  });

  it("rejects malformed retired-key entries", () => {
    expect(() =>
      sealedFieldsFromEnv(["PII"], { env: { SEALED_KEY_PII: K1, SEALED_KEY_PII_RETIRED: "nocolon" } }),
    ).toThrow(SealedFieldsError);
  });
});
