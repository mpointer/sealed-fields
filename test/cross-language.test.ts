import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createSealedFields } from "../src/index.js";

// Shared cross-language vectors: every token in test/vectors.json must decode
// in BOTH implementations (this suite and python/tests). The set includes a
// token from the original Python reference implementation (padded urlsafe
// base64), one from this TypeScript implementation, and one from the Python
// package — proving the wire format end to end:
// AES-256-GCM, nonce || ciphertext || tag, key version as AAD.
const VECTORS = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")) as {
  key: string;
  plaintext: string;
  tokens: Record<string, string>;
  blindIndex: { key: string; value: string; hex: string };
};

describe("cross-language wire compatibility", () => {
  it("unseals every shared vector token", () => {
    const sf = createSealedFields({
      namespaces: { PII: { key: VECTORS.key } },
      blindIndexKey: VECTORS.blindIndex.key,
    });
    for (const [name, token] of Object.entries(VECTORS.tokens)) {
      expect(sf.unseal(token), name).toBe(VECTORS.plaintext);
    }
    expect(sf.blindIndex(VECTORS.blindIndex.value)).toBe(VECTORS.blindIndex.hex);
  });

  it("our own output stays self-consistent under the shared key", () => {
    const sf = createSealedFields({ namespaces: { PII: { key: VECTORS.key } } });
    const token = sf.seal(VECTORS.plaintext);
    expect(sf.unseal(token)).toBe(VECTORS.plaintext);
    expect(token).toMatch(/^v1:[A-Za-z0-9_-]+$/);
  });
});
