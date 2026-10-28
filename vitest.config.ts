import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**"],
      reporter: ["text"],
      // A few points under current levels: fails on a real drop, not noise.
      thresholds: { lines: 94, statements: 94, branches: 90, functions: 100 },
    },
  },
});
