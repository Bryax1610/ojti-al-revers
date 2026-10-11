import { expect, it } from "vitest";
import {
  javaScriptAnalysisResourceControlsSchema,
  javaScriptStaticCheckpointReserveBytes,
} from "./javascriptAnalysisResourceControls.js";

it("keeps omitted operational choices absent and validates explicit semantic budgets", () => {
  expect(javaScriptAnalysisResourceControlsSchema.parse({})).toEqual({});
  expect(
    javaScriptAnalysisResourceControlsSchema.parse({
      max_semantic_nodes: 750_000,
      max_semantic_nodes_per_file: 700_000,
    }),
  ).toEqual({
    max_semantic_nodes: 750_000,
    max_semantic_nodes_per_file: 700_000,
  });
  for (const value of [0, -1, 1.5, 1_000_001, Infinity, NaN]) {
    for (const key of ["max_semantic_nodes", "max_semantic_nodes_per_file"])
      expect(
        javaScriptAnalysisResourceControlsSchema.safeParse({ [key]: value })
          .success,
      ).toBe(false);
  }
});

it("reserves the bounded size of remaining static checkpoints instead of stranding most capacity", () => {
  const mib = 1024 * 1024;
  // One future 8 MiB checkpoint cannot consume 80% of an 8 GiB result budget.
  expect(
    javaScriptStaticCheckpointReserveBytes(8192 * mib, 0, 1, 8 * mib),
  ).toBe(48 * mib);
  expect(
    javaScriptStaticCheckpointReserveBytes(8192 * mib, 0, 2, 8 * mib),
  ).toBe(96 * mib);
  // Large inventories retain the existing proportional protection.
  expect(javaScriptStaticCheckpointReserveBytes(1000, 100, 100, 8 * mib)).toBe(
    700,
  );
  expect(javaScriptStaticCheckpointReserveBytes(1000, 900, 100, 8 * mib)).toBe(
    0,
  );
  expect(javaScriptStaticCheckpointReserveBytes(1000, 0, 0, 8 * mib)).toBe(0);
  expect(
    javaScriptStaticCheckpointReserveBytes(1000, 0, undefined, 8 * mib),
  ).toBe(0);
});
