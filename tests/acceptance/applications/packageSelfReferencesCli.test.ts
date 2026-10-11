import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect } from "vitest";
import { z } from "zod";

import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "resolves ESM package self exports with import conditions through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-esm-self-exports-");
    const source = [
      'import rootValue from "rea-self-fixture";',
      'import feature from "rea-self-fixture/feature";',
      "console.log(rootValue, feature);",
    ].join("\n");
    const files = {
      "package.json": JSON.stringify({
        name: "rea-self-fixture",
        exports: {
          ".": { import: "./root.cjs", require: "./require.cjs" },
          "./feature": { import: "./feature.cjs", require: "./require.cjs" },
        },
      }),
      "main.mjs": source,
      "root.cjs": "module.exports = 11;",
      "feature.cjs": "module.exports = 22;",
      "require.cjs": "module.exports = -1;",
    };
    await Promise.all(
      Object.entries(files).map(([path, text]) =>
        writeFile(join(root, path), text),
      ),
    );
    const native = await promisify(execFile)(
      process.execPath,
      [join(root, "main.mjs")],
      { timeout: 5_000 },
    );
    expect(native.stdout.trim()).toBe("11 22");

    let document: unknown;
    if (surface === "CLI") {
      const response = await cli.run({
        arguments: ["analyze-javascript-application", root, "--format", "json"],
        environment: { REA_LOG_LEVEL: "silent" },
      });
      expect(response.exitCode, response.stderr).toBe(0);
      document = response.json;
    } else {
      const { call } = await connectLocalToolsMcp();
      const response = await call("analyze_javascript_application", {
        input_path: root,
        format: "directory",
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      document = response.structuredContent;
    }
    const { graph } = z
      .object({ normalized_result: javascriptApplicationAnalysisResultSchema })
      .parse(document).normalized_result;
    for (const [specifier, path] of [
      ["rea-self-fixture", "root.cjs"],
      ["rea-self-fixture/feature", "feature.cjs"],
    ])
      expect(graph.edges).toContainEqual(
        expect.objectContaining({
          relation: "imports",
          properties: expect.objectContaining({
            module_link_kind: "import",
            specifier,
            resolved_path: path,
            resolution_status: "resolved",
          }),
          evidence: expect.objectContaining({
            artifact: expect.objectContaining({
              sha256: createHash("sha256").update(source).digest("hex"),
            }),
            location: expect.objectContaining({
              value: expect.objectContaining({ source: "main.mjs" }),
            }),
          }),
        }),
      );
  },
);
