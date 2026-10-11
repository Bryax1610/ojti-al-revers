import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect } from "vitest";
import { z } from "zod";

import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "keeps bare package query and fragment keys exact through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-package-specifier-suffix-");
    const packagePath = join(root, "node_modules", "fixture");
    await mkdir(packagePath, { recursive: true });
    await writeFile(
      join(packagePath, "package.json"),
      JSON.stringify({
        exports: {
          "./feature": "./feature.cjs",
          "./literal?cache=1": "./literal.cjs",
        },
      }),
    );
    await writeFile(
      join(packagePath, "feature.cjs"),
      'module.exports = "feature";',
    );
    await writeFile(
      join(packagePath, "literal.cjs"),
      'module.exports = "literal";',
    );
    const requests = [
      {
        specifier: "fixture/feature?cache=1",
        target: null,
        status: "external",
        value: null,
        error: "ERR_PACKAGE_PATH_NOT_EXPORTED",
      },
      {
        specifier: "fixture/feature#entry",
        target: null,
        status: "external",
        value: null,
        error: "ERR_PACKAGE_PATH_NOT_EXPORTED",
      },
      {
        specifier: "fixture/literal?cache=1",
        target: "node_modules/fixture/literal.cjs",
        status: "resolved",
        value: "literal",
        error: null,
      },
    ];
    await writeFile(
      join(root, "main.mjs"),
      requests
        .map(
          ({ specifier }, index) =>
            `import value${index} from ${JSON.stringify(specifier)};`,
        )
        .join("\n"),
    );
    for (const { specifier, value, error } of requests) {
      const native = await promisify(execFile)(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `try {
            const result = await import(${JSON.stringify(specifier)});
            console.log(JSON.stringify({value: result.default, error: null}));
          } catch (error) {
            console.log(JSON.stringify({value: null, error: error.code}));
          }`,
        ],
        { cwd: root, timeout: 5_000 },
      );
      expect(JSON.parse(native.stdout)).toEqual({ value, error });
    }

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
    for (const { specifier, target, status } of requests)
      expect(graph.edges).toContainEqual(
        expect.objectContaining({
          relation: "imports",
          properties: expect.objectContaining({
            module_link_kind: "import",
            specifier,
            resolved_path: target,
            resolution_status: status,
          }),
        }),
      );
  },
);
