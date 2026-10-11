import { createHash } from "node:crypto";

import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const mapDependencies = (table: string, indexes: string): string =>
  "const __vite__mapDeps = (i, m = __vite__mapDeps, d = " +
  "(m.f || (m.f = " +
  table +
  "))) => i.map(i => d[i]);\n" +
  "__vite__mapDeps(" +
  indexes +
  ");";

const scenarios = [
  {
    file: "escaped.js",
    source: mapDependencies(
      String.raw`["./caf\u00e9.js", './nested\/dep.js', "./bracket].js"]`,
      "[0, 1, 2]",
    ),
    resolved: ["café.js", "nested/dep.js", "bracket].js"],
    unknown: false,
  },
  {
    file: "dynamic.js",
    source: mapDependencies(
      '["./first.js", runtimeUrl("./decoy.js"), "./last.js"]',
      "[1, 2]",
    ),
    resolved: ["last.js"],
    unknown: true,
  },
  {
    file: "sparse.js",
    source: mapDependencies('["./first.js", , "./last.js"]', "[1, 2]"),
    resolved: ["last.js"],
    unknown: true,
  },
  {
    file: "spread.js",
    source: mapDependencies(
      '["./first.js", ...runtimeUrls, "./last.js"]',
      "[0, 2]",
    ),
    resolved: ["first.js"],
    unknown: true,
  },
  {
    file: "scoped.js",
    source:
      "{\n" +
      mapDependencies('["./left.js"]', "[0]") +
      "\n}\n{\n" +
      mapDependencies('["./right.js"]', "[0]") +
      "\n}",
    resolved: ["left.js", "right.js"],
    unknown: false,
  },
  {
    file: "comment.js",
    source:
      '// decoy.f || (decoy.f = ["./decoy.js"])\n' +
      mapDependencies('["./last.js"]', "[0]"),
    resolved: ["last.js"],
    unknown: false,
  },
  {
    file: "shadowed.js",
    source:
      mapDependencies('["./left.js"]', "[0]") +
      "\nfunction unrelated(__vite__mapDeps) { __vite__mapDeps([0]); }",
    resolved: ["left.js"],
    unknown: false,
  },
  {
    file: "cache.js",
    source: mapDependencies('["./left.js"]', "[0]").replace(
      "__vite__mapDeps([0]);",
      "__vite__mapDeps.f = runtimeUrls;\n__vite__mapDeps([0]);",
    ),
    resolved: [],
    unknown: true,
  },
  {
    file: "overridden.js",
    source: mapDependencies('["./left.js"]', "[0]").replace(
      "__vite__mapDeps([0]);",
      "__vite__mapDeps([0], runtimeMapper);",
    ),
    resolved: [],
    unknown: true,
  },
  {
    file: "indices.js",
    source: mapDependencies('["./first.js", "./last.js"]', "[0, runtimeIndex]"),
    resolved: ["first.js"],
    unknown: true,
  },
  {
    file: "unrelated.js",
    source: mapDependencies('["./decoy.js"]', "[0]").replace(
      "i.map(i => d[i])",
      '["./first.js"]',
    ),
    resolved: [],
    unknown: false,
  },
  {
    file: "reassigned.js",
    source: mapDependencies('["./left.js"]', "[0]")
      .replace("const __vite__mapDeps", "let __vite__mapDeps")
      .replace(
        "__vite__mapDeps([0]);",
        "__vite__mapDeps = runtimeMapper;\n__vite__mapDeps([0]);",
      ),
    resolved: [],
    unknown: true,
  },
  {
    file: "self-shadowed.js",
    source: mapDependencies('["./decoy.js"]', "[0]")
      .replace("d = (m.f", "__vite__mapDeps = (m.f")
      .replace("d[i]", "__vite__mapDeps[i]"),
    resolved: [],
    unknown: false,
  },
] as const;

cliTest.for(["CLI", "stdio MCP"] as const)(
  "resolves Vite dependency values without inventing paths through %s",
  { timeout: 120_000 },
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-vite-dependencies-");
    const sources = Object.fromEntries(
      scenarios.map(({ file, source }) => [
        file,
        source + '\nthrow new Error("fixture source must never execute");\n',
      ]),
    );
    await writeFixtureFiles(root, {
      ...sources,
      ...Object.fromEntries(
        [
          "café.js",
          "nested/dep.js",
          "bracket].js",
          "first.js",
          "last.js",
          "left.js",
          "right.js",
          "decoy.js",
        ].map((path) => [path, "export const dependency = true;\n"]),
      ),
    });
    let document: unknown;
    if (surface === "CLI") {
      const response = await cli.run({
        arguments: ["analyze-javascript-application", root, "--json"],
      });
      expect(response.exitCode, response.stderr).toBe(0);
      document = response.json;
    } else {
      const { call } = await connectLocalToolsMcp();
      const response = await call("analyze_javascript_application", {
        input_path: root,
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      document = response.structuredContent;
    }
    const { graph } = javascriptApplicationAnalysisResultSchema.parse(
      parseEvidence(document).normalized_result,
    );
    for (const scenario of scenarios) {
      const imports = graph.edges.filter(
        ({ relation, properties, evidence }) =>
          relation === "imports" &&
          properties.kind === "dynamic-import" &&
          evidence.location.available &&
          evidence.location.value.kind === "source-range" &&
          evidence.location.value.source === scenario.file,
      );
      expect
        .soft(
          imports
            .flatMap(({ properties }) =>
              properties.resolved_path === null
                ? []
                : [properties.resolved_path],
            )
            .sort(),
          scenario.file,
        )
        .toEqual([...scenario.resolved].sort());
      expect
        .soft(
          imports.some(({ properties }) => properties.specifier === null),
          scenario.file,
        )
        .toBe(scenario.unknown);
      for (const edge of imports) {
        const resolved = edge.properties.resolved_path;
        if (typeof resolved === "string")
          expect.soft(edge.properties, scenario.file).toMatchObject({
            specifier: "./" + resolved,
            resolved_path: resolved,
          });
        else {
          expect.soft(edge.properties, scenario.file).toMatchObject({
            specifier: null,
            expression: expect.stringContaining("__vite__mapDeps("),
          });
          expect
            .soft(edge.evidence.coverage.status, scenario.file)
            .toBe("partial");
        }
        const location = edge.evidence.location;
        expect.soft(edge.evidence.artifact, scenario.file).toMatchObject({
          available: true,
          sha256: createHash("sha256")
            .update(sources[scenario.file] ?? "")
            .digest("hex"),
        });
        if (location.available && location.value.kind === "source-range") {
          const source = sources[scenario.file] ?? "";
          const lines = source.split("\n");
          const line = lines[location.value.start.line - 1] ?? "";
          expect.soft(location.value, scenario.file).toMatchObject({
            start: { column: 0 },
            end: {
              line: location.value.start.line,
              column: line.length - 1,
            },
          });
          expect
            .soft(
              line.slice(
                location.value.start.column,
                location.value.end.column,
              ),
              scenario.file,
            )
            .toBe(line.slice(0, -1));
          expect.soft(line, scenario.file).toMatch(/^__vite__mapDeps\(/u);
        }
      }
    }
  },
);
