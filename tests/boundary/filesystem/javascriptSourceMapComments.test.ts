import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { reconstructJavaScriptArtifact } from "../../support/javascriptApplicationScope.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("creates source-map graph relationships only for real comments", async () => {
  const root = await createTestTempDirectory("rea-source-map-comments-");
  const path = join(root, "documentation.js");
  const quoted = 'const documentation = "//# sourceMappingURL=ghost.map ";';
  await writeFile(path, quoted);
  const withoutDirective = await reconstructJavaScriptArtifact({
    input_path: root,
  });
  expect(withoutDirective.statistics.parse_failures).toBe(0);
  expect(
    withoutDirective.graph.nodes.filter(({ kind }) => kind === "source-map"),
  ).toEqual([]);
  expect(
    withoutDirective.graph.edges.filter(
      ({ relation, target_node_id }) =>
        relation === "maps_to" &&
        withoutDirective.graph.nodes.some(
          ({ kind, node_id }) =>
            kind === "source-map" && node_id === target_node_id,
        ),
    ),
  ).toEqual([]);

  await writeFile(path, `${quoted}\n//# sourceMappingURL=real.map\n`);
  const withDirective = await reconstructJavaScriptArtifact({
    input_path: root,
  });
  expect(
    withDirective.graph.nodes.filter(({ kind }) => kind === "source-map"),
  ).toHaveLength(1);
  const nodes = new Map(
    withDirective.graph.nodes.map((node) => [node.node_id, node]),
  );
  const sourceMapEdge = withDirective.graph.edges.find(
    ({ relation, target_node_id }) =>
      relation === "maps_to" &&
      nodes.get(target_node_id)?.kind === "source-map",
  );
  expect(
    nodes
      .get(sourceMapEdge?.target_node_id ?? "")
      ?.observations.map(({ properties }) => properties.declared_url),
  ).toContain("real.map");
});

it.each(["//#", "//@"])(
  "keeps an asterisk in a %s line-comment URL and links the map",
  async (marker) => {
    const root = await createTestTempDirectory("rea-source-map-asterisk-");
    const directive = `${marker} sourceMappingURL=app*part.js.map`;
    await writeFile(
      join(root, "app.js"),
      `export const value = 1;\n${directive}\n`,
    );
    await writeFile(
      join(root, "app*part.js.map"),
      JSON.stringify({ version: 3, sources: [], names: [], mappings: "" }),
    );
    const result = await reconstructJavaScriptArtifact({ input_path: root });
    const nodes = new Map(
      result.graph.nodes.map((node) => [node.node_id, node]),
    );
    const mapNodes = result.graph.nodes.filter(
      ({ kind }) => kind === "source-map",
    );
    expect(mapNodes).toHaveLength(1);
    expect(
      mapNodes[0]?.observations.map(({ properties }) => properties),
    ).toContainEqual(
      expect.objectContaining({
        declared_url: "app*part.js.map",
        resolved_path: "app*part.js.map",
        available: true,
      }),
    );
    const edge = result.graph.edges.find(
      ({ relation, target_node_id }) =>
        relation === "maps_to" &&
        nodes.get(target_node_id)?.kind === "source-map",
    );
    expect(edge).toMatchObject({
      target_node_id: mapNodes[0]?.node_id,
      properties: { resolved_path: "app*part.js.map" },
      evidence: {
        location: {
          value: {
            start: { line: 2, column: 0 },
            end: { line: 2, column: directive.length },
          },
        },
      },
    });
  },
);
