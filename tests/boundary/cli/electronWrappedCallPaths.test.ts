import { expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";
import { cliTest, type TestCli } from "../../support/cli/cliFixture.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { applicationFeatureTraceResultSchema } from "../../../src/domain/javascript/javascriptFeatureTraceSchemas.js";

const analyze = async (cli: TestCli, extra = "") => {
  const root = await createTestTempDirectory("rea-electron-wrapped-paths-");
  await writeFixtureFiles(root, {
    "preload.js": `const e=require("electron");
      const sender=channel=>(...args)=>e.ipcRenderer.send(channel,...args);
      e.contextBridge.exposeInMainWorld("desktop",{copy:sender("test:copy"),cut:sender("test:cut")});`,
    "main.js": `const e=require("electron");
      function register(channel,handler){e.ipcMain.addListener(channel,event=>allowed(event)&&handler(event))}
      register("test:copy",event=>event.sender.copy());
      register("test:cut",event=>event.sender.cut());${extra}`,
  });
  const output = await cli.run({
    arguments: ["analyze-javascript-application", root, "--json"],
  });
  expect(output.exitCode).toBe(0);
  const { normalized_result: result } = z
    .object({
      normalized_result: javascriptApplicationAnalysisResultSchema,
    })
    .parse(output.json);
  return { root, application: output.json, ...result };
};

cliTest(
  "traces a wrapped bridge member through a unique IPC channel using the public CLI",
  async ({ cli }) => {
    const { root, application, graph } = await analyze(cli);
    const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
    const joins = graph.edges.filter(
      (e) => e.evidence.extractor.operation === "join-electron-wrapper-paths",
    );
    expect(joins).toHaveLength(2);
    for (const edge of joins) {
      expect(edge.evidence).toMatchObject({
        state: "inferred",
        authority: "static-relationship-inference",
      });
      expect(edge.properties.pairing_basis).toBe(
        "unique-exact-literal-channel",
      );
      expect(
        byId.get(edge.source_node_id)?.observations[0]?.properties.channel,
      ).toBe(edge.properties.channel);
      expect(
        byId.get(edge.target_node_id)?.observations[0]?.properties.channel,
      ).toBe(edge.properties.channel);
      expect(edge.properties.conditions).toEqual([
        expect.objectContaining({ expression: "allowed(event)" }),
      ]);
    }
    const start = graph.nodes.find((n) =>
      n.observations.some(
        (o) =>
          o.properties.entry === "desktop.copy" &&
          o.properties.step_kind === "exposure",
      ),
    );
    expect(start).toBeDefined();
    const visited = new Set<string>(),
      pending = start ? [start.node_id] : [];
    while (pending.length) {
      const id = pending.pop();
      if (!id || visited.has(id)) continue;
      visited.add(id);
      for (const edge of graph.edges)
        if (edge.source_node_id === id) pending.push(edge.target_node_id);
    }
    expect(
      [...visited].some((id) =>
        byId
          .get(id)
          ?.observations.some((o) => o.label === "ipc-event.sender.copy"),
      ),
    ).toBe(true);
    expect(
      [...visited].some((id) =>
        byId
          .get(id)
          ?.observations.some((o) => o.label === "ipc-event.sender.cut"),
      ),
    ).toBe(false);
    const input = join(root, "trace-input.json");
    await writeFile(
      input,
      JSON.stringify({
        application,
        seed: { kind: "api", value: "desktop.copy", match: "exact" },
        direction: "outgoing",
      }),
    );
    const traced = await cli.run({
      arguments: ["trace-application-feature", input, "--json"],
    });
    expect(traced.exitCode).toBe(0);
    const { normalized_result: trace } = z
      .object({
        normalized_result: applicationFeatureTraceResultSchema,
      })
      .parse(traced.json);
    expect(trace.seed_matches).toHaveLength(1);
    expect(
      trace.paths.some(
        (path) =>
          path.contains_inference &&
          path.node_ids.length > 8 &&
          byId
            .get(path.end_node_id)
            ?.observations.some((o) => o.label === "ipc-event.sender.copy"),
      ),
    ).toBe(true);
  },
);

cliTest(
  "does not join a channel with another untraced compatible handler",
  async ({ cli }) => {
    const { graph } = await analyze(
      cli,
      'e.ipcMain.on("test:copy",event=>unresolved(event));',
    );
    const joins = graph.edges.filter(
      (e) => e.evidence.extractor.operation === "join-electron-wrapper-paths",
    );
    expect(joins.map((e) => e.properties.channel)).toEqual(["test:cut"]);
  },
);
