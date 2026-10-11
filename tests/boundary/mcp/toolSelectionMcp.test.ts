import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { describe, expect, it, onTestFinished } from "vitest";

import { parseMcpToolSelection } from "../../../src/config/mcpToolSelection.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { MCP_TOOLSETS } from "../../../src/contracts/toolsets.js";
import { createServer } from "../../../src/server/createServer.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const connect = async (server: EvidenceMcpServer): Promise<Client> => {
  const client = new Client({ name: "tool-selection", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  onTestFinished(async () => {
    await Promise.allSettled([client.close(), server.close()]);
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

const selectedServer = (
  environment: Readonly<Record<string, string>>,
): EvidenceMcpServer => {
  const selection = parseMcpToolSelection(environment);
  if (!selection.ok) throw selection.error;
  const server = new EvidenceMcpServer(
    { name: "tool-selection", version: "0" },
    { capabilities: {} },
    undefined,
    new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
    undefined,
    selection.value,
  );
  for (const contract of TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      async () => ({ content: [{ type: "text" as const, text: "called" }] }),
    );
  return server;
};

describe("MCP tool selection", () => {
  it("advertises only the selected toolsets plus core", async () => {
    const client = await connect(selectedServer({ REA_MCP_TOOLSETS: "web" }));
    const advertised = (await client.listTools()).tools.map(({ name }) => name);
    expect(advertised.sort()).toEqual(
      [...MCP_TOOLSETS.web, ...MCP_TOOLSETS.core].sort(),
    );
  });

  it("does not let a client invoke a tool removed by an effect denial", async () => {
    const client = await connect(
      selectedServer({ REA_MCP_DENY_EFFECTS: "mutatesTarget" }),
    );
    const advertised = (await client.listTools()).tools.map(({ name }) => name);
    expect(advertised).toContain("inspect_web_page");
    expect(advertised).not.toContain("capture_browser_scenario");
    // A removed tool is unknown to the server: the request is rejected as
    // invalid parameters and never reaches the registered handler.
    await expect(
      client.callTool({ name: "capture_browser_scenario", arguments: {} }),
    ).rejects.toMatchObject({ code: -32602 });
  });

  it("applies the environment selection when composing the production server", async () => {
    const session = createTestBinarySession(() => {
      throw new Error("Tool listing must not acquire a deep provider");
    });
    onTestFinished(async () => {
      await session.close();
    });
    const server = createServer(
      { kind: "session", session },
      {
        environment: {
          REA_LOG_LEVEL: "silent",
          REA_MCP_TOOLSETS: "web,javascript",
          REA_MCP_DENY_TOOLS: "capture_process_scenario",
        },
      },
    );
    const client = await connect(server);
    const advertised = (await client.listTools()).tools.map(({ name }) => name);
    expect(advertised).toContain("analyze_web_bundle");
    expect(advertised).toContain("analyze_javascript_application");
    expect(advertised).toContain("list_unknowns");
    expect(advertised).not.toContain("procedure_pseudo_code");
    expect(advertised).not.toContain("capture_process_scenario");
    expect(advertised.length).toBeLessThan(TOOL_CONTRACTS.length);
    // Session discovery inventories exactly the registered tools.
    const status = await client.callTool({
      name: "binary_session",
      arguments: {},
    });
    const inventory = status.structuredContent as {
      readonly result?: {
        readonly tool_availability?: readonly { readonly name: string }[];
      };
      readonly tool_availability?: readonly { readonly name: string }[];
    };
    const availability =
      inventory.tool_availability ?? inventory.result?.tool_availability;
    expect(availability?.map(({ name }) => name).sort()).toEqual(
      [...advertised].sort(),
    );
  });

  it("refuses to compose a server from an invalid selection", () => {
    const session = createTestBinarySession(() => {
      throw new Error("Invalid configuration must not acquire a provider");
    });
    onTestFinished(async () => {
      await session.close();
    });
    expect(() =>
      createServer(
        { kind: "session", session },
        { environment: { REA_MCP_TOOLSETS: "browser" } },
      ),
    ).toThrow(/REA_MCP_TOOLSETS/u);
  });
});
