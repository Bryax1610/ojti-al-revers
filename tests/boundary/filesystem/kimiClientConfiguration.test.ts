import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse as parseJsonc } from "jsonc-parser";

import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { configureClientConfiguration } from "../../../src/application/SetupClientConfiguration.js";
import { supportedClients } from "../../../src/application/SupportedClients.js";
import { systemUninstallHost } from "../../../src/application/Uninstall.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  clearClientLocationEnvironment,
  NPX_REGISTRATION_COMMAND,
} from "../../fixtures/clientEnvironment.js";

const command = NPX_REGISTRATION_COMMAND;

beforeEach(clearClientLocationEnvironment);
afterEach(() => vi.unstubAllEnvs());

const kimiPath = (
  home: string,
  platform: NodeJS.Platform,
  env: Parameters<typeof supportedClients>[2] = {},
) =>
  supportedClients(home, platform, env).find(
    ({ name }) => name === "kimi_code",
  );

describe("Kimi Code configuration paths", () => {
  it("resolves the user mcp.json file and marker directory", () => {
    expect(kimiPath("/home/a", "linux")).toEqual({
      name: "kimi_code",
      displayName: "Kimi Code",
      configPath: join("/home/a", ".kimi-code", "mcp.json"),
      markerPath: join("/home/a", ".kimi-code"),
      format: "json",
    });
    expect(kimiPath("/Users/a", "darwin")?.configPath).toBe(
      join("/Users/a", ".kimi-code", "mcp.json"),
    );
  });

  it.each([
    ["", join("/home/a", ".kimi-code")],
    ["/custom/kimi", "/custom/kimi"],
    ["~/kimi", "~/kimi"],
    ["profiles/work", "profiles/work"],
  ])("uses KIMI_CODE_HOME %j unexpanded", (override, directory) => {
    vi.stubEnv("KIMI_CODE_HOME", override);
    const client = kimiPath("/home/a", process.platform, {
      KIMI_CODE_HOME: override,
    });
    expect(
      supportedClients("/home/a").find(({ name }) => name === "kimi_code"),
    ).toEqual(client);
    expect(client).toMatchObject({
      configPath: join(directory, "mcp.json"),
      markerPath: directory,
    });
  });
});

describe("Kimi Code client lifecycle", () => {
  const kimiClient = async () => {
    const home = await createTestTempDirectory("rea-kimi-");
    const client = kimiPath(home, process.platform, {});
    if (client?.markerPath === undefined)
      throw new Error("missing Kimi Code client");
    await mkdir(client.markerPath, { recursive: true });
    return { home, client };
  };

  it("registers rea with the compact schema profile while preserving unrelated settings and comments", async () => {
    const { home, client } = await kimiClient();
    await writeFile(
      client.configPath,
      `{
  // Keep this note.
  "mcpServers": { "other": { "command": "other-server" } }
}
`,
    );
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const text = await readFile(client.configPath, "utf8");
    expect(text).toContain("// Keep this note.");
    expect(parseJsonc(text)).toEqual({
      mcpServers: {
        other: { command: "other-server" },
        rea: {
          command: "npx",
          args: command.slice(1),
          env: { REA_MCP_INPUT_SCHEMA_PROFILE: "compact" },
        },
      },
    });
    expect(await configureClientConfiguration(client, {}, command)).toEqual({
      status: "unchanged",
    });
    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    const removedText = await readFile(client.configPath, "utf8");
    const removed = parseJsonc(removedText);
    expect(removed).toEqual({
      mcpServers: { other: { command: "other-server" } },
    });
    expect(removedText).toContain("// Keep this note.");
  });

  it("keeps an explicit schema profile over the compact seed", async () => {
    const { client } = await kimiClient();
    await writeFile(
      client.configPath,
      `{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ${JSON.stringify(command.slice(1))},
      "env": { "REA_MCP_INPUT_SCHEMA_PROFILE": "full" }
    }
  }
}
`,
    );
    expect(await configureClientConfiguration(client, {}, command)).toEqual({
      status: "unchanged",
    });
    expect(parseJsonc(await readFile(client.configPath, "utf8"))).toMatchObject(
      {
        mcpServers: {
          rea: { env: { REA_MCP_INPUT_SCHEMA_PROFILE: "full" } },
        },
      },
    );
  });

  it("reports a package-runner registration as aligned", async () => {
    const { home, client } = await kimiClient();
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const entry = resolve("scripts/rea.mjs");
    const status = (
      await readClientRegistrationStatuses(home, entry, { environment: {} })
    ).find(({ client: name }) => name === "kimi_code");
    expect(status).toMatchObject({ state: "aligned" });
  });
});
