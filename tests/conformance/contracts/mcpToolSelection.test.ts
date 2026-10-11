import { describe, expect, it } from "vitest";

import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { TOOL_EFFECTS } from "../../../src/contracts/toolEffects.js";
import {
  MCP_TOOLSETS,
  MCP_TOOLSET_NAMES,
} from "../../../src/contracts/toolsets.js";
import { parseMcpToolSelection } from "../../../src/config/mcpToolSelection.js";

const allNames = TOOL_CONTRACTS.map(({ name }) => name);

const select = (environment: Readonly<Record<string, string | undefined>>) => {
  const parsed = parseMcpToolSelection(environment);
  if (!parsed.ok) throw parsed.error;
  return allNames.filter((name) => parsed.value(name));
};

const rejection = (
  environment: Readonly<Record<string, string | undefined>>,
): string => {
  const parsed = parseMcpToolSelection(environment);
  if (parsed.ok) throw new Error("Expected an invalid tool selection");
  return parsed.error.message;
};

describe("MCP toolsets", () => {
  it("partition the public inventory so every tool belongs to exactly one toolset", () => {
    const assigned = MCP_TOOLSET_NAMES.flatMap((toolset) => [
      ...MCP_TOOLSETS[toolset],
    ]);
    expect([...assigned].sort()).toEqual([...allNames].sort());
    expect(new Set(assigned).size).toBe(assigned.length);
  });

  it("place web and JavaScript investigation tools in their own toolsets", () => {
    expect(MCP_TOOLSETS.web).toEqual(
      expect.arrayContaining([
        "inspect_web_page",
        "analyze_web_bundle",
        "inspect_web_network_capture",
      ]),
    );
    expect(MCP_TOOLSETS.javascript).toEqual(
      expect.arrayContaining([
        "analyze_javascript_application",
        "trace_application_feature",
      ]),
    );
    expect(MCP_TOOLSETS.core).toEqual(
      expect.arrayContaining([
        "list_unknowns",
        "get_evidence_bundle",
        // Pages retained JavaScript application Evidence as well as native.
        "inspect_analysis_view",
        // Reconstruction accounting applies to every target kind.
        "build_reconstruction_obligation_ledger",
        "evaluate_reconstruction_coverage",
      ]),
    );
  });

  it("keeps caller-command process capture out of the always-retained core", () => {
    expect(MCP_TOOLSETS.process).toEqual(
      expect.arrayContaining(["capture_process_scenario"]),
    );
    expect(MCP_TOOLSETS.core).not.toContain("capture_process_scenario");
  });

  it("places package-inventory graph projections with their package toolsets", () => {
    expect(MCP_TOOLSETS.android).toContain("project_android_application_graph");
    expect(MCP_TOOLSETS.artifacts).toContain("project_apple_application_graph");
    expect(MCP_TOOLSETS.javascript).not.toContain(
      "project_android_application_graph",
    );
  });
});

describe("MCP tool selection configuration", () => {
  it("selects the complete inventory when nothing is configured", () => {
    expect(select({})).toEqual(allNames);
  });

  it("selects the requested toolsets and always retains the core toolset", () => {
    const selected = select({ REA_MCP_TOOLSETS: " web , javascript " });
    expect(selected).toEqual(
      allNames.filter(
        (name) =>
          MCP_TOOLSETS.web.includes(name) ||
          MCP_TOOLSETS.javascript.includes(name) ||
          MCP_TOOLSETS.core.includes(name),
      ),
    );
    expect(selected).not.toContain("procedure_pseudo_code");
    expect(selected).not.toContain("install_adb_package");
  });

  it("removes every tool whose declared effects include a denied effect", () => {
    const selected = select({ REA_MCP_DENY_EFFECTS: "mutatesTarget" });
    const mutating = allNames.filter(
      (name) => TOOL_EFFECTS[name]?.mutatesTarget === true,
    );
    expect(mutating).toEqual(
      expect.arrayContaining([
        "capture_browser_scenario",
        "install_adb_package",
      ]),
    );
    // Selection fails closed: a tool without declared effects is never kept
    // while any effect is denied.
    expect(selected).toEqual(
      allNames.filter(
        (name) => TOOL_EFFECTS[name] !== undefined && !mutating.includes(name),
      ),
    );
  });

  it("removes explicitly denied tools after toolset and effect selection", () => {
    const selected = select({
      REA_MCP_TOOLSETS: "web,javascript",
      REA_MCP_DENY_EFFECTS: "mutatesTarget",
      REA_MCP_DENY_TOOLS: "capture_process_scenario,capture_electron_scenario",
    });
    expect(selected).toContain("inspect_web_page");
    expect(selected).toContain("list_unknowns");
    expect(selected).not.toContain("capture_browser_scenario");
    expect(selected).not.toContain("capture_process_scenario");
    expect(selected).not.toContain("capture_electron_scenario");
  });

  it("keeps the documented web investigation example free of tools that run caller commands or local applications", () => {
    const selected = select({
      REA_MCP_TOOLSETS: "web,javascript,artifacts",
      REA_MCP_DENY_TOOLS: "capture_electron_scenario",
    });
    for (const name of [
      "capture_process_scenario",
      "capture_electron_scenario",
      "capture_native_ui_scenario",
      "install_adb_package",
      "start_adb_app",
      "procedure_pseudo_code",
    ])
      expect(selected).not.toContain(name);
    // Documented: the browser scenario drives an operator-supplied browser.
    expect(selected).toContain("capture_browser_scenario");
    expect(selected).toContain("analyze_javascript_application");
  });

  it.each(["", " ", "web,,javascript", "web,", "WEB", "browser"])(
    "rejects an invalid toolset list: %j",
    (value) => {
      const message = rejection({ REA_MCP_TOOLSETS: value });
      expect(message).toContain("REA_MCP_TOOLSETS");
      expect(message).toContain("javascript");
    },
  );

  it.each(["", "mutates_target", "launchesProcess,", "readOnly"])(
    "rejects an unknown denied effect: %j",
    (value) => {
      expect(rejection({ REA_MCP_DENY_EFFECTS: value })).toContain(
        "REA_MCP_DENY_EFFECTS",
      );
    },
  );

  it("rejects denied tool names outside the public inventory so typos never fail open", () => {
    const message = rejection({
      REA_MCP_DENY_TOOLS: "capture_browser_scenario,capture_browser_scenaro",
    });
    expect(message).toContain("REA_MCP_DENY_TOOLS");
    expect(message).toContain("capture_browser_scenaro");
  });
});
