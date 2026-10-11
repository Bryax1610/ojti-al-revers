import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import { TOOL_EFFECTS, type ToolEffects } from "../contracts/toolEffects.js";
import { MCP_TOOLSETS, MCP_TOOLSET_NAMES } from "../contracts/toolsets.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/** Decide whether one public tool is registered on this server. */
export type McpToolSelection = (name: string) => boolean;

type DeniableToolEffect = Exclude<keyof ToolEffects, "idempotent">;

const DENIABLE_TOOL_EFFECTS = [
  "mutatesTarget",
  "mutatesSession",
  "writesFilesystem",
  "launchesProcess",
  "accessesNetwork",
  "changesUiState",
  "mayDiscardData",
] as const satisfies readonly DeniableToolEffect[];

const PUBLIC_TOOL_NAMES: ReadonlySet<string> = new Set(
  TOOL_CONTRACTS.map(({ name }) => name),
);

const toolsetConstraint = `REA_MCP_TOOLSETS must be a comma-separated list of toolsets: ${MCP_TOOLSET_NAMES.join(", ")}. The core toolset is always retained.`;
const effectConstraint = `REA_MCP_DENY_EFFECTS must be a comma-separated list of declared tool effects: ${DENIABLE_TOOL_EFFECTS.join(", ")}.`;
const toolConstraint =
  "REA_MCP_DENY_TOOLS must be a comma-separated list of public tool names.";

const rejected = (
  setting: string,
  constraint: string,
  detail = "",
): Result<never, ConfigurationError> =>
  err(
    new ConfigurationError(`${constraint}${detail}`, {
      settings: [{ setting, constraint }],
    }),
  );

/** Split a comma-separated setting, rejecting empty lists and empty items. */
const listItems = (value: string): readonly string[] | undefined => {
  const items = value.split(",").map((item) => item.trim());
  return items.every((item) => item.length > 0) ? items : undefined;
};

const parseToolsets = (
  value: string | undefined,
): Result<ReadonlySet<string> | undefined, ConfigurationError> => {
  if (value === undefined) return ok(undefined);
  const items = listItems(value);
  const known: readonly string[] = MCP_TOOLSET_NAMES;
  if (items === undefined || !items.every((item) => known.includes(item)))
    return rejected("REA_MCP_TOOLSETS", toolsetConstraint);
  const selected = new Set<string>(MCP_TOOLSETS.core);
  for (const toolset of MCP_TOOLSET_NAMES)
    if (items.includes(toolset))
      for (const name of MCP_TOOLSETS[toolset]) selected.add(name);
  return ok(selected);
};

const parseDeniedEffects = (
  value: string | undefined,
): Result<readonly DeniableToolEffect[], ConfigurationError> => {
  if (value === undefined) return ok([]);
  const items = listItems(value);
  const known: readonly string[] = DENIABLE_TOOL_EFFECTS;
  if (items === undefined || !items.every((item) => known.includes(item)))
    return rejected("REA_MCP_DENY_EFFECTS", effectConstraint);
  return ok(DENIABLE_TOOL_EFFECTS.filter((effect) => items.includes(effect)));
};

const parseDeniedTools = (
  value: string | undefined,
): Result<ReadonlySet<string>, ConfigurationError> => {
  if (value === undefined) return ok(new Set());
  const items = listItems(value);
  if (items === undefined)
    return rejected("REA_MCP_DENY_TOOLS", toolConstraint);
  // Tool names are public identifiers, so naming the rejected ones is safe and
  // keeps a misspelled denial from silently leaving the tool registered.
  const unknown = items.filter((item) => !PUBLIC_TOOL_NAMES.has(item));
  if (unknown.length > 0)
    return rejected(
      "REA_MCP_DENY_TOOLS",
      toolConstraint,
      ` Unknown tools: ${unknown.join(", ")}.`,
    );
  return ok(new Set(items));
};

/**
 * Parse the operator tool selection. With no setting every public tool is
 * selected. Toolsets narrow the inventory first, denied effects then remove
 * tools whose declared effects include any of them (failing closed for tools
 * without declared effects), and denied tools are removed last.
 */
export const parseMcpToolSelection = (
  environment: Readonly<Record<string, string | undefined>>,
): Result<McpToolSelection, ConfigurationError> => {
  const toolsets = parseToolsets(environment.REA_MCP_TOOLSETS);
  if (!toolsets.ok) return toolsets;
  const deniedEffects = parseDeniedEffects(environment.REA_MCP_DENY_EFFECTS);
  if (!deniedEffects.ok) return deniedEffects;
  const deniedTools = parseDeniedTools(environment.REA_MCP_DENY_TOOLS);
  if (!deniedTools.ok) return deniedTools;
  return ok((name) => {
    if (toolsets.value !== undefined && !toolsets.value.has(name)) return false;
    if (deniedEffects.value.length > 0) {
      const effects = TOOL_EFFECTS[name];
      if (effects === undefined) return false;
      if (deniedEffects.value.some((effect) => effects[effect])) return false;
    }
    return !deniedTools.value.has(name);
  });
};
