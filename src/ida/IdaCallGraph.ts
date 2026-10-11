import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  idaAddressSchema,
  modernCallGraphSchema,
} from "./IdaProtocolValues.js";

/** Reported when `callees` returned nothing for a non-x86 procedure. */
export const EMPTY_CALLEES_LIMITATION =
  "Upstream callees reported no calls for this procedure on a target that is not proven x86-only; REA adds edges from the upstream call graph when it is available, and that graph reports calls to recognized functions only, so other call targets remain unknown.";
const TRUNCATED_LIMITATION =
  "Upstream callgraph was truncated; additional callees remain unknown.";
const POSSIBLY_TRUNCATED_LIMITATION =
  "Upstream callgraph may be truncated; additional callees may remain unknown.";

const X86_FAMILIES: ReadonlySet<string> = new Set(["x86", "x86_64"]);

/**
 * True only when every slice the file can load is x86-family. Upstream `callees`
 * recognises x86 call instructions only, so any other or unproven processor
 * needs the call graph as a second source.
 */
export const isX86OnlyTarget = (target: BinaryTarget): boolean =>
  target.kind === "executable" &&
  // IDA can load a managed PE with the CLI loader instead of as x86 code.
  !(target.format === "pe" && target.managed) &&
  X86_FAMILIES.has(target.architecture) &&
  target.availableArchitectures.every((family) => X86_FAMILIES.has(family));

/** Callees observed in a depth-one call graph, with what stays unknown. */
export interface CallGraphCallees {
  readonly callees: readonly {
    readonly address: string;
    readonly name: string;
  }[];
  readonly limitations: readonly string[];
}

/** The call graph could not be read; the caller keeps its other observations. */
export const unavailableCallGraph = (reason: string): CallGraphCallees => ({
  callees: [],
  limitations: [
    `Upstream callgraph was unavailable (${reason}); callees may be incomplete.`,
  ],
});

/**
 * Read the direct call edges of one procedure from upstream `callgraph`.
 * A failing tool, an error row or an unreadable reply keeps the caller's other
 * observations and is reported as a limitation; cancellation still propagates.
 */
export const readCallGraphCallees = async (
  call: (
    tool: string,
    args: Readonly<Record<string, JsonValue>>,
  ) => Promise<JsonValue>,
  address: string,
): Promise<CallGraphCallees> => {
  let raw: JsonValue;
  try {
    raw = await call("callgraph", { roots: [address], max_depth: 1 });
  } catch (cause: unknown) {
    if (cause instanceof AnalysisProtocolError)
      return unavailableCallGraph(cause.message);
    throw cause;
  }
  const parsed = modernCallGraphSchema.safeParse(raw);
  const row = parsed.success ? parsed.data[0] : undefined;
  if (row === undefined) return unavailableCallGraph("unreadable reply");
  if (row.error !== undefined) return unavailableCallGraph(row.error);
  const rootAddress = idaAddressSchema.safeParse(row.root);
  if (!rootAddress.success || rootAddress.data !== address)
    return unavailableCallGraph("the reply is for a different root");
  const edges = row.edges.filter(
    ({ type, from }) => type === "call" && from === address,
  );
  const names = new Map(row.nodes.map(({ addr, name }) => [addr, name]));
  const targets = [...new Set(edges.map(({ to }) => to))].sort((left, right) =>
    BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0,
  );
  const truncated =
    row.truncated === true || (row.limit_reason ?? null) !== null;
  // Reaching the per-function cap can break the scan without setting a flag,
  // so a saturated count is a possible, not a certain, truncation.
  const saturated =
    row.max_edges_per_func !== undefined &&
    edges.length >= row.max_edges_per_func;
  return {
    callees: targets.map((to) => {
      const name = names.get(to);
      return {
        address: to,
        name: name === null || name === undefined || name === "" ? to : name,
      };
    }),
    limitations: truncated
      ? [TRUNCATED_LIMITATION]
      : saturated
        ? [POSSIBLY_TRUNCATED_LIMITATION]
        : [],
  };
};
