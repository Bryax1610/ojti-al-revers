import { ADB_TOOL_CONTRACTS } from "./adb/adbToolContracts.js";
import { ANALYSIS_VIEW_TOOL_CONTRACTS } from "./analysisViewToolContracts.js";
import { ANDROID_TOOL_CONTRACTS } from "./android/androidToolContracts.js";
import { APKTOOL_TOOL_CONTRACTS } from "./apktool/apktoolToolContracts.js";
import { APPLICATION_TOOL_CONTRACTS } from "./applicationToolContracts.js";
import { ARTIFACT_TOOL_CONTRACTS } from "./artifactToolContracts.js";
import { BROWSER_PROVIDER_TOOL_CONTRACTS } from "./browserProviderToolContracts.js";
import { ENHANCED_TOOL_CONTRACTS } from "./enhancedToolContracts.js";
import { EVM_TOOL_CONTRACTS } from "./evm/evmToolContracts.js";
import { FIRMWARE_TOOL_CONTRACTS } from "./firmware/firmwareToolContracts.js";
import { ELECTRON_TOOL_CONTRACTS } from "./javascript/electronToolContracts.js";
import { JAVASCRIPT_RECOVERY_TOOL_CONTRACTS } from "./javascript/javascriptRecoveryToolContracts.js";
import { JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS } from "./javascript/javascriptRuntimeObservationToolContracts.js";
import { JEB_TOOL_CONTRACTS } from "./jeb/jebToolContracts.js";
import { MANAGED_TOOL_CONTRACTS } from "./managed/managedToolContracts.js";
import { MANAGED_WORKFLOW_TOOL_CONTRACTS } from "./managed/managedWorkflowToolContracts.js";
import { BINARY_DIAGNOSTICS_TOOL_CONTRACTS } from "./native/binaryDiagnosticsToolContracts.js";
import { NATIVE_TOOL_CONTRACTS } from "./native/nativeToolContracts.js";
import { OFFICIAL_TOOL_CONTRACTS } from "./officialToolContracts.js";
import { SESSION_TOOL_CONTRACTS } from "./sessionToolContracts.js";
import { WEB_NETWORK_CAPTURE_TOOL_CONTRACTS } from "./webNetworkCaptureToolContracts.js";
import { WEB_RUNTIME_TOOL_CONTRACTS } from "./webRuntimeToolContracts.js";
import { WEB_SCRIPT_TOOL_CONTRACTS } from "./webScriptToolContracts.js";

const names = (
  ...families: readonly (readonly { readonly name: string }[])[]
): readonly string[] =>
  families.flatMap((family) => family.map(({ name }) => name));

// Tools placed by purpose rather than by the contract family that declares
// them: process capture executes caller commands; Android and Apple graph
// projections consume package inventories; the reconstruction ledger and
// coverage evaluation apply to every target kind.
const PROCESS_TOOL_NAMES = [
  "capture_process_scenario",
  "compare_process_captures",
] as const;
const ANDROID_PROJECTION_TOOL_NAMES = [
  "project_android_application_graph",
] as const;
const APPLE_PROJECTION_TOOL_NAMES = [
  "project_apple_application_graph",
] as const;
const RECONSTRUCTION_TOOL_NAMES = [
  "build_reconstruction_obligation_ledger",
  "evaluate_reconstruction_coverage",
] as const;
const RELOCATED_TOOL_NAMES: ReadonlySet<string> = new Set([
  ...PROCESS_TOOL_NAMES,
  ...ANDROID_PROJECTION_TOOL_NAMES,
  ...APPLE_PROJECTION_TOOL_NAMES,
  ...RECONSTRUCTION_TOOL_NAMES,
]);

const familyTools = (
  ...families: readonly (readonly { readonly name: string }[])[]
): readonly string[] =>
  names(...families).filter((name) => !RELOCATED_TOOL_NAMES.has(name));

/**
 * Operator-selectable partitions of the public tool inventory. Every public
 * tool belongs to exactly one toolset; `core` holds session, target lifecycle,
 * unknown, Evidence bundle, analysis-view and reconstruction-accounting tools
 * and is retained by every selection. Process capture, which runs caller
 * commands, is its own toolset.
 */
export const MCP_TOOLSETS = {
  // inspect_analysis_view pages retained binary-layout, JavaScript application
  // and native Evidence alike, so it belongs with the shared session tools.
  core: [
    ...familyTools(SESSION_TOOL_CONTRACTS, ANALYSIS_VIEW_TOOL_CONTRACTS),
    ...RECONSTRUCTION_TOOL_NAMES,
  ],
  process: PROCESS_TOOL_NAMES,
  native: familyTools(
    OFFICIAL_TOOL_CONTRACTS,
    ENHANCED_TOOL_CONTRACTS,
    NATIVE_TOOL_CONTRACTS,
    BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
  ),
  artifacts: [
    ...familyTools(ARTIFACT_TOOL_CONTRACTS),
    ...APPLE_PROJECTION_TOOL_NAMES,
  ],
  evm: familyTools(EVM_TOOL_CONTRACTS),
  managed: familyTools(MANAGED_TOOL_CONTRACTS, MANAGED_WORKFLOW_TOOL_CONTRACTS),
  android: [
    ...familyTools(
      ANDROID_TOOL_CONTRACTS,
      APKTOOL_TOOL_CONTRACTS,
      JEB_TOOL_CONTRACTS,
      ADB_TOOL_CONTRACTS,
    ),
    ...ANDROID_PROJECTION_TOOL_NAMES,
  ],
  firmware: familyTools(FIRMWARE_TOOL_CONTRACTS),
  web: familyTools(
    BROWSER_PROVIDER_TOOL_CONTRACTS,
    WEB_SCRIPT_TOOL_CONTRACTS,
    WEB_RUNTIME_TOOL_CONTRACTS,
    WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
  ),
  javascript: familyTools(
    ELECTRON_TOOL_CONTRACTS,
    JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
    JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
    APPLICATION_TOOL_CONTRACTS,
  ),
} as const satisfies Readonly<Record<string, readonly string[]>>;

export type McpToolsetName = keyof typeof MCP_TOOLSETS;

/** Stable toolset names in their documented order. */
export const MCP_TOOLSET_NAMES = Object.keys(
  MCP_TOOLSETS,
) as readonly McpToolsetName[];
