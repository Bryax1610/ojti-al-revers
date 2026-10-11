import { satisfies } from "semver";
import { toolContract } from "../../contracts/toolContracts.js";
import type { ProviderCapability } from "../../contracts/toolOutputSchemaPrimitives.js";

const SQLITE_RUNTIME_REQUIREMENT =
  "SQLite inspection requires Node.js 24.x >=24.15 or 26+ with the native DatabaseSync.limits API. Other REA features retain their published runtime requirements. The inspection worker verifies the API before querying the snapshot.";

/** Discover inspection readiness without opening a database or starting a worker. */
export const sqliteDatabaseCapability = (
  nodeVersion: string,
): ProviderCapability => {
  const contract = toolContract("inspect_sqlite_database");
  const facts = {
    operation: contract.name,
    effects: {
      mutates_artifact: contract.effects.mutatesTarget,
      launches_process: contract.effects.launchesProcess,
      may_show_ui: contract.effects.changesUiState,
      may_access_network: contract.effects.accessesNetwork,
      may_write_filesystem: contract.effects.writesFilesystem,
      changes_permissions: false,
      requires_root: false,
    },
    limitations: [SQLITE_RUNTIME_REQUIREMENT],
  };
  return satisfies(nodeVersion, "^24.15.0 || >=26.0.0")
    ? { ...facts, available: true, reason: null, availability_code: null }
    : {
        ...facts,
        available: false,
        reason: SQLITE_RUNTIME_REQUIREMENT,
        availability_code: "unsupported_version",
      };
};
