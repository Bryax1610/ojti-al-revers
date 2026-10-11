import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import { createServerIdentity } from "../serverIdentity.js";
import { silentLogger } from "../logger.js";
import type { Logger } from "pino";
import type { DirectAnalysisDependencies } from "./DirectAnalysisDependencies.js";
import { providerCapability } from "../contracts/toolOutputSchemaPrimitives.js";
import { sqliteDatabaseCapability } from "./sqlite/SqliteDatabaseCapability.js";

/** Read target-free provider status and operation availability. */
export const runSessionStatus = async (
  dependencies: Pick<
    DirectAnalysisDependencies,
    "createBinarySession" | "readConfiguration"
  >,
  logger: Logger = silentLogger,
): Promise<JsonValue> => {
  const config = dependencies.readConfiguration();
  if (!config.ok) return { error: projectAnalysisError(config.error) };
  const session = dependencies.createBinarySession(config.value, logger);
  try {
    const status = jsonObjectSchema.parse(session.status());
    return {
      ...status,
      capabilities: [
        ...providerCapability.array().parse(status.capabilities),
        sqliteDatabaseCapability(process.versions.node),
      ].sort((left, right) => left.operation.localeCompare(right.operation)),
      server_identity: createServerIdentity({
        startedAt: new Date().toISOString(),
      }),
    };
  } finally {
    await session.close();
  }
};
