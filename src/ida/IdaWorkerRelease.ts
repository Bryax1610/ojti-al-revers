import { z } from "zod";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  closeDatabaseSchema,
  databaseListSchema,
} from "./IdaProtocolValues.js";
import { idaFileDigest, sameIdaHostPath } from "./IdaWorkspace.js";

/**
 * Internal trusted-adapter evidence, not an upstream IDA MCP wire schema.
 * A missing release capability never turns absent registry entries into proof.
 */
const verifiedWorkerEvidence = z.strictObject({
  session_id: z.string().min(1),
  input_path: z.string().min(1),
  owned: z.literal(true),
  backend: z.literal("worker"),
  process_exited: z.literal(true),
  discovery: z.strictObject({
    status: z.literal("complete"),
    sessions: databaseListSchema.shape.sessions,
  }),
});

export const closeVerifiedIdaWorker = async (options: {
  readonly connection: IdaMcpConnection;
  readonly database: string;
  readonly privateSessionId: string;
  readonly inputPath: string;
  readonly sha256: string;
  readonly openCompleted: boolean;
}): Promise<"close-confirmed" | "release-verified"> => {
  const {
    connection,
    database,
    privateSessionId,
    inputPath,
    sha256,
    openCompleted,
  } = options;
  try {
    const closed = closeDatabaseSchema.parse(
      await connection.call("idb_close", { database, save: false }),
    );
    if (
      closed.session_id !== database ||
      closed.saved === true ||
      closed.owned !== true ||
      closed.backend !== "worker"
    )
      throw new AnalysisProtocolError(
        "IDA database close did not confirm the requested owned, unsaved session release.",
      );
    return "close-confirmed";
  } catch (closeFailure: unknown) {
    const verify = connection.verifyWorkerRelease;
    if (!openCompleted || verify === undefined) throw closeFailure;
    const proof = verifiedWorkerEvidence.parse(
      await verify.call(connection, { sessionId: database, inputPath }),
    );
    if (
      database !== privateSessionId ||
      proof.session_id !== database ||
      !sameIdaHostPath(proof.input_path, inputPath) ||
      proof.discovery.sessions.some(
        (entry) =>
          entry.session_id === database ||
          sameIdaHostPath(entry.input_path, inputPath),
      )
    )
      throw new AnalysisProtocolError(
        "IDA release proof does not identify an exclusively released private worker.",
      );
    if ((await idaFileDigest(inputPath)) !== sha256)
      throw new AnalysisProtocolError(
        "IDA private input changed before proven release.",
      );
    return "release-verified";
  }
};
