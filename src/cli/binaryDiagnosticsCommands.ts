import { z } from "incur";
import { resolve } from "node:path";
import {
  createRecordedCrashService,
  createBinaryLayoutService,
  createPeResourcesService,
} from "../composition/binaryDiagnostics.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { inspectPeResourcesInputSchema } from "../domain/native/peResources.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { Result } from "../domain/result.js";

/** Complete one CLI inspection, including cleanup when the workflow rejects unexpectedly. */
const completeBinaryDiagnostic = async <Value>(
  inspect: () => Promise<Result<Value, AnalysisError>>,
  close: () => Promise<void>,
  providerId: string,
  operation: string,
) => {
  let result: Result<Value, AnalysisError> | undefined;
  let rejected = false;
  let primary: unknown;
  try {
    result = await inspect();
  } catch (cause: unknown) {
    rejected = true;
    primary = cause;
  }
  try {
    await close();
  } catch (cause: unknown) {
    const cleanup =
      cause instanceof AnalysisError
        ? cause
        : new ProviderCleanupError(
            providerId,
            [],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { cause, operation },
          );
    const failure = result?.ok === false ? result.error : primary;
    if (failure instanceof AnalysisError)
      return projectAnalysisError(
        analysisErrorWithCleanupFailure(failure, cleanup, operation),
      );
    if (rejected)
      throw new AggregateError(
        [primary, cleanup],
        "Analysis and provider cleanup both failed",
        { cause: primary },
      );
    return projectAnalysisError(cleanup);
  }
  if (rejected) throw primary;
  if (result === undefined)
    throw new Error("Binary inspection result is missing");
  return result.ok ? result.value : projectAnalysisError(result.error);
};

/** Inspect operator-selected files through the same shared workflow as MCP. */
export const registerBinaryDiagnosticsCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const pe = createPeResourcesService();
  cli.command(CLI_COMMANDS.inspectPeResources, {
    description:
      "Inspect PE resource identities, payload ranges, hashes and icon-group relationships",
    args: z.object({ path: z.string().describe("Local PE32/PE32+ image") }),
    options: z.object({
      maxFileBytes: inspectPeResourcesInputSchema.shape.max_file_bytes,
      maxEntries: inspectPeResourcesInputSchema.shape.max_entries,
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectPeResources, async () => {
          const result = await pe.inspect(
            {
              path: resolve(args.path),
              max_file_bytes: options.maxFileBytes,
              max_entries: options.maxEntries,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
  const service = createBinaryLayoutService(environment);
  cli.command(CLI_COMMANDS.inspectBinaryLayout, {
    description:
      "Inspect binary file/linked layout without executing the selected object",
    args: z.object({
      path: z.string().describe("Local ELF binary or relocatable object"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectBinaryLayout, () =>
          completeBinaryDiagnostic(
            () => service.inspect({ path: resolve(args.path) }, { signal }),
            () => service.close(),
            service.provider.identity.id,
            CLI_COMMANDS.inspectBinaryLayout,
          ),
        ),
      ),
  });
  const recorded = createRecordedCrashService(environment);
  cli.command(CLI_COMMANDS.inspectRecordedCrash, {
    description:
      "Inspect supplied core registers/signals and optional debugger mapping evidence",
    args: z.object({ path: z.string().describe("Local Linux amd64 ELF core") }),
    options: z.object({
      debuggerContext: z
        .boolean()
        .default(false)
        .describe("Add BYO core-only GDB/pwndbg mapping candidates"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectRecordedCrash, () =>
          completeBinaryDiagnostic(
            () =>
              recorded.inspect(
                {
                  path: resolve(args.path),
                  include_debugger_context: options.debuggerContext,
                },
                { signal },
              ),
            () => recorded.close(),
            recorded.provider.identity.id,
            CLI_COMMANDS.inspectRecordedCrash,
          ),
        ),
      ),
  });
};
