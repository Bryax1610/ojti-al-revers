import { afterEach, expect, it, vi } from "vitest";

import { createCli } from "../../src/cli.js";
import { CLI_COMMANDS } from "../../src/cliCommandNames.js";
import * as composition from "../../src/composition/binaryDiagnostics.js";
import { BinaryLayoutService } from "../../src/application/binaryDiagnostics/BinaryLayoutService.js";
import { RecordedCrashService } from "../../src/application/binaryDiagnostics/RecordedCrashService.js";
import { AnalysisOutputError } from "../../src/domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../src/domain/providerCleanupError.js";
import { err } from "../../src/domain/result.js";

const exitCode = process.exitCode;
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = exitCode;
});

it.each(["layout-returned", "recorded-rejected"] as const)(
  "preserves primary diagnostics and cleanup resources through the public CLI: %s",
  async (scenario) => {
    const primary = new AnalysisOutputError(
      "inspect_binary_layout",
      "fixture decoder output overflow",
      {
        capturedOutput: {
          stdout: "partial original output",
          stderr: "warning",
          truncated: true,
        },
      },
    );
    const cleanup = new ProviderCleanupError(
      "fixture-decoder",
      ["owned-process", "/retained/runtime"],
      { reason: "fixture process inspection still denied" },
    );
    const close = vi.fn(() => Promise.reject(cleanup));
    const identity = {
      id: "fixture-decoder",
      name: "Fixture decoder",
      version: "1",
    };
    if (scenario === "layout-returned")
      vi.spyOn(composition, "createBinaryLayoutService").mockReturnValue(
        new BinaryLayoutService({
          identity,
          inspect: () => Promise.resolve(err(primary)),
          close,
        }),
      );
    else
      vi.spyOn(composition, "createRecordedCrashService").mockReturnValue(
        new RecordedCrashService({
          identity,
          inspect: () => Promise.reject(primary),
          close,
        }),
      );

    const cli = createCli({});
    let stdout = "";
    await cli.serve(
      [
        scenario === "layout-returned"
          ? CLI_COMMANDS.inspectBinaryLayout
          : CLI_COMMANDS.inspectRecordedCrash,
        "/selected/fixture.elf",
        "--json",
      ],
      {
        env: {},
        stdout: (text) => {
          stdout += text;
        },
        exit: () => undefined,
      },
    );
    const output: unknown = JSON.parse(stdout);
    expect(output).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        cleanup: "incomplete",
        resources: ["owned-process", "/retained/runtime"],
        captured_output: {
          stdout: "partial original output",
          stderr: "warning",
          truncated: true,
        },
        diagnostics: {
          primary_error: { code: "unreadable_output" },
          cleanup_error: { code: "cleanup_incomplete" },
        },
      },
    });
    expect(close).toHaveBeenCalledOnce();
    expect(process.exitCode).toBe(1);
  },
);
