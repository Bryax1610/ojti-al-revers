import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { access, rm } from "node:fs/promises";
import { dirname } from "node:path";

import { expect, it, vi } from "vitest";

import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessLaunch,
  ProviderProcessSupervisor,
} from "../../src/process/ProviderProcess.js";
import { verifyGhidraPrototypeDiagnostics } from "../../scripts/verify-ghidra-prototype-diagnostics.mjs";
import { waitForExit } from "../support/process/processFixture.js";

const control = vi.hoisted(() => ({
  child: undefined as ChildProcess | undefined,
  supervisor: undefined as ProviderProcessSupervisor | undefined,
  workspace: undefined as string | undefined,
  allowCleanup: false,
}));

// Inject a hung producer and an unavailable ownership observation, while retaining
// the actual supervisor, child streams, assembly build, and workspace lifecycle.
vi.mock("../../dist/process/ProviderProcess.js", async () => {
  const actual = await import("../../src/process/ProviderProcess.js");
  return {
    spawnOwnedProviderProcess: async (
      options: OwnedProviderProcessSpawnOptions,
    ) => {
      const project = options.arguments[0];
      if (project === undefined) throw new Error("Missing producer project");
      control.workspace = dirname(project);
      const child = spawn(
        process.execPath,
        [
          "-e",
          "process.stdin.on('data', chunk => process.stdout.write(chunk)); process.stdout.write('ready');",
        ],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      control.child = child;
      if (child.stdout === null) throw new Error("Missing child output");
      await once(child.stdout, "data");
      return {
        process: child,
        ownership: {
          runId: options.runId,
          leaderPid: child.pid,
          processGroupId: child.pid,
          expectedParentPid: process.pid,
        },
      };
    },
    ProviderProcessSupervisor: class extends actual.ProviderProcessSupervisor {
      constructor(launch: ProviderProcessLaunch) {
        super(launch);
        control.supervisor = this;
      }

      override waitForExit(timeoutMs: number): Promise<boolean> {
        return super.waitForExit(Math.min(timeoutMs, 50));
      }
    },
  };
});

vi.mock("../../dist/process/ProcessOwnership.js", () => ({
  cleanupOwnedProcessGroup: () => {
    if (!control.allowCleanup)
      return Promise.resolve({
        cleaned: false,
        reason: "observation unavailable",
      });
    control.child?.kill("SIGTERM");
    return Promise.resolve({ cleaned: true });
  },
}));

it.runIf(process.platform === "linux" && process.arch === "x64")(
  "retains a failed cleanup's project and supervision so ownership can be retried",
  async () => {
    const previousRunId = process.env.REA_PROCESS_RUN_ID;
    try {
      const failure: unknown = await verifyGhidraPrototypeDiagnostics({
        installation: { analyzeHeadlessPath: "controlled-test-producer" },
      }).catch((cause: unknown) => cause);
      const { child, workspace, supervisor } = control;
      if (
        child === undefined ||
        workspace === undefined ||
        supervisor === undefined
      )
        throw new Error("Producer control was not launched");

      expect(child.exitCode).toBeNull();
      expect(child.signalCode).toBeNull();
      await expect(access(workspace)).resolves.toBeUndefined();
      expect(failure).toMatchObject({
        cleanupFailure: "observation unavailable",
        cleanupOwner: supervisor,
        resources: expect.arrayContaining([workspace]),
        cause: expect.objectContaining({
          message: "Prototype producer probe exceeded its headless deadline",
        }),
      });
      child.stdin?.write("still-owned");
      await expect
        .poll(() => supervisor.snapshot().stdout.text)
        .toContain("still-owned");

      control.allowCleanup = true;
      expect(await supervisor.stop()).toEqual({ status: "verified-cleanup" });
      expect(await waitForExit(child, 1_000)).toBe(true);
    } finally {
      control.allowCleanup = true;
      await control.supervisor?.stop();
      if (control.child !== undefined) {
        control.child.kill("SIGKILL");
        await waitForExit(control.child, 1_000);
      }
      if (control.workspace !== undefined)
        await rm(control.workspace, { recursive: true, force: true });
      if (previousRunId === undefined) delete process.env.REA_PROCESS_RUN_ID;
      else process.env.REA_PROCESS_RUN_ID = previousRunId;
    }
  },
);
