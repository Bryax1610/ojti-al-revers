import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
import { AnalysisCancelledError } from "../../../src/domain/analysisErrorCore.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../tests/support/workspace/workspaceFixture.js";
import { inspectPwndbgCore } from "../../../src/native/pwndbg/PwndbgCoreContext.js";
import {
  spawnOwnedProviderProcess,
  type ProviderProcessSupervisor,
} from "../../../src/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { stopProviderProcessFixture } from "../../fixtures/providerProcess.js";

const diagnostics = { stdout: "", stderr: "", truncated: false };

it.each(["pre-aborted", "aborted-during-probe"] as const)(
  "cancellation wins over debugger path failures: %s",
  async (scenario) => {
    const workspace = await createTestWorkspace("rea-pwndbg-cancel-");
    onTestFinished(() => removeTestWorkspace(workspace.root));
    const controller = new AbortController();
    const gdb = join(workspace.root, "missing-gdb");
    let probes = 0;
    const probePath = async () => {
      probes++;
      if (scenario === "aborted-during-probe") {
        await new Promise<void>((resolve) => {
          setImmediate(() => {
            controller.abort();
            resolve();
          });
        });
        throw new Error("path became unavailable");
      }
      throw new Error("path is unavailable");
    };
    if (scenario === "pre-aborted") controller.abort();
    await expect(
      inspectPwndbgCore({
        environment: {
          REA_PWNDBG_GDB: gdb,
          REA_PWNDBG_GDBINIT: join(workspace.root, "missing-init"),
          REA_PWNDBG_VENV_PATH: join(workspace.root, "missing-venv"),
        },
        rootPath: workspace.root,
        diagnostics,
        options: { signal: controller.signal },
        probePath,
        retainProcessCleanup: () => {
          throw new Error("No process should exist before cancellation");
        },
      }),
    ).rejects.toBeInstanceOf(AnalysisCancelledError);
    expect(probes).toBe(scenario === "pre-aborted" ? 0 : 1);
    await expect(
      access(join(workspace.root, "debugger")),
    ).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

it.skipIf(process.platform === "win32")(
  "transfers a live debugger with failed cleanup to the owner of its snapshot",
  async () => {
    const workspace = await createTestWorkspace("rea-pwndbg-cleanup-");
    let owner: ProviderProcessSupervisor | undefined;
    let cleanupAllowed = false;
    let pid: number | undefined;
    let releaseFixture: (() => Promise<void>) | undefined;
    onTestFinished(async () => {
      cleanupAllowed = true;
      await owner?.stop();
      await releaseFixture?.();
      await removeTestWorkspace(workspace.root);
    });
    await expect(
      inspectPwndbgCore({
        environment: {
          REA_PWNTOOLS_PYTHON: process.execPath,
          REA_PWNDBG_GDB: join(workspace.root, "owned-gdb"),
          REA_PWNDBG_GDBINIT: join(workspace.root, "owned-init"),
          REA_PWNDBG_VENV_PATH: join(workspace.root, "owned-venv"),
        },
        rootPath: workspace.root,
        diagnostics,
        options: undefined,
        probePath: async () => undefined,
        retainProcessCleanup: (retained) => {
          owner = retained;
        },
        launcher: async (input) => {
          const launched = await spawnOwnedProviderProcess({
            ...input,
            arguments: [
              "-e",
              'process.stdout.write("x".repeat(1048577)); setInterval(() => undefined, 1000)',
            ],
          });
          pid = launched.process.pid;
          releaseFixture = () => stopProviderProcessFixture(launched.process);
          return {
            ...launched,
            cleanup: () =>
              cleanupAllowed
                ? cleanupOwnedProcessGroup(launched.ownership)
                : Promise.resolve({
                    cleaned: false as const,
                    reason: "fixture ownership inspection unavailable",
                  }),
          };
        },
      }),
    ).rejects.toMatchObject({
      cleanupIncomplete: true,
      diagnostics: {
        previous_error: { failure_kind: "output-limit" },
        captured_output: { truncated: true },
      },
    });
    if (owner === undefined || pid === undefined)
      throw new Error("Live debugger cleanup ownership was lost");
    const workerPid = pid;
    expect(() => process.kill(workerPid, 0)).not.toThrow();
    expect(
      JSON.parse(
        await readFile(
          join(workspace.root, "debugger", "request.json"),
          "utf8",
        ),
      ),
    ).toMatchObject({ snapshot_path: join(workspace.root, "object.snapshot") });
    cleanupAllowed = true;
    expect(await owner.stop()).toMatchObject({ status: "verified-cleanup" });
    expect(() => process.kill(workerPid, 0)).toThrow();
  },
);
