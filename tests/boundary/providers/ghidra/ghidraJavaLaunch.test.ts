import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { ghidraJavaLaunch } from "../../../../src/ghidra/GhidraJavaLaunch.js";

// HotSpot writes unified-logging warnings to stdout unless redirected, as it
// does for cgroup controller warnings when the process left its cgroup
// namespace root (for example inside a desktop-app scope in a container).
const hotSpotLaunchSupport = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (!args.includes("-Xlog:all=warning:stderr"))
  process.stdout.write("[0.004s][warning][os,container] Cgroup memory controller path at '/sys/fs/cgroup' seems to have moved to '/../../../app.slice/app.scope', detected limits won't be accurate\\n");
if (args.at(-1) === "-envvars") process.stdout.write("GHIDRA_MAXMEM=\\n");
if (args.at(-1) === "-vmargs") process.stdout.write("-Dfile.encoding=UTF8\\n");
`;

describe.skipIf(process.platform === "win32")("Ghidra Java launch", () => {
  it("keeps JVM warnings out of LaunchSupport output", async () => {
    const root = await createTestTempDirectory("rea-ghidra-java-launch-");
    const java = join(root, "jdk", "bin", "java");
    await mkdir(join(root, "jdk", "bin"), { recursive: true });
    await writeFile(java, hotSpotLaunchSupport);
    await chmod(java, 0o755);

    const launch = await ghidraJavaLaunch({
      platform: process.platform,
      analyzeHeadlessPath: join(root, "ghidra", "support", "analyzeHeadless"),
      javaHome: join(root, "jdk"),
      homeRoot: join(root, "home"),
      tempRoot: join(root, "tmp"),
      arguments: [],
      environment: { PATH: process.env.PATH ?? "" },
    });

    expect(launch.arguments[0]).toBe("-Dfile.encoding=UTF8");
    expect(launch.arguments).not.toContainEqual(
      expect.stringContaining("[warning]"),
    );
  });
});
