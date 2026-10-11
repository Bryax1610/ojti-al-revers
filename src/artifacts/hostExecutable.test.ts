import { describe, expect, it } from "vitest";

import { hostExecutable } from "./hostExecutable.js";

const file = (mode: number) => ({ mode, isFile: () => true });
const directory = (mode: number) => ({ mode, isFile: () => false });

describe("hostExecutable", () => {
  it("reads the POSIX execute permission bits", () => {
    expect(hostExecutable("/bin/tool", file(0o100755), "linux")).toBe(true);
    expect(hostExecutable("/bin/tool", file(0o100744), "darwin")).toBe(true);
    expect(hostExecutable("/data/app.exe", file(0o100644), "linux")).toBe(
      false,
    );
  });

  it("marks launchable Windows files without an execute bit", () => {
    // Node reports 0o666 (0o444 when read-only) for every NTFS file.
    for (const path of [
      "C:\\Windows\\System32\\whoami.exe",
      "tools/SETUP.EXE",
      "run.Cmd",
      "build.bat",
      "legacy.com",
    ])
      expect(hostExecutable(path, file(0o100666), "win32")).toBe(true);
    expect(hostExecutable("readonly.exe", file(0o100444), "win32")).toBe(true);
  });

  it("does not mark other Windows entries as executable", () => {
    for (const path of [
      "library.dll",
      "notes.txt",
      "README",
      "archive.exe.bak",
    ])
      expect(hostExecutable(path, file(0o100777), "win32")).toBe(false);
    expect(hostExecutable("bundle.exe", directory(0o40777), "win32")).toBe(
      false,
    );
  });
});
