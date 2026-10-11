import type { Stats } from "node:fs";
import { extname } from "node:path";

// Windows has no execute permission bit: libuv derives stat modes from file
// attributes alone. The shell and CreateProcess launch these extensions
// directly; PATHEXT is ambient configuration and is deliberately not read.
const WINDOWS_LAUNCHABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".bat",
  ".cmd",
  ".com",
  ".exe",
]);

/** Whether a host filesystem entry carries the host's executable marking. */
export const hostExecutable = (
  path: string,
  metadata: Pick<Stats, "mode" | "isFile">,
  platform: NodeJS.Platform = process.platform,
): boolean =>
  platform === "win32"
    ? metadata.isFile() &&
      WINDOWS_LAUNCHABLE_EXTENSIONS.has(extname(path).toLowerCase())
    : (metadata.mode & 0o111) !== 0;
