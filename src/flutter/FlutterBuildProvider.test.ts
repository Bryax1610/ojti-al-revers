import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { expect, onTestFinished, test } from "vitest";

import {
  aotFixtureImage,
  buildElf64Image,
  REFERENCE_HASH,
} from "./FlutterTestFixtures.js";
import { snapshotSection } from "./DartElf.js";
import { FlutterBuildProvider } from "./FlutterBuildProvider.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";

const it = test.skipIf(process.platform === "win32");
const run = promisify(execFile);

const buildIdNote = (): Buffer =>
  Buffer.concat([
    Buffer.from([4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, 0x47, 0x4e, 0x55, 0]),
    Buffer.from([
      0xe8, 0xd9, 0x07, 0xef, 0x7c, 0x17, 0x5e, 0xc4, 0x31, 0x3f, 0x47, 0x11,
      0x10, 0x19, 0xad, 0xc9, 0x58, 0x8c, 0x5f, 0x61,
    ]),
  ]);

const TOOLCHAIN_LINE =
  "Android (5900059 based on r365631c) clang version 9.0.8 (based on LLVM 9.0.8svn)";

const libapp = (hash: string): Buffer =>
  Buffer.concat([
    // A minimal ELF64 header with valid type, table offsets, and counts,
    // so the structural validity check passes alongside the magic.
    (() => {
      const header = Buffer.alloc(64);
      header.writeUInt32LE(0x464c457f, 0); // magic
      header[4] = 2; // ELFCLASS64
      header[5] = 1; // little-endian
      header.writeUInt16LE(3, 0x10); // ET_DYN
      header.writeBigUInt64LE(BigInt(64), 0x20); // e_phoff
      header.writeBigUInt64LE(BigInt(128), 0x28); // e_shoff
      header.writeUInt16LE(1, 0x38); // e_phnum
      header.writeUInt16LE(2, 0x3c); // e_shnum
      return header;
    })(),
    Buffer.from("payload-prefix\x00"),
    snapshotSection(hash),
    Buffer.from("middle\x00"),
    snapshotSection(hash),
  ]);

const libflutter = (): Buffer =>
  Buffer.concat([
    Buffer.from("ELF-payload-prefix\x00"),
    buildIdNote(),
    Buffer.from(`\x00${TOOLCHAIN_LINE}\x00`),
  ]);

/**
 * Self-contained Dart AOT image: a synthetic ELF64 carrying the four
 * snapshot symbols, two snapshot sections, and a string pool, so goldens
 * do not depend on any file outside the repository.
 */
const aotImage = aotFixtureImage;

/** Two data symbols at one offset and size: aliased exports. */
const aliasedDataImage = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x1000, size: 52 },
  ]);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    snapshotSection(REFERENCE_HASH),
  ]);
};

/** Two data symbols whose snapshot hashes disagree. */
const conflictingHashImage = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x1200, size: 52 },
  ]);
  const vm = snapshotSection("11111111111111111111111111111111");
  const isolate = snapshotSection("22222222222222222222222222222222");
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    vm,
    Buffer.alloc(0x1200 - 0x1000 - vm.length),
    isolate,
  ]);
};

/** Build a real APK-shaped zip with the `zip` CLI. */
const buildApk = async (
  name: string,
  files: ReadonlyArray<{ readonly path: string; readonly bytes: Buffer }>,
): Promise<string> => {
  const root = await mkdtemp(join("/tmp", "rea-flutter-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  for (const file of files) {
    const target = join(root, file.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, file.bytes);
  }
  await run(
    "zip",
    ["-q", "-X", join(root, name), ...files.map((file) => file.path)],
    { cwd: root },
  );
  return join(root, name);
};

it("projects each payload shape through the owned snapshot", async () => {
  const hash = REFERENCE_HASH;
  const agreeBoth = await buildApk("agree.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: libapp(hash) },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
    { path: "lib/x86_64/libapp.so", bytes: libapp(hash) },
    { path: "lib/x86_64/libflutter.so", bytes: libflutter() },
  ]);
  const half = await buildApk("half.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: libapp(hash) },
  ]);
  const disagree = await buildApk("disagree.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: Buffer.concat([
        snapshotSection("11111111111111111111111111111111"),
        snapshotSection("22222222222222222222222222222222"),
      ]),
    },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
  ]);
  const plain = await buildApk("plain.apk", [
    { path: "classes.dex", bytes: Buffer.from("dex\n0123456789") },
    { path: "lib/arm64-v8a/libnative.so", bytes: Buffer.from("plain-elf") },
  ]);
  const provider = new FlutterBuildProvider({ environment: {} });
  const identify = async (apk: string) => {
    const outcome = await provider.execute({
      operation: "identify_flutter_build",
      input: { path: apk },
    });
    if (!outcome.ok) throw new Error(outcome.error.message);
    return outcome.value.result as {
      flutter_detected: boolean;
      coverage: string;
      abis: {
        abi: string;
        libapp: {
          present: boolean;
          snapshot_hash: string | null;
          snapshot_hash_sources: number;
          snapshot_hash_candidates: string[];
        };
        libflutter: { present: boolean; build_id: string | null };
      }[];
    };
  };

  const both = await identify(agreeBoth);
  expect(both.flutter_detected).toBe(true);
  expect(both.coverage).toBe("complete");
  expect(both.abis.map((abi) => abi.abi)).toEqual(["arm64-v8a", "x86_64"]);
  for (const abi of both.abis) {
    expect(abi.libapp.snapshot_hash).toBe(hash);
    expect(abi.libapp.snapshot_hash_sources).toBe(2);
    expect(abi.libflutter.build_id).toBe(
      "e8d907ef7c175ec4313f47111019adc9588c5f61",
    );
  }

  const engineless = await identify(half);
  expect(engineless.coverage).toBe("partial");
  expect(engineless.abis[0]?.libapp.present).toBe(true);
  expect(engineless.abis[0]?.libflutter.present).toBe(false);

  const conflicted = await identify(disagree);
  expect(conflicted.coverage).toBe("partial");
  expect(conflicted.abis[0]?.libapp.snapshot_hash).toBeNull();
  expect(conflicted.abis[0]?.libapp.snapshot_hash_candidates).toEqual([
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
  ]);

  const negative = await identify(plain);
  expect(negative.flutter_detected).toBe(false);
  expect(negative.abis).toEqual([]);
  expect(negative.coverage).toBe("complete");
});

it("rejects a target that is not a readable file", async () => {
  const projected = await (async () => {
    const result = await new FlutterBuildProvider({
      environment: {},
    }).execute({
      operation: "identify_flutter_build",
      input: { path: "/nonexistent/app.apk" },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    return projectAnalysisError(result.error);
  })();
  expect(projected).toMatchObject({ code: "invalid_request" });
});

it("refuses an APK without a Dart payload", async () => {
  const apk = await buildApk("noflutter.apk", [
    { path: "classes.dex", bytes: Buffer.from("dex\n0123456789") },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "unsupported_target",
  });
});

it("refuses a requested ABI the payload does not carry", async () => {
  const apk = await buildApk("oneabi.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk, abi: "x86_64" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "unsupported_target",
  });
  expect(result.error.message).toContain("arm64-v8a");
});

test.skipIf(process.platform === "win32")(
  "inspects a full synthetic AOT image end to end",
  async () => {
    const apk = await buildApk("realgallery.apk", [
      { path: "lib/arm64-v8a/libapp.so", bytes: aotImage() },
    ]);
    const result = await new FlutterBuildProvider({
      environment: {},
    }).execute({
      operation: "inspect_dart_aot",
      input: { path: apk },
    });
    if (!result.ok) throw new Error(result.error.message);
    const value = result.value.result as {
      abi: string;
      libapp: {
        snapshot_hash: string | null;
        snapshot_hash_candidates: string[];
        snapshot_hash_sources: number;
        sections: { name: string; magic_valid: boolean }[];
      };
      string_pool: {
        package_uri_count_at_least: number;
        dart_uri_count_at_least: number;
      };
      coverage: string;
    };
    expect(value.abi).toBe("arm64-v8a");
    expect(value.libapp.snapshot_hash).toBe(REFERENCE_HASH);
    expect(value.libapp.snapshot_hash_candidates).toEqual([REFERENCE_HASH]);
    expect(value.libapp.snapshot_hash_sources).toBe(2);
    expect(value.libapp.sections.map((section) => section.name)).toEqual([
      "_kDartVmSnapshotData",
      "_kDartVmSnapshotInstructions",
      "_kDartIsolateSnapshotData",
      "_kDartIsolateSnapshotInstructions",
    ]);
    expect(
      value.libapp.sections
        .filter((section) => section.name.endsWith("Data"))
        .every((section) => section.magic_valid),
    ).toBe(true);
    expect(value.string_pool.package_uri_count_at_least).toBe(2);
    expect(value.string_pool.dart_uri_count_at_least).toBe(2);
    // All four symbols present, both data magics valid, pool under budget:
    // the honest answer for a complete payload is complete coverage.
    expect(value.coverage).toBe("complete");
  },
);

it("reports aliased snapshot data symbols as partial coverage", async () => {
  const apk = await buildApk("aliased.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: aliasedDataImage() },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as {
    coverage: string;
    libapp: {
      snapshot_hash: string | null;
      snapshot_hash_candidates: string[];
      snapshot_hash_sources: number;
    };
  };
  // The aliased range is scanned once, so one candidate no longer counts
  // as two agreeing sources.
  expect(value.coverage).toBe("partial");
  expect(value.libapp.snapshot_hash_sources).toBe(1);
  expect(value.libapp.snapshot_hash_candidates).toEqual([REFERENCE_HASH]);
  expect(result.value.limitations).toContain(
    "Two or more snapshot data symbols share one offset and size; the aliased range is scanned once, so its hash counts as one source instead of two agreeing ones",
  );
});

it("preserves conflicting snapshot hash candidates from the AOT image", async () => {
  const apk = await buildApk("conflicted.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: conflictingHashImage() },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as {
    coverage: string;
    libapp: {
      snapshot_hash: string | null;
      snapshot_hash_candidates: string[];
      snapshot_hash_sources: number;
    };
  };
  expect(value.coverage).toBe("partial");
  expect(value.libapp.snapshot_hash).toBeNull();
  expect(value.libapp.snapshot_hash_sources).toBe(2);
  expect(value.libapp.snapshot_hash_candidates).toEqual([
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
  ]);
});

it("accepts an APK whose path contains spaces through the owned snapshot", async () => {
  const apk = await buildApk("flutter spaced.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
  ]);
  expect(apk).toContain(" ");
  const result = await new FlutterBuildProvider({
    environment: {},
  }).execute({
    operation: "identify_flutter_build",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as { flutter_detected: boolean };
  expect(value.flutter_detected).toBe(true);
});

it("retains failed snapshot cleanup and retries it on close", async () => {
  const apk = await buildApk("cleanup.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const spaces: string[] = [];
  let failing = true;
  const provider = new FlutterBuildProvider({
    environment: {},
    removeRoot: async (path) => {
      if (failing) throw new Error("cleanup refused");
      spaces.push(path);
    },
  });
  const result = await provider.execute({
    operation: "identify_flutter_build",
    input: { path: apk },
  });
  expect(result.ok).toBe(true);
  await expect(provider.close()).rejects.toThrow(/snapshot cleanup failed/u);
  failing = false;
  await provider.close();
  expect(spaces.length).toBeGreaterThanOrEqual(1);
});

it("cancels before creating any snapshot root", async () => {
  const apk = await buildApk("cancel.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const controller = new AbortController();
  controller.abort();
  const provider = new FlutterBuildProvider({ environment: {} });
  const result = await provider.execute(
    { operation: "identify_flutter_build", input: { path: apk } },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  await provider.close();
});
