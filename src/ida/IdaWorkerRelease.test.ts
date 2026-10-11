import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { JsonValue } from "../domain/jsonValue.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { closeVerifiedIdaWorker } from "./IdaWorkerRelease.js";

const roots: string[] = [];
afterEach(async () => {
  for (const path of roots.splice(0))
    await rm(path, { recursive: true, force: true });
});

const fixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ida-release-test-"));
  roots.push(root);
  const inputPath = join(root, "source-owned.bin");
  const bytes = Buffer.from("harmless source-owned IDA release fixture");
  await writeFile(inputPath, bytes);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const database = "rea-source-owned-session";
  const calls: Array<{
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }> = [];
  const connection: IdaMcpConnection = {
    async connect() {
      return ["idb_close"];
    },
    async call(name, args) {
      calls.push({ name, args });
      if (name !== "idb_close") throw new Error("unexpected tool");
      return { error: "Session not found" };
    },
    serverInfo: () => null,
    async close() {},
  };
  const options = {
    connection,
    database,
    privateSessionId: database,
    inputPath,
    sha256,
    openCompleted: true,
  };
  const proof = () => ({
    session_id: database,
    input_path: inputPath,
    owned: true,
    backend: "worker",
    process_exited: true,
    discovery: { status: "complete", sessions: [] },
  });
  return { options, connection, calls, proof, inputPath, database };
};

describe("IDA worker release receipt trust boundary", () => {
  it("rejects a foreign session before any close request, even if a normal close would acknowledge it", async () => {
    const { options, calls, connection, proof } = await fixture();
    connection.verifyWorkerRelease = async () => proof();
    await expect(
      closeVerifiedIdaWorker({
        ...options,
        database: "foreign-worker",
      }),
    ).rejects.toThrow("outside its private worker ownership");
    expect(calls).toHaveLength(0);
  });

  it("closes only the owned worker with save=false in the normal case", async () => {
    const { options, connection, calls, database } = await fixture();
    connection.call = async (name, args) => {
      calls.push({ name, args });
      return {
        success: true,
        session_id: database,
        saved: null,
        owned: true,
        backend: "worker",
      };
    };
    await expect(closeVerifiedIdaWorker(options)).resolves.toBe(
      "close-confirmed",
    );
    expect(calls).toEqual([
      { name: "idb_close", args: { database, save: false } },
    ]);
  });

  it("recovers a reaped worker only with complete, identity-matching, independently verified exit", async () => {
    const { options, connection, proof, inputPath, database } = await fixture();
    let verified = 0;
    connection.verifyWorkerRelease = async (identity) => {
      expect(identity).toEqual({ sessionId: database, inputPath });
      verified++;
      return proof();
    };
    await expect(closeVerifiedIdaWorker(options)).resolves.toBe(
      "release-verified",
    );
    expect(verified).toBe(1);
  });

  it("rejects empty inventory without a separate proof or with uncompleted startup", async () => {
    const { options, connection, proof } = await fixture();
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
    connection.verifyWorkerRelease = async () => proof();
    await expect(
      closeVerifiedIdaWorker({ ...options, openCompleted: false }),
    ).rejects.toThrow();
  });

  it.each([
    "foreign-session",
    "foreign-input",
    "unowned",
    "gui",
    "worker-still-alive",
    "discovery-failed",
    "discovery-missing",
    "worker-still-listed",
    "no-exit-evidence",
  ] as const)("refuses unsafe proof %s", async (kind) => {
    const { options, connection, proof, database, inputPath } = await fixture();
    const evidence: Record<string, JsonValue> = proof();
    if (kind === "foreign-session") evidence.session_id = "foreign";
    if (kind === "foreign-input") evidence.input_path = inputPath + ".foreign";
    if (kind === "unowned") evidence.owned = false;
    if (kind === "gui") evidence.backend = "gui";
    if (kind === "worker-still-alive") evidence.process_exited = false;
    if (kind === "discovery-failed")
      evidence.discovery = { status: "failed", sessions: [] };
    if (kind === "discovery-missing") delete evidence.discovery;
    if (kind === "no-exit-evidence") delete evidence.process_exited;
    if (kind === "worker-still-listed")
      evidence.discovery = {
        status: "complete",
        sessions: [
          {
            session_id: database,
            input_path: inputPath,
            owned: true,
            backend: "worker",
            is_active: true,
          },
        ],
      };
    connection.verifyWorkerRelease = async () => evidence;
    await expect(closeVerifiedIdaWorker(options), kind).rejects.toThrow();
  });

  it("rejects failed proof lookup or tampered input bytes", async () => {
    const { options, connection, proof, inputPath } = await fixture();
    connection.verifyWorkerRelease = async () => {
      throw new Error("unverified worker process exit");
    };
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
    connection.verifyWorkerRelease = async () => proof();
    await writeFile(inputPath, "tampered source-owned test data");
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
  });
});
