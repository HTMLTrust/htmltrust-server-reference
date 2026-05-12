#!/usr/bin/env node
/**
 * Convenience orchestrator: boots a disposable MongoDB (via
 * mongodb-memory-server), starts the Node reference server pointed at
 * that mongo, runs the conformance suite, and tears everything down.
 *
 * Used by `npm run conformance`. For arbitrary target servers, drive
 * run.mjs directly.
 *
 * Exit code mirrors the runner's: 0 pass, 1 fail, 2 setup error.
 */
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SELF_DIR, "..", "..");
const requireFromRoot = createRequire(resolve(REPO_ROOT, "package.json"));

const MONGO_PORT = parseInt(process.env.MONGO_PORT || "37017", 10);
const SERVER_PORT = parseInt(process.env.SERVER_PORT || "3000", 10);
const GENERAL_API_KEY = process.env.GENERAL_API_KEY || "conformance_general_key";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "conformance_admin_key";

// Forward any extra CLI args to the runner.
const extraArgs = process.argv.slice(2);

let mongod = null;
let serverProc = null;

async function shutdown(exitCode) {
  try {
    if (serverProc && !serverProc.killed) {
      serverProc.kill("SIGTERM");
      // Brief grace period.
      await sleep(500);
      if (!serverProc.killed) serverProc.kill("SIGKILL");
    }
  } catch {}
  try {
    if (mongod) await mongod.stop();
  } catch {}
  process.exit(exitCode);
}

process.on("SIGINT", () => shutdown(130));
process.on("SIGTERM", () => shutdown(143));

async function main() {
  // 1. Spin up mongodb-memory-server.
  let MongoMemoryServer;
  try {
    ({ MongoMemoryServer } = requireFromRoot("mongodb-memory-server"));
  } catch (e) {
    console.error("mongodb-memory-server is not installed.");
    console.error("Run `npm install --save-dev mongodb-memory-server` in the repo root,");
    console.error("or use conformance/run-conformance.sh (docker-based) instead.");
    process.exit(2);
  }

  console.log(`booting in-process mongo on port ${MONGO_PORT}`);
  mongod = await MongoMemoryServer.create({ instance: { port: MONGO_PORT } });
  const mongoUri = mongod.getUri();
  console.log(`mongo ready: ${mongoUri}`);

  // 2. Spawn the reference server.
  console.log(`starting reference server on port ${SERVER_PORT}`);
  const serverEnv = {
    ...process.env,
    MONGO_URI: `mongodb://localhost:${MONGO_PORT}/htmltrust-conformance`,
    PORT: String(SERVER_PORT),
    GENERAL_API_KEY,
    ADMIN_API_KEY,
    NODE_ENV: "test",
  };
  serverProc = spawn(process.execPath, [resolve(REPO_ROOT, "src/server.js")], {
    env: serverEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let serverExited = false;
  let serverOutput = "";
  serverProc.stdout.on("data", (b) => { serverOutput += b.toString(); });
  serverProc.stderr.on("data", (b) => { serverOutput += b.toString(); });
  serverProc.on("exit", (code, signal) => {
    serverExited = true;
    if (!shuttingDown) {
      console.error(`reference server exited unexpectedly (code=${code} signal=${signal})`);
      console.error("--- server output ---");
      console.error(serverOutput);
      shutdown(2);
    }
  });

  // 3. Poll for liveness.
  const healthUrl = `http://localhost:${SERVER_PORT}/api/claims`;
  let ready = false;
  for (let i = 0; i < 60; i++) {
    if (serverExited) break;
    try {
      const res = await fetch(healthUrl);
      if (res.ok) {
        ready = true;
        break;
      }
    } catch {}
    await sleep(500);
  }
  if (!ready) {
    console.error(`reference server did not become ready within 30s`);
    console.error("--- server output ---");
    console.error(serverOutput);
    return shutdown(2);
  }
  console.log("server ready");
  console.log("");

  // 4. Run the conformance runner.
  const runnerArgs = [
    resolve(SELF_DIR, "run.mjs"),
    "--target-url", `http://localhost:${SERVER_PORT}`,
    "--base-path", "/api",
    "--general-api-key", GENERAL_API_KEY,
    "--admin-api-key", ADMIN_API_KEY,
    "--accept-mongo-ids",
    ...extraArgs,
  ];
  const runner = spawn(process.execPath, runnerArgs, { stdio: "inherit" });
  const runnerExit = await new Promise((resolveExit) => {
    runner.on("exit", (code) => resolveExit(code ?? 1));
  });

  shuttingDown = true;
  await shutdown(runnerExit);
}

let shuttingDown = false;

main().catch((e) => {
  console.error("orchestrator error:", e.stack || e.message);
  shuttingDown = true;
  shutdown(2);
});
