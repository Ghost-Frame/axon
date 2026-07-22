// Integration tests for Axon's public HTTP validation boundary.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";

const TEST_PORT = 14601;
let serverProcess: ChildProcess | null = null;

// Waits until the spawned Axon server accepts health checks.
async function waitForServer(timeoutMs = 10_000): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(`http://127.0.0.1:${TEST_PORT}/health`);
      if (response.ok) return;
    } catch {
      // The child has not bound its socket yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Axon test server did not start in time");
}

before(async () => {
  serverProcess = spawn(
    process.execPath,
    ["--experimental-strip-types", "src/server.ts"],
    {
      env: {
        ...process.env,
        PORT: String(TEST_PORT),
        HOST: "127.0.0.1",
        DB_PATH: ":memory:",
        AXON_AUTH: "disabled",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  await waitForServer();
});

after(() => {
  serverProcess?.kill("SIGTERM");
  serverProcess = null;
});

test("POST /publish rejects an SSE event type containing a newline", async () => {
  const response = await fetch(`http://127.0.0.1:${TEST_PORT}/publish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      channel: "security",
      source: "test",
      type: "valid\nforged",
      payload: {},
    }),
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "type must not contain newline characters",
  });
});
