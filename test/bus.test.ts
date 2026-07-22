// Tests for src/bus.ts: retention pruning and cursor readback.
//
// These guard two properties that were previously broken or missing:
//   1. pruneEvents() must delete expired events even on a channel that was
//      never registered in the `channels` table, since publish() never
//      requires registration and such events would otherwise never be
//      pruned and would grow unbounded.
//   2. getCursor() must report an agent's cursor position on a channel
//      without ever advancing it, unlike poll() which both reads and
//      advances the cursor as a side effect.

import { test } from "node:test";
import assert from "node:assert/strict";
import { initDb } from "../src/db.ts";
import { publish, pruneEvents, poll, getCursor } from "../src/bus.ts";

// Backdates an event's created_at so it falls outside any retention window,
// mirroring how the Rust reference test ages an event past 168 hours.
function backdate(db: ReturnType<typeof initDb>, id: number, hoursAgo: number) {
  db.prepare("UPDATE events SET created_at = datetime('now', ?) WHERE id = ?").run(`-${hoursAgo} hours`, id);
}

test("pruneEvents deletes an expired event on an unregistered channel", () => {
  const db = initDb(":memory:");
  const event = publish(db, "ad-hoc-never-registered", "test", "test.event", {});
  backdate(db, event.id, 200); // past the 168-hour default retention window

  const deleted = pruneEvents(db);
  assert.equal(deleted, 1, "expired event on unregistered channel must be pruned");

  const remaining = db.prepare("SELECT COUNT(*) as c FROM events WHERE channel = ?").get("ad-hoc-never-registered") as any;
  assert.equal(remaining.c, 0);
});

test("pruneEvents keeps a recent event on an unregistered channel", () => {
  const db = initDb(":memory:");
  publish(db, "ad-hoc-never-registered", "test", "test.event", {});

  const deleted = pruneEvents(db);
  assert.equal(deleted, 0, "recent event on unregistered channel must not be pruned");

  const remaining = db.prepare("SELECT COUNT(*) as c FROM events WHERE channel = ?").get("ad-hoc-never-registered") as any;
  assert.equal(remaining.c, 1);
});

test("pruneEvents still honors an explicit retain_hours for a registered channel", () => {
  const db = initDb(":memory:");
  // "system" is seeded with the schema's default retain_hours (168).
  const event = publish(db, "system", "test", "test.event", {});
  backdate(db, event.id, 1); // well within the 168-hour window

  const deleted = pruneEvents(db);
  assert.equal(deleted, 0, "event within its channel's retention window must survive");
});

test("getCursor reports 0 for an agent/channel pair with no cursor row", () => {
  const db = initDb(":memory:");
  const result = getCursor(db, "agent-a", "tasks");
  assert.deepEqual(result, { agent: "agent-a", channel: "tasks", cursor: 0 });
});

test("getCursor returns the current position without advancing it", () => {
  const db = initDb(":memory:");
  publish(db, "tasks", "test", "task.created", {});
  publish(db, "tasks", "test", "task.created", {});

  const polled = poll(db, "agent-a", "tasks", 50);
  assert.equal(polled.events.length, 2);
  assert.equal(polled.cursor, polled.events[1].id);

  // Calling getCursor repeatedly must return the same value poll() left
  // behind, and must not itself move the cursor.
  const first = getCursor(db, "agent-a", "tasks");
  const second = getCursor(db, "agent-a", "tasks");
  assert.deepEqual(first, { agent: "agent-a", channel: "tasks", cursor: polled.cursor });
  assert.deepEqual(second, first);

  // A subsequent poll() should see no new events, proving getCursor() did
  // not advance the stored cursor past what poll() itself set.
  const polledAgain = poll(db, "agent-a", "tasks", 50);
  assert.equal(polledAgain.events.length, 0);
});
