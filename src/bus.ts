import type { Db } from "./db.ts";
import type { IncomingMessage, ServerResponse } from "node:http";
import { safeFetch, validateUrl } from "./net.ts";

// ============================================================================
// TYPES
// ============================================================================

export interface AxonEvent {
  id: number;
  channel: string;
  source: string;
  type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

// Describes one agent's channel subscription and optional delivery filters.
export interface Subscription {
  id: number;
  agent: string;
  channel: string;
  filter_type: string | null;
  webhook_url: string | null;
  created_at: string;
}

// Tracks one connected SSE consumer and its current delivery cursor.
interface SSEClient {
  agent: string;
  channels: Set<string>;
  filterType: string | null;
  res: ServerResponse;
  lastEventId: number;
}

// ============================================================================
// IN-MEMORY SSE CLIENTS
// ============================================================================

const sseClients: Map<string, SSEClient> = new Map();
let clientIdCounter = 0;

// Strip CR and LF from a value destined for an SSE frame header line.
// The publish route rejects these up front; this is the second layer, applied
// at the sink itself so the frame stays well-formed no matter which caller
// produced the event.
function sseHeaderSafe(value: string): string {
  return value.replace(/[\r\n]/g, " ");
}

// Delivers a published event to every matching connected SSE consumer.
function broadcastToSSE(event: AxonEvent) {
  for (const [id, client] of sseClients) {
    if (!client.channels.has("*") && !client.channels.has(event.channel)) continue;
    if (client.filterType && event.type !== client.filterType) continue;
    try {
      client.res.write(`id: ${event.id}\nevent: ${sseHeaderSafe(event.type)}\ndata: ${JSON.stringify(event)}\n\n`);
      client.lastEventId = event.id;
    } catch {
      sseClients.delete(id);
    }
  }
}

// ============================================================================
// PUBLISH
// ============================================================================

export function publish(db: Db, channel: string, source: string, type: string, payload: Record<string, unknown>): AxonEvent {
  const row = db.prepare(
    "INSERT INTO events (channel, source, type, payload) VALUES (?, ?, ?, ?) RETURNING *"
  ).get(channel, source, type, JSON.stringify(payload)) as any;
  const event: AxonEvent = {
    id: row.id,
    channel: row.channel,
    source: row.source,
    type: row.type,
    payload: JSON.parse(row.payload),
    created_at: row.created_at,
  };

  // Fan out to SSE listeners
  broadcastToSSE(event);

  // Fan out to webhook subscribers
  fanOutWebhooks(db, event);

  return event;
}

// ============================================================================
// WEBHOOK FAN-OUT
// ============================================================================

function fanOutWebhooks(db: Db, event: AxonEvent) {
  const subs = db.prepare(
    "SELECT * FROM subscriptions WHERE channel = ? AND webhook_url IS NOT NULL"
  ).all(event.channel) as Subscription[];

  for (const sub of subs) {
    if (sub.filter_type && sub.filter_type !== event.type) continue;
    // Fire and forget. safeFetch re-resolves and revalidates the target at
    // this moment rather than trusting the check made when the subscription
    // was stored, which closes the DNS-rebinding window, and it revalidates
    // each redirect hop so a public origin cannot bounce us somewhere internal.
    safeFetch(sub.webhook_url!, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(5000),
    }).catch((e) => {
      console.error(
        JSON.stringify({
          msg: "axon_webhook_delivery_failed",
          agent: sub.agent,
          channel: sub.channel,
          error: e instanceof Error ? e.message : String(e),
        }),
      );
    });
  }
}

// ============================================================================
// QUERY
// ============================================================================

export function getEvents(
  db: Db,
  opts: { channel?: string; source?: string; type?: string; since_id?: number; limit?: number }
): AxonEvent[] {
  let query = "SELECT * FROM events WHERE 1=1";
  const params: Array<string | number> = [];

  if (opts.channel) { query += " AND channel = ?"; params.push(opts.channel); }
  if (opts.source) { query += " AND source = ?"; params.push(opts.source); }
  if (opts.type) { query += " AND type = ?"; params.push(opts.type); }
  if (opts.since_id) { query += " AND id > ?"; params.push(opts.since_id); }

  query += " ORDER BY id DESC LIMIT ?";
  params.push(opts.limit ?? 50);

  const rows = db.prepare(query).all(...params) as any[];
  return rows.map(r => ({ ...r, payload: JSON.parse(r.payload) }));
}

// Retrieves one event by numeric identifier, parsing its JSON payload.
export function getEvent(db: Db, id: number): AxonEvent | undefined {
  const row = db.prepare("SELECT * FROM events WHERE id = ?").get(id) as any;
  if (!row) return undefined;
  return { ...row, payload: JSON.parse(row.payload) };
}

// ============================================================================
// CHANNELS
// ============================================================================

export function listChannels(db: Db) {
  return db.prepare(`
    SELECT c.*, (SELECT COUNT(*) FROM events e WHERE e.channel = c.name) as event_count,
           (SELECT COUNT(*) FROM subscriptions s WHERE s.channel = c.name) as subscriber_count
    FROM channels c ORDER BY c.name
  `).all();
}

// Creates a channel or updates its description and retention policy.
export function createChannel(db: Db, name: string, description?: string, retainHours?: number) {
  return db.prepare(
    "INSERT INTO channels (name, description, retain_hours) VALUES (?, ?, ?) RETURNING *"
  ).get(name, description ?? null, retainHours ?? 168);
}

// ============================================================================
// SUBSCRIPTIONS
// ============================================================================

export function subscribe(db: Db, agent: string, channel: string, filterType?: string, webhookUrl?: string): Subscription {
  // Reject obviously-internal targets before they are ever persisted. This is
  // the cheap literal check; delivery re-validates with DNS resolution, since
  // a hostname that is public now may point inward later.
  if (webhookUrl) validateUrl(webhookUrl);
  return db.prepare(
    "INSERT INTO subscriptions (agent, channel, filter_type, webhook_url) VALUES (?, ?, ?, ?) ON CONFLICT(agent, channel) DO UPDATE SET filter_type = excluded.filter_type, webhook_url = excluded.webhook_url RETURNING *"
  ).get(agent, channel, filterType ?? null, webhookUrl ?? null) as Subscription;
}

// Removes an agent's subscription to one channel.
export function unsubscribe(db: Db, agent: string, channel: string): boolean {
  return db.prepare("DELETE FROM subscriptions WHERE agent = ? AND channel = ?").run(agent, channel).changes > 0;
}

// Lists subscriptions, optionally limited to one agent.
export function getSubscriptions(db: Db, agent?: string): Subscription[] {
  if (agent) {
    return db.prepare("SELECT * FROM subscriptions WHERE agent = ? ORDER BY channel").all(agent) as Subscription[];
  }
  return db.prepare("SELECT * FROM subscriptions ORDER BY channel, agent").all() as Subscription[];
}

// ============================================================================
// CURSORS (poll-based consumption)
// ============================================================================

export function poll(db: Db, agent: string, channel: string, limit: number = 50): { events: AxonEvent[]; cursor: number } {
  const cursor = db.prepare("SELECT last_event_id FROM cursors WHERE agent = ? AND channel = ?").get(agent, channel) as any;
  const sinceId = cursor?.last_event_id ?? 0;

  const rows = db.prepare(
    "SELECT * FROM events WHERE channel = ? AND id > ? ORDER BY id ASC LIMIT ?"
  ).all(channel, sinceId, limit) as any[];

  const events = rows.map(r => ({ ...r, payload: JSON.parse(r.payload) }));

  if (events.length > 0) {
    const newCursor = events[events.length - 1].id;
    db.prepare(
      "INSERT INTO cursors (agent, channel, last_event_id, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(agent, channel) DO UPDATE SET last_event_id = excluded.last_event_id, updated_at = datetime('now')"
    ).run(agent, channel, newCursor);
  }

  return { events, cursor: events.length > 0 ? events[events.length - 1].id : sinceId };
}

// Returns an agent's current cursor position on a channel without consuming
// events or advancing the cursor, unlike poll() which does both as a side
// effect. Useful for a caller that wants to know how far behind it is before
// deciding whether to poll or stream.
export function getCursor(db: Db, agent: string, channel: string): { agent: string; channel: string; cursor: number } {
  const row = db.prepare(
    "SELECT last_event_id FROM cursors WHERE agent = ? AND channel = ?"
  ).get(agent, channel) as { last_event_id: number } | undefined;
  return { agent, channel, cursor: row?.last_event_id ?? 0 };
}

// ============================================================================
// SSE STREAM
// ============================================================================

// Loads events published on the given channels (or every channel, if the set
// contains the "*" wildcard) after lastEventId, respecting an optional type
// filter. Used at SSE connect time to replay whatever a client missed while
// disconnected, mirroring the semantics of broadcastToSSE's own filtering.
function catchUpEvents(db: Db, channels: Set<string>, filterType: string | null, lastEventId: number): AxonEvent[] {
  const wildcard = channels.has("*");
  let rows: any[];
  if (wildcard) {
    rows = db.prepare(
      "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 1000"
    ).all(lastEventId) as any[];
  } else if (channels.size === 0) {
    return [];
  } else {
    const list = [...channels];
    const placeholders = list.map(() => "?").join(",");
    rows = db.prepare(
      `SELECT * FROM events WHERE channel IN (${placeholders}) AND id > ? ORDER BY id ASC LIMIT 1000`
    ).all(...list, lastEventId) as any[];
  }
  const events = rows.map(r => ({ ...r, payload: JSON.parse(r.payload) })) as AxonEvent[];
  return filterType ? events.filter(e => e.type === filterType) : events;
}

// Opens an SSE stream, replays missed events, and registers live delivery.
export function startSSE(
  db: Db,
  req: IncomingMessage,
  res: ServerResponse,
  agent: string,
  channels: string[],
  filterType?: string,
  lastEventId?: number,
) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(":ok\n\n");

  const clientId = `sse-${++clientIdCounter}`;
  const channelSet = new Set(channels);
  let trackedLastId = lastEventId ?? 0;

  // Replay whatever was published while this client was disconnected before
  // it joins the live broadcast below. Because this whole block runs
  // synchronously (no await), nothing else can publish in between the query
  // and the client being registered in sseClients, so there is no gap for an
  // event to be either lost or delivered twice.
  if (lastEventId !== undefined && lastEventId > 0) {
    const missed = catchUpEvents(db, channelSet, filterType ?? null, lastEventId);
    for (const event of missed) {
      try {
        res.write(`id: ${event.id}\nevent: ${sseHeaderSafe(event.type)}\ndata: ${JSON.stringify(event)}\n\n`);
        trackedLastId = event.id;
      } catch {
        // Connection died mid-replay; the "close" handler registered below
        // will still fire and clean up sseClients once this function returns.
        break;
      }
    }
  }

  const client: SSEClient = {
    agent,
    channels: channelSet,
    filterType: filterType ?? null,
    res,
    lastEventId: trackedLastId,
  };
  sseClients.set(clientId, client);

  req.on("close", () => { sseClients.delete(clientId); });

  // Send heartbeat every 30s
  const heartbeat = setInterval(() => {
    try { res.write(":heartbeat\n\n"); } catch { clearInterval(heartbeat); sseClients.delete(clientId); }
  }, 30000);
  req.on("close", () => clearInterval(heartbeat));
}

// ============================================================================
// MAINTENANCE
// ============================================================================

// Default retention window (7 days) applied to a channel that has events but
// no row in `channels` -- mirrors the schema's own DEFAULT for retain_hours.
const DEFAULT_RETAIN_HOURS = 168;

// Deletes events older than their channel's retention window. publish() never
// requires a channel to be registered in `channels`, so events on an ad-hoc
// channel would never match the old channel-table-driven loop and would grow
// unbounded. This instead enumerates every channel that actually has events,
// falling back to DEFAULT_RETAIN_HOURS for any that lack a `channels` row.
export function pruneEvents(db: Db) {
  const configured = new Map<string, number>();
  for (const ch of db.prepare("SELECT name, retain_hours FROM channels").all() as Array<{ name: string; retain_hours: number }>) {
    configured.set(ch.name, ch.retain_hours);
  }

  const eventChannels = (db.prepare("SELECT DISTINCT channel FROM events").all() as Array<{ channel: string }>)
    .map(r => r.channel);

  let total = 0;
  for (const channel of eventChannels) {
    const retainHours = configured.get(channel) ?? DEFAULT_RETAIN_HOURS;
    const result = db.prepare(
      "DELETE FROM events WHERE channel = ? AND created_at < datetime('now', ?)"
    ).run(channel, `-${retainHours} hours`);
    total += result.changes;
  }
  return total;
}

// Returns aggregate event, channel, subscription, and cursor counts.
export function getStats(db: Db) {
  const eventCount = (db.prepare("SELECT COUNT(*) as c FROM events").get() as any).c;
  const channelCount = (db.prepare("SELECT COUNT(*) as c FROM channels").get() as any).c;
  const subCount = (db.prepare("SELECT COUNT(*) as c FROM subscriptions").get() as any).c;
  const activeSSE = sseClients.size;
  return { events: eventCount, channels: channelCount, subscriptions: subCount, sse_clients: activeSSE };
}
