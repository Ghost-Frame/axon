import { createServer, type ServerResponse, type IncomingMessage } from "node:http";
import { initDb } from "./db.ts";
import {
  publish, getEvents, getEvent, listChannels, createChannel,
  subscribe, unsubscribe, getSubscriptions,
  poll, getCursor, startSSE, pruneEvents, getStats,
} from "./bus.ts";

const DB_PATH = process.env.DB_PATH ?? "./axon.db";
const HOST = process.env.HOST ?? "0.0.0.0";
const AUTH_DISABLED = process.env.AXON_AUTH === "disabled";
const AXON_API_KEY = process.env.AXON_API_KEY;
const CORS_ALLOW_ORIGIN = process.env.CORS_ALLOW_ORIGIN;

// Parses an integer environment setting and falls back when it is invalid.
function envInt(v: string | undefined, fallback: number): number {
  const n = Number.parseInt(v ?? "", 10);
  return Number.isFinite(n) ? n : fallback;
}

const PORT = envInt(process.env.PORT, 4600);
const BODY_MAX = envInt(process.env.BODY_MAX_BYTES, 64 * 1024);

if (!AXON_API_KEY && !AUTH_DISABLED) {
  console.error("FATAL: AXON_API_KEY is not set.");
  console.error("  Set AXON_API_KEY to enable auth, or");
  console.error("  set AXON_AUTH=disabled to run without auth.");
  process.exit(1);
}

const db = initDb(DB_PATH);

// Prune expired events every hour
setInterval(() => { pruneEvents(db); }, 60 * 60 * 1000).unref();
pruneEvents(db);

// ============================================================================
// HELPERS
// ============================================================================

function json(res: ServerResponse, data: unknown, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

// Writes a JSON error response with the requested HTTP status.
function error(res: ServerResponse, message: string, status = 400) {
  json(res, { error: message }, status);
}

// Applies the configured CORS policy to one response.
function applyCors(origin: string | undefined, res: ServerResponse) {
  if (!CORS_ALLOW_ORIGIN) return;
  if (CORS_ALLOW_ORIGIN === "*" || origin === CORS_ALLOW_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN === "*" ? "*" : origin ?? CORS_ALLOW_ORIGIN);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Vary", "Origin");
  }
}

// Validates the request bearer token unless authentication is disabled.
function authenticate(req: IncomingMessage): boolean {
  if (AUTH_DISABLED) return true;
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return false;
  return auth.slice(7) === AXON_API_KEY;
}

// Reads and validates a size-limited JSON object request body.
async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const done = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > BODY_MAX) { done(() => { req.resume(); reject(new Error("Body too large")); }); return; }
      chunks.push(chunk);
    });
    req.on("end", () => done(() => {
      if (chunks.length === 0) { resolve({}); return; }
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString());
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) { reject(new Error("Must be JSON object")); return; }
        resolve(parsed);
      } catch { reject(new Error("Invalid JSON")); }
    }));
    req.on("error", (e) => done(() => reject(e)));
  });
}

// Parses and clamps a numeric query parameter to an allowed range.
function bounded(v: string | null, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(v ?? "", 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : fallback;
}

// ============================================================================
// HTTP SERVER
// ============================================================================

const server = createServer(async (req, res) => {
  applyCors(req.headers.origin, res);
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  try {
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const path = url.pathname;

    // Health -- always open
    if (path === "/health" && req.method === "GET") {
      return json(res, { status: "ok", version: "0.1.0", ...getStats(db) });
    }

    // Auth gate
    if (!authenticate(req)) return error(res, "Unauthorized", 401);

    // ---- PUBLISH ----
    if (path === "/publish" && req.method === "POST") {
      const body = await readBody(req);
      const { channel, source, type, payload } = body as {
        channel?: string; source?: string; type?: string; payload?: Record<string, unknown>;
      };
      if (!channel || typeof channel !== "string") return error(res, "channel required");
      if (!source || typeof source !== "string") return error(res, "source required");
      if (!type || typeof type !== "string") return error(res, "type required");
      // `type` is written into the SSE frame's `event:` line. A CR or LF would
      // terminate that line early and let a publisher forge arbitrary frames
      // into every connected stream, so reject both here.
      if (/[\r\n]/.test(type)) return error(res, "type must not contain newline characters");
      const event = publish(db, channel, source, type, payload ?? {});
      return json(res, event, 201);
    }

    // ---- EVENTS ----
    if (path === "/events" && req.method === "GET") {
      const events = getEvents(db, {
        channel: url.searchParams.get("channel") ?? undefined,
        source: url.searchParams.get("source") ?? undefined,
        type: url.searchParams.get("type") ?? undefined,
        since_id: url.searchParams.has("since_id") ? Number(url.searchParams.get("since_id")) : undefined,
        limit: bounded(url.searchParams.get("limit"), 50, 1, 500),
      });
      return json(res, events);
    }

    // GET /events/:id
    const eventMatch = path.match(/^\/events\/(\d+)$/);
    if (eventMatch && req.method === "GET") {
      const event = getEvent(db, parseInt(eventMatch[1], 10));
      if (!event) return error(res, "Event not found", 404);
      return json(res, event);
    }

    // ---- CHANNELS ----
    if (path === "/channels" && req.method === "GET") {
      return json(res, listChannels(db));
    }

    if (path === "/channels" && req.method === "POST") {
      const body = await readBody(req);
      const { name, description, retain_hours } = body as {
        name?: string; description?: string; retain_hours?: number;
      };
      if (!name || typeof name !== "string") return error(res, "name required");
      try {
        return json(res, createChannel(db, name, description, retain_hours), 201);
      } catch (e: any) {
        if (e.message?.includes("UNIQUE")) return error(res, "Channel already exists", 409);
        throw e;
      }
    }

    // ---- SUBSCRIBE ----
    if (path === "/subscribe" && req.method === "POST") {
      const body = await readBody(req);
      const { agent, channel, filter_type, webhook_url } = body as {
        agent?: string; channel?: string; filter_type?: string; webhook_url?: string;
      };
      if (!agent || typeof agent !== "string") return error(res, "agent required");
      if (!channel || typeof channel !== "string") return error(res, "channel required");
      // subscribe() rejects webhook targets pointing at internal address space.
      // That is caller error, so surface it as 400 rather than letting it fall
      // through to the generic 500 handler.
      try {
        return json(res, subscribe(db, agent, channel, filter_type, webhook_url), 201);
      } catch (e) {
        return error(res, e instanceof Error ? e.message : "invalid subscription");
      }
    }

    if (path === "/unsubscribe" && req.method === "POST") {
      const body = await readBody(req);
      const { agent, channel } = body as { agent?: string; channel?: string };
      if (!agent || !channel) return error(res, "agent and channel required");
      const ok = unsubscribe(db, agent, channel);
      return json(res, { ok });
    }

    if (path === "/subscriptions" && req.method === "GET") {
      const agent = url.searchParams.get("agent") ?? undefined;
      return json(res, getSubscriptions(db, agent));
    }

    // ---- POLL ----
    if (path === "/poll" && req.method === "GET") {
      const agent = url.searchParams.get("agent");
      const channel = url.searchParams.get("channel");
      if (!agent || !channel) return error(res, "agent and channel required");
      const limit = bounded(url.searchParams.get("limit"), 50, 1, 500);
      return json(res, poll(db, agent, channel, limit));
    }

    // ---- SSE STREAM ----
    if (path === "/stream" && req.method === "GET") {
      const agent = url.searchParams.get("agent");
      if (!agent) return error(res, "agent required");
      const channels = (url.searchParams.get("channels") ?? "*").split(",");
      const filterType = url.searchParams.get("type") ?? undefined;
      const lastId = url.searchParams.has("last_event_id") ? Number(url.searchParams.get("last_event_id")) : undefined;
      return startSSE(db, req, res, agent, channels, filterType, lastId);
    }

    // ---- CURSOR ----
    if (path === "/cursor" && req.method === "GET") {
      const agent = url.searchParams.get("agent");
      const channel = url.searchParams.get("channel");
      if (!agent || !channel) return error(res, "agent and channel required");
      return json(res, getCursor(db, agent, channel));
    }

    // ---- STATS ----
    if (path === "/stats" && req.method === "GET") {
      const stats = getStats(db);
      const channelStats = db.prepare(`
        SELECT channel, COUNT(*) as count, MAX(created_at) as latest
        FROM events GROUP BY channel ORDER BY count DESC
      `).all();
      return json(res, { ...stats, by_channel: channelStats });
    }

    error(res, "Not found", 404);
  } catch (err) {
    console.error("Unhandled:", err);
    if (!res.headersSent) res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Internal server error" }));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Axon running on http://${HOST}:${PORT}`);
  console.log(`Database: ${DB_PATH}`);
  console.log(`Auth: ${AUTH_DISABLED ? "DISABLED" : "enabled"}`);
  console.log(`CORS: ${CORS_ALLOW_ORIGIN ?? "disabled"}`);
});
