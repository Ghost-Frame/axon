# Axon

Agent event bus for the Syntheos agent OS stack.

Axon provides pub/sub messaging, real-time SSE streaming, webhook fan-out, and cursor-based polling. Agents publish typed events to named channels; other agents consume them via streaming, polling, or webhook callbacks.

Port: **4600**  
Stack: Node 22 + libsql (SQLite-compatible)  

---

## What It Does

- Accepts events published by any agent and fans them out to all subscribers immediately
- Streams events in real time via Server-Sent Events (SSE) to any connected listener
- Delivers events to registered webhook URLs with optional per-channel type filtering
- Supports cursor-based polling for agents that cannot hold a persistent connection
- Persists all events in libsql with configurable per-channel retention windows
- Auto-prunes expired events every hour

---

## Quick Start

```bash
docker run -d \
  --name axon \
  -p 4600:4600 \
  -v axon-data:/data \
  -e AXON_API_KEY=your-key-here \
  ghcr.io/syntheos-dev/axon:latest
```

To run without authentication (development only):

```bash
docker run -d -p 4600:4600 -e AXON_AUTH=disabled ghcr.io/syntheos-dev/axon:latest
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `4600` | HTTP port to listen on |
| `DB_PATH` | `/data/axon.db` in the Docker image (the code's own fallback is `./axon.db` when run outside Docker without `DB_PATH` set) | Path to the libsql database file |
| `AXON_API_KEY` | required | Bearer token for authenticated endpoints |
| `AXON_AUTH` | — | Set to `disabled` to skip auth entirely |
| `CORS_ALLOW_ORIGIN` | — | Allowed CORS origin, or `*` for all |
| `BODY_MAX_BYTES` | `65536` | Maximum request body size in bytes |

---

## Default Channels

| Channel | Purpose |
|---|---|
| `system` | Service startup, shutdown, health events |
| `memory` | Engram store, search, and link events |
| `tasks` | Chiasm task created, updated, completed events |
| `deploy` | Deployment started, succeeded, failed, rolled-back events |
| `alerts` | Triggered alerts and warnings |

Additional channels can be created via `POST /channels`.

---

## API Reference

All endpoints except `/health` require `Authorization: Bearer <AXON_API_KEY>` unless `AXON_AUTH=disabled`.

### Publish an Event

```
POST /publish
```

Body:

```json
{
  "channel": "tasks",
  "source": "chiasm",
  "type": "task.created",
  "payload": { "agent": "claude-code", "title": "Fix auth bug", "project": "engram" }
}
```

Response `201`: the persisted event object with `id` and `created_at`.

### List Events

```
GET /events
```

Query params:

| Param | Description |
|---|---|
| `channel` | Filter by channel name |
| `source` | Filter by source agent or service |
| `type` | Filter by event type |
| `since_id` | Return only events with id greater than this value |
| `limit` | Max results (1-500, default 50) |

### Get Single Event

```
GET /events/:id
```

### Real-Time SSE Stream

```
GET /stream?agent=myagent&channels=tasks,deploy&type=task.created&last_event_id=0
```

Establishes a persistent SSE connection. Events are pushed as they are published.

| Param | Description |
|---|---|
| `agent` | Required. Identifies the consuming agent |
| `channels` | Comma-separated list of channels, or `*` for all |
| `type` | Optional event type filter |
| `last_event_id` | Resume from this event id (replay missed events) |

Each event is delivered in SSE format:

```
id: 42
event: task.created
data: {"id":42,"channel":"tasks","source":"chiasm","type":"task.created","payload":{...},"created_at":"..."}
```

### Cursor-Based Polling

```
GET /poll?agent=myagent&channel=tasks&limit=50
```

Returns all events in the channel since the agents last poll cursor. The cursor is stored per agent per channel and advances automatically on each call. Use this for agents that cannot hold a persistent HTTP connection.

### Get Cursor Position

```
GET /cursor?agent=myagent&channel=tasks
```

Returns `{ "agent": ..., "channel": ..., "cursor": <last_event_id> }` for the given agent/channel pair without consuming events or advancing the cursor, unlike `/poll`.
