# Drawgo — API Reference

All endpoints are prefixed with `/api/v1`. The frontend proxies requests via Next.js rewrites.

## Authentication

Auth uses JWT with HttpOnly cookies. Access tokens (15min) are sent via `access_token` cookie.
Refresh tokens (30 days) are sent via `refresh_token` cookie. Cookies are set automatically on login.

## Response Format

### Success Envelope

```json
{
  "data": { ... }
}
```

### Paginated Response

```json
{
  "data": [ ... ],
  "meta": {
    "total": 42,
    "limit": 50,
    "offset": 0
  }
}
```

### Error Envelope

```json
{
  "data": null,
  "error": {
    "code": "NOT_FOUND",
    "message": "Board not found"
  }
}
```

---

## Health & System

### `GET /health`

Health check. Returns 200 if server is running.

```json
{ "data": { "status": "ok" } }
```

### `GET /ready`

Readiness check. Verifies database and S3 connectivity.

```json
{ "data": { "status": "ready", "database": "ok", "storage": "ok" } }
```

### `GET /version`

Build version information.

```json
{
  "data": {
    "version": "1.0.0",
    "commit": "abc1234",
    "buildTime": "2026-03-01T00:00:00Z"
  }
}
```

### `GET /stats` (auth required)

System-wide statistics including row counts, CRUD breakdown, backup info, log summary, Go runtime metrics, connection pool stats, S3 storage, process metrics, container/cgroup stats, request metrics, and build info.

```json
{
  "data": {
    "counts": {
      "users": 12,
      "organizations": 5,
      "boards": 47,
      "boardVersions": 312,
      "auditEvents": 1893,
      "boardAssets": 89,
      "memberships": 28,
      "shareLinks": 15,
      "accounts": 14,
      "refreshTokens": 8,
      "backups": 23
    },
    "database": {
      "databaseSizeBytes": 44040192,
      "tables": [
        {
          "table": "boards",
          "totalBytes": 28672,
          "dataBytes": 16384,
          "indexBytes": 12288,
          "rowCount": 47
        }
      ],
      "activeConnections": 3,
      "maxConnections": 25,
      "cacheHitRatio": 0.98,
      "uptime": "3 days 04:12:33"
    },
    "pool": {
      "acquireCount": 14523,
      "acquiredConns": 2,
      "idleConns": 3,
      "totalConns": 5,
      "constructingConns": 0,
      "maxConns": 25,
      "emptyAcquireCount": 12,
      "canceledAcquireCount": 0
    },
    "runtime": {
      "goroutines": 42,
      "heapAlloc": 8388608,
      "heapSys": 16777216,
      "heapInuse": 9437184,
      "stackInuse": 1048576,
      "gcPauseNs": 256000,
      "numGC": 15,
      "numCPU": 4,
      "goVersion": "go1.25.0"
    },
    "storage": {
      "buckets": [
        {
          "bucket": "drawgo-data",
          "objectCount": 142,
          "totalBytes": 52428800,
          "largestBytes": 2097152
        },
        {
          "bucket": "drawgo-backups",
          "objectCount": 18,
          "totalBytes": 10485760,
          "largestBytes": 5242880
        }
      ],
      "totalBytes": 62914560,
      "totalObjects": 160
    },
    "process": {
      "pid": 1,
      "rss": 67108864,
      "openFDs": 24,
      "uptimeSeconds": 86400,
      "startTime": "2025-01-15T00:00:00Z"
    },
    "build": {
      "version": "1.2.0",
      "commitSHA": "abc1234def5678",
      "buildTime": "2025-01-15T12:00:00Z",
      "goVersion": "go1.25.0"
    },
    "container": {
      "isContainer": true,
      "memoryLimitBytes": 1073741824,
      "memoryUsageBytes": 67108864,
      "memoryUsagePercent": 6.25,
      "cpuQuota": 200000,
      "cpuPeriod": 100000,
      "effectiveCpus": 2.0,
      "containerId": "a1b2c3d4e5f6"
    },
    "requests": {
      "totalRequests": 14523,
      "totalErrors": 12,
      "total4xx": 45,
      "errorRate": 0.00083,
      "uptimeSeconds": 86400,
      "requestsPerSec": 0.168,
      "latencyP50Ms": 1.2,
      "latencyP95Ms": 8.5,
      "latencyP99Ms": 42.1,
      "statusCodes": { "2xx": 14400, "3xx": 66, "4xx": 45, "5xx": 12 },
      "methodCounts": { "GET": 12000, "POST": 1500, "PUT": 800, "DELETE": 223 }
    },
    "crudBreakdown": {
      "byAction": [
        { "action": "board.create", "count": 47 },
        { "action": "board.update", "count": 312 },
        { "action": "user.login", "count": 580 },
        { "action": "version.create", "count": 312 }
      ],
      "totalEvents": 1893
    },
    "backupInfo": {
      "totalBackups": 23,
      "lastBackupAt": "2026-01-15T03:00:12Z",
      "lastBackupSizeBytes": 5242880,
      "lastBackupStatus": "completed",
      "scheduleEnabled": true,
      "scheduleCron": "0 3 * * *"
    },
    "logs": {
      "debug": 120,
      "info": 4500,
      "warn": 23,
      "error": 2,
      "fatal": 0,
      "total": 4645
    }
  }
}
```

---

## Authentication

### `POST /auth/register`

Create a new account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "Alice"
}
```

**Response (201):**
```json
{
  "data": {
    "user": {
      "id": "cq1234567890abcdef",
      "email": "user@example.com",
      "name": "Alice"
    }
  }
}
```

Sets `access_token` and `refresh_token` cookies.

### `POST /auth/login`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):** Same as register. Sets cookies.

### `POST /auth/refresh`

Rotate access and refresh tokens. Requires valid `refresh_token` cookie.

**Response (200):** Sets new cookies. Returns user data.

### `POST /auth/logout` (auth required)

Clears cookies and invalidates refresh token.

**Response (200):**
```json
{ "data": { "message": "logged out" } }
```

### `GET /auth/me` (auth required)

Get current user profile.

**Response (200):**
```json
{
  "data": {
    "id": "cq1234567890abcdef",
    "email": "user@example.com",
    "name": "Alice",
    "image": null,
    "emailVerified": null
  }
}
```

### `GET /auth/oauth/{provider}`

Initiate OAuth flow. Redirects to provider. `provider` is `google` or `github`.

### `GET /auth/oauth/{provider}/callback`

OAuth callback. Sets cookies and redirects to frontend.

---

## Organizations

### `POST /orgs` (auth required)

Create an organization. The creator becomes the OWNER.

**Request:**
```json
{
  "name": "My Team",
  "slug": "my-team"
}
```

**Response (201):**
```json
{
  "data": {
    "id": "cq...",
    "name": "My Team",
    "slug": "my-team",
    "createdAt": "2026-03-01T00:00:00Z"
  }
}
```

### `GET /orgs` (auth required)

List organizations the user belongs to.

**Response (200):**
```json
{
  "data": [
    { "id": "cq...", "name": "My Team", "slug": "my-team", "role": "OWNER" }
  ]
}
```

### `PATCH /orgs/{id}` (auth required, OWNER)

Rename an organization.

**Request:**
```json
{ "name": "New Name" }
```

### `DELETE /orgs/{id}` (auth required, OWNER)

Delete an organization. Fails if it has boards or is the user's only org.

---

## Members

### `GET /orgs/{id}/members` (auth required, VIEWER+)

List organization members.

**Response (200):**
```json
{
  "data": [
    {
      "id": "membership-id",
      "userId": "user-id",
      "userName": "Alice",
      "userEmail": "alice@example.com",
      "role": "OWNER",
      "joinedAt": "2026-03-01T00:00:00Z"
    }
  ]
}
```

### `POST /orgs/{id}/members` (auth required, ADMIN+)

Invite a user to the organization.

**Request:**
```json
{
  "email": "bob@example.com",
  "role": "MEMBER"
}
```

### `PATCH /orgs/{id}/members/{membershipId}` (auth required, ADMIN+)

Update a member's role. Cannot change OWNER role.

**Request:**
```json
{ "role": "ADMIN" }
```

### `DELETE /orgs/{id}/members/{membershipId}` (auth required, ADMIN+)

Remove a member. Cannot remove the OWNER.

---

## Boards

### `POST /orgs/{id}/boards` (auth required)

Create a board in an organization.

**Request:**
```json
{
  "title": "Architecture Diagram",
  "description": "System design overview",
  "tags": ["architecture", "design"]
}
```

**Response (201):**
```json
{
  "data": {
    "id": "cq...",
    "title": "Architecture Diagram",
    "description": "System design overview",
    "tags": ["architecture", "design"],
    "orgId": "cq...",
    "ownerId": "cq...",
    "currentVersion": 1,
    "isArchived": false,
    "etag": "v-1709337600000-a1b2c3",
    "createdAt": "2026-03-01T00:00:00Z",
    "updatedAt": "2026-03-01T00:00:00Z"
  }
}
```

### `GET /orgs/{id}/boards` (auth required)

List boards with search and pagination.

**Query Parameters:**
- `query` — Search title, description, content
- `tags` — Comma-separated tag filter
- `archived` — `true` to include archived
- `limit` — Page size (default 50, max 100)
- `offset` — Pagination offset

**Response (200):**
```json
{
  "data": [ { ... } ],
  "meta": { "total": 42, "limit": 50, "offset": 0 }
}
```

### `GET /boards/{id}` (auth required)

Get a board with its latest version content.

### `PATCH /boards/{id}` (auth required, EDITOR+)

Update board metadata (title, description, tags, isArchived).

### `DELETE /boards/{id}` (auth required, OWNER)

Delete a board and all its versions/assets.

---

## Versions

### `POST /boards/{id}/versions` (auth required, EDITOR+)

Save a new board version. Uses ETag for optimistic concurrency.

**Request:**
```json
{
  "sceneJson": { "elements": [...], "appState": {...}, "files": {...} },
  "etag": "v-1709337600000-a1b2c3",
  "label": "Added diagram"
}
```

**Response (200):**
```json
{
  "data": {
    "version": 2,
    "etag": "v-1709337700000-d4e5f6",
    "createdAt": "2026-03-01T00:01:40Z"
  }
}
```

**409 Conflict** if etag doesn't match (another save happened).

### `GET /boards/{id}/versions` (auth required)

List all versions for a board (newest first).

### `GET /boards/{id}/versions/{version}` (auth required)

Get a specific version's content.

### `POST /boards/{id}/versions/{version}/restore` (auth required, EDITOR+)

Restore a previous version. Creates a new version with the old content.

---

## Files

### `POST /boards/{id}/files` (auth required, EDITOR+)

Upload a file to S3. Multipart form data.

**Request:** `multipart/form-data` with `file` field + optional `fileId` field.

**Response (201):**
```json
{
  "data": {
    "fileId": "abc123",
    "url": "https://...",
    "mimeType": "image/png",
    "size": 102400
  }
}
```

Limits: 25MB per file. Allowed types: PNG, JPEG, GIF, WebP, SVG.

### `GET /boards/{id}/files` (auth required)

List all file assets for a board.

### `GET /boards/{id}/files/{fileId}` (auth required)

Download a file or get a presigned URL.

**Query Parameters:**
- `presign=true` — Return a presigned URL instead of file content

### `GET /boards/{id}/storage` (auth required)

Board storage breakdown.

### `GET /orgs/{id}/storage` (auth required)

Organization-wide storage summary.

---

## Share Links

### `POST /boards/{id}/share` (auth required, EDITOR+)

Create a share link.

**Request:**
```json
{
  "role": "VIEWER",
  "expiresInHours": 72
}
```

**Response (201):**
```json
{
  "data": {
    "id": "cq...",
    "token": "a1b2c3d4...",
    "role": "VIEWER",
    "expiresAt": "2026-03-04T00:00:00Z",
    "createdAt": "2026-03-01T00:00:00Z"
  }
}
```

### `GET /boards/{id}/share` (auth required, EDITOR+)

List active share links for a board.

### `DELETE /boards/{id}/share/{linkId}` (auth required, EDITOR+)

Revoke a share link.

### `GET /share/{token}` (public)

Access a shared board via token. Returns board data with the role granted by the link.

---

## Audit

### `GET /orgs/{id}/audit` (auth required, ADMIN+)

Query audit logs.

**Query Parameters:**
- `action` — Filter by action type (e.g., `board.create`)
- `actorId` — Filter by actor
- `targetId` — Filter by target resource
- `from` / `to` — Date range (ISO 8601)
- `limit` / `offset` — Pagination

### `GET /orgs/{id}/audit/stats` (auth required, ADMIN+)

Audit statistics (action counts over time).

**Query Parameters:**
- `days` — Time range (default 30, max 365)

### `GET /orgs/{id}/stats` (auth required, VIEWER+)

Organization-scoped counts and CRUD breakdown.

**Response (200):**
```json
{
  "data": {
    "boards": 12,
    "members": 5,
    "boardVersions": 156,
    "boardAssets": 34,
    "shareLinks": 8,
    "crudBreakdown": [
      { "action": "board.create", "count": 12 },
      { "action": "board.update", "count": 97 }
    ]
  }
}
```

---

## Logs

### `GET /logs` (auth required)

Query backend log entries from the in-memory ring buffer.

**Query Parameters:**
- `level` — Filter by log level (`debug`, `info`, `warn`, `error`, `fatal`)
- `search` — Text search across log messages
- `start` / `end` — Date range (ISO 8601 / RFC 3339)
- `limit` — Page size (default 100, max 1000)
- `offset` — Pagination offset

**Response (200):**
```json
{
  "data": [
    {
      "timestamp": "2026-03-30T12:00:00Z",
      "level": "info",
      "message": "board saved",
      "fields": { "boardId": "cq...", "version": 5 }
    }
  ],
  "meta": { "total": 4500, "limit": 100, "offset": 0 }
}
```

### `GET /logs/summary` (auth required)

Log level counts from the ring buffer.

**Response (200):**
```json
{
  "data": {
    "debug": 120,
    "info": 4500,
    "warn": 23,
    "error": 2,
    "fatal": 0,
    "total": 4645
  }
}
```

---

## Backups

### `POST /backups` (auth required)

Trigger a manual backup (pg_dump → S3).

### `GET /backups` (auth required)

List backup metadata.

### `GET /backups/{id}` (auth required)

Get backup details.

### `GET /backups/{id}/download` (auth required)

Get a presigned S3 URL to download the backup.

### `DELETE /backups/{id}` (auth required)

Delete a backup from S3 and metadata.

### `POST /backups/{id}/restore` (auth required)

Restore from a backup. Creates a safety backup first.

### `GET /backups/schedule` (auth required)

Get the backup schedule configuration.

### `PUT /backups/schedule` (auth required)

Update the backup schedule.

**Request:**
```json
{
  "enabled": true,
  "cron": "0 3 * * *",
  "keepDaily": 7,
  "keepWeekly": 4,
  "keepMonthly": 6
}
```

---

## WebSocket

### `GET /ws/boards/{id}` (auth via cookie or query params)

Upgrade to WebSocket for real-time collaboration.

**Authentication (in priority order):**
1. `token=<jwt>` query parameter — JWT access token
2. `share=<shareToken>` query parameter — Share link token
3. `access_token` HttpOnly cookie — Automatic cookie-based auth (no query param needed)

**Per-Client Rate Limiting:** Each client has a sliding-window rate limiter — cursor messages are capped at 30/second and scene updates at 5/second. Excessive messages are silently dropped.

**Message Format:**
```json
{
  "type": "cursor_update",
  "payload": { "x": 100, "y": 200 },
  "senderId": "user-id"
}
```

**Message Types:**
- `cursor_move` — Cursor position (client → server)
- `cursor_update` — Batched cursor positions (server → client)
- `scene_update` — Scene change broadcast
- `scene_synced` — Scene sync acknowledgement
- `presence` — Active viewers list
- `joined` / `left` — User join/leave events
- `ping` / `pong` — Keepalive
- `broadcast` — General broadcast
- `error` — Error notification

### `GET /ws/stats` (auth required)

WebSocket hub statistics.

```json
{
  "data": {
    "activeRooms": 3,
    "totalClients": 8
  }
}
```

---

## Rate Limits

| Tier     | Limit           | Applies To                    |
| -------- | --------------- | ----------------------------- |
| General  | 60/min per IP   | All API routes                |
| Auth     | 10/min per IP   | Login, register, refresh      |
| Upload   | 30/min per IP   | File uploads                  |
| WebSocket| 10/min per IP   | WebSocket upgrade             |

Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.
429 Too Many Requests is returned when the limit is exceeded.
