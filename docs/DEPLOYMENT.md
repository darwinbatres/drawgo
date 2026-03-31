# Drawgo — Deployment Guide

## Docker Compose (Recommended)

The project ships with a complete `docker-compose.yml` that runs all services.

### Quick Start

```bash
cp .env.example .env

# Generate secrets (REQUIRED)
sed -i "s/CHANGE_ME_RUN_openssl_rand_hex_32/$(openssl rand -hex 32)/" .env
sed -i "s/CHANGE_ME_USE_STRONG_PASSWORD/$(openssl rand -base64 32 | tr -d '\n')/" .env

# Start all services
docker compose up -d --build

# Verify
curl http://localhost:3021/api/v1/health
```

### Services

| Service        | Image          | Port (Host) | Port (Internal) | Description                  |
| -------------- | -------------- | ----------- | --------------- | ---------------------------- |
| `postgres`     | postgres:16-alpine | 5433    | 5432            | Database                     |
| `minio`        | minio/minio:latest | 9010, 9011 | 9000, 9001   | Object storage               |
| `backend`      | Go (built)     | 8090        | 8080            | REST API + WS                |
| `frontend`     | Node.js (built)| —           | 3000            | Next.js app (internal only)  |
| `caddy`        | caddy:2-alpine | 3021        | 80              | Reverse proxy (entry point)  |

All host ports are configurable via `.env`:

```bash
POSTGRES_PORT=5433
MINIO_API_PORT=9010
MINIO_CONSOLE_PORT=9011
BACKEND_PORT=8090
APP_PORT=3021
```

### Optional Profiles

```bash
# With automated backups
docker compose --profile backup up -d --build

# With Cloudflare Tunnel
docker compose --profile tunnel up -d --build

# Both
docker compose --profile backup --profile tunnel up -d --build
```

---

## Production Checklist

Before deploying to production:

- [ ] **`JWT_SECRET`** — Generate with `openssl rand -hex 32`
- [ ] **`POSTGRES_PASSWORD`** — Use a strong, unique password
- [ ] **`S3_ACCESS_KEY` / `S3_SECRET_KEY`** — Change from `minioadmin` defaults
- [ ] **`CORS_ALLOWED_ORIGINS`** — Set to your actual domain(s)
- [ ] **`NEXT_PUBLIC_APP_URL`** — Set to your public URL
- [ ] **HTTPS** — Enable via reverse proxy or Cloudflare Tunnel
- [ ] **Ports** — Remove external port bindings for postgres/minio in production
- [ ] **Backups** — Enable the backup profile with appropriate retention

---

## Cloudflare Tunnel

Zero-config HTTPS access without opening firewall ports.

### Setup

1. Go to [Cloudflare One Dashboard](https://one.dash.cloudflare.com) → Networks → Tunnels
2. Create a tunnel, copy the token
3. Add a public hostname:
   - **Service Type:** HTTP
   - **URL:** `caddy:80`
4. Configure `.env`:

```bash
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiYWNj...
CORS_ALLOWED_ORIGINS=https://drawgo.yourdomain.com
NEXT_PUBLIC_APP_URL=https://drawgo.yourdomain.com
```

5. Start with tunnel profile:

```bash
docker compose --profile tunnel up -d --build
```

### Tips

- The tunnel connects outbound — no inbound firewall ports needed
- Caddy is the single entry point — it handles both API/WebSocket and frontend routing
- Caddy binds to `127.0.0.1` only by default — the tunnel connects internally via Docker network
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) are set by Caddy in the `Caddyfile`
- Go middleware also sets security headers as defense-in-depth
- Monitor at [Cloudflare One Dashboard](https://one.dash.cloudflare.com) → Networks → Tunnels

---

## External Reverse Proxy (Advanced)

> **Note:** Caddy is already included in the Docker Compose stack as the default reverse proxy. You only need an external reverse proxy if you're integrating with an existing infrastructure (e.g., Traefik, HAProxy, or a cloud load balancer).

When using an external proxy, point it at the Caddy port (`APP_PORT`, default 3021). Caddy handles internal routing between the frontend and backend, so your external proxy only needs a single upstream.

Example (nginx-style syntax — adapt for your proxy):

```nginx
upstream drawgo {
    server 127.0.0.1:3021;
}

# Route all traffic (HTTP + WebSocket) to Caddy
# Caddy internally routes /api/v1/* to the Go backend and everything else to Next.js
```

Ensure your external proxy:
- Passes `Upgrade` and `Connection` headers for WebSocket support
- Sets `X-Real-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` headers
- Has sufficient read timeout for WebSocket connections (~86400s)
```

---

## Backups

### Automated Backups

Enable the backup scheduler:

```bash
# In .env
BACKUP_ENABLED=true
BACKUP_CRON=0 3 * * *        # Daily at 3 AM
BACKUP_KEEP_DAILY=7
BACKUP_KEEP_WEEKLY=4
BACKUP_KEEP_MONTHLY=6
BACKUP_S3_BUCKET=backups

# Start with backup profile
docker compose --profile backup up -d
```

The scheduler uses Grandfather-Father-Son (GFS) retention:
- **Daily:** Keep last 7 daily backups
- **Weekly:** Keep one per week for 4 weeks
- **Monthly:** Keep one per month for 6 months

### Manual Backup

```bash
# Via API
curl -X POST http://localhost:8090/api/v1/backups \
  -H "Cookie: access_token=<token>"

# Via pg_dump directly
docker compose exec postgres pg_dump -U drawgo drawgo > backup.sql
```

### Restore

```bash
# Via API (creates safety backup first)
curl -X POST http://localhost:8090/api/v1/backups/{id}/restore \
  -H "Cookie: access_token=<token>"

# Via psql directly
docker compose exec -T postgres psql -U drawgo drawgo < backup.sql
```

---

## Scaling Considerations

### Single Server (Current)

The default deployment runs all services on a single machine. This is suitable for teams up to ~50 users.

### Horizontal Scaling

For larger deployments:

- **Backend:** Run multiple instances behind a load balancer. Rate limiting is in-memory per-instance — consider a shared backend (e.g., a database counter or external rate limiter) if running multiple instances.
- **Frontend:** Stateless — run as many instances as needed.
- **PostgreSQL:** Use managed PostgreSQL (AWS RDS, DigitalOcean, Supabase, etc.) for HA.
- **MinIO:** Use managed S3 (AWS S3, DigitalOcean Spaces, etc.) or run MinIO in distributed mode.
- **WebSocket:** Sticky sessions required. Cross-instance messaging would require a pub/sub layer (not currently implemented).

### Resource Guidelines

| Service    | CPU    | RAM    | Disk     |
| ---------- | ------ | ------ | -------- |
| Frontend   | 0.5    | 256MB  | —        |
| Backend    | 1.0    | 512MB  | —        |
| PostgreSQL | 1.0    | 1GB    | 10GB+    |
| MinIO      | 0.5    | 512MB  | 50GB+    |

---

## Monitoring

### Health Endpoints

| Endpoint            | Purpose                          |
| ------------------- | -------------------------------- |
| `GET /api/v1/health`  | Liveness check (always 200)      |
| `GET /api/v1/ready`   | Readiness (DB + S3 connectivity) |
| `GET /api/v1/version` | Build version info               |

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
docker compose logs -f frontend

# Go backend produces JSON logs (parseable by Loki, Datadog, etc.)
```

### Metrics

The backend exposes rich metrics via authenticated API endpoints:

| Endpoint                  | Data                                                                              |
| ------------------------- | --------------------------------------------------------------------------------- |
| `GET /api/v1/stats`       | System counts (11 tables), CRUD breakdown, backup info, log summary, DB health, table sizes, pgxpool, Go runtime, S3 storage, process, container stats, request metrics, brute force stats, build info |
| `GET /api/v1/orgs/{id}/stats` | Org-scoped board, member, version, asset, share link counts, CRUD breakdown   |
| `GET /api/v1/ws/stats`    | Active WebSocket rooms + connected clients                                        |
| `GET /api/v1/logs`        | Searchable backend logs with level/date filtering, pagination                     |
| `GET /api/v1/logs/summary`| Log level counts (debug, info, warn, error, fatal)                                |
| `GET /api/v1/health`      | Liveness status                                                                   |
| `GET /api/v1/ready`       | DB + S3 connectivity                                                              |
| `GET /api/v1/version`     | Build version, commit, build time                                                 |

**Admin Dashboard** (`/settings`) displays all metrics in a single page:
- **Overview**: Total users, organizations, boards, versions, assets, audit events, share links, accounts, sessions, backups
- **CRUD Breakdown**: All audit actions grouped by domain (board, user, member, share, backup, etc.) with per-action counts and visual bars
- **Backup Status**: Total backups, last backup time/size/status, schedule info
- **Log Summary**: Ring buffer log counts by level (debug/info/warn/error/fatal) with stacked bar visualization
- **Build Info**: Server version, commit SHA, build time, Go version
- **Process**: PID, RSS memory, open file descriptors, process uptime, start time
- **S3 Storage**: Per-bucket breakdown (object count, total size, largest object), aggregate totals
- **Go Runtime**: Goroutines, heap allocation, GC pause, CPU count
- **Connection Pool**: pgxpool acquired/idle/max connections, acquire counts
- **Database Health**: Size, uptime, cache hit ratio, active connections
- **Table Storage**: Per-table row counts and disk usage
- **WebSocket Hub**: Active rooms, connected clients, avg clients per room
- **Container**: cgroup memory/CPU usage, OOM kills, PID limits, network I/O
- **Brute Force**: Tracked and locked IPs
- **Request Metrics**: Total requests, RPS, latency percentiles, status code distribution, top endpoints
- **Backend Logs**: Searchable log viewer with level/date filtering
- **Client Logs**: Browser-side structured log viewer with level filtering

The backend logs include request duration, status code, and path for each request. These can be parsed by log aggregation tools (Loki, Datadog, etc.) for dashboarding.
