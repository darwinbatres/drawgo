# Drawgo — Go Backend

REST API and WebSocket server for Drawgo.

## Stack

| Component       | Library                      | Purpose                        |
| --------------- | ---------------------------- | ------------------------------ |
| Router          | chi v5                       | HTTP routing, middleware       |
| Database        | pgx v5 + pgxpool             | PostgreSQL driver + pool       |
| Migrations      | golang-migrate v4            | SQL migration management       |
| Auth            | golang-jwt v5                | JWT access/refresh tokens      |
| Object Storage  | minio-go v7                  | S3-compatible file storage     |
| WebSocket       | coder/websocket              | Real-time cursors & presence   |
| Validation      | go-playground/validator v10  | Struct validation              |
| Logging         | zerolog                      | Structured JSON logging        |
| Config          | caarlos0/env v11             | Environment variable parsing   |
| Rate Limiting   | httprate                     | Per-IP rate limiting           |
| CORS            | go-chi/cors                  | Cross-origin request handling  |

## Project Structure

```
backend/
├── cmd/server/main.go          # Entry point, wiring, graceful shutdown
├── Dockerfile                  # Multi-stage production build
├── go.mod / go.sum
└── internal/
    ├── config/                 # Environment-based configuration
    ├── database/
    │   ├── database.go         # pgxpool connection + auto-migration
    │   └── migrations/         # SQL migration files (001_init.sql, ...)
    ├── handler/                # HTTP handlers (one per domain)
    │   ├── auth_handler.go     # Register, Login, Refresh, Logout, Me
    │   ├── oauth_handler.go    # Google/GitHub OAuth flow
    │   ├── org_handler.go      # CRUD organizations
    │   ├── member_handler.go   # Invite, update role, remove members
    │   ├── board_handler.go    # CRUD boards
    │   ├── version_handler.go  # Save, list, get, restore versions
    │   ├── file_handler.go     # Upload, download, presign, storage
    │   ├── share_handler.go    # Create, list, revoke share links
    │   ├── audit_handler.go    # Audit logs, stats, system stats, org stats
    │   ├── log_handler.go      # Backend log query + summary
    │   ├── backup_handler.go   # Backup CRUD, schedule, restore
    │   ├── ws_handler.go       # WebSocket upgrade + stats
    │   └── health_handler.go   # Health, readiness, version
    ├── middleware/              # HTTP middleware
    │   ├── auth.go             # JWT cookie extraction + context
    │   ├── bodysize.go         # Request body limits
    │   ├── bruteforce.go       # IP-based login lockout
    │   ├── cache.go            # Cache-Control + ETag
    │   ├── csrf.go             # Origin/Referer validation
    │   ├── logging.go          # Request logging (zerolog)
    │   ├── metrics.go          # Request metrics (latency, status codes, RPS)
    │   ├── ratelimit.go        # Per-IP rate limit tiers
    │   ├── recovery.go         # Panic recovery
    │   ├── security.go         # Security headers
    │   └── timeout.go          # Request timeouts
    ├── models/                 # Domain models (User, Board, Org, ...)
    ├── pkg/                    # Shared utilities
    │   ├── apierror/           # Typed API errors with HTTP codes
    │   ├── buildinfo/          # Build version injection via ldflags
    │   ├── cookie/             # Secure cookie helpers
    │   ├── jwt/                # JWT manager (sign, verify, refresh)
    │   ├── logbuffer/          # In-memory ring buffer for log viewer
    │   ├── pagination/         # Limit/offset helpers
    │   ├── response/           # JSON envelope response helpers
    │   ├── token/              # Crypto token generation
    │   └── validate/           # Struct validation + custom tags
    ├── realtime/               # WebSocket infrastructure
    │   ├── hub.go              # Room manager + tick loops
    │   ├── room.go             # Per-board room with cursor batching
    │   ├── client.go           # Read/write pumps
    │   └── message.go          # Wire format + typed payloads
    ├── repository/             # Database access layer
    │   ├── interfaces.go       # 12 repository interfaces
    │   ├── user_repo.go        # Users CRUD
    │   ├── org_repo.go         # Organizations
    │   ├── membership_repo.go  # Org memberships
    │   ├── board_repo.go       # Boards + search
    │   ├── board_version_repo.go
    │   ├── board_permission_repo.go
    │   ├── board_asset_repo.go # File assets (S3 refs)
    │   ├── share_link_repo.go  # Share links
    │   ├── audit_repo.go       # Audit events + stats
    │   ├── backup_repo.go      # Backup metadata + schedule
    │   ├── refresh_token_repo.go
    │   └── account_repo.go     # OAuth accounts
    ├── router/router.go        # Route registration + middleware wiring
    ├── service/                # Business logic layer
    │   ├── auth_service.go     # Register, login, token rotation
    │   ├── oauth_service.go    # OAuth provider flow
    │   ├── access_service.go   # RBAC (org roles + board permissions)
    │   ├── org_service.go      # Org lifecycle + member management
    │   ├── board_service.go    # Board CRUD + versioning
    │   ├── file_service.go     # S3 upload/download + dedup
    │   ├── share_service.go    # Share link CRUD + validation
    │   ├── audit_service.go    # Audit queries + system metrics
    │   ├── cleanup_service.go  # Orphan file removal + audit pruning
    │   ├── backup_service.go   # pg_dump, restore, GFS rotation
    │   └── backup_scheduler.go # Cron-based backup scheduler
    ├── storage/                # Object storage abstraction
    │   ├── interfaces.go       # ObjectStorage interface
    │   └── s3.go               # MinIO/S3 implementation
    └── testutil/               # Test infrastructure
        ├── containers.go       # Testcontainers (Postgres, MinIO)
        ├── fixtures.go         # Test data factories
        ├── helpers.go          # Logger, Docker skip
        └── mocks/              # Generated mocks (gomock)
```

## Development

### Prerequisites

- Go 1.25+
- Docker (for PostgreSQL and MinIO during development/testing)

### Running Locally

```bash
# Start infrastructure
docker compose up -d postgres minio

# Run the server
go run ./cmd/server

# Or with live reload (install air first)
go install github.com/air-verse/air@latest
air
```

The server starts on `:8080` by default. In Docker, Caddy reverse-proxies `/api/v1/*` requests here.

### Configuration

All configuration is via environment variables. See `.env.example` in the project root.

Key variables:

| Variable         | Default       | Description                   |
| ---------------- | ------------- | ----------------------------- |
| `PORT`           | `8080`        | Server listen port            |
| `ENV`            | `development` | `development` or `production` |
| `DATABASE_URL`   | —             | PostgreSQL connection string  |
| `JWT_SECRET`     | —             | JWT signing secret            |
| `S3_ENDPOINT`    | —             | MinIO/S3 endpoint             |
| `S3_ACCESS_KEY`  | `minioadmin`  | S3 access key                 |
| `S3_SECRET_KEY`  | `minioadmin`  | S3 secret key                 |
| `LOG_LEVEL`      | `info`        | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT`     | `json`        | `json` or `console`          |

## Testing

```bash
# Run all tests (requires Docker for testcontainers)
go test ./... -count=1

# Run with verbose output
go test ./... -v -count=1

# Run specific package
go test ./internal/service/... -v

# Run a specific test
go test ./internal/handler/... -run TestBackupHandler -v
```

### Test Categories

| Category          | Location                    | Dependencies       | Count |
| ----------------- | --------------------------- | ------------------ | ----- |
| Unit tests        | `*_test.go`                 | None               | ~95   |
| Mock-based        | `*_mock_test.go`            | gomock             | ~45   |
| Integration       | `*_integration_test.go`     | Testcontainers     | ~32   |
| Handler (httptest)| `handler/*_test.go`         | gomock + httptest   | ~15   |

**Total: ~440+ tests**

### Regenerating Mocks

```bash
go generate ./internal/repository/...
go generate ./internal/storage/...
```

## API Overview

All endpoints are under `/api/v1`. See [docs/API.md](../docs/API.md) for full reference.

### Route Groups

| Group              | Prefix                        | Auth     |
| ------------------ | ----------------------------- | -------- |
| Health             | `/health`, `/ready`, `/version` | Public |
| Auth               | `/auth/*`                     | Mixed    |
| Organizations      | `/orgs/*`                     | Required |
| Boards             | `/boards/*`, `/orgs/{id}/boards` | Required |
| Files              | `/boards/{id}/files/*`        | Required |
| Versions           | `/boards/{id}/versions/*`     | Required |
| Share              | `/boards/{id}/share/*`        | Required |
| Share (public)     | `/share/{token}`              | Public   |
| Audit              | `/orgs/{id}/audit/*`          | Required |
| Logs               | `/logs`, `/logs/summary`      | Required |
| Backups            | `/backups/*`                  | Required |
| WebSocket          | `/ws/boards/{id}`             | Cookie/Query |
| WebSocket Stats    | `/ws/stats`                   | Required |
| System Stats       | `/stats`                      | Required |

### Middleware Stack (order)

1. `RequestID` — Unique request ID header
2. `RealIP` — Extract client IP from proxy headers
3. `Recovery` — Panic recovery with structured logging
4. `Logger` — Request/response logging
5. `RequestMetrics` — Latency, status codes, RPS tracking
6. `Security` — Security headers (X-Frame-Options, etc.)
7. `CORS` — Cross-origin request handling
8. `RateLimit` — Per-IP rate limiting
9. `MaxBodySize` — Request body size limits
10. `Compress` — gzip/deflate response compression
11. `CSRF` — Origin/Referer validation

## Build

```bash
# Development build
go build ./cmd/server

# Production build with version info
PKG=github.com/darwinbatres/drawgo/backend/internal/pkg/buildinfo
go build -ldflags "-s -w -X $PKG.Version=1.0.0 -X $PKG.CommitSHA=$(git rev-parse --short HEAD) -X $PKG.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/server

# Docker build
docker build -t drawgo-backend .
```
