# Drawgo — Architecture

## System Overview

```mermaid
graph TB
    subgraph Browser
        B["Browser"]
    end

    subgraph Docker Compose Stack
        CD["Caddy :80<br/>(Reverse Proxy)"] -->|"/*"| FE["Next.js 16 Frontend<br/>(React 19, TypeScript 6, Tailwind 4)"]
        CD -->|"/api/v1/*"| BE["Go Backend :8080<br/>(chi v5, zerolog)"]
        CD -->|"WebSocket /api/v1/ws/*"| BE
        BE -->|"pgx v5"| PG[("PostgreSQL 16<br/>:5432")]
        BE -->|"minio-go v7"| S3[("MinIO (S3)<br/>:9000")]
        BK["Backup Scheduler"] -->|"pg_dump"| PG
        BK -->|"Upload"| S3
    end

    B --> CD

    subgraph Optional
        CF["Cloudflare Tunnel"] --> CD
    end
```

## Request Flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant C as Caddy
    participant N as Next.js
    participant G as Go Backend
    participant P as PostgreSQL
    participant S as MinIO (S3)

    B->>C: GET /boards/abc
    C->>N: Proxy (non-API route)
    N-->>C: HTML + React (SSR/CSR)
    C-->>B: Response
    
    B->>C: GET /api/v1/boards/abc
    C->>G: Proxy (/api/v1/*)
    G->>G: Auth middleware (JWT cookie)
    G->>G: RBAC check (AccessService)
    G->>P: Query board + latest version
    P-->>G: Board data
    G-->>C: JSON envelope {data: {...}}
    C-->>B: JSON response
    
    B->>C: POST /api/v1/boards/abc/files
    C->>G: Proxy (/api/v1/*)
    G->>G: Validate MIME + size
    G->>S: Upload to S3
    S-->>G: OK
    G->>P: Upsert board_asset
    G-->>B: {data: {fileId, url, ...}}
```

## Data Model

```mermaid
erDiagram
    USER ||--o{ MEMBERSHIP : "belongs to"
    USER ||--o{ BOARD : "owns"
    USER ||--o{ ACCOUNT : "OAuth"
    USER ||--o{ REFRESH_TOKEN : "auth"
    USER ||--o{ AUDIT_EVENT : "actor"

    ORGANIZATION ||--o{ MEMBERSHIP : "has"
    ORGANIZATION ||--o{ BOARD : "contains"

    BOARD ||--o{ BOARD_VERSION : "versions"
    BOARD ||--o{ BOARD_ASSET : "files"
    BOARD ||--o{ BOARD_PERMISSION : "access"
    BOARD ||--o{ SHARE_LINK : "shared via"

    MEMBERSHIP }o--|| ORGANIZATION : ""
    MEMBERSHIP }o--|| USER : ""

    BOARD_PERMISSION }o--|| BOARD : ""
    BOARD_PERMISSION }o--|| MEMBERSHIP : ""

    USER {
        text id PK "xid"
        text email UK
        text name
        text password_hash
        bool email_verified
        timestamp created_at
    }

    ORGANIZATION {
        text id PK "xid"
        text name
        text slug UK
        timestamp created_at
    }

    MEMBERSHIP {
        text id PK "xid"
        text user_id FK
        text org_id FK
        text role "OWNER|ADMIN|MEMBER|VIEWER"
    }

    BOARD {
        text id PK "xid"
        text title
        text description
        text org_id FK
        text owner_id FK
        int current_version
        text etag
        text search_content
        bool is_archived
    }

    BOARD_VERSION {
        text id PK "xid"
        text board_id FK
        int version
        jsonb scene_json
        text label
        text created_by FK
        timestamp created_at
    }

    BOARD_ASSET {
        text id PK "xid"
        text board_id FK
        text file_id
        text storage_key
        text content_type
        bigint size_bytes
        text sha256
    }

    SHARE_LINK {
        text id PK "xid"
        text board_id FK
        text token UK "crypto/rand 256-bit"
        text role "VIEWER|EDITOR"
        timestamp expires_at
    }

    AUDIT_EVENT {
        text id PK "xid"
        text org_id FK
        text actor_id FK
        text action
        text target_type
        text target_id
        jsonb metadata
        text ip_address
        text user_agent
        timestamp created_at
    }

    ACCOUNT {
        text id PK "xid"
        text user_id FK
        text type
        text provider
        text provider_account_id UK
        text access_token
        integer expires_at
    }

    REFRESH_TOKEN {
        text id PK "xid"
        text user_id FK
        text token_hash
        timestamp expires_at
        timestamp revoked_at
        text user_agent
        text ip
    }

    BACKUP_METADATA {
        text id PK "xid"
        text status "in_progress|completed|failed"
        text storage_key
        bigint size_bytes
        timestamp started_at
        timestamp completed_at
    }

    BACKUP_SCHEDULE {
        text id PK "default (singleton)"
        bool enabled
        text cron_expr
        int keep_daily
        int keep_weekly
        int keep_monthly
        timestamp updated_at
    }
```

## Backend Architecture

```mermaid
graph LR
    subgraph Handler Layer
        H[HTTP Handlers]
    end

    subgraph Service Layer
        AS[AuthService]
        OS[OrgService]
        BS[BoardService]
        FS[FileService]
        SS[ShareService]
        AUS[AuditService]
        BKS[BackupService]
        ACS[AccessService]
    end

    subgraph Repository Layer
        UR[UserRepo]
        OR[OrgRepo]
        MR[MembershipRepo]
        BR[BoardRepo]
        BVR[BoardVersionRepo]
        BAR[BoardAssetRepo]
        SLR[ShareLinkRepo]
        AR[AuditRepo]
        BKR[BackupRepo]
    end

    subgraph Infrastructure
        PG[(PostgreSQL)]
        S3[(MinIO)]
    end

    H --> AS & OS & BS & FS & SS & AUS & BKS
    AS & OS & BS --> ACS
    AS --> UR
    OS --> OR & MR
    BS --> BR & BVR
    FS --> BAR & S3
    SS --> SLR
    AUS --> AR
    BKS --> BKR & S3
    ACS --> MR & BR
    UR & OR & MR & BR & BVR & BAR & SLR & AR & BKR --> PG
```

### Layers

| Layer        | Responsibility                              | Key Pattern                     |
| ------------ | ------------------------------------------- | ------------------------------- |
| **Handler**  | HTTP request/response, validation           | Decode → Service → Respond      |
| **Service**  | Business logic, authorization               | Accept interfaces, return structs |
| **Repository** | Database queries, transactions            | Parameterized SQL via pgx       |
| **Storage**  | S3 operations                               | Interface-based abstraction     |

### Middleware Stack

```mermaid
graph TD
    REQ[Request] --> RID[RequestID]
    RID --> RIP[RealIP]
    RIP --> REC[Recovery]
    REC --> LOG[Logger]
    LOG --> MET[Request Metrics]
    MET --> SEC[Security Headers]
    SEC --> CORS[CORS]
    CORS --> RL[Rate Limit]
    RL --> BODY[Max Body Size]
    BODY --> COMP[Compress]
    COMP --> CSRF[CSRF]
    CSRF --> AUTH{Auth Required?}
    AUTH -->|Yes| JWT[JWT Auth]
    AUTH -->|No| HANDLER[Handler]
    JWT --> HANDLER
```

## RBAC Model

```mermaid
graph TD
    OWNER["OWNER (100)"] --> ADMIN["ADMIN (75)"]
    ADMIN --> MEMBER["MEMBER (50)"]
    MEMBER --> VIEWER["VIEWER (25)"]
```

| Role     | Level | Permissions |
| -------- | ----- | ----------- |
| OWNER    | 100   | All org operations, delete org, manage any member |
| ADMIN    | 75    | Invite/remove members, manage boards, view audit |
| MEMBER   | 50    | Create/edit boards, upload files |
| VIEWER   | 25    | View boards and members |

Board-level permissions can override org roles via `board_permissions` table.

## Observability

The system collects metrics at multiple layers, exposed via `GET /api/v1/stats`:

| Layer | Metrics |
|-------|---------|
| **Row Counts** | Users, organizations, boards, versions, assets, audit events, memberships, share links, accounts, refresh tokens, backups |
| **CRUD Breakdown** | Global audit events grouped by action (board.create, board.update, user.login, etc.) with per-action counts and total |
| **Backup Info** | Total backups, last backup time/size/status, schedule enabled, cron expression |
| **Log Summary** | In-memory ring buffer counts by level: debug, info, warn, error, fatal, total |
| **Database** | Size, table breakdown, connections, cache hit ratio, uptime |
| **Connection Pool** | pgxpool acquired/idle/total connections, acquire counts |
| **Go Runtime** | Goroutines, heap (alloc/sys/inuse), stack, GC pause/cycles, CPU count |
| **S3 Storage** | Per-bucket object count, total bytes, largest object |
| **Process** | PID, RSS memory, open file descriptors, uptime |
| **Build** | Version, commit SHA, build time, Go version |
| **Request Metrics** | Total requests, RPS, error rate (5xx/4xx), latency percentiles (P50/P95/P99), status code distribution, HTTP method breakdown |
| **Container** | cgroup v1/v2 memory limit/usage, CPU quota/period, effective CPUs, container detection |
| **Brute Force** | Tracked IPs, locked IPs |

Build-time variables are injected via `-ldflags` targeting `pkg/buildinfo` and are shared between the health handler (`/version`) and the stats endpoint.

The admin dashboard (`/settings`) auto-refreshes every 30 seconds when live mode is enabled and visualizes all metrics with color-coded status cards, progress bars, and distribution charts. New in the latest release: CRUD operations breakdown (grouped by domain), backup status section, and log level summary with visual bar chart.

## WebSocket Architecture

```mermaid
graph TB
    subgraph Hub
        H[Hub Manager]
        H --> R1[Room: board-1]
        H --> R2[Room: board-2]
    end

    subgraph "Room: board-1"
        R1 --> C1[Client A]
        R1 --> C2[Client B]
        R1 --> CB[Cursor Buffer]
    end

    CT[Cursor Ticker<br/>33ms default] -->|FlushCursors| R1
    CT -->|FlushCursors| R2
```

- **Hub:** Manages rooms (one per board), runs tick loops for cursor batching
- **Room:** Tracks connected clients, buffers cursor updates, broadcasts
- **Client:** Goroutine pair (readPump + writePump), 64-slot buffered send channel, per-client sliding-window rate limiter (cursor: 30/sec, scene: 5/sec)
- **Cursor Batching:** Cursors batched at configurable intervals (default 33ms / ~30fps) to reduce network traffic; frontend interpolates to 60fps via `requestAnimationFrame`
- **Auth:** JWT via HttpOnly `access_token` cookie (default), `?token=` query param, or share link via `?share=` query parameter
- **Cursor Rendering:** Custom `LiveCursors` component with requestAnimationFrame-based interpolation for smooth 60fps cursor movement, color coding, and user name labels

## Frontend Architecture

```
src/
├── pages/                    # Next.js Pages Router
│   ├── index.tsx             # Dashboard (board list, create, search)
│   ├── boards/[id].tsx       # Board editor page
│   ├── boards/shared/[token].tsx  # Public shared board
│   ├── settings.tsx          # Admin dashboard (stats, runtime, pool, WS hub, DB health, storage, client logs)
│   ├── _app.tsx              # AuthProvider + AppProvider
│   └── _document.tsx         # HTML document
├── contexts/
│   ├── AuthContext.tsx        # JWT auth state, auto-refresh
│   └── AppContext.tsx         # Org selection, user state
├── services/
│   ├── api.client.ts         # Typed API client (fetch + envelope unwrap)
│   ├── logger.ts             # Frontend observability (log buffer, API metrics)
│   └── ws.client.ts          # WebSocket client (reconnect, keepalive)
├── components/
│   ├── ErrorBoundary.tsx     # React error boundary with fallback UI
│   ├── excalidraw/           # Editor components
│   │   ├── BoardEditor.tsx   # Main editor + autosave + file upload + collaboration
│   │   ├── LiveCursors.tsx   # Remote cursor overlay (60fps interpolation)
│   │   ├── PresenceBar.tsx   # Active viewers indicator
│   │   ├── MarkdownCard.tsx  # Markdown renderer (+ Mermaid + search highlighting)
│   │   ├── MarkdownCardEditor.tsx  # Markdown edit/preview modal
│   │   ├── RichTextCard.tsx  # Tiptap rich text renderer
│   │   ├── RichTextCardEditor.tsx  # Notion-style WYSIWYG editor (toolbar, tables, links)
│   │   ├── MermaidRenderer.tsx     # Mermaid diagram rendering with DOMPurify
│   │   ├── SaveIndicator.tsx # Save status (6 states: idle/saving/saved/error/conflict/offline)
│   │   └── VersionHistory.tsx
│   ├── dashboard/            # Admin dashboard sections (17 components)
│   │   ├── OverviewSection.tsx
│   │   ├── BuildInfoSection.tsx
│   │   ├── ProcessSection.tsx
│   │   ├── S3StorageSection.tsx
│   │   ├── RuntimeSection.tsx
│   │   ├── PoolSection.tsx
│   │   ├── DatabaseHealthSection.tsx
│   │   ├── TableStorageSection.tsx
│   │   ├── WebSocketSection.tsx
│   │   ├── ContainerSection.tsx
│   │   ├── BruteForceSection.tsx
│   │   ├── RequestMetricsSection.tsx
│   │   ├── BackendLogsSection.tsx
│   │   ├── ClientLogsSection.tsx
│   │   ├── CRUDBreakdownSection.tsx
│   │   ├── BackupInfoSection.tsx
│   │   └── LogSummarySection.tsx
│   ├── ui/                   # Reusable UI primitives (14 components)
│   │   ├── Button.tsx
│   │   ├── ConfirmDialog.tsx
│   │   ├── EmptyState.tsx
│   │   ├── ErrorAlert.tsx
│   │   ├── Icons.tsx
│   │   ├── Input.tsx
│   │   ├── LogTable.tsx
│   │   ├── Modal.tsx
│   │   ├── Pagination.tsx
│   │   ├── ProgressBar.tsx
│   │   ├── SectionHeader.tsx
│   │   ├── ShareDialog.tsx
│   │   ├── Spinner.tsx
│   │   └── StatCard.tsx
│   └── layout/
│       ├── Header.tsx        # Top nav with org dropdown, user menu, workspace management
│       └── Layout.tsx        # App wrapper with Header + container
├── types/index.ts            # Shared TypeScript types (500+ lines)
├── lib/
│   ├── constants.ts          # Size limits, config, validation helpers
│   ├── hooks.ts              # Custom hooks (useAsyncAction, useModal, useOutsideClick)
│   └── utils.ts              # ID generation, debouncing, formatting
└── styles/globals.css        # Tailwind 4
```

### Data Flow

```mermaid
sequenceDiagram
    participant U as User
    participant E as Excalidraw
    participant BE as BoardEditor
    participant API as api.client
    participant WS as ws.client
    participant GO as Go Backend

    U->>E: Draw on canvas
    E->>BE: onChange (debounced)
    BE->>API: boardApi.saveVersion()
    API->>GO: POST /api/v1/boards/{id}/versions
    GO-->>API: {data: {version, etag}}
    API-->>BE: Update etag

    U->>E: Move cursor
    E->>BE: onPointerUpdate
    BE->>WS: sendCursor(x, y)
    WS->>GO: WS message (cursor_update)
    GO-->>WS: WS message (cursor_batch)
    WS-->>BE: onCursorBatch
    BE->>E: Update collaborators Map (native rendering)
```
