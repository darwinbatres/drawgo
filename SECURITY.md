# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please do **not** open a public GitHub issue.

Instead, report security issues responsibly by emailing the maintainers directly or using GitHub's private vulnerability reporting feature.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fixes (optional)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity (critical issues prioritized)

## Security Architecture

### Authentication

- **JWT tokens** — Short-lived access tokens (15 min) + rotating refresh tokens (30 days)
- **Password hashing** — bcrypt with cost factor 12 (Go `golang.org/x/crypto/bcrypt`)
- **OAuth 2.0** — GitHub and Google providers via server-side PKCE flow
- **No user enumeration** — Login/register failures return generic messages

### Authorization

- **RBAC** — Organization roles (Owner > Admin > Member > Viewer) with numeric levels
- **Board permissions** — Optional per-board overrides via `board_permissions` table
- **Share links** — Scoped read/write access with optional expiration

### Data Protection

- **SQL injection** — All database queries use parameterized placeholders (`$1`, `$2`) via pgx
- **Input validation** — Request structs validated with `go-playground/validator` struct tags
- **File uploads** — MIME type validation, configurable size limits, content-type checks
- **CSRF protection** — Origin/Referer validation on state-changing requests (POST/PUT/PATCH/DELETE)

### Network Security

- **Rate limiting** — Per-IP rate limits (httprate), configurable via environment variables:
  - General: `RATE_LIMIT_REQUESTS_PER_MINUTE` (default 60)
  - Auth: `RATE_LIMIT_AUTH_PER_MINUTE` (default 10)
  - Upload: `RATE_LIMIT_UPLOAD_PER_MINUTE` (default 30)
  - WebSocket: `RATE_LIMIT_WS_PER_MINUTE` (default 10)
- **Per-client WS rate limiting** — Each WebSocket client has a sliding-window rate limiter. Cursor messages are capped at 30/second and scene updates at 5/second. Excessive messages are silently dropped to prevent DoS via message flooding.
- **Brute-force protection** — IP lockout after configurable failed login attempts (`BRUTEFORCE_MAX_ATTEMPTS`, default 5)
- **Security headers** — Set by Go middleware and Caddy reverse proxy:
  - `X-Frame-Options: DENY` (Caddy) / `SAMEORIGIN` (Go)
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss: ws:; frame-ancestors 'none'`
  - Server header removed by Caddy
- **CORS** — Configurable allowed origins (strict by default)
- **Secure cookies** — httpOnly, sameSite=lax, secure flag in production
- **WebSocket authentication** — Supports three methods: HttpOnly `access_token` cookie (preferred), `?token=` JWT query parameter, or `?share=` share link token

### Audit Trail

- All significant actions logged with actor, target, IP address, and user agent
- Queryable via `/api/v1/orgs/{id}/audit` with role-based access (ADMIN+)
- System-wide stats via `/api/v1/stats` (authenticated)
- Backend log viewer via `/api/v1/logs` with level/date/search filtering (authenticated)

## Security Best Practices for Deployment

### Required Before Production

1. **Set JWT_SECRET** — Generate a cryptographically secure random string:
   ```bash
   openssl rand -base64 32
   ```

2. **Set POSTGRES_PASSWORD** — Use a strong, unique password

3. **Set S3 credentials** — Change default MinIO access/secret keys:
   ```bash
   S3_ACCESS_KEY=$(openssl rand -hex 16)
   S3_SECRET_KEY=$(openssl rand -hex 32)
   ```

4. **Enable HTTPS** — Use Caddy (included) or Cloudflare Tunnel

5. **Restrict database access** — Remove the `127.0.0.1:5433` port binding in production

6. **Restrict MinIO console** — Remove the `9011` port mapping or firewall it

7. **Set CORS origin** — Configure `CORS_ALLOWED_ORIGINS` to your exact domain

### Environment Variables

| Variable             | Security Impact |
| -------------------- | --------------- |
| `JWT_SECRET`         | Signs all auth tokens — keep secret, rotate periodically |
| `POSTGRES_PASSWORD`  | Database access — never commit to version control |
| `S3_ACCESS_KEY`      | Object storage access — change from defaults |
| `S3_SECRET_KEY`      | Object storage access — change from defaults |
| `CORS_ALLOWED_ORIGINS` | Prevents cross-origin abuse — set to exact production URL |

## Dependencies

### Go Backend

Run `go vuln check` or `govulncheck ./...` inside `backend/` to check for known vulnerabilities in Go dependencies.

### Frontend

Run `pnpm audit` to check for known vulnerabilities in npm packages.

## Acknowledgments

Thanks to all security researchers who responsibly disclose vulnerabilities.
