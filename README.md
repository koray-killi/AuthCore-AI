> ⚠️ **Experimental Research Repository**
>
> AuthCore-AI is an experimental spin-off of my core authentication service, [AuthCore](https://github.com/koray-killi/AuthCore).
> While the main repository focuses on deterministic application security, this repository serves as a
> DevSecOps research playground to explore how LLMs (Claude 5.5 Sonnet) can be implemented as
> asynchronous SIEM agents to detect anomalies in audit logs.
>
> **Core auth logic remains 100% deterministic.** The AI layer is a cold-path observer that never
> intercepts or modifies the authentication request flow.

# AuthCore-AI

A production-discipline authentication service with an experimental AI-powered SIEM layer. Claude 5.5 Sonnet analyzes append-only audit logs as an asynchronous security analyst — detecting slow brute-force attacks, impossible travel anomalies, and credential stuffing patterns that static rate limiters miss.

---

## Live Demo

The service is deployed on Railway:

**Base URL:** `https://authcore-production-d9ce.up.railway.app`

```bash
# Health check
curl -s https://authcore-production-d9ce.up.railway.app/healthz | python3 -m json.tool

# Register a test account
curl -s -X POST https://authcore-production-d9ce.up.railway.app/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"SecurePass123"}' | python3 -m json.tool
```

---

## Why I Built This

Most auth tutorials hand you a JWT package and call it done. I wanted to see what production auth actually looks like end-to-end: token rotation with reuse detection, enumeration-safe login, Argon2id instead of bcrypt, a two-tier rate limiter that can swap to Redis later, and an append-only audit trail. Clean architecture felt like the right frame — it forced me to think about where each piece of logic actually belongs.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│              HOT PATH (Deterministic Core)                  │
│                                                             │
│  HTTP ──▶ Rate Limiter ──▶ Handler ──▶ Service ──▶ Repo    │
│                                                     │       │
│                                              audit_logs     │
│                                             (append-only)   │
└──────────────────────────────────────┬──────────────────────┘
                                       │ read-only
                              ╔════════╧════════╗
                              ║   COLD PATH     ║
                              ║   (AI Observer)  ║
                              ╚════════╤════════╝
                                       │
            ┌──────────┬───────────────┼───────────┐
            ▼          ▼               ▼           ▼
      Batch Reader  Sanitizer   Claude API   Report Store
      (cursor)      (PII mask)  (async)      (anomalies)
```

---

## Security Properties

These aren't just documented — they're enforced by the layer boundaries:

| Property | Implementation |
|----------|---------------|
| Passwords & OTPs stored as Argon2id hashes | `golang.org/x/crypto/argon2` |
| Refresh tokens stored as SHA-256 hashes | Raw token never touches the database |
| Refresh token rotation with reuse detection | Revoked token replay → revoke **all** sessions + audit log |
| Enumeration-safe login & resend | Dummy Argon2id verify for non-existent users; resend always returns 202 |
| Account lockout after 5 failed logins | 15-minute lock via `locked_until` column |
| OTP: 6-digit, 10-min TTL, 5 attempts, single-use | Enforced in `OTPService.Validate`; invalidated on resend |
| User ID always from JWT claim, never request body | Enforced by JWT middleware → context |
| Domain structs never serialized directly | Explicit response DTOs for every endpoint |
| Audit log is append-only | No UPDATE/DELETE on `AuditRepository` interface |
| Config injected, no global mutable state | `config.Config` passed through all constructors |
| Three-tier rate limiter (IP + account + email) | In-memory sliding window behind `RateLimiter` interface |
| Email format validated before processing | RFC-5322 regex in `middleware.ValidateEmail()` |
| **AI layer is cold-path only** | Claude never intercepts auth requests; operates on read-only audit log snapshots |
| **PII sanitized before API transmission** | Email addresses and IP octets are masked before leaving the server |
| **AI failure is non-disruptive** | If Claude API is unavailable, core auth continues with zero degradation |

---

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose

### Run with Docker Compose

```bash
# Copy the example environment file and set your JWT secret
cp .env.example .env

# Optional: Enable AI SIEM layer
# Add your Anthropic API key to .env:
# ANTHROPIC_API_KEY=sk-ant-...
# The SIEM worker starts automatically when the key is present.

# Start Postgres, MailHog, and the app
docker compose up --build -d

# Verify it's healthy
curl -s localhost:8080/healthz | jq
```

MailHog (for catching verification emails in development) is available at **http://localhost:8025**.

### Run Locally

```bash
# Start backing services only
docker compose up postgres mailhog -d

# Export required environment variables
export DATABASE_URL="postgres://authcore:authcore@localhost:5432/authcore?sslmode=disable"
export JWT_SECRET="replace-with-a-long-random-string"
export SMTP_HOST=localhost
export SMTP_PORT=1025

make run
```

---

## AI SIEM Worker Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Anthropic API key. Worker only starts when set. |
| `SIEM_SCAN_INTERVAL` | `5m` | How often the worker scans for new audit logs |
| `SIEM_BATCH_SIZE` | `100` | Number of logs per analysis batch |
| `SIEM_ENABLED` | `true` | Kill switch. Set to `false` to disable even with API key set. |

---

## Sample Anomaly Report

```json
{
  "anomaly_type": "geo_impossible_travel",
  "severity": "high",
  "description": "User u***r-uuid logged in from 192.168.xxx.xxx (Istanbul, TR) at 14:03 UTC and from 10.0.xxx.xxx (São Paulo, BR) at 14:07 UTC. A 4-minute interval between two cities 10,200 km apart implies compromised credentials.",
  "affected_users": ["<user-uuid>"],
  "evidence": {
    "login_1": {"masked_ip": "192.168.xxx.xxx", "timestamp": "2025-01-15T14:03:22Z", "action": "login"},
    "login_2": {"masked_ip": "10.0.xxx.xxx", "timestamp": "2025-01-15T14:07:11Z", "action": "login"}
  },
  "recommended_action": "Force session revocation and notify user via email"
}
```

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | — | ✅ | PostgreSQL connection string |
| `JWT_SECRET` | — | ✅ | HMAC-SHA256 signing key |
| `SERVER_PORT` | `8080` | | HTTP listen port |
| `SERVER_READ_TIMEOUT` | `10s` | | |
| `SERVER_WRITE_TIMEOUT` | `10s` | | |
| `SERVER_SHUTDOWN_TIMEOUT` | `15s` | | Graceful shutdown window |
| `JWT_ACCESS_EXPIRY` | `15m` | | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `168h` | | Refresh token lifetime (7 days) |
| `SMTP_HOST` | `localhost` | | |
| `SMTP_PORT` | `1025` | | |
| `SMTP_FROM` | `noreply@authcore.local` | | |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | | Comma-separated |
| `RATE_LIMIT_IP_REQUESTS` | `60` | | Max requests per IP per window |
| `RATE_LIMIT_IP_WINDOW` | `1m` | | IP rate limit window |
| `RATE_LIMIT_ACCOUNT_REQUESTS` | `10` | | Max login attempts per email per window |
| `RATE_LIMIT_ACCOUNT_WINDOW` | `1m` | | Account rate limit window |
| `RATE_LIMIT_EMAIL_REQUESTS` | `3` | | Max email-sending actions per address per window |
| `RATE_LIMIT_EMAIL_WINDOW` | `10m` | | Email rate limit window (register, resend, forgot-password) |

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/healthz` | Public | Health check with DB ping |
| `POST` | `/api/v1/auth/register` | Public | Register; sends email verification OTP. Re-sends OTP if account is inactive. |
| `POST` | `/api/v1/auth/verify-email` | Public | Confirm OTP, activate account |
| `POST` | `/api/v1/auth/resend-verification` | Public | Request a fresh OTP; always returns 202 (enumeration-safe) |
| `POST` | `/api/v1/auth/login` | Public | Returns access token + sets refresh cookie |
| `POST` | `/api/v1/auth/refresh` | Cookie | Rotates refresh token |
| `POST` | `/api/v1/auth/logout` | Bearer | Revokes current session |
| `POST` | `/api/v1/auth/logout-all` | Bearer | Revokes all user sessions |
| `POST` | `/api/v1/auth/forgot-password` | Public | Always returns 202 (enumeration-safe) |
| `POST` | `/api/v1/auth/reset-password` | Public | OTP + new password; revokes all sessions |
| `GET` | `/api/v1/auth/me` | Bearer | Authenticated user profile |
| `GET` | `/api/v1/admin/audit-logs` | Bearer + admin | Paginated audit log |

Full request/response examples are in [`docs/api.md`](docs/api.md).

---

## Testing

```bash
# Unit tests with race detector and coverage
make test

# View coverage as HTML
make coverage-html && open coverage.html

# Integration test against a real Postgres + MailHog
make docker-test-up
make test-integration
make docker-test-down
```

The unit test suite covers the service layer with fake repositories (~78% coverage). The integration test in `internal/e2e/` runs a full register → verify → login → refresh → logout cycle against a containerized database.

---

## Project Layout

```
AuthCore-AI/
├── cmd/authcore/main.go          # Wires everything together, starts the server
├── internal/
│   ├── config/                   # Loads config from environment
│   ├── database/                 # pgxpool connection + golang-migrate runner
│   ├── domain/                   # Entities (User, RefreshSession, AnomalyReport)
│   ├── repository/               # SQL access — pure data, no business logic
│   ├── service/                  # All business rules live here
│   ├── handler/                  # HTTP handlers, DTOs, chi router
│   ├── middleware/               # JWT auth, rate limiting, request logging
│   ├── httperr/                  # Typed error → JSON response mapping
│   ├── mailer/                   # Mailer interface + SMTP implementation
│   └── siem/                     # AI SIEM Worker (Claude integration & PII sanitizer)
├── migrations/                   # Up/down SQL files (including anomaly_reports)
├── docs/                         # Architecture, ADRs, API reference
├── Dockerfile                    # Multi-stage build (~20 MB final image)
├── docker-compose.yml            # Dev: Postgres + MailHog + app
├── docker-compose.test.yml       # Test: isolated Postgres + MailHog
└── Makefile                      # build, test, lint, docker targets
```

---

## Roadmap

- [x] Append-only audit log infrastructure
- [ ] Claude 5.5 Sonnet SIEM integration (see #1)
- [ ] GeoIP enrichment for impossible travel detection
- [ ] Webhook alerts for critical anomalies
- [ ] Redis-backed rate limiter (interface is already in place)
- [ ] TOTP two-factor authentication
- [ ] OAuth2 provider integration (Google, GitHub)
- [ ] Password history (block reuse of last N passwords)
- [ ] OpenTelemetry tracing

---

## Contributing

Issues and Pull Requests are welcome!

---

## License

MIT
