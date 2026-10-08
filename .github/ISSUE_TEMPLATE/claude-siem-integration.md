---
name: "Claude SIEM Integration"
about: "Feature: Integrate Claude 5.5 Sonnet as Asynchronous SIEM Agent for Audit Log Anomaly Detection"
title: "Feature: Integrate Claude 5.5 Sonnet as Asynchronous SIEM Agent for Audit Log Anomaly Detection"
labels: ["enhancement", "security", "ai-integration"]
assignees: ""
---

**1. Problem Statement**

AuthCore's current 3-tier rate limiter (IP + account + email) effectively blocks simple brute-force attacks. However, static, threshold-based rules fail to detect the following complex attack vectors:

- **Slow Brute-Force (Low-and-Slow):** An attacker makes only 2-3 attempts per hour, using a different IP each time. Each request stays well below the rate limit threshold, but creates a clear attack pattern over a weekly window.
- **Credential Stuffing with Distributed IPs:** Botnets originate from thousands of different IPs, rendering per-IP rate limits meaningless. Each IP only makes 1-2 requests.
- **Impossible Travel:** The same user logs in from Istanbul at 14:00 and from Brazil at 14:05. Each login is legitimate on its own, but together they indicate stolen credentials.
- **Credential Reuse After Breach:** After a user's email is leaked in a data breach, the traffic pattern from different services changes.
- **Off-Hours Access Anomalies:** A user who normally logs in during business hours logs in at 3 AM from a new device.

**Why an LLM?**
Traditional rule engines (YARA, Sigma) can detect these attacks but require writing a new rule for every new attack vector. An LLM, guided by natural language instructions, can catch undefined patterns—especially its ability to evaluate correlations between multiple signals (IP + time + geography + user-agent changes) simultaneously provides a critical advantage here.

**2. Proposed Architecture**

Observer Pattern:
- Claude operates OUTSIDE the core auth flow (hot path).
- It reads the append-only `audit_logs` table READ-ONLY.
- PII masking is MANDATORY — raw emails and IPs are never sent to the API.
- The worker does not start at all if `ANTHROPIC_API_KEY` is not set (feature flag).
- A Claude API outage DOES NOT AFFECT the core system.

**3. Implementation Plan**

Phase 1 — Data Pipeline:
- [ ] `AuditRepository.ListAfterCursor(ctx, cursorID, limit)` method
- [ ] `internal/siem/sanitizer.go` — PII masking (email, IP)
- [ ] Cursor-based batch reader

Phase 2 — Claude Integration:
- [ ] `internal/siem/claude_client.go` — Anthropic Messages API wrapper
- [ ] System prompt design (security analyst persona)
- [ ] JSON structured output parsing
- [ ] Rate limit and retry logic (exponential backoff + circuit breaker)

Phase 3 — Reporting:
- [ ] `000005_create_anomaly_reports` migration
- [ ] `domain.AnomalyReport` struct
- [ ] Anomaly report storage

Phase 4 — Observability:
- [ ] Worker health endpoint (`/healthz` extension)
- [ ] Prometheus metrics (batch_processed, anomalies_detected, api_errors)
- [ ] Structured logging (zap)

**4. Expected Output — Sample Anomaly Report**

```json
{
  "anomalies": [
    {
      "anomaly_type": "geo_impossible_travel",
      "severity": "high",
      "description": "User u***r-id logged in from Istanbul (192.168.xxx.xxx) at 14:03 UTC and São Paulo (10.0.xxx.xxx) at 14:07 UTC. 4-minute gap across 10,200 km is physically impossible.",
      "affected_users": ["<uuid>"],
      "evidence": {
        "event_1": {"masked_ip": "192.168.xxx.xxx", "timestamp": "2025-01-15T14:03:22Z", "action": "login"},
        "event_2": {"masked_ip": "10.0.xxx.xxx", "timestamp": "2025-01-15T14:07:11Z", "action": "login"}
      },
      "recommended_action": "Revoke all active sessions for this user and trigger email notification"
    },
    {
      "anomaly_type": "slow_brute_force",
      "severity": "medium",
      "description": "14 failed login attempts for e***l@g***l.com over 72 hours from 9 distinct /16 subnets. Each IP sent ≤2 requests (below per-IP rate limit), but the aggregate pattern indicates a distributed credential guessing campaign.",
      "affected_users": ["<uuid>"],
      "evidence": {
        "total_failures": 14,
        "distinct_subnets": 9,
        "time_window_hours": 72,
        "peak_hour": "03:00-04:00 UTC"
      },
      "recommended_action": "Enable MFA prompt on next successful login and add source subnets to watchlist"
    }
  ],
  "batch_metadata": {
    "logs_analyzed": 100,
    "time_range": {"from": "2025-01-15T12:00:00Z", "to": "2025-01-15T14:30:00Z"},
    "model": "claude-sonnet-4-20250514",
    "analysis_duration_ms": 1240
  }
}
```

**5. Security Constraints**

- PII MUST be sanitized before transmission (emails masked, IP last two octets replaced)
- Claude API key stored as environment variable, never committed to source
- AI layer failure MUST NOT degrade core auth functionality
- All anomaly reports are append-only (consistent with audit log philosophy)
- Worker respects Anthropic rate limits with exponential backoff

**6. Out of Scope (Future Work)**

- Real-time streaming analysis (current design is batch-oriented)
- GeoIP database integration for precise location data
- Automated response actions (session revocation) — reports are advisory only
- Multi-model comparison (Claude vs GPT vs local models)
