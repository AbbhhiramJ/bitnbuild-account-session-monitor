# Production foundation (provider-neutral)

This repository now includes an authenticated event API foundation. It is **not yet a production-ready security monitoring service** and does not connect to Microsoft Entra ID, Google Workspace, Okta, or another identity provider.

## Components

- Static dashboard: current demo UI and synthetic sample events.
- `GET /api/health`: reports whether required environment configuration exists; it does not prove database connectivity or provider integration.
- `GET /api/events`: returns newest stored events, with optional `limit` (1–100) and `before` timestamp.
- `POST /api/events`: accepts a normalized event and persists it to PostgreSQL.
- `db/schema.sql`: database migration.
- `MONITOR_API_KEY`: bearer token required for both event API methods.

## Required setup

1. Provision a managed PostgreSQL database with TLS.
2. Apply `db/schema.sql`.
3. Add `DATABASE_URL` and a high-entropy `MONITOR_API_KEY` to Vercel environment variables for the intended environment.
4. Deploy and verify `GET /api/health` reports `configured`.
5. Test authenticated ingestion with synthetic events before connecting a real provider.

Example request:

```bash
curl -X POST "$APP_URL/api/events" \
  -H "Authorization: Bearer $MONITOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"eventType":"sign_in","actor":"demo.user","source":"test","severity":"low","riskScore":12,"summary":"Synthetic test event"}'
```

## Security boundaries and remaining work

- Never expose the ingestion key in browser JavaScript or the public dashboard. Keep it in a trusted server-side connector or integration worker.
- The current API uses one shared bearer key. Before multi-analyst use, add user authentication, role-based authorization, per-tenant scoping, key rotation, rate limiting, and audit logging.
- Add provider-specific OAuth/service-principal adapters with least-privilege scopes and verified webhook signatures where supported.
- Define retention/deletion policies, PII minimization, alert thresholds, event deduplication, and operational monitoring.
- Session revocation is not implemented. No real session or account changes are performed.
- The static dashboard still displays synthetic sample events; it does not fetch these API records yet.
- Use a separate staging database and key. Do not send real user or identity data until access controls, privacy review, and deployment verification are complete.

## Local development

The static dashboard can still be opened directly. API routes require Vercel Functions or a compatible Node runtime and a configured PostgreSQL database. Install dependencies with `npm install`.
