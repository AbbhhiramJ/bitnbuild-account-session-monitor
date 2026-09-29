# Account Takeover & Session Security Monitor

A defensive security workspace for reviewing account and session events. The current dashboard is a demo UI; a provider-neutral authenticated event API foundation is also included.

## Dashboard demo
https://bitnbuild-account-session-monitor.vercel.app

## Demo walkthrough
1. Review the seeded event timeline and use search or filters.
2. Open a record to inspect its context and outcome.
3. Work through the guided incident-response checklist.
4. Add local notes and export the incident report.

## API foundation
- `GET /api/health` — reports required configuration status.
- `GET /api/events` — authenticated event retrieval.
- `POST /api/events` — authenticated event ingestion into PostgreSQL.
- `db/schema.sql` — database schema.
- `docs/PRODUCTION_FOUNDATION.md` — setup, API contract, and security gaps.

The API requires a PostgreSQL database and server-side `DATABASE_URL` and `MONITOR_API_KEY` environment variables. Apply the SQL schema before use. See the production foundation guide.

## Important limitations
This is **not yet a production-ready monitoring product**. No identity provider is connected, the dashboard still uses synthetic events and browser-local state, and no real account/session action is performed. The shared API key is a foundation, not multi-user authentication or tenant authorization. Do not ingest real identity data until the remaining security, privacy, and operational controls are implemented and reviewed.

## Local run
Open `index.html` for the static demo. API routes require Vercel Functions or a compatible Node runtime, PostgreSQL, and environment configuration.
