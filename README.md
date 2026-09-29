# Sentinel / Identity — Account & Session Monitor

A defensive identity-security workspace that helps an analyst review suspicious sign-in and session signals, document investigation steps, and export an incident report.

**Submission demo:** https://bitnbuild-account-session-monitor.vercel.app  
**Status:** Interactive prototype with synthetic records and a provider-neutral API foundation. It is not connected to a live identity tenant.

## Problem

Identity incidents often require analysts to correlate sign-in context, unfamiliar sessions, and risky third-party app grants before deciding what to investigate or remediate. Sentinel / Identity demonstrates a structured review workflow without pretending that sample data is real telemetry.

## What the demo includes

- Searchable, filterable sample sign-in and session event timeline.
- Record detail view with contextual evidence.
- Guided investigation and incident-response checklists.
- Local analyst notes and incident report export.
- CSV export of the sample event set.
- Browser-local demo state with reset control.
- Responsive dashboard and keyboard-accessible record inspection.

## Suggested judging walkthrough

1. Open the live demo and point out the synthetic-data / no-live-tenant label.
2. Filter for high-risk events and open the unfamiliar session or OAuth grant.
3. Explain the evidence an analyst would verify before taking action.
4. Track response steps, add a short note, and export the incident report.
5. Show the API foundation and explain the integration boundary: provider events are not connected yet.

## Architecture

- Dashboard: static HTML, CSS, and JavaScript.
- API: Vercel Node functions (api/health.js, api/events.js).
- Storage: PostgreSQL schema in db/schema.sql.
- Authentication boundary: server-side shared bearer key for API access; it must never be placed in browser code.
- Integration direction: provider-specific least-privilege adapters normalize identity events into the common event schema.

## API foundation

- GET /api/health — reports whether required environment variables are present; does not verify database connectivity.
- GET /api/events — authenticated retrieval with bounded pagination.
- POST /api/events — authenticated event ingestion into PostgreSQL.
- See docs/PRODUCTION_FOUNDATION.md for setup and request examples.

## Run locally

Open index.html to explore the static demo. API routes require Node.js 20+, PostgreSQL, and a Vercel-compatible function runtime.

npm install

Set DATABASE_URL and MONITOR_API_KEY as server-side environment variables and apply db/schema.sql before using the API.

## Important limitations

- Dashboard events are seeded synthetic examples; it does not fetch the API event store.
- No identity provider is connected, and no live session/account action is performed.
- The shared API key is not analyst login, role-based access, or tenant isolation.
- Do not ingest real identity data until authentication, authorization, privacy, retention, rate limiting, monitoring, and deployment controls have been reviewed.
- The API and deployment have not been verified against a configured production database.

## Project validation

A GitHub Actions workflow checks API JavaScript syntax and verifies key documentation/schema files on pushes and pull requests.