# Account Takeover & Session Security Monitor

A defensive, demo-first security workspace for reviewing suspicious identity events, session activity, and containment status.

## MVP
- Seeded identity-event timeline with normal and suspicious sessions
- Explainable risk indicators and evidence attached to each alert
- Simulated session revocation with explicit simulation labeling
- Post-containment recheck and incident summary

## Live demo
https://bitnbuild-account-session-monitor.vercel.app

## Demo walkthrough
1. Review the seeded event timeline and use search or filters to narrow the records.
2. Open a record to inspect its context and outcome.
3. Review the guided incident-response steps and mark demo steps as reviewed.
4. Add local notes and save them in the browser.
5. Download the incident report.

## Scope and limitations
The demo uses synthetic data and browser-local state. It does not connect to an identity provider, revoke real sessions, or verify real account activity. Treat risk indicators as triage clues, not proof of compromise; IP location alone is not proof.

## Local run
Open `index.html` in a modern browser. No backend is required.

See [project brief](docs/PROJECT_BRIEF.md).
