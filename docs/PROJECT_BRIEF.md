# Project brief — Account Takeover & Session Security Monitor

## User and problem
**Primary user:** a small-organization IT administrator or junior SOC analyst responding to a suspected account takeover, often without a dedicated identity-security team.

Community incident reports describe stolen sessions bypassing password/MFA assumptions, and containment being incomplete when app grants or mailbox rules remain. These are practitioner anecdotes, not prevalence measurements.

## Product promise
Turn a small set of identity events into a reviewable incident timeline, explain why an event is suspicious, and guide a user through a clearly simulated containment-and-verification workflow.

## MVP workflow
1. Open a seeded incident.
2. Review the chronological event stream and risk evidence.
3. Inspect a session/app grant/mailbox-rule artifact.
4. Mark a containment action as simulated.
5. Run a post-action checklist and export a concise incident summary.

## Acceptance criteria
- Every alert shows the underlying evidence and a plain-language rationale.
- Unknown or missing evidence is shown as unknown, not assumed safe.
- Simulation actions are visibly labeled and never imply a real account was changed.
- Demo includes a normal session, suspicious session replay, and lingering app grant scenario.

## Boundaries
Synthetic fixtures only for MVP. No credential collection, token replay, or real account actions. Any future provider integration must use explicit authorization and least-privilege scopes.

## Research leads
- Community report describing session-cookie replay and later OAuth access: https://www.reddit.com/r/Infosec/comments/1wdd9r7/how_are_you_catching_account_takeovers_that_ride/
- Microsoft compromised identity response SOP: https://learn.microsoft.com/en-us/defender-xdr/sop-documentation-template
