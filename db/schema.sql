-- Apply once to the PostgreSQL database configured for the Vercel API.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at TIMESTAMPTZ NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source VARCHAR(120) NOT NULL,
  actor VARCHAR(255) NOT NULL,
  event_type VARCHAR(40) NOT NULL CHECK (event_type IN (
    'sign_in','sign_out','session_created','session_revoked',
    'mfa_challenge','password_changed','risk_detected','other'
  )),
  ip_address VARCHAR(64),
  user_agent VARCHAR(512),
  severity VARCHAR(16) NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  summary VARCHAR(1000) NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS security_events_occurred_at_idx
  ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_events_actor_idx
  ON security_events (actor);
