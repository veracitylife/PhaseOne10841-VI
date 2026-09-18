-- PhaseOne10841 v0.8.0 — Wave B/C: learn loop, multi-tenant orgs, signed canary metadata

CREATE TABLE IF NOT EXISTS playbook_outcomes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  playbook_id TEXT NOT NULL,
  action_type TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('confirmed', 'denied', 'auto_resolved', 'expired')),
  confirmation_id TEXT,
  admin_notes TEXT,
  actor_email TEXT,
  trigger_event JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_outcomes_playbook ON playbook_outcomes(playbook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_outcomes_outcome ON playbook_outcomes(outcome, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_outcomes_created ON playbook_outcomes(created_at DESC);

CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  settings_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  soft_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orgs_active ON orgs(soft_deleted, name);

ALTER TABLE agents ADD COLUMN IF NOT EXISTS org_id TEXT REFERENCES orgs(id) ON DELETE SET NULL;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org_id TEXT REFERENCES orgs(id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS org_id TEXT REFERENCES orgs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_id);

CREATE TABLE IF NOT EXISTS org_api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  label TEXT,
  created_by TEXT,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_api_keys_org ON org_api_keys(org_id) WHERE revoked = FALSE;

ALTER TABLE canary_state ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE canary_state ADD COLUMN IF NOT EXISTS signature_prev TEXT;
ALTER TABLE canary_state ADD COLUMN IF NOT EXISTS public_key_id TEXT;

INSERT INTO schema_migrations (id) VALUES ('004_phase8')
ON CONFLICT (id) DO NOTHING;
