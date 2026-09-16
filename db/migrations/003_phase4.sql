-- PhaseOne10841 v0.4 — admin audit log, canary state, detection rule hits

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_email TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_email);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action);

CREATE TABLE IF NOT EXISTS canary_state (
  canary_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  marker TEXT NOT NULL,
  file_hint TEXT,
  rotated_at TIMESTAMPTZ,
  last_trigger_at TIMESTAMPTZ,
  last_trigger_session TEXT,
  last_trigger_agent TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detection_rule_hits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id TEXT NOT NULL,
  session_id TEXT,
  agent_id TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  matched_fields JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_hits_rule ON detection_rule_hits(rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rule_hits_created ON detection_rule_hits(created_at DESC);

INSERT INTO schema_migrations (id) VALUES ('003_phase4')
ON CONFLICT (id) DO NOTHING;
