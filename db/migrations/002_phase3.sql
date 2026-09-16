-- PhaseOne10841 v0.3 — approvals polish + session metadata
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS risk TEXT;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS note TEXT;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS resolution_note TEXT;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Allow expired status
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
  CHECK (status IN ('pending', 'approved', 'denied', 'expired'));

CREATE INDEX IF NOT EXISTS idx_approvals_expires ON approvals(expires_at) WHERE status = 'pending';

INSERT INTO schema_migrations (id) VALUES ('002_phase3')
ON CONFLICT (id) DO NOTHING;
