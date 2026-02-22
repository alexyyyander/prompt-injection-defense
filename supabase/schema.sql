-- prompt-injection-defense: Attack Reports Database
-- Run this in your Supabase SQL editor to set up the schema.
-- https://github.com/alexyyyander/prompt-injection-defense

-- ─────────────────────────────────────────────
-- TABLE
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_reports (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Report content (submitted by agent)
  summary          TEXT        NOT NULL,
  example_input    TEXT        NOT NULL,
  suspicion_reason TEXT        NOT NULL,
  attacker_goal    TEXT        NOT NULL,
  suggested_defense TEXT       NOT NULL,

  -- Agent metadata
  agent_platform   TEXT        NOT NULL DEFAULT 'unspecified',
  confidence       TEXT        NOT NULL DEFAULT 'medium'
                               CHECK (confidence IN ('low', 'medium', 'high')),
  heuristic_flags  TEXT[]      NOT NULL DEFAULT '{}',
  suspicion_level  INTEGER     NOT NULL DEFAULT 0
                               CHECK (suspicion_level BETWEEN 0 AND 4),

  -- Review workflow (set by maintainer)
  status           TEXT        NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'approved', 'rejected')),
  attack_category  TEXT,         -- e.g. ATTACK-13, assigned on approval
  reviewer_notes   TEXT,
  reviewed_at      TIMESTAMPTZ
);

-- ─────────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_attack_reports_status
  ON attack_reports (status);

CREATE INDEX IF NOT EXISTS idx_attack_reports_created_at
  ON attack_reports (created_at DESC);

-- ─────────────────────────────────────────────
-- ROW LEVEL SECURITY
-- ─────────────────────────────────────────────
ALTER TABLE attack_reports ENABLE ROW LEVEL SECURITY;

-- Anyone (agents) can INSERT new reports
CREATE POLICY "agents_can_submit"
  ON attack_reports FOR INSERT
  TO anon
  WITH CHECK (status = 'pending');

-- Anyone can READ approved reports (public threat intel feed)
CREATE POLICY "public_can_read_approved"
  ON attack_reports FOR SELECT
  TO anon
  USING (status = 'approved');

-- Service role (GitHub Action, maintainer) has full access
-- (service role bypasses RLS by default in Supabase)

-- ─────────────────────────────────────────────
-- NOTIFY on new submission (optional webhook trigger)
-- ─────────────────────────────────────────────
-- Uncomment to enable real-time notifications when a new report arrives.
-- Pair with a Supabase webhook → GitHub Actions dispatch or Slack.
--
-- CREATE OR REPLACE FUNCTION notify_new_report()
-- RETURNS TRIGGER LANGUAGE plpgsql AS $$
-- BEGIN
--   PERFORM pg_notify('new_attack_report', row_to_json(NEW)::text);
--   RETURN NEW;
-- END;
-- $$;
--
-- CREATE TRIGGER on_new_report
--   AFTER INSERT ON attack_reports
--   FOR EACH ROW EXECUTE FUNCTION notify_new_report();
