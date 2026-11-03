-- =============================================================================
--  Board share links — view-only public links for boards (opened at /b/<token>)
--  Run once: Supabase → SQL Editor → New query → paste → Run.
--  Safe to run more than once.
-- =============================================================================
CREATE TABLE IF NOT EXISTS board_shares (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  board_id        UUID        NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
  token           TEXT        NOT NULL UNIQUE,
  expires_at      TIMESTAMPTZ,                       -- NULL = never expires
  created_by      UUID        REFERENCES team_members(id) ON DELETE SET NULL,
  created_by_name TEXT,
  view_count      INT         NOT NULL DEFAULT 0,
  last_viewed_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS board_shares_board_idx ON board_shares(board_id);

-- Only the server (service key) reads this table. No public policies on purpose.
ALTER TABLE board_shares ENABLE ROW LEVEL SECURITY;
