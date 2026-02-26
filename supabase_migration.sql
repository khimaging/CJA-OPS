-- ================================================================
--  Creative Juice Agency — Supabase Migration
--  Run this entire file in:
--  Supabase Dashboard → SQL Editor → New query → Paste → Run
-- ================================================================


-- ── Extensions ──────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid()


-- ================================================================
--  TABLE: team_members
-- ================================================================
CREATE TABLE IF NOT EXISTS team_members (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT        NOT NULL,
  role             TEXT        NOT NULL DEFAULT '',
  auth_role        TEXT        NOT NULL DEFAULT 'member'
                               CHECK (auth_role IN ('admin','member')),
  color            TEXT        NOT NULL DEFAULT '#5a8fd4',
  profit_share_pct NUMERIC     NOT NULL DEFAULT 0,
  active           BOOLEAN     NOT NULL DEFAULT TRUE,
  pin_hash         TEXT        NOT NULL,               -- bcrypt hash
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ================================================================
--  TABLE: deals
-- ================================================================
CREATE TABLE IF NOT EXISTS deals (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT        NOT NULL,
  client         TEXT        NOT NULL DEFAULT '',
  value          NUMERIC     NOT NULL DEFAULT 0,
  expenses       NUMERIC     NOT NULL DEFAULT 0,
  stage          TEXT        NOT NULL DEFAULT 'Lead'
                             CHECK (stage IN ('Lead','Qualified','Proposal','Negotiation','Closed Won')),
  owner          TEXT        NOT NULL DEFAULT '',
  close_date     TEXT,                                -- stored as 'YYYY-MM'
  invoice_status TEXT        NOT NULL DEFAULT 'none'
                             CHECK (invoice_status IN ('none','sent','deposit','paid')),
  buckets        JSONB       NOT NULL DEFAULT '[]',
  prob           INTEGER     NOT NULL DEFAULT 0,       -- win probability 0-100
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ================================================================
--  TABLE: projects
-- ================================================================
CREATE TABLE IF NOT EXISTS projects (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT        NOT NULL,
  client     TEXT        NOT NULL DEFAULT '',
  deal_id    UUID        REFERENCES deals(id) ON DELETE SET NULL,
  start_date DATE,
  end_date   DATE,
  status     TEXT        NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','complete','archived')),
  archived   BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ================================================================
--  TABLE: tasks
-- ================================================================
CREATE TABLE IF NOT EXISTS tasks (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  title       TEXT        NOT NULL,
  project_id  UUID        REFERENCES projects(id) ON DELETE CASCADE,
  assignee_id UUID        REFERENCES team_members(id) ON DELETE SET NULL,
  due_date    DATE,
  priority    TEXT        NOT NULL DEFAULT 'med'
                          CHECK (priority IN ('high','med','low')),
  status      TEXT        NOT NULL DEFAULT 'todo'
                          CHECK (status IN ('todo','progress','review','done')),
  est_hours   NUMERIC     NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ================================================================
--  TABLE: expenses
-- ================================================================
CREATE TABLE IF NOT EXISTS expenses (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  description  TEXT        NOT NULL,
  amount       NUMERIC     NOT NULL DEFAULT 0,
  project_id   UUID        REFERENCES projects(id) ON DELETE CASCADE,
  category     TEXT        NOT NULL DEFAULT 'other'
                           CHECK (category IN ('software','contractor','assets','advertising','printing','travel','equipment','other')),
  date         DATE        NOT NULL DEFAULT CURRENT_DATE,
  submitted_by TEXT        NOT NULL DEFAULT '',
  receipt_url  TEXT        NOT NULL DEFAULT '',
  payment_type TEXT        NOT NULL DEFAULT 'company'
                           CHECK (payment_type IN ('company','reimbursement')),
  reimbursed   BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ================================================================
--  TABLE: pay_status
--  Tracks which project/member pay periods have been marked paid
-- ================================================================
CREATE TABLE IF NOT EXISTS pay_status (
  project_id UUID    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  member_id  UUID    NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
  paid       BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (project_id, member_id)
);


-- ================================================================
--  TABLE: profit_share_status
--  Tracks which quarter/member profit share amounts have been paid
-- ================================================================
CREATE TABLE IF NOT EXISTS profit_share_status (
  quarter_key TEXT    NOT NULL,    -- e.g. 'Q1-2025'
  member_id   UUID    NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
  paid        BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (quarter_key, member_id)
);


-- ================================================================
--  ROW-LEVEL SECURITY
--  The API uses the service-role key which bypasses RLS.
--  These policies protect the database if anyone ever accidentally
--  uses the anon key on the server, and are required for Realtime
--  subscriptions from the browser (anon key is used there).
-- ================================================================

ALTER TABLE team_members       ENABLE ROW LEVEL SECURITY;
ALTER TABLE deals              ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects           ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks              ENABLE ROW LEVEL SECURITY;
ALTER TABLE expenses           ENABLE ROW LEVEL SECURITY;
ALTER TABLE pay_status         ENABLE ROW LEVEL SECURITY;
ALTER TABLE profit_share_status ENABLE ROW LEVEL SECURITY;

-- Allow SELECT for authenticated anon key users (realtime reads)
-- The API server uses service-role which bypasses these entirely.

CREATE POLICY "anon_read_team"    ON team_members        FOR SELECT USING (true);
CREATE POLICY "anon_read_deals"   ON deals               FOR SELECT USING (true);
CREATE POLICY "anon_read_proj"    ON projects            FOR SELECT USING (true);
CREATE POLICY "anon_read_tasks"   ON tasks               FOR SELECT USING (true);
CREATE POLICY "anon_read_exp"     ON expenses            FOR SELECT USING (true);
CREATE POLICY "anon_read_pay"     ON pay_status          FOR SELECT USING (true);
CREATE POLICY "anon_read_ps"      ON profit_share_status FOR SELECT USING (true);

-- Block all writes via anon key (only the API server can write)
CREATE POLICY "deny_anon_insert_team" ON team_members        FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_deal" ON deals               FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_proj" ON projects            FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_task" ON tasks               FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_exp"  ON expenses            FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_pay"  ON pay_status          FOR INSERT WITH CHECK (false);
CREATE POLICY "deny_anon_insert_ps"   ON profit_share_status FOR INSERT WITH CHECK (false);


-- ================================================================
--  REALTIME
--  Enable Postgres Changes for all tables so Supabase broadcasts
--  INSERT/UPDATE/DELETE events to connected browser clients.
-- ================================================================

ALTER PUBLICATION supabase_realtime ADD TABLE team_members;
ALTER PUBLICATION supabase_realtime ADD TABLE deals;
ALTER PUBLICATION supabase_realtime ADD TABLE projects;
ALTER PUBLICATION supabase_realtime ADD TABLE tasks;
ALTER PUBLICATION supabase_realtime ADD TABLE expenses;
ALTER PUBLICATION supabase_realtime ADD TABLE pay_status;
ALTER PUBLICATION supabase_realtime ADD TABLE profit_share_status;


-- ================================================================
--  SEED DATA — Creative Juice Agency team members
--
--  PIN hashes below are bcrypt(cost=12) of the PIN shown in comment.
--  To generate your own:  node -e "console.log(require('bcryptjs').hashSync('YOUR_PIN', 12))"
--
--  IMPORTANT: Change these PINs before going live.
--    Kyle  Harries   → PIN: 1234  (admin)
--    Nathan Blumberg → PIN: 5678
--    Blaise Freeman  → PIN: 9012
-- ================================================================

INSERT INTO team_members (name, role, auth_role, color, profit_share_pct, active, pin_hash) VALUES
  (
    'Kyle Harries',
    'Creative Director',
    'admin',
    '#c9a84c',
    40,
    TRUE,
    -- bcrypt hash of '1234'
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbRHBpGTe'
  ),
  (
    'Nathan Blumberg',
    'Lead Designer',
    'member',
    '#4caf7a',
    35,
    TRUE,
    -- bcrypt hash of '5678'
    '$2a$12$8K3t7pDI1dKYvKHCBSb2XuL/QWyMqMDi1rFBEd/vR2MiI3EiVxaVe'
  ),
  (
    'Blaise Freeman',
    'Copywriter',
    'member',
    '#5a8fd4',
    25,
    TRUE,
    -- bcrypt hash of '9012'
    '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/hy4N2iGHjGJZIeYZ6'
  );


-- ================================================================
--  DONE
--  After running this script:
--  1. Copy the team member UUIDs from the team_members table if
--     you need to reference them elsewhere.
--  2. Set up your .env file (see .env.example).
--  3. Deploy to Vercel (see SETUP.md).
-- ================================================================
