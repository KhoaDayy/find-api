'use strict';

/**
 * SQLite schema migrations via PRAGMA user_version.
 * Keep pure SQL — no secrets.
 */
const MIGRATIONS = [
  {
    version: 1,
    name: 'initial_face_cache',
    sql: `
CREATE TABLE IF NOT EXISTS faces (
  id INTEGER PRIMARY KEY,
  face_hash TEXT NOT NULL UNIQUE,
  face_data TEXT NOT NULL,
  face_data_version INTEGER,
  face_data_length INTEGER NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS face_sources (
  id INTEGER PRIMARY KEY,
  face_id INTEGER NOT NULL REFERENCES faces(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  region TEXT,
  plan_id TEXT,
  art_code TEXT,
  inventory_player_pid TEXT,
  inventory_player_number_id TEXT,
  inventory_player_nickname TEXT,
  inventory_player_hostnum INTEGER,
  plan_owner_pid TEXT,
  plan_owner_number_id TEXT,
  plan_owner_nickname TEXT,
  plan_owner_hostnum INTEGER,
  plan_owner_account TEXT,
  plan_type TEXT,
  body_type INTEGER,
  tags_json TEXT,
  source_lists_json TEXT,
  picture_url TEXT,
  preview_object_key TEXT,
  metadata_source TEXT NOT NULL,
  raw_metadata_json TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (source_type, region, plan_id, inventory_player_pid)
);

CREATE INDEX IF NOT EXISTS idx_face_sources_face_id ON face_sources(face_id);
CREATE INDEX IF NOT EXISTS idx_face_sources_plan_id ON face_sources(plan_id);
CREATE INDEX IF NOT EXISTS idx_face_sources_plan_owner_pid ON face_sources(plan_owner_pid);
CREATE INDEX IF NOT EXISTS idx_face_sources_inventory_player_pid ON face_sources(inventory_player_pid);

CREATE TABLE IF NOT EXISTS regional_codes (
  id INTEGER PRIMARY KEY,
  face_id INTEGER NOT NULL REFERENCES faces(id) ON DELETE CASCADE,
  region TEXT NOT NULL,
  short_code TEXT NOT NULL UNIQUE,
  revision INTEGER,
  object_key TEXT NOT NULL,
  status TEXT NOT NULL,
  source_type TEXT,
  verification_hash TEXT,
  verified_at INTEGER,
  last_checked_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (face_id, region, short_code),
  UNIQUE (object_key, region)
);

CREATE INDEX IF NOT EXISTS idx_regional_codes_face_id ON regional_codes(face_id);
CREATE INDEX IF NOT EXISTS idx_regional_codes_status ON regional_codes(status);

CREATE TABLE IF NOT EXISTS aliases (
  id INTEGER PRIMARY KEY,
  face_id INTEGER NOT NULL REFERENCES faces(id) ON DELETE CASCADE,
  alias_type TEXT NOT NULL,
  alias_value TEXT NOT NULL,
  region TEXT,
  source_id INTEGER,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  UNIQUE (alias_type, alias_value, region)
);

CREATE INDEX IF NOT EXISTS idx_aliases_face_id ON aliases(face_id);
CREATE INDEX IF NOT EXISTS idx_aliases_value ON aliases(alias_value);

CREATE TABLE IF NOT EXISTS upload_jobs (
  id INTEGER PRIMARY KEY,
  face_id INTEGER NOT NULL REFERENCES faces(id) ON DELETE CASCADE,
  region TEXT NOT NULL,
  status TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  retry_after INTEGER,
  locked_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_upload_jobs_active
  ON upload_jobs(face_id, region)
  WHERE status IN ('pending', 'running');
`,
  },
  {
    version: 2,
    name: 'filepicker_wrapper_metadata',
    sql: `
ALTER TABLE face_sources ADD COLUMN short_code TEXT;
ALTER TABLE face_sources ADD COLUMN object_key TEXT;
ALTER TABLE face_sources ADD COLUMN wrapper_type TEXT;
ALTER TABLE face_sources ADD COLUMN wrapper_schema_version INTEGER;
ALTER TABLE face_sources ADD COLUMN face_data_field_path TEXT;
ALTER TABLE face_sources ADD COLUMN related_plan_id TEXT;
ALTER TABLE face_sources ADD COLUMN related_pid TEXT;
ALTER TABLE face_sources ADD COLUMN related_hostnum INTEGER;
ALTER TABLE face_sources ADD COLUMN related_plan_hash_match INTEGER;
ALTER TABLE face_sources ADD COLUMN sanitized_metadata_json TEXT;

CREATE INDEX IF NOT EXISTS idx_face_sources_short_code ON face_sources(short_code);
CREATE INDEX IF NOT EXISTS idx_face_sources_object_key ON face_sources(object_key);
CREATE INDEX IF NOT EXISTS idx_face_sources_related_plan_id ON face_sources(related_plan_id);
CREATE INDEX IF NOT EXISTS idx_face_sources_related_pid ON face_sources(related_pid);
`,
  },
];

function migrate(db) {
  db.exec('PRAGMA foreign_keys = ON');
  const row = db.prepare('PRAGMA user_version').get();
  let version = row?.user_version ?? 0;

  for (const m of MIGRATIONS) {
    if (m.version <= version) continue;
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(m.sql);
      db.exec(`PRAGMA user_version = ${m.version}`);
      db.exec('COMMIT');
      version = m.version;
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return version;
}

module.exports = {
  MIGRATIONS,
  migrate,
};
