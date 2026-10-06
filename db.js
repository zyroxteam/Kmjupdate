/**
 * SQLite database layer (Node built-in node:sqlite — zero native deps).
 *
 * Tables:
 *   admins      — panel login (bcrypt-hashed passwords, never plaintext)
 *   keys        — activation keys + status lifecycle
 *   key_events  — audit trail (created / verified) for dashboard charts
 *   app_update  — single-row table with the current update metadata
 */
const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'kmj-tips.db');

const db = new DatabaseSync(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key         TEXT UNIQUE NOT NULL,
  prefix      TEXT DEFAULT '',
  label       TEXT DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active'
              CHECK (status IN ('active','used','expired','revoked')),
  single_use  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,              -- epoch ms, NULL = lifetime
  used_at     INTEGER,
  device_id   TEXT DEFAULT '',
  use_count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);
CREATE INDEX IF NOT EXISTS idx_keys_created ON keys(created_at);

CREATE TABLE IF NOT EXISTS key_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id     INTEGER,
  event      TEXT NOT NULL,         -- 'created' | 'verified' | 'revoked'
  device_id  TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_created ON key_events(created_at);

CREATE TABLE IF NOT EXISTS app_update (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  version_name TEXT NOT NULL DEFAULT '1.0.0',
  version_code INTEGER NOT NULL DEFAULT 1,
  title        TEXT NOT NULL DEFAULT 'New Update Available',
  changelog    TEXT NOT NULL DEFAULT 'Bug fixes and improvements.',
  download_url TEXT NOT NULL DEFAULT '',
  website_url  TEXT NOT NULL DEFAULT '',
  force_update INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL
);
`);

// Seed the single update row if missing.
const seed = db.prepare('SELECT COUNT(*) AS c FROM app_update').get();
if (seed.c === 0) {
  db.prepare(`INSERT INTO app_update
    (id, version_name, version_code, title, changelog, download_url, website_url, force_update, updated_at)
    VALUES (1, '1.0.0', 1, 'New Update Available', 'Bug fixes and improvements.', '', '', 0, ?)`)
    .run(Date.now());
}

module.exports = db;
