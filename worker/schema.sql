CREATE TABLE IF NOT EXISTS elders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  elder_code TEXT NOT NULL UNIQUE,
  family_code TEXT NOT NULL UNIQUE,
  nickname TEXT NOT NULL,
  tz TEXT NOT NULL,
  remind_at TEXT NOT NULL,
  deadline TEXT NOT NULL,
  pause_until TEXT,
  start_day TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  last_day TEXT,
  remind_day TEXT,
  alert_day TEXT,
  alert_count INTEGER NOT NULL DEFAULT 0,
  alert_at INTEGER,
  alert_sent INTEGER NOT NULL DEFAULT 0,
  call_at INTEGER,
  keep_days INTEGER NOT NULL DEFAULT 100,
  cleared_day TEXT
);
CREATE TABLE IF NOT EXISTS checkins (
  elder_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (elder_id, day)
);
CREATE TABLE IF NOT EXISTS subs (
  endpoint TEXT NOT NULL,
  elder_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  each_checkin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (endpoint, elder_id, role)
);
CREATE INDEX IF NOT EXISTS subs_elder ON subs (elder_id, role);
CREATE TABLE IF NOT EXISTS rate (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  exp INTEGER NOT NULL
);
