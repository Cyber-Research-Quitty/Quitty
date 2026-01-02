CREATE TABLE IF NOT EXISTS revocation_events (
  event_id TEXT PRIMARY KEY,
  type     TEXT NOT NULL,
  value    TEXT NOT NULL,
  ts       TEXT NOT NULL,
  nonce    TEXT NOT NULL,
  kid      TEXT NOT NULL,
  sig      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rev_type_value ON revocation_events(type, value);
CREATE INDEX IF NOT EXISTS idx_rev_ts ON revocation_events(ts);
