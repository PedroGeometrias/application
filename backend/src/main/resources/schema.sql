PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    indicator TEXT NOT NULL,
    normalized_indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    provider_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    briefing TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_created
    ON investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_indicator
    ON investigations(normalized_indicator, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_filters
    ON investigations(indicator_type, verdict, created_at DESC);
