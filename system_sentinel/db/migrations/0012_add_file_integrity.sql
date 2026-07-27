CREATE TABLE IF NOT EXISTS file_integrity_baselines (
    path              TEXT PRIMARY KEY,
    source_path       TEXT NOT NULL,
    expected_sha256   TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    last_verified_at  TEXT,
    last_status       TEXT,
    last_actual_sha256 TEXT,
    last_error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_file_integrity_baselines_source
    ON file_integrity_baselines (source_path);

CREATE TABLE IF NOT EXISTS file_integrity_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at      TEXT NOT NULL,
    path            TEXT NOT NULL,
    expected_sha256 TEXT,
    actual_sha256   TEXT,
    status          TEXT NOT NULL,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_file_integrity_events_path_time
    ON file_integrity_events (path, checked_at);
