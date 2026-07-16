CREATE TABLE IF NOT EXISTS directory_change_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at        TEXT    NOT NULL,  -- ISO 8601 UTC
    watched_directory  TEXT    NOT NULL,
    change_type        TEXT    NOT NULL,  -- created | deleted | modified | renamed
    file_path          TEXT    NOT NULL,
    destination_path   TEXT,
    process_owner      TEXT,
    alert_suppressed   INTEGER NOT NULL DEFAULT 0,
    suppression_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_directory_change_events_time
    ON directory_change_events (observed_at);

CREATE INDEX IF NOT EXISTS idx_directory_change_events_path_time
    ON directory_change_events (file_path, observed_at);

