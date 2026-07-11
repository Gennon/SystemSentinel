CREATE TABLE IF NOT EXISTS old_file_scans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at         TEXT    NOT NULL,  -- ISO 8601 UTC
    watched_directory  TEXT    NOT NULL,
    age_threshold_days INTEGER NOT NULL,
    file_count         INTEGER NOT NULL,
    total_size_bytes   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_old_file_scans_directory_time
    ON old_file_scans (watched_directory, scanned_at);

CREATE INDEX IF NOT EXISTS idx_old_file_scans_time
    ON old_file_scans (scanned_at);

CREATE TABLE IF NOT EXISTS old_file_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL,
    file_path     TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    last_modified TEXT    NOT NULL,  -- ISO 8601 UTC
    age_days      INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES old_file_scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_old_file_entries_scan_id
    ON old_file_entries (scan_id);

