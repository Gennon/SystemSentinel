CREATE TABLE IF NOT EXISTS connection_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,  -- ISO 8601 UTC
    ip_address TEXT    NOT NULL,
    dest_port  INTEGER NOT NULL,
    protocol   TEXT    NOT NULL DEFAULT 'tcp'
);

CREATE INDEX IF NOT EXISTS idx_connection_attempts_ip_time
    ON connection_attempts (ip_address, timestamp);

CREATE INDEX IF NOT EXISTS idx_connection_attempts_time
    ON connection_attempts (timestamp);

CREATE TABLE IF NOT EXISTS monitor_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
