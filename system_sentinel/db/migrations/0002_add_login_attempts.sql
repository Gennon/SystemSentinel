CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,  -- ISO 8601 UTC of the failed attempt
    ip_address  TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    port        INTEGER,           -- SSH source port; NULL if not captured
    host        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts
    ON login_attempts (ip_address, timestamp);
