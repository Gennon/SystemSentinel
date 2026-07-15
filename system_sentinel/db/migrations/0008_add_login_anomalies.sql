CREATE TABLE IF NOT EXISTS login_successes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,  -- ISO 8601 UTC of successful login
    ip_address  TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    port        INTEGER,
    auth_method TEXT    NOT NULL DEFAULT 'unknown',
    host        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_successes_user_ts
    ON login_successes (username, timestamp);

CREATE INDEX IF NOT EXISTS idx_login_successes_ip_ts
    ON login_successes (ip_address, timestamp);

CREATE TABLE IF NOT EXISTS login_anomalies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at  TEXT    NOT NULL,  -- ISO 8601 UTC
    anomaly_type TEXT    NOT NULL,  -- brute_force | off_hours | new_user | impossible_travel
    username     TEXT    NOT NULL,
    ip_address   TEXT    NOT NULL,
    details_json TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_anomalies_time
    ON login_anomalies (observed_at);

CREATE INDEX IF NOT EXISTS idx_login_anomalies_type_time
    ON login_anomalies (anomaly_type, observed_at);
