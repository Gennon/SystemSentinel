CREATE TABLE IF NOT EXISTS known_connections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT    NOT NULL,
    dest_port    INTEGER NOT NULL,
    protocol     TEXT    NOT NULL DEFAULT 'tcp',
    first_seen   TEXT    NOT NULL,  -- ISO 8601 UTC
    last_alerted TEXT    NOT NULL,  -- ISO 8601 UTC
    UNIQUE (ip_address, dest_port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_known_connections_ip_port
    ON known_connections (ip_address, dest_port, protocol);
