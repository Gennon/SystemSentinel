CREATE TABLE IF NOT EXISTS connection_classifications (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at             TEXT    NOT NULL,  -- ISO 8601 UTC
    ip_address              TEXT    NOT NULL,
    protocol                TEXT    NOT NULL DEFAULT 'tcp',
    category                TEXT    NOT NULL,  -- background_scan | suspicious | likely_access_attempt
    confidence              REAL    NOT NULL,
    recommended_action      TEXT    NOT NULL,  -- ignore | watch | block
    reasons_json            TEXT    NOT NULL,  -- JSON array
    attempts                INTEGER NOT NULL,
    distinct_ports          INTEGER NOT NULL,
    recurrence_count        INTEGER NOT NULL,
    sensitive_port_targeted INTEGER NOT NULL DEFAULT 0,
    reverse_dns             TEXT,
    asn_organization        TEXT,
    geoip_country           TEXT
);

CREATE INDEX IF NOT EXISTS idx_connection_classifications_time
    ON connection_classifications (observed_at);

CREATE INDEX IF NOT EXISTS idx_connection_classifications_category_time
    ON connection_classifications (category, observed_at);

CREATE INDEX IF NOT EXISTS idx_connection_classifications_ip_time
    ON connection_classifications (ip_address, observed_at);
