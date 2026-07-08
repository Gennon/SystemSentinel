CREATE TABLE IF NOT EXISTS system_metrics (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,  -- ISO 8601 UTC
    metric_type  TEXT    NOT NULL,  -- cpu | ram | disk | network
    data_json    TEXT    NOT NULL   -- JSON blob with metric values
);

CREATE INDEX IF NOT EXISTS idx_system_metrics_type_ts
    ON system_metrics (metric_type, timestamp);
