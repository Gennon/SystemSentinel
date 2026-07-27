CREATE TABLE IF NOT EXISTS twofa_audit_runs (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    audited_at             TEXT    NOT NULL, -- ISO 8601 UTC
    pass_count             INTEGER NOT NULL,
    fail_count             INTEGER NOT NULL,
    unknown_count          INTEGER NOT NULL,
    exempt_count           INTEGER NOT NULL,
    non_compliant_count    INTEGER NOT NULL,
    exempt_accounts_json   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_twofa_audit_runs_audited_at
    ON twofa_audit_runs (audited_at);

CREATE TABLE IF NOT EXISTS twofa_audit_accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_run_id  INTEGER NOT NULL REFERENCES twofa_audit_runs (id) ON DELETE CASCADE,
    username      TEXT    NOT NULL,
    status        TEXT    NOT NULL, -- pass|fail|unknown|exempt
    reason        TEXT    NOT NULL,
    methods_json  TEXT    NOT NULL,
    is_exempt     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_twofa_audit_accounts_run
    ON twofa_audit_accounts (audit_run_id);
