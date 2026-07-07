CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,  -- ISO 8601 UTC
    action_type  TEXT    NOT NULL,  -- tool_run | alert_fired | chat_command | config_reload | llm_query
    source       TEXT    NOT NULL,  -- scheduler | chat:discord:user123 | daemon
    description  TEXT    NOT NULL,
    outcome      TEXT    NOT NULL,  -- success | failure | skipped
    details_json TEXT              -- JSON blob; NULL when no extra context
);

-- Enforce append-only semantics: no row may ever be modified or removed.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
    BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
    BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;
