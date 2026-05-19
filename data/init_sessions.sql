-- Session database schema with WAL mode and AI decision audit trail

-- Enable WAL mode for better concurrency
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    test_type       TEXT NOT NULL DEFAULT 'web_app',
    scope           TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'initialized',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    findings_count  INTEGER DEFAULT 0,
    metadata        TEXT DEFAULT '{}'
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    attack_type     TEXT NOT NULL,
    confidence      REAL DEFAULT 0.5,
    endpoint        TEXT DEFAULT '',
    parameter       TEXT,
    evidence        TEXT DEFAULT '',
    status          TEXT DEFAULT 'potential',
    cvss_score      REAL,
    severity        TEXT,
    remediation     TEXT,
    metadata        TEXT DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Running processes tracking
CREATE TABLE IF NOT EXISTS running_processes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    pid             INTEGER NOT NULL,
    command         TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- AI decision audit trail
CREATE TABLE IF NOT EXISTS ai_decisions (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    decision_type   TEXT NOT NULL,  -- 'plan' | 'evaluate' | 'report'
    provider        TEXT NOT NULL,  -- which LLM provider was used
    decision_json   TEXT NOT NULL,  -- full JSON of the decision
    tokens_used     INTEGER DEFAULT 0,
    latency_ms      INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    action          TEXT NOT NULL,
    command         TEXT,
    result          TEXT,
    user            TEXT DEFAULT 'system',
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(attack_type);
CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(cvss_score);
CREATE INDEX IF NOT EXISTS idx_processes_session ON running_processes(session_id);
CREATE INDEX IF NOT EXISTS idx_ai_decisions_session ON ai_decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);

-- Trigger to update findings_count
CREATE TRIGGER IF NOT EXISTS update_findings_count
AFTER INSERT ON findings
BEGIN
    UPDATE sessions 
    SET findings_count = (SELECT COUNT(*) FROM findings WHERE session_id = NEW.session_id),
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE session_id = NEW.session_id;
END;

-- Trigger to update updated_at on session changes
CREATE TRIGGER IF NOT EXISTS update_session_timestamp
AFTER UPDATE ON sessions
BEGIN
    UPDATE sessions SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE session_id = NEW.session_id;
END;
