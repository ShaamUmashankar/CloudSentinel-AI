-- CloudSentinel AI Database Schema (SQLite)

CREATE TABLE IF NOT EXISTS raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    event_time TEXT NOT NULL,
    event_name TEXT NOT NULL,
    event_source TEXT NOT NULL,
    aws_region TEXT,
    source_ip TEXT,
    user_identity TEXT,
    user_name TEXT,
    user_type TEXT,
    user_agent TEXT,
    error_code TEXT,
    error_message TEXT,
    request_parameters TEXT,
    response_elements TEXT,
    raw_payload TEXT NOT NULL,
    batch_id TEXT,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_log_id INTEGER,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    event_name TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_source TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_type TEXT,
    source_ip TEXT NOT NULL,
    is_internal_ip INTEGER DEFAULT 0,
    is_error INTEGER DEFAULT 0,
    error_code TEXT,
    target_resource TEXT,
    action_type TEXT,
    risk_score REAL DEFAULT 0.0,
    is_privilege_related INTEGER DEFAULT 0,
    is_auth_failure INTEGER DEFAULT 0,
    is_tampering INTEGER DEFAULT 0,
    FOREIGN KEY(raw_log_id) REFERENCES raw_logs(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code TEXT UNIQUE NOT NULL,
    event_id TEXT NOT NULL,
    title TEXT NOT NULL,
    event_name TEXT NOT NULL,
    event_time TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    ml_anomaly_score REAL NOT NULL,
    is_ml_anomaly INTEGER DEFAULT 1,
    rule_triggered TEXT,
    risk_factors TEXT,
    principal TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Investigating', 'Resolved', 'False Positive')),
    assigned_to TEXT DEFAULT 'Unassigned',
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    action_name TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Simulated',
    performed_by TEXT NOT NULL,
    parameters TEXT,
    details TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_category TEXT NOT NULL,
    action_name TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_id TEXT,
    details TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    chunk_count INTEGER DEFAULT 0,
    indexed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS etl_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    source_type TEXT NOT NULL,
    filename TEXT,
    total_records INTEGER NOT NULL,
    processed_records INTEGER NOT NULL,
    duplicate_records INTEGER NOT NULL,
    rejected_records INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Indexes for fast querying & security filtering
CREATE INDEX IF NOT EXISTS idx_norm_events_timestamp ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_norm_events_principal ON normalized_events(principal_id);
CREATE INDEX IF NOT EXISTS idx_norm_events_source_ip ON normalized_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_norm_events_name ON normalized_events(event_name);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp);
