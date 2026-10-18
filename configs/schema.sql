-- ContextHunter (KINETIX) SQLite 3 WAL Schema
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS targets (
    target_id TEXT PRIMARY KEY,
    base_url TEXT NOT NULL UNIQUE,
    waf_vendor TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS http_cache (
    req_hash TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ns INTEGER NOT NULL,
    resp_headers_json TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    body_sample BLOB,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(target_id)
);

CREATE TABLE IF NOT EXISTS tech_stack (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id TEXT NOT NULL,
    cpe_uri TEXT NOT NULL,
    confidence REAL NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(target_id)
);

CREATE TABLE IF NOT EXISTS contextual_findings (
    finding_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    endpoint_path TEXT NOT NULL,
    probability_score REAL NOT NULL,
    contextual_risk REAL NOT NULL,
    tier TEXT NOT NULL,
    poc_validated BOOLEAN NOT NULL DEFAULT 0,
    evidence_sha256 TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(target_id)
);
