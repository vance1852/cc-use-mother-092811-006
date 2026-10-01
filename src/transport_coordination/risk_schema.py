"""重点路桥风险处置服务的 SQLite 表结构。

表按登记对象、观测、规则、事件、处置、技术确认六类组织。
所有版本化对象只追加不覆盖；处置阶段严格单向推进。
"""

RISK_SCHEMA = """
CREATE TABLE IF NOT EXISTS facilities (
    facility_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    facility_type TEXT NOT NULL,
    name TEXT NOT NULL,
    kilometrage TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    version INTEGER NOT NULL CHECK(version >= 1),
    registered_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    superseded_at TEXT
);
CREATE TABLE IF NOT EXISTS facility_links (
    link_id TEXT PRIMARY KEY,
    upstream_facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    downstream_facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    relation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(upstream_facility_id, downstream_facility_id, relation)
);
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    metric TEXT NOT NULL,
    unit TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    version INTEGER NOT NULL CHECK(version >= 1),
    registered_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS calibration_records (
    calibration_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL REFERENCES sensors(sensor_id),
    status TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    drift REAL,
    evidence_ref TEXT,
    payload_json TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    sensor_id TEXT REFERENCES sensors(sensor_id),
    source TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL,
    quality TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    business_hash TEXT NOT NULL UNIQUE,
    recorded_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_facility_time ON observations(facility_id, observed_at);
CREATE TABLE IF NOT EXISTS rule_versions (
    rule_version_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK(version >= 1),
    status TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    published_by TEXT NOT NULL,
    published_at TEXT NOT NULL,
    superseded_at TEXT,
    UNIQUE(version)
);
CREATE TABLE IF NOT EXISTS plan_versions (
    plan_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    status TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    published_by TEXT NOT NULL,
    published_at TEXT NOT NULL,
    superseded_at TEXT,
    UNIQUE(facility_id, version)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    rule_version_id TEXT NOT NULL REFERENCES rule_versions(rule_version_id),
    correlation_key TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    impact_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    opened_by TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    UNIQUE(correlation_key)
);
CREATE TABLE IF NOT EXISTS incident_signals (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    observation_id TEXT NOT NULL REFERENCES observations(observation_id),
    rule_id TEXT,
    matched_level TEXT,
    weight REAL NOT NULL,
    calibration_status TEXT,
    source TEXT NOT NULL,
    qualified INTEGER NOT NULL CHECK(qualified IN (0, 1)),
    evaluation_json TEXT NOT NULL,
    attached_at TEXT NOT NULL,
    PRIMARY KEY(incident_id, observation_id)
);
CREATE TABLE IF NOT EXISTS incident_facilities (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    role TEXT NOT NULL,
    PRIMARY KEY(incident_id, facility_id)
);
CREATE TABLE IF NOT EXISTS incident_basis (
    basis_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    kind TEXT NOT NULL,
    rule_version_id TEXT REFERENCES rule_versions(rule_version_id),
    plan_id TEXT REFERENCES plan_versions(plan_id),
    observation_ids_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dispositions (
    disposition_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    stage TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    rule_version_id TEXT NOT NULL REFERENCES rule_versions(rule_version_id),
    plan_id TEXT REFERENCES plan_versions(plan_id),
    basis_id TEXT REFERENCES incident_basis(basis_id),
    confidence REAL NOT NULL,
    impact_json TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    UNIQUE(incident_id, facility_id, ordinal)
);
CREATE TABLE IF NOT EXISTS technical_confirmations (
    confirmation_id TEXT PRIMARY KEY,
    disposition_id TEXT NOT NULL REFERENCES dispositions(disposition_id),
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    channel TEXT NOT NULL,
    result TEXT NOT NULL,
    opinion TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    confirmed_by TEXT NOT NULL,
    confirmed_by_organization TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(disposition_id, channel)
);
CREATE TABLE IF NOT EXISTS disposition_reviews (
    review_id TEXT PRIMARY KEY,
    disposition_id TEXT NOT NULL REFERENCES dispositions(disposition_id),
    required INTEGER NOT NULL CHECK(required IN (0, 1)),
    reason TEXT NOT NULL,
    resolved INTEGER NOT NULL CHECK(resolved IN (0, 1)),
    created_at TEXT NOT NULL,
    resolved_at TEXT
);
"""
