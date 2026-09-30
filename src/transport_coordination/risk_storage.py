"""重点路桥风险处置服务的 SQLite 表结构。

所有表均以 ``risk_`` 前缀登记在基础服务同一数据库内，审计事件继续写入
基础服务的 ``audit_events`` 哈希链，命令重放时可按时间复原完整时间线。
"""

from __future__ import annotations

RISK_SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_facilities (
    facility_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    facility_type TEXT NOT NULL,
    name TEXT NOT NULL,
    criticality TEXT NOT NULL CHECK(criticality IN ('high', 'normal')),
    control_status TEXT NOT NULL CHECK(control_status IN ('normal', 'restricted', 'closed', 'open')),
    payload_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_facility_links (
    link_id TEXT PRIMARY KEY,
    upstream_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    downstream_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    relation TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(upstream_id, downstream_id, relation)
);
CREATE TABLE IF NOT EXISTS risk_sensors (
    sensor_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    metric TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    calibration_status TEXT NOT NULL CHECK(calibration_status IN ('valid', 'failed')),
    calibrated_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_calibrations (
    calibration_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL REFERENCES risk_sensors(sensor_id),
    status TEXT NOT NULL CHECK(status IN ('valid', 'failed')),
    effective_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_rule_versions (
    rule_version_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('draft', 'active', 'superseded')),
    rules_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT
);
CREATE TABLE IF NOT EXISTS risk_plan_versions (
    plan_version_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('draft', 'active', 'superseded')),
    scope_json TEXT NOT NULL,
    content_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT
);
CREATE TABLE IF NOT EXISTS risk_observations (
    observation_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('sensor', 'manual')),
    sensor_id TEXT,
    reporter_id TEXT,
    episode_id TEXT,
    metric TEXT NOT NULL,
    double_value REAL,
    text_value TEXT NOT NULL DEFAULT '',
    reported_level TEXT,
    is_reinspection INTEGER NOT NULL DEFAULT 0 CHECK(is_reinspection IN (0, 1)),
    late INTEGER NOT NULL DEFAULT 0 CHECK(late IN (0, 1)),
    duplicate INTEGER NOT NULL DEFAULT 0 CHECK(duplicate IN (0, 1)),
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_signals (
    signal_id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL UNIQUE REFERENCES risk_observations(observation_id),
    facility_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    metric TEXT NOT NULL,
    level TEXT NOT NULL CHECK(level IN ('watch', 'warning', 'danger')),
    source_kind TEXT NOT NULL,
    sensor_id TEXT,
    reporter_id TEXT,
    episode_id TEXT,
    rule_version_id TEXT,
    rule_content_hash TEXT,
    matched_json TEXT NOT NULL,
    tainted INTEGER NOT NULL DEFAULT 0 CHECK(tainted IN (0, 1)),
    late INTEGER NOT NULL DEFAULT 0 CHECK(late IN (0, 1)),
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_event_signals (
    event_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    correlation_json TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY(event_id, signal_id)
);
CREATE TABLE IF NOT EXISTS risk_events (
    event_id TEXT PRIMARY KEY,
    episode_id TEXT,
    primary_facility_id TEXT NOT NULL REFERENCES risk_facilities(facility_id),
    state TEXT NOT NULL,
    response_level INTEGER NOT NULL DEFAULT 1 CHECK(response_level BETWEEN 1 AND 4),
    severity TEXT NOT NULL CHECK(severity IN ('watch', 'warning', 'danger')),
    confidence REAL NOT NULL,
    review_required INTEGER NOT NULL DEFAULT 0 CHECK(review_required IN (0, 1)),
    rule_version_id TEXT,
    rule_content_hash TEXT,
    plan_version_id TEXT,
    plan_content_hash TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_decisions (
    decision_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    action TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    basis_json TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_confirmations (
    confirmation_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    actor_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    role TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    opinion TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(event_id, actor_id)
);
CREATE TABLE IF NOT EXISTS risk_rejected_steps (
    reject_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_reviews (
    review_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES risk_events(event_id),
    failed_sensor_id TEXT,
    reviewer_id TEXT NOT NULL,
    conclusion TEXT NOT NULL CHECK(conclusion IN ('valid', 'invalid')),
    evidence_json TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# 处置状态的严格推进顺序，索引只能增大。
DISPOSAL_STATES = ("detected", "escalated", "restricted", "closed", "repairing", "reinspected", "opened")
STATE_INDEX = {state: index for index, state in enumerate(DISPOSAL_STATES)}

# 信号严重度顺序。
SIGNAL_LEVELS = ("watch", "warning", "danger")
LEVEL_INDEX = {level: index for index, level in enumerate(SIGNAL_LEVELS)}

# 每种处置动作对应的状态迁移。
TRANSITIONS = {
    "escalate": ("detected", "escalated"),
    "restrict": ("escalated", "restricted"),
    "close": ("restricted", "closed"),
    "repair": ("closed", "repairing"),
    "reinspect": ("repairing", "reinspected"),
    "open": ("reinspected", "opened"),
}

# 执行处置动作所需角色。
ACTION_ROLES = {
    "escalate": ("admin", "operator"),
    "restrict": ("admin", "operator"),
    "close": ("admin", "operator"),
    "repair": ("admin", "operator"),
    "reinspect": ("admin", "reviewer"),
    "open": ("admin", "operator"),
}

# 严重度对应的默认响应级别（可被激活预案覆盖）。
DEFAULT_RESPONSE_LEVELS = {"watch": 1, "warning": 2, "danger": 3}

# 不同风险等级设施开放所需的相互独立技术确认份数。
DEFAULT_OPEN_CONFIRMATIONS = {"high": 2, "normal": 1}

# 同一场灾害内跨设施信号的归并时间窗（小时）。
CORRELATION_WINDOW_HOURS = 24

COMPARATORS = {
    ">=": lambda value, threshold: value >= threshold,
    ">": lambda value, threshold: value > threshold,
    "<=": lambda value, threshold: value <= threshold,
    "<": lambda value, threshold: value < threshold,
}
