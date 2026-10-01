"""重点路桥风险处置服务的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Facility:
    facility_id: str
    site_id: str
    facility_type: str
    name: str
    kilometrage: str
    risk_level: str
    attributes: dict[str, Any]
    active: bool
    version: int


@dataclass(frozen=True)
class Sensor:
    sensor_id: str
    facility_id: str
    metric: str
    unit: str
    attributes: dict[str, Any]
    active: bool
    version: int


@dataclass(frozen=True)
class Observation:
    observation_id: str
    facility_id: str
    sensor_id: str | None
    source: str
    metric: str
    value: float | None
    quality: str
    observed_at: str
    received_at: str
    payload: dict[str, Any]
    evaluation: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SignalView:
    observation_id: str
    facility_id: str
    sensor_id: str | None
    source: str
    metric: str
    value: float | None
    quality: str
    observed_at: str
    calibration_status: str | None
    matches: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class IncidentView:
    incident_id: str
    site_id: str
    status: str
    severity: str
    confidence: float
    rule_version_id: str
    correlation_key: str
    hypothesis: str
    impact: dict[str, Any]
    summary: str
    opened_at: str
    closed_at: str | None
    signals: tuple[SignalView, ...]
    facilities: tuple[dict[str, Any], ...]
    dispositions: tuple[dict[str, Any], ...]
    pending_reviews: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class DispositionView:
    disposition_id: str
    incident_id: str
    facility_id: str
    stage: str
    ordinal: int
    status: str
    reason: str
    rule_version_id: str
    plan_id: str | None
    basis_id: str
    confidence: float
    impact: dict[str, Any]
    decided_by: str
    decided_at: str
    confirmations: tuple[dict[str, Any], ...] = ()
    review: dict[str, Any] | None = None
