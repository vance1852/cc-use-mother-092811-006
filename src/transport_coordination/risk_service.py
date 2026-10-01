"""重点路桥风险处置领域服务。

在基础登记服务之上实现：
- 设施拓扑、传感器、人工观测与校准状态登记；
- 阈值规则版本与应急预案版本的发布、换版和冻结引用；
- 多源信号归并为可追踪事件，给出置信度与影响范围；
- 升级、限行、封闭、抢修、复检、开放的单向有序处置；
- 开放高风险设施所需的相互独立技术确认；
- 校准失效后未结事件的复审队列。
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from .audit import append_event, canonical_json, digest
from .risk_engine import (
    STAGE_LABELS,
    STAGE_ORDINALS,
    active_plan,
    active_version_at,
    calibration_at,
    evaluate_observation,
    facility_cluster,
    find_incident,
    format_ts,
    impact_scope,
    parse_ts,
    synthesize,
)
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .risk_models import DispositionView, Facility, IncidentView, Observation, SignalView, Sensor
from .service import DomainService

FACILITY_TYPES = frozenset({"bridge", "slope", "tunnel", "roadbed", "culvert"})
RISK_LEVELS = frozenset({"normal", "high"})
OBSERVATION_SOURCES = frozenset({"sensor", "inspector"})
CALIBRATION_STATUSES = frozenset({"valid", "expired", "unverified", "failed"})
CONFIRMATION_RESULTS = frozenset({"approved", "rejected"})
OPEN_CONFIRMATIONS_REQUIRED = {"normal": 1, "high": 2}

STAGE_ROLES = {
    "heighten": ("operator", "admin", "engineer"),
    "restrict": ("operator", "admin"),
    "close": ("admin",),
    "repair": ("engineer", "admin"),
    "recheck": ("engineer", "admin", "reviewer"),
    "reopen": ("admin",),
}


class RiskService(DomainService):
    """协调风险登记、信号归并和处置状态机。"""

    # ---------- 登记：设施与拓扑 ----------

    def register_facility(self, *, request_id: str, actor_id: str, site_id: str, facility_id: str,
                          facility_type: str, name: str, kilometrage: str, risk_level: str,
                          attributes: dict[str, Any] | None = None) -> Any:
        attributes = attributes or {}
        payload = {"actor_id": actor_id, "site_id": site_id, "facility_id": facility_id,
                   "facility_type": facility_type, "name": name, "kilometrage": kilometrage,
                   "risk_level": risk_level, "attributes": attributes}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            site = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if site is None:
                raise NotFoundError("场所不存在")
            if actor.organization_id != site["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能为其他组织登记设施")
            facility_id = self._identifier(facility_id, "facility_id")
            if facility_type not in FACILITY_TYPES:
                raise ValidationError("facility_type 不在允许范围内")
            if risk_level not in RISK_LEVELS:
                raise ValidationError("risk_level 必须是 normal 或 high")
            name = self._text(name, "name")
            kilometrage = self._text(kilometrage, "kilometrage", 80)
            if not isinstance(attributes, dict):
                raise ValidationError("attributes 必须是对象")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO facilities(facility_id,site_id,facility_type,name,kilometrage,"
                        "risk_level,payload_json,active,version,registered_by,created_at) "
                        "VALUES(?,?,?,?,?,?,?,1,1,?,?)",
                        (facility_id, site_id, facility_type, name, kilometrage, risk_level,
                         canonical_json(attributes), actor_id, now),
                    )
                except Exception as exc:
                    raise ConflictError("设施编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="facility.registered",
                             resource_type="facility", resource_id=facility_id,
                             detail={"site_id": site_id, "facility_type": facility_type,
                                     "risk_level": risk_level, "name": name}, occurred_at=now)
                return "facility", facility_id, {"facility_id": facility_id, "version": 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_facility", payload=payload, create=create)

    def link_facilities(self, *, request_id: str, actor_id: str, link_id: str,
                        upstream_facility_id: str, downstream_facility_id: str,
                        relation: str) -> Any:
        relation = self._text(relation, "relation", 40)
        payload = {"actor_id": actor_id, "link_id": link_id,
                   "upstream_facility_id": upstream_facility_id,
                   "downstream_facility_id": downstream_facility_id, "relation": relation}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            link_id = self._identifier(link_id, "link_id")
            upstream_facility_id = self._identifier(upstream_facility_id, "upstream_facility_id")
            downstream_facility_id = self._identifier(downstream_facility_id, "downstream_facility_id")
            if upstream_facility_id == downstream_facility_id:
                raise ValidationError("拓扑边不能连接设施自身")
            if not connection.execute("SELECT 1 FROM facilities WHERE facility_id=?",
                                      (upstream_facility_id,)).fetchone():
                raise NotFoundError("上游设施不存在")
            if not connection.execute("SELECT 1 FROM facilities WHERE facility_id=?",
                                      (downstream_facility_id,)).fetchone():
                raise NotFoundError("下游设施不存在")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO facility_links(link_id,upstream_facility_id,"
                        "downstream_facility_id,relation,created_at) VALUES(?,?,?,?,?)",
                        (link_id, upstream_facility_id, downstream_facility_id, relation, now),
                    )
                except Exception as exc:
                    raise ConflictError("拓扑边已经存在") from exc
                append_event(connection, actor_id=actor_id, action="facility.linked",
                             resource_type="facility_link", resource_id=link_id,
                             detail={"upstream": upstream_facility_id,
                                     "downstream": downstream_facility_id, "relation": relation},
                             occurred_at=now)
                return "facility_link", link_id, {"link_id": link_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="link_facilities", payload=payload, create=create)

    # ---------- 登记：传感器与校准 ----------

    def register_sensor(self, *, request_id: str, actor_id: str, sensor_id: str, facility_id: str,
                        metric: str, unit: str, attributes: dict[str, Any] | None = None) -> Any:
        attributes = attributes or {}
        payload = {"actor_id": actor_id, "sensor_id": sensor_id, "facility_id": facility_id,
                   "metric": metric, "unit": unit, "attributes": attributes}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            sensor_id = self._identifier(sensor_id, "sensor_id")
            facility_id = self._identifier(facility_id, "facility_id")
            metric = self._text(metric, "metric", 60)
            unit = self._text(unit, "unit", 30)
            facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                          (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            self._require_same_organization(connection, actor, facility["site_id"])
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO sensors(sensor_id,facility_id,metric,unit,payload_json,"
                        "active,version,registered_by,created_at) VALUES(?,?,?,?,?,1,1,?,?)",
                        (sensor_id, facility_id, metric, unit, canonical_json(attributes),
                         actor_id, now),
                    )
                except Exception as exc:
                    raise ConflictError("传感器编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="sensor.registered",
                             resource_type="sensor", resource_id=sensor_id,
                             detail={"facility_id": facility_id, "metric": metric, "unit": unit},
                             occurred_at=now)
                return "sensor", sensor_id, {"sensor_id": sensor_id, "version": 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_sensor", payload=payload, create=create)

    def record_calibration(self, *, request_id: str, actor_id: str, sensor_id: str,
                           calibration_id: str, status: str, valid_from: str,
                           valid_until: str | None = None, drift: float | None = None,
                           evidence_ref: str | None = None, notes: str | None = None) -> Any:
        payload = {"actor_id": actor_id, "sensor_id": sensor_id, "calibration_id": calibration_id,
                   "status": status, "valid_from": valid_from, "valid_until": valid_until,
                   "drift": drift, "evidence_ref": evidence_ref, "notes": notes}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "engineer", "operator")
            calibration_id = self._identifier(calibration_id, "calibration_id")
            sensor_id = self._identifier(sensor_id, "sensor_id")
            if status not in CALIBRATION_STATUSES:
                raise ValidationError("校准状态不在允许范围内")
            valid_from_text = format_ts(parse_ts(valid_from))
            valid_until_text = format_ts(parse_ts(valid_until)) if valid_until else None
            if valid_until_text and valid_until_text <= valid_from_text:
                raise ValidationError("校准失效时间必须晚于生效时间")
            sensor = connection.execute("SELECT * FROM sensors WHERE sensor_id=?",
                                        (sensor_id,)).fetchone()
            if sensor is None:
                raise NotFoundError("传感器不存在")
            self._require_same_organization(connection, actor, sensor["facility_id"], "facility")
            notes = notes or ""
            evidence_ref = evidence_ref or ""
            now = self._now()
            calibration_payload = {"drift": drift, "notes": notes}

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO calibration_records(calibration_id,sensor_id,status,"
                        "valid_from,valid_until,drift,evidence_ref,payload_json,recorded_by,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (calibration_id, sensor_id, status, valid_from_text, valid_until_text,
                         drift, evidence_ref, canonical_json(calibration_payload), actor_id, now),
                    )
                except Exception as exc:
                    raise ConflictError("校准记录编号已经存在") from exc
                flagged = []
                if status == "failed":
                    flagged = self._flag_reviews_for_sensor(
                        connection, sensor_id,
                        reason=f"传感器 {sensor_id} 校准失效（记录 {calibration_id}）", now=now)
                append_event(connection, actor_id=actor_id, action="calibration.recorded",
                             resource_type="calibration", resource_id=calibration_id,
                             detail={"sensor_id": sensor_id, "status": status,
                                     "valid_from": valid_from_text, "valid_until": valid_until_text,
                                     "review_flagged": len(flagged)}, occurred_at=now)
                return "calibration", calibration_id, {
                    "calibration_id": calibration_id, "status": status,
                    "review_flagged_incidents": flagged}

            return self._idempotent(connection, request_id=request_id,
                                    action="record_calibration", payload=payload, create=create)

    # ---------- 登记：规则与预案版本 ----------

    def publish_rules(self, *, request_id: str, actor_id: str, version: int,
                      rules: list[dict[str, Any]], window_minutes: int = 120,
                      activate: bool = True) -> Any:
        payload = {"actor_id": actor_id, "version": version, "rules": rules,
                   "window_minutes": window_minutes, "activate": activate}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            if not isinstance(version, int) or version < 1:
                raise ValidationError("规则版本必须是不小于 1 的整数")
            if not isinstance(rules, list) or not rules:
                raise ValidationError("规则列表不能为空")
            if not isinstance(window_minutes, int) or not 1 <= window_minutes <= 24 * 60:
                raise ValidationError("归并时间窗必须在 1 到 1440 分钟之间")
            normalized = [self._normalize_rule(rule) for rule in rules]
            rules_payload = {"rules": normalized, "window_minutes": window_minutes}
            now = self._now()
            rule_version_id = uuid.uuid4().hex

            def create() -> tuple[str, str, dict[str, Any]]:
                if connection.execute("SELECT 1 FROM rule_versions WHERE version=?",
                                      (version,)).fetchone():
                    raise ConflictError("规则版本号已经存在")
                connection.execute(
                    "INSERT INTO rule_versions(rule_version_id,version,status,rules_json,"
                    "published_by,published_at) VALUES(?,?,?,?,?,?)",
                    (rule_version_id, version, "active" if activate else "draft",
                     canonical_json(rules_payload), actor_id, now),
                )
                if activate:
                    connection.execute(
                        "UPDATE rule_versions SET status='superseded', superseded_at=? "
                        "WHERE status='active' AND rule_version_id<>?",
                        (now, rule_version_id),
                    )
                append_event(connection, actor_id=actor_id, action="rules.published",
                             resource_type="rule_version", resource_id=rule_version_id,
                             detail={"version": version, "status": "active" if activate else "draft",
                                     "rule_count": len(normalized),
                                     "rules_hash": digest(rules_payload)}, occurred_at=now)
                return "rule_version", rule_version_id, {
                    "rule_version_id": rule_version_id, "version": version,
                    "rules_hash": digest(rules_payload)}

            return self._idempotent(connection, request_id=request_id,
                                    action="publish_rules", payload=payload, create=create)

    def activate_rules(self, *, request_id: str, actor_id: str, version: int) -> Any:
        payload = {"actor_id": actor_id, "version": version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            target = connection.execute("SELECT * FROM rule_versions WHERE version=?",
                                        (version,)).fetchone()
            if target is None:
                raise NotFoundError("规则版本不存在")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE rule_versions SET status='superseded', superseded_at=? WHERE status='active'",
                    (now,),
                )
                connection.execute(
                    "UPDATE rule_versions SET status='active', superseded_at=NULL WHERE version=?",
                    (version,),
                )
                append_event(connection, actor_id=actor_id, action="rules.activated",
                             resource_type="rule_version", resource_id=target["rule_version_id"],
                             detail={"version": version}, occurred_at=now)
                return "rule_version", target["rule_version_id"], {"version": version}

            return self._idempotent(connection, request_id=request_id,
                                    action="activate_rules", payload=payload, create=create)

    def publish_plan(self, *, request_id: str, actor_id: str, facility_id: str, version: int,
                     steps: list[str], activate: bool = True) -> Any:
        payload = {"actor_id": actor_id, "facility_id": facility_id, "version": version,
                   "steps": steps, "activate": activate}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            facility_id = self._identifier(facility_id, "facility_id")
            if not isinstance(version, int) or version < 1:
                raise ValidationError("预案版本必须是不小于 1 的整数")
            if not isinstance(steps, list) or not steps:
                raise ValidationError("预案步骤不能为空")
            last_index = -1
            for stage in steps:
                if stage not in STAGE_ORDINALS:
                    raise ValidationError(f"未知处置阶段：{stage}")
                if STAGE_ORDINALS[stage] <= last_index:
                    raise ValidationError("预案步骤必须按处置顺序排列且不能重复")
                last_index = STAGE_ORDINALS[stage]
            if "reopen" not in steps:
                raise ValidationError("应急预案必须包含开放步骤")
            facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                          (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            self._require_same_organization(connection, actor, facility["site_id"])
            now = self._now()
            plan_id = uuid.uuid4().hex

            def create() -> tuple[str, str, dict[str, Any]]:
                if connection.execute(
                        "SELECT 1 FROM plan_versions WHERE facility_id=? AND version=?",
                        (facility_id, version)).fetchone():
                    raise ConflictError("该设施的预案版本号已经存在")
                connection.execute(
                    "INSERT INTO plan_versions(plan_id,facility_id,version,status,steps_json,"
                    "published_by,published_at) VALUES(?,?,?,?,?,?,?)",
                    (plan_id, facility_id, version, "active" if activate else "draft",
                     canonical_json({"steps": steps}), actor_id, now),
                )
                if activate:
                    connection.execute(
                        "UPDATE plan_versions SET status='superseded', superseded_at=? "
                        "WHERE facility_id=? AND status='active' AND plan_id<>?",
                        (now, facility_id, plan_id),
                    )
                append_event(connection, actor_id=actor_id, action="plan.published",
                             resource_type="plan_version", resource_id=plan_id,
                             detail={"facility_id": facility_id, "version": version,
                                     "status": "active" if activate else "draft",
                                     "steps": steps}, occurred_at=now)
                return "plan_version", plan_id, {"plan_id": plan_id, "version": version}

            return self._idempotent(connection, request_id=request_id,
                                    action="publish_plan", payload=payload, create=create)

    # ---------- 信号接入与归并 ----------

    def ingest_observation(self, *, actor_id: str, facility_id: str, metric: str, source: str,
                           observed_at: str, value: float | None = None,
                           sensor_id: str | None = None, quality: str = "ok",
                           payload: dict[str, Any] | None = None,
                           observation_id: str | None = None) -> dict[str, Any]:
        """登记一条观测并驱动归并；重复观测幂等返回且不改变任何处置状态。"""

        payload = payload or {}
        facility_id = self._identifier(facility_id, "facility_id")
        metric = self._text(metric, "metric", 60)
        if source not in OBSERVATION_SOURCES:
            raise ValidationError("观测来源必须是 sensor 或 inspector")
        observed_dt = parse_ts(observed_at)
        observed_text = format_ts(observed_dt)
        if quality not in ("ok", "qualified", "dropped"):
            raise ValidationError("观测质量标记无效")
        if not isinstance(payload, dict):
            raise ValidationError("payload 必须是对象")
        business = {
            "facility_id": facility_id, "sensor_id": sensor_id, "source": source,
            "metric": metric, "value": value, "observed_at": observed_text,
            "quality": quality, "payload": payload,
        }
        business_hash = digest(business)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "engineer", "reviewer")
            facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                          (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            self._require_same_organization(connection, actor, facility["site_id"])
            sensor_row = None
            if sensor_id:
                sensor_row = connection.execute("SELECT * FROM sensors WHERE sensor_id=?",
                                                (sensor_id,)).fetchone()
                if sensor_row is None:
                    raise NotFoundError("传感器不存在")
                if sensor_row["facility_id"] != facility_id:
                    raise ValidationError("传感器不属于该设施")
                if sensor_row["metric"] != metric:
                    raise ValidationError("观测指标与传感器登记指标不一致")
            existing = connection.execute(
                "SELECT observation_id FROM observations WHERE business_hash=?", (business_hash,)
            ).fetchone()
            now_text = self._now()
            if existing:
                return {"observation_id": existing["observation_id"], "replayed": True,
                        "incident_id": self._incident_of(connection, existing["observation_id"])}
            observation_id = self._identifier(observation_id or uuid.uuid4().hex, "observation_id")
            if value is not None and not isinstance(value, (int, float)):
                raise ValidationError("观测值必须是数值")
            connection.execute(
                "INSERT INTO observations(observation_id,facility_id,sensor_id,source,metric,"
                "value,quality,observed_at,received_at,payload_json,business_hash,recorded_by) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (observation_id, facility_id, sensor_id, source, metric, value, quality,
                 observed_text, now_text, canonical_json(payload), business_hash, actor_id),
            )
            append_event(connection, actor_id=actor_id, action="observation.ingested",
                         resource_type="observation", resource_id=observation_id,
                         detail={"facility_id": facility_id, "metric": metric, "source": source,
                                 "observed_at": observed_text, "quality": quality},
                         occurred_at=now_text)
            incident_id = None
            if quality != "dropped":
                incident_id = self._correlate(connection, facility_id=facility_id,
                                              observation_id=observation_id, source=source,
                                              metric=metric, value=value, payload=payload,
                                              sensor_id=sensor_id, observed_dt=observed_dt,
                                              observed_text=observed_text, actor_id=actor_id,
                                              now_text=now_text)
            return {"observation_id": observation_id, "replayed": False,
                    "incident_id": incident_id}

    def _correlate(self, connection, *, facility_id: str, observation_id: str, source: str,
                   metric: str, value: Any, payload: dict[str, Any], sensor_id: str | None,
                   observed_dt, observed_text: str, actor_id: str, now_text: str) -> str | None:
        rule_row = active_version_at(connection, "rule_versions", observed_text)
        if rule_row is None:
            return None
        rules_payload = json.loads(rule_row["rules_json"])
        calibration_status = "valid"
        if sensor_id:
            calibration_status, _ = calibration_at(connection, sensor_id, observed_dt)
        observation = {"facility_id": facility_id, "source": source, "metric": metric,
                       "value": value, "payload": payload}
        matches = evaluate_observation(connection, rules_payload, observation, calibration_status)
        if not matches:
            return None
        best = max(matches, key=lambda item: (STAGE_ORDINALS[item["matched_level"]], item["weight"]))
        # 校准失效或从未校准传感器的孤立信号只留在观测台账，不单独支撑事件。
        if best["qualified"] and source == "sensor" and all(item["qualified"] for item in matches):
            return None
        cluster = facility_cluster(connection, facility_id)
        window = rules_payload.get("window_minutes", 120)
        incident = find_incident(connection, site_id=self._site_of(connection, facility_id),
                                 cluster=cluster, observed_at=observed_dt,
                                 window_minutes=window)
        if incident is None:
            return self._open_incident(connection, rule_row=rule_row, rules_payload=rules_payload,
                                       cluster=cluster,
                                       facility_id=facility_id, observation_id=observation_id,
                                       source=source, metric=metric, value=value,
                                       payload=payload, sensor_id=sensor_id,
                                       calibration_status=calibration_status, matches=matches,
                                       observed_text=observed_text, actor_id=actor_id,
                                       now_text=now_text)
        return self._attach_signal(connection, incident=incident, rule_row=rule_row,
                                   rules_payload=rules_payload, facility_id=facility_id,
                                   observation_id=observation_id, source=source, metric=metric,
                                   value=value, payload=payload, sensor_id=sensor_id,
                                   calibration_status=calibration_status, matches=matches,
                                   observed_text=observed_text, actor_id=actor_id,
                                   now_text=now_text)

    def _open_incident(self, connection, *, rule_row, rules_payload, cluster, facility_id,
                       observation_id,
                       source, metric, value, payload, sensor_id, calibration_status, matches,
                       observed_text, actor_id, now_text) -> str:
        incident_id = uuid.uuid4().hex
        top_level = max((item["matched_level"] for item in matches),
                        key=lambda level: STAGE_ORDINALS[level])
        signals = [{
            "observation_id": observation_id, "facility_id": facility_id, "source": source,
            "matched_level": top_level,
            "weight": max(item["weight"] for item in matches
                          if item["matched_level"] == top_level),
            "calibration_status": calibration_status,
            "qualified": all(item["qualified"] for item in matches),
        }]
        severity, confidence, qualified_only = synthesize(signals)
        facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                      (facility_id,)).fetchone()
        impact = impact_scope(connection, {facility_id}, severity)
        correlation_key = uuid.uuid4().hex
        hypothesis = f"{facility['name']}出现{metric}风险信号"
        summary = f"首条信号：{source}/{metric}，命中等级 {STAGE_LABELS[severity]}"
        connection.execute(
            "INSERT INTO incidents(incident_id,site_id,status,severity,confidence,"
            "rule_version_id,correlation_key,hypothesis,impact_json,summary,opened_by,opened_at) "
            "VALUES(?,?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (incident_id, facility["site_id"], severity, confidence, rule_row["rule_version_id"],
             correlation_key, hypothesis, canonical_json(impact), summary, actor_id, observed_text),
        )
        connection.execute(
            "INSERT INTO incident_facilities(incident_id,facility_id,role) VALUES(?,?,'primary')",
            (incident_id, facility_id),
        )
        for neighbor in impact["facilities"]:
            if neighbor["facility_id"] != facility_id:
                connection.execute(
                    "INSERT OR IGNORE INTO incident_facilities(incident_id,facility_id,role) "
                    "VALUES(?,?,?)", (incident_id, neighbor["facility_id"], neighbor["role"]))
        self._insert_signal_rows(connection, incident_id=incident_id,
                                 observation_id=observation_id, source=source,
                                 calibration_status=calibration_status, matches=matches,
                                 attached_at=now_text)
        # 人工等可靠信号后到时，追溯归并时间窗内早先“挂起”的合格性受限信号。
        promoted = self._promote_recent_observations(
            connection, incident_id=incident_id, cluster=cluster,
            around=parse_ts(observed_text), window_minutes=rules_payload.get("window_minutes", 120),
            actor_id=actor_id, now_text=now_text)
        if promoted:
            signals = self._signal_rows(connection, incident_id)
            severity, confidence, _ = synthesize(signals)
            primary_ids = {row["facility_id"] for row in connection.execute(
                "SELECT facility_id FROM incident_facilities WHERE incident_id=? AND role='primary'",
                (incident_id,))}
            impact = impact_scope(connection, primary_ids, severity)
            connection.execute(
                "UPDATE incidents SET severity=?, confidence=?, impact_json=? WHERE incident_id=?",
                (severity, confidence, canonical_json(impact), incident_id))
        append_event(connection, actor_id=actor_id, action="incident.opened",
                     resource_type="incident", resource_id=incident_id,
                     detail={"facility_id": facility_id, "severity": severity,
                             "confidence": confidence, "rule_version": rule_row["version"],
                             "observation_id": observation_id,
                             "promoted_observations": promoted}, occurred_at=now_text)
        return incident_id

    def _promote_recent_observations(self, connection, *, incident_id: str, cluster: set[str],
                                     around, window_minutes: int, actor_id: str,
                                     now_text: str) -> list[str]:
        """把时间窗内尚未归并且按当时规则命中的观测补挂到新事件。"""

        lower = around - timedelta(minutes=window_minutes)
        promoted: list[str] = []
        rows = connection.execute(
            "SELECT * FROM observations WHERE quality!='dropped' "
            "AND facility_id IN (%s) ORDER BY observed_at" %
            ",".join("?" for _ in cluster),
            (*cluster,)).fetchall()
        for row in rows:
            observed_dt = parse_ts(row["observed_at"])
            if not (lower <= observed_dt <= around):
                continue
            linked = connection.execute(
                "SELECT 1 FROM incident_signals WHERE observation_id=?",
                (row["observation_id"],)).fetchone()
            if linked:
                continue
            rule_row = active_version_at(connection, "rule_versions", row["observed_at"])
            if rule_row is None:
                continue
            cal_status = "valid"
            if row["sensor_id"]:
                cal_status, _ = calibration_at(connection, row["sensor_id"],
                                               parse_ts(row["observed_at"]))
            obs_payload = json.loads(row["payload_json"])
            matches = evaluate_observation(
                connection, json.loads(rule_row["rules_json"]),
                {"facility_id": row["facility_id"], "source": row["source"],
                 "metric": row["metric"], "value": row["value"], "payload": obs_payload},
                cal_status)
            if not matches:
                continue
            self._insert_signal_rows(connection, incident_id=incident_id,
                                     observation_id=row["observation_id"], source=row["source"],
                                     calibration_status=cal_status, matches=matches,
                                     attached_at=now_text)
            connection.execute(
                "INSERT OR IGNORE INTO incident_facilities(incident_id,facility_id,role) "
                "VALUES(?,?,'primary')", (incident_id, row["facility_id"]))
            connection.execute(
                "UPDATE incident_facilities SET role='primary' WHERE incident_id=? AND facility_id=?",
                (incident_id, row["facility_id"]))
            promoted.append(row["observation_id"])
        return promoted

    def _attach_signal(self, connection, *, incident, rule_row, rules_payload, facility_id,
                       observation_id, source, metric, value, payload, sensor_id,
                       calibration_status, matches, observed_text, actor_id, now_text) -> str:
        incident_id = incident["incident_id"]
        last_at = self._last_disposition_at(connection, incident_id)
        late = bool(last_at) and parse_ts(observed_text) < parse_ts(last_at)
        self._insert_signal_rows(connection, incident_id=incident_id,
                                 observation_id=observation_id, source=source,
                                 calibration_status=calibration_status, matches=matches,
                                 attached_at=now_text)
        connection.execute(
            "INSERT OR IGNORE INTO incident_facilities(incident_id,facility_id,role) "
            "VALUES(?,?,'primary')", (incident_id, facility_id))
        signals = self._signal_rows(connection, incident_id)
        severity, confidence, _ = synthesize(signals)
        primary_ids = {row["facility_id"] for row in connection.execute(
            "SELECT facility_id FROM incident_facilities WHERE incident_id=? AND role='primary'",
            (incident_id,))}
        impact = impact_scope(connection, primary_ids, severity)
        connection.execute(
            "UPDATE incidents SET severity=?, confidence=?, impact_json=? WHERE incident_id=?",
            (severity, confidence, canonical_json(impact), incident_id))
        append_event(connection, actor_id=actor_id,
                     action="incident.signal_attached" if not late else "incident.late_signal_attached",
                     resource_type="incident", resource_id=incident_id,
                     detail={"observation_id": observation_id, "facility_id": facility_id,
                             "matched_level": max(m["matched_level"] for m in matches),
                             "late": late, "severity": severity, "confidence": confidence,
                             "dispositions_unchanged": True}, occurred_at=now_text)
        return incident_id

    def _insert_signal_rows(self, connection, *, incident_id: str, observation_id: str,
                            source: str, calibration_status: str | None,
                            matches: list[dict[str, Any]], attached_at: str) -> None:
        for index, match in enumerate(matches):
            connection.execute(
                "INSERT INTO incident_signals(incident_id,observation_id,rule_id,matched_level,"
                "weight,calibration_status,source,qualified,evaluation_json,attached_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, observation_id, match["rule_id"], match["matched_level"],
                 match["weight"], calibration_status, source, 1 if match["qualified"] else 0,
                 canonical_json(match), attached_at),
            )

    # ---------- 处置状态机 ----------

    def advance_disposition(self, *, request_id: str, actor_id: str, incident_id: str,
                            facility_id: str, stage: str, reason: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "facility_id": facility_id,
                   "stage": stage, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident_id = self._identifier(incident_id, "incident_id")
            facility_id = self._identifier(facility_id, "facility_id")
            reason = self._text(reason, "reason", 500)
            if stage not in STAGE_ORDINALS:
                raise ValidationError(f"未知处置阶段：{stage}")
            incident = connection.execute("SELECT * FROM incidents WHERE incident_id=?",
                                          (incident_id,)).fetchone()
            if incident is None:
                raise NotFoundError("事件不存在")
            if incident["status"] != "open":
                raise ConflictError("事件已经关闭，不能继续处置")
            facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                          (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            self._require_same_organization(connection, actor, facility["site_id"])
            self._require(actor, *STAGE_ROLES[stage])
            membership = connection.execute(
                "SELECT 1 FROM incident_facilities WHERE incident_id=? AND facility_id=?",
                (incident_id, facility_id)).fetchone()
            if membership is None:
                raise ValidationError("设施不属于该事件")
            action = f"advance_{stage}"
            # 幂等重放优先于状态机检查：重复请求永远返回原始回执，不能制造冲突。
            replayed = self._replay_receipt(connection, request_id=request_id, action=action,
                                            payload=payload)
            if replayed is not None:
                return replayed
            current = connection.execute(
                "SELECT * FROM dispositions WHERE incident_id=? AND facility_id=? "
                "ORDER BY ordinal DESC LIMIT 1", (incident_id, facility_id)).fetchone()
            if current and current["stage"] == stage and current["status"] != "cancelled":
                raise ConflictError(f"设施已经处于{STAGE_LABELS[stage]}状态，重复观测不能重复处置")
            if current and STAGE_ORDINALS[current["stage"]] > STAGE_ORDINALS[stage] \
                    and current["status"] != "cancelled":
                raise ConflictError("处置只能向前推进，不能倒退到既有阶段之前")
            self._validate_stage_prerequisites(connection, incident_id, facility_id, stage)
            basis = self._build_basis(connection, incident=incident, facility_id=facility_id,
                                      stage=stage, reason=reason)
            ordinal = (current["ordinal"] + 1) if current else 1
            disposition_id = uuid.uuid4().hex
            requires = OPEN_CONFIRMATIONS_REQUIRED[facility["risk_level"]] if stage == "reopen" else 0
            status = "pending_confirmation" if requires else "effective"
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO incident_basis(basis_id,incident_id,kind,rule_version_id,plan_id,"
                    "observation_ids_json,snapshot_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (basis["basis_id"], incident_id, "disposition", basis["rule_version_id"],
                     basis["plan_id"], canonical_json(basis["observation_ids"]),
                     canonical_json(basis["snapshot"]), now),
                )
                connection.execute(
                    "INSERT INTO dispositions(disposition_id,incident_id,facility_id,stage,ordinal,"
                    "status,reason,rule_version_id,plan_id,basis_id,confidence,impact_json,"
                    "decided_by,decided_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (disposition_id, incident_id, facility_id, stage, ordinal, status, reason,
                     basis["rule_version_id"], basis["plan_id"], basis["basis_id"],
                     basis["snapshot"]["confidence"], canonical_json(basis["snapshot"]["impact"]),
                     actor_id, now),
                )
                if stage == "recheck":
                    self._resolve_reviews(connection, disposition_id, incident_id, facility_id, now)
                append_event(connection, actor_id=actor_id, action=f"disposition.{stage}",
                             resource_type="disposition", resource_id=disposition_id,
                             detail={"incident_id": incident_id, "facility_id": facility_id,
                                     "stage": stage, "ordinal": ordinal, "status": status,
                                     "rule_version_id": basis["rule_version_id"],
                                     "plan_id": basis["plan_id"],
                                     "confirmations_required": requires,
                                     "basis_id": basis["basis_id"]}, occurred_at=now)
                return "disposition", disposition_id, {
                    "disposition_id": disposition_id, "stage": stage, "ordinal": ordinal,
                    "status": status, "confirmations_required": requires,
                    "rule_version_id": basis["rule_version_id"], "plan_id": basis["plan_id"],
                    "basis_id": basis["basis_id"]}

            return self._idempotent(connection, request_id=request_id,
                                    action=action, payload=payload, create=create)

    def _validate_stage_prerequisites(self, connection, incident_id: str, facility_id: str,
                                      stage: str) -> None:
        def effective(target: str) -> bool:
            return connection.execute(
                "SELECT 1 FROM dispositions WHERE incident_id=? AND facility_id=? AND stage=? "
                "AND status='effective' LIMIT 1",
                (incident_id, facility_id, target)).fetchone() is not None

        if stage == "repair" and not effective("close"):
            raise ConflictError("抢修必须在封闭生效之后")
        if stage == "recheck" and not effective("repair"):
            raise ConflictError("复检必须在抢修生效之后")
        if stage == "reopen" and not effective("recheck"):
            raise ConflictError("开放前必须完成复检")

    def add_technical_confirmation(self, *, request_id: str, actor_id: str, incident_id: str,
                                   facility_id: str, channel: str, result: str, opinion: str,
                                   evidence_ref: str, confirmed_by: str,
                                   confirmed_by_organization: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "facility_id": facility_id,
                   "channel": channel, "result": result, "opinion": opinion,
                   "evidence_ref": evidence_ref, "confirmed_by": confirmed_by,
                   "confirmed_by_organization": confirmed_by_organization}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "engineer")
            incident_id = self._identifier(incident_id, "incident_id")
            facility_id = self._identifier(facility_id, "facility_id")
            channel = self._text(channel, "channel", 40)
            opinion = self._text(opinion, "opinion", 500)
            evidence_ref = self._text(evidence_ref, "evidence_ref", 200)
            confirmed_by = self._text(confirmed_by, "confirmed_by", 100)
            confirmed_by_organization = self._text(confirmed_by_organization,
                                                   "confirmed_by_organization", 100)
            if result not in CONFIRMATION_RESULTS:
                raise ValidationError("确认结论必须是 approved 或 rejected")
            facility = connection.execute("SELECT * FROM facilities WHERE facility_id=?",
                                          (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            operating_org = connection.execute(
                "SELECT organization_id FROM sites WHERE site_id=?",
                (facility["site_id"],)).fetchone()["organization_id"]
            if actor.organization_id != operating_org and actor.role != "admin":
                raise PermissionDenied("只有设施运营方可以登记技术确认")
            if confirmed_by_organization == operating_org:
                raise ValidationError("技术确认必须来自相互独立的外部机构，不能是运营方自身")
            replayed = self._replay_receipt(
                connection, request_id=request_id, action="technical_confirmation",
                payload=payload)
            if replayed is not None:
                return replayed
            pending = connection.execute(
                "SELECT * FROM dispositions WHERE incident_id=? AND facility_id=? AND stage='reopen' "
                "AND status='pending_confirmation' ORDER BY ordinal DESC LIMIT 1",
                (incident_id, facility_id)).fetchone()
            if pending is None:
                raise ConflictError("没有等待技术确认的开放申请")
            existing = connection.execute(
                "SELECT channel, confirmed_by, confirmed_by_organization FROM technical_confirmations "
                "WHERE disposition_id=?", (pending["disposition_id"],)).fetchall()
            for row in existing:
                if row["channel"] == channel:
                    raise ConflictError("技术确认渠道必须相互独立")
                if row["confirmed_by"] == confirmed_by:
                    raise ConflictError("技术确认人不能重复")
                if row["confirmed_by_organization"] == confirmed_by_organization:
                    raise ConflictError("技术确认机构必须相互独立")
            confirmation_id = uuid.uuid4().hex
            now = self._now()
            required = OPEN_CONFIRMATIONS_REQUIRED[facility["risk_level"]]

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO technical_confirmations(confirmation_id,disposition_id,incident_id,"
                    "facility_id,channel,result,opinion,evidence_ref,confirmed_by,"
                    "confirmed_by_organization,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (confirmation_id, pending["disposition_id"], incident_id, facility_id, channel,
                     result, opinion, evidence_ref, confirmed_by, confirmed_by_organization, now),
                )
                approved = connection.execute(
                    "SELECT COUNT(*) AS count FROM technical_confirmations "
                    "WHERE disposition_id=? AND result='approved'",
                    (pending["disposition_id"],)).fetchone()["count"]
                effective = False
                if result == "rejected":
                    connection.execute(
                        "UPDATE dispositions SET status='cancelled' WHERE disposition_id=?",
                        (pending["disposition_id"],))
                elif approved >= required:
                    connection.execute(
                        "UPDATE dispositions SET status='effective' WHERE disposition_id=?",
                        (pending["disposition_id"],))
                    effective = True
                append_event(connection, actor_id=actor_id,
                             action="confirmation.recorded",
                             resource_type="technical_confirmation", resource_id=confirmation_id,
                             detail={"disposition_id": pending["disposition_id"],
                                     "incident_id": incident_id, "facility_id": facility_id,
                                     "channel": channel, "result": result,
                                     "risk_level": facility["risk_level"],
                                     "approved_count": approved, "required": required,
                                     "reopen_effective": effective}, occurred_at=now)
                return "technical_confirmation", confirmation_id, {
                    "confirmation_id": confirmation_id, "result": result,
                    "approved_count": approved, "required": required,
                    "reopen_effective": effective}

            return self._idempotent(connection, request_id=request_id,
                                    action="technical_confirmation", payload=payload, create=create)

    def close_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                       summary: str = "") -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "summary": summary}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            incident_id = self._identifier(incident_id, "incident_id")
            replayed = self._replay_receipt(connection, request_id=request_id,
                                            action="close_incident", payload=payload)
            if replayed is not None:
                return replayed
            incident = connection.execute("SELECT * FROM incidents WHERE incident_id=?",
                                          (incident_id,)).fetchone()
            if incident is None:
                raise NotFoundError("事件不存在")
            if incident["status"] != "open":
                raise ConflictError("事件已经关闭")
            pending_reviews = connection.execute(
                "SELECT COUNT(*) AS count FROM disposition_reviews r "
                "JOIN dispositions d ON d.disposition_id=r.disposition_id "
                "WHERE d.incident_id=? AND r.required=1 AND r.resolved=0",
                (incident_id,)).fetchone()["count"]
            if pending_reviews:
                raise ConflictError("仍有校准失效导致的未决复审，不能关闭事件")
            primaries = connection.execute(
                "SELECT facility_id FROM incident_facilities WHERE incident_id=? AND role='primary'",
                (incident_id,)).fetchall()
            for row in primaries:
                reopened = connection.execute(
                    "SELECT 1 FROM dispositions WHERE incident_id=? AND facility_id=? "
                    "AND stage='reopen' AND status='effective' LIMIT 1",
                    (incident_id, row["facility_id"])).fetchone()
                if reopened is None:
                    raise ConflictError("所有直接受影响设施完成开放后才能关闭事件")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE incidents SET status='closed', closed_at=?, summary=? WHERE incident_id=?",
                    (now, summary or incident["summary"], incident_id))
                append_event(connection, actor_id=actor_id, action="incident.closed",
                             resource_type="incident", resource_id=incident_id,
                             detail={"summary": summary}, occurred_at=now)
                return "incident", incident_id, {"incident_id": incident_id, "status": "closed"}

            return self._idempotent(connection, request_id=request_id,
                                    action="close_incident", payload=payload, create=create)

    # ---------- 查询 ----------

    def get_facility(self, facility_id: str) -> Facility:
        row = self.database.connection.execute(
            "SELECT * FROM facilities WHERE facility_id=?", (facility_id,)).fetchone()
        if row is None:
            raise NotFoundError("设施不存在")
        return Facility(row["facility_id"], row["site_id"], row["facility_type"], row["name"],
                        row["kilometrage"], row["risk_level"], json.loads(row["payload_json"]),
                        bool(row["active"]), row["version"])

    def list_facilities(self, site_id: str | None = None) -> list[Facility]:
        query = "SELECT * FROM facilities WHERE active=1"
        params: list[Any] = []
        if site_id:
            query += " AND site_id=?"
            params.append(site_id)
        query += " ORDER BY facility_id"
        return [Facility(row["facility_id"], row["site_id"], row["facility_type"], row["name"],
                         row["kilometrage"], row["risk_level"], json.loads(row["payload_json"]),
                         bool(row["active"]), row["version"])
                for row in self.database.connection.execute(query, params)]

    def list_sensors(self, facility_id: str) -> list[Sensor]:
        rows = self.database.connection.execute(
            "SELECT * FROM sensors WHERE facility_id=? ORDER BY sensor_id", (facility_id,))
        return [Sensor(row["sensor_id"], row["facility_id"], row["metric"], row["unit"],
                       json.loads(row["payload_json"]), bool(row["active"]), row["version"])
                for row in rows]

    def list_observations(self, facility_id: str) -> list[Observation]:
        rows = self.database.connection.execute(
            "SELECT * FROM observations WHERE facility_id=? ORDER BY observed_at, observation_id",
            (facility_id,))
        return [self._observation_view(row) for row in rows]

    def get_incident(self, incident_id: str) -> IncidentView:
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM incidents WHERE incident_id=?",
                                     (incident_id,)).fetchone()
            if row is None:
                raise NotFoundError("事件不存在")
            return self._incident_view(connection, row)

    def list_open_incidents(self, site_id: str | None = None) -> list[IncidentView]:
        query = "SELECT * FROM incidents WHERE status='open'"
        params: list[Any] = []
        if site_id:
            query += " AND site_id=?"
            params.append(site_id)
        query += " ORDER BY opened_at, incident_id"
        with self.database.transaction() as connection:
            return [self._incident_view(connection, row)
                    for row in connection.execute(query, params)]

    def get_disposition(self, disposition_id: str) -> DispositionView:
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM dispositions WHERE disposition_id=?",
                                     (disposition_id,)).fetchone()
            if row is None:
                raise NotFoundError("处置记录不存在")
            return self._disposition_view(connection, row)

    def decision_basis(self, disposition_id: str) -> dict[str, Any]:
        row = self.database.connection.execute(
            "SELECT b.*, d.stage, d.facility_id, d.incident_id FROM incident_basis b "
            "JOIN dispositions d ON d.basis_id=b.basis_id WHERE d.disposition_id=?",
            (disposition_id,)).fetchone()
        if row is None:
            raise NotFoundError("决策依据不存在")
        snapshot = json.loads(row["snapshot_json"])
        return {"basis_id": row["basis_id"], "incident_id": row["incident_id"],
                "facility_id": row["facility_id"], "stage": row["stage"], "kind": row["kind"],
                "rule_version_id": row["rule_version_id"], "plan_id": row["plan_id"],
                "observation_ids": json.loads(row["observation_ids_json"]),
                "snapshot": snapshot, "created_at": row["created_at"]}

    def timeline(self, incident_id: str) -> dict[str, Any]:
        """按时间重放事件从首个信号到恢复通行的完整时间线。"""

        with self.database.transaction() as connection:
            incident = connection.execute("SELECT * FROM incidents WHERE incident_id=?",
                                          (incident_id,)).fetchone()
            if incident is None:
                raise NotFoundError("事件不存在")
            items: list[dict[str, Any]] = []
            signal_rows = connection.execute(
                "SELECT o.* FROM observations o JOIN incident_signals s "
                "ON s.observation_id=o.observation_id WHERE s.incident_id=? "
                "GROUP BY o.observation_id ORDER BY o.observed_at",
                (incident_id,)).fetchall()
            for row in signal_rows:
                top_match = connection.execute(
                    "SELECT * FROM incident_signals WHERE incident_id=? AND observation_id=? "
                    "ORDER BY CASE matched_level WHEN 'close' THEN 3 "
                    "WHEN 'restrict' THEN 2 ELSE 1 END DESC, weight DESC LIMIT 1",
                    (incident_id, row["observation_id"])).fetchone()
                evaluation = json.loads(top_match["evaluation_json"])
                items.append({
                    "at": row["observed_at"], "kind": "signal",
                    "observation_id": row["observation_id"], "facility_id": row["facility_id"],
                    "sensor_id": row["sensor_id"],
                    "source": row["source"], "metric": row["metric"], "value": row["value"],
                    "matched_level": top_match["matched_level"],
                    "calibration_status": top_match["calibration_status"],
                    "rule_id": evaluation.get("rule_id"),
                    "threshold": evaluation.get("threshold"),
                    "operator": evaluation.get("operator"),
                    "quality": row["quality"],
                })
            for row in connection.execute(
                    "SELECT d.*, rv.version AS rule_version, pv.version AS plan_version "
                    "FROM dispositions d LEFT JOIN rule_versions rv ON rv.rule_version_id=d.rule_version_id "
                    "LEFT JOIN plan_versions pv ON pv.plan_id=d.plan_id "
                    "WHERE d.incident_id=? ORDER BY d.decided_at, d.ordinal", (incident_id,)):
                items.append({
                    "at": row["decided_at"], "kind": "disposition",
                    "disposition_id": row["disposition_id"], "facility_id": row["facility_id"],
                    "stage": row["stage"], "stage_label": STAGE_LABELS[row["stage"]],
                    "ordinal": row["ordinal"], "status": row["status"], "reason": row["reason"],
                    "rule_version": row["rule_version"], "plan_version": row["plan_version"],
                    "basis_id": row["basis_id"], "confidence": row["confidence"],
                    "decided_by": row["decided_by"],
                })
            for row in connection.execute(
                    "SELECT * FROM technical_confirmations WHERE incident_id=? ORDER BY created_at",
                    (incident_id,)):
                items.append({
                    "at": row["created_at"], "kind": "confirmation",
                    "facility_id": row["facility_id"], "channel": row["channel"],
                    "result": row["result"], "opinion": row["opinion"],
                    "evidence_ref": row["evidence_ref"], "confirmed_by": row["confirmed_by"],
                    "confirmed_by_organization": row["confirmed_by_organization"],
                })
            for row in connection.execute(
                    "SELECT r.*, d.facility_id, d.stage FROM disposition_reviews r "
                    "JOIN dispositions d ON d.disposition_id=r.disposition_id "
                    "WHERE d.incident_id=? ORDER BY r.created_at", (incident_id,)):
                items.append({
                    "at": row["created_at"], "kind": "review_required" if not row["resolved"]
                    else "review_resolved", "facility_id": row["facility_id"],
                    "stage": row["stage"], "reason": row["reason"],
                    "resolved_at": row["resolved_at"]})
            kind_rank = {"signal": 0, "disposition": 1, "confirmation": 2,
                         "review_required": 3, "review_resolved": 4}
            items.sort(key=lambda item: (
                parse_ts(item["at"]), kind_rank.get(item["kind"], 9)))
            return {"incident_id": incident_id, "status": incident["status"],
                    "severity": incident["severity"], "confidence": incident["confidence"],
                    "opened_at": incident["opened_at"], "closed_at": incident["closed_at"],
                    "hypothesis": incident["hypothesis"], "items": items}

    def review_queue(self) -> list[dict[str, Any]]:
        """识别校准失效（含证书到期）后需要重新审查的未结事件。"""

        queued: dict[str, dict[str, Any]] = {}
        connection = self.database.connection
        rows = connection.execute(
            "SELECT DISTINCT i.* FROM incidents i JOIN dispositions d ON d.incident_id=i.incident_id "
            "JOIN disposition_reviews r ON r.disposition_id=d.disposition_id "
            "WHERE i.status='open' AND r.required=1 AND r.resolved=0"
        ).fetchall()
        for incident in rows:
            entry = queued.setdefault(incident["incident_id"], {
                "incident_id": incident["incident_id"], "reasons": [], "dispositions": []})
        review_rows = connection.execute(
            "SELECT r.*, d.incident_id, d.facility_id, d.stage FROM disposition_reviews r "
            "JOIN dispositions d ON d.disposition_id=r.disposition_id "
            "JOIN incidents i ON i.incident_id=d.incident_id "
            "WHERE i.status='open' AND r.required=1 AND r.resolved=0"
        ).fetchall()
        for row in review_rows:
            queued[row["incident_id"]]["reasons"].append(row["reason"])
            queued[row["incident_id"]]["dispositions"].append({
                "disposition_id": row["disposition_id"], "facility_id": row["facility_id"],
                "stage": row["stage"], "created_at": row["created_at"]})
        # 动态识别：信号当时按有效校准采纳，但校准证书现在已经到期或失效。
        incident_sensors = connection.execute(
            "SELECT DISTINCT i.incident_id AS incident_id, o.sensor_id AS sensor_id, "
            "MAX(o.observed_at) AS last_signal_at "
            "FROM incidents i JOIN incident_signals s ON s.incident_id=i.incident_id "
            "JOIN observations o ON o.observation_id=s.observation_id "
            "WHERE i.status='open' AND s.source='sensor' AND o.sensor_id IS NOT NULL "
            "GROUP BY i.incident_id, o.sensor_id").fetchall()
        for row in incident_sensors:
            incident_id = row["incident_id"]
            sensor_id = row["sensor_id"]
            status, _cal = calibration_at(connection, sensor_id, self.clock.now())
            if status not in ("failed", "expired"):
                continue
            # 复检生效且晚于该传感器最后信号时，视为已人工复核覆盖。
            recheck = connection.execute(
                "SELECT MAX(d.decided_at) AS last_recheck FROM dispositions d "
                "WHERE d.incident_id=? AND d.stage='recheck' AND d.status='effective'",
                (incident_id,)).fetchone()
            if recheck["last_recheck"] and \
                    parse_ts(recheck["last_recheck"]) >= parse_ts(row["last_signal_at"]):
                continue
            entry = queued.setdefault(incident_id, {
                "incident_id": incident_id, "reasons": [], "dispositions": []})
            reason = f"传感器 {sensor_id} 校准证书当前状态为 {status}"
            if reason not in entry["reasons"]:
                entry["reasons"].append(reason)
        return [queued[key] for key in sorted(queued) if queued[key]["reasons"]]

    # ---------- 内部辅助 ----------

    def _normalize_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(rule, dict):
            raise ValidationError("每条规则必须是对象")
        rule_id = self._text(rule.get("rule_id", ""), "rule_id", 60)
        metric = rule.get("metric")
        source = rule.get("source")
        if not metric and not source:
            raise ValidationError("规则至少要指定 metric 或 source")
        facility_type = rule.get("facility_type")
        if facility_type and facility_type not in FACILITY_TYPES:
            raise ValidationError("规则限定的设施类型无效")
        operator = rule.get("operator", ">=")
        if operator not in (">=", "<="):
            raise ValidationError("比较算子只能是 >= 或 <=")
        weight = rule.get("weight", 0.5)
        if not isinstance(weight, (int, float)) or not 0 < weight <= 1:
            raise ValidationError("规则权重必须在 0 到 1 之间")
        normalized: dict[str, Any] = {"rule_id": rule_id, "weight": float(weight),
                                      "operator": operator}
        if metric:
            normalized["metric"] = self._text(metric, "metric", 60)
        if source:
            if source not in OBSERVATION_SOURCES:
                raise ValidationError("规则来源必须是 sensor 或 inspector")
            normalized["source"] = source
        if facility_type:
            normalized["facility_type"] = facility_type
        thresholds = rule.get("thresholds")
        report_levels = rule.get("report_levels")
        if thresholds is not None:
            if not isinstance(thresholds, dict) or not thresholds:
                raise ValidationError("阈值表必须是非空对象")
            clean: dict[str, float] = {}
            for level, bound in thresholds.items():
                if level not in ("heighten", "restrict", "close"):
                    raise ValidationError("阈值等级必须是 heighten/restrict/close")
                if not isinstance(bound, (int, float)):
                    raise ValidationError("阈值必须是数值")
                clean[level] = float(bound)
            normalized["thresholds"] = clean
        elif report_levels is not None:
            if not isinstance(report_levels, dict) or not report_levels:
                raise ValidationError("巡检报告等级表必须是非空对象")
            clean_reports: dict[str, list[str]] = {}
            for level, keywords in report_levels.items():
                if level not in ("heighten", "restrict", "close"):
                    raise ValidationError("报告等级必须是 heighten/restrict/close")
                if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
                    raise ValidationError("报告关键词必须是字符串列表")
                clean_reports[level] = keywords
            normalized["report_levels"] = clean_reports
        else:
            raise ValidationError("规则必须提供 thresholds 或 report_levels")
        return normalized

    def _require_same_organization(self, connection, actor, target_id: str,
                                   table: str = "site", strict: bool = True) -> None:
        if actor.role == "admin" and not strict:
            return
        if table == "site":
            org = connection.execute("SELECT organization_id FROM sites WHERE site_id=?",
                                     (target_id,)).fetchone()
        else:
            row = connection.execute("SELECT site_id FROM facilities WHERE facility_id=?",
                                     (target_id,)).fetchone()
            org = connection.execute("SELECT organization_id FROM sites WHERE site_id=?",
                                     (row["site_id"],)).fetchone() if row else None
        if org is None:
            raise NotFoundError("所属场所不存在")
        if actor.organization_id != org["organization_id"] and actor.role != "admin":
            raise PermissionDenied("不能操作其他组织的设施")

    def _site_of(self, connection, facility_id: str) -> str:
        return connection.execute("SELECT site_id FROM facilities WHERE facility_id=?",
                                  (facility_id,)).fetchone()["site_id"]

    def _incident_of(self, connection, observation_id: str) -> str | None:
        row = connection.execute(
            "SELECT incident_id FROM incident_signals WHERE observation_id=? LIMIT 1",
            (observation_id,)).fetchone()
        return row["incident_id"] if row else None

    def _last_disposition_at(self, connection, incident_id: str) -> str:
        row = connection.execute(
            "SELECT MAX(decided_at) AS last_at FROM dispositions WHERE incident_id=?",
            (incident_id,)).fetchone()
        return row["last_at"] or ""

    def _signal_rows(self, connection, incident_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT observation_id, matched_level, weight, calibration_status, source, qualified "
            "FROM incident_signals WHERE incident_id=?", (incident_id,)).fetchall()
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = grouped.get(row["observation_id"])
            if entry is None:
                grouped[row["observation_id"]] = {
                    "observation_id": row["observation_id"],
                    "matched_level": row["matched_level"], "weight": row["weight"],
                    "calibration_status": row["calibration_status"], "source": row["source"],
                    "qualified": bool(row["qualified"])}
                continue
            if STAGE_ORDINALS[row["matched_level"]] > STAGE_ORDINALS[entry["matched_level"]]:
                entry["matched_level"] = row["matched_level"]
                entry["weight"] = row["weight"]
            elif row["matched_level"] == entry["matched_level"]:
                entry["weight"] = max(entry["weight"], row["weight"])
            entry["qualified"] = entry["qualified"] and bool(row["qualified"])
        return list(grouped.values())

    def _build_basis(self, connection, *, incident, facility_id: str, stage: str,
                     reason: str) -> dict[str, Any]:
        # 关键：决策依据引用决策时刻生效的规则与预案版本，并整体冻结快照。
        rule_row = active_version_at(connection, "rule_versions", self._now())
        if rule_row is None:
            raise ConflictError("当前没有生效的阈值规则版本")
        plan_row = active_plan(connection, facility_id, self._now())
        plan_id = plan_row["plan_id"] if plan_row else None
        signal_rows = self._signal_rows(connection, incident["incident_id"])
        severity, confidence, _ = synthesize(signal_rows)
        primary_ids = {row["facility_id"] for row in connection.execute(
            "SELECT facility_id FROM incident_facilities WHERE incident_id=? AND role='primary'",
            (incident["incident_id"],))}
        impact = impact_scope(connection, primary_ids, stage)
        observation_ids = sorted({row["observation_id"] for row in connection.execute(
            "SELECT observation_id FROM incident_signals WHERE incident_id=?",
            (incident["incident_id"],))})
        evidence = []
        for observation_id in observation_ids:
            obs = connection.execute("SELECT * FROM observations WHERE observation_id=?",
                                     (observation_id,)).fetchone()
            sig = connection.execute(
                "SELECT * FROM incident_signals WHERE incident_id=? AND observation_id=? LIMIT 1",
                (incident["incident_id"], observation_id)).fetchone()
            evidence.append({
                "observation_id": observation_id, "facility_id": obs["facility_id"],
                "source": obs["source"], "metric": obs["metric"], "value": obs["value"],
                "observed_at": obs["observed_at"], "matched_level": sig["matched_level"],
                "calibration_status": sig["calibration_status"],
                "evaluation": json.loads(sig["evaluation_json"]),
                "payload": json.loads(obs["payload_json"]),
            })
        calibration_state = {}
        for obs_id in observation_ids:
            obs = connection.execute(
                "SELECT sensor_id, observed_at FROM observations WHERE observation_id=?",
                (obs_id,)).fetchone()
            if obs["sensor_id"]:
                status, cal = calibration_at(connection, obs["sensor_id"],
                                             parse_ts(obs["observed_at"]))
                calibration_state[obs["sensor_id"]] = {
                    "status_at_observation": status,
                    "calibration_id": cal["calibration_id"] if cal else None}
        snapshot = {
            "stage": stage, "reason": reason,
            "rule_version": rule_row["version"],
            "rules": json.loads(rule_row["rules_json"]),
            "plan_version": plan_row["version"] if plan_row else None,
            "plan_steps": json.loads(plan_row["steps_json"])["steps"] if plan_row else None,
            "incident_severity": severity, "confidence": confidence, "impact": impact,
            "signals": evidence, "calibration": calibration_state,
        }
        return {"basis_id": uuid.uuid4().hex, "rule_version_id": rule_row["rule_version_id"],
                "plan_id": plan_id, "observation_ids": observation_ids, "snapshot": snapshot}

    def _flag_reviews_for_sensor(self, connection, sensor_id: str, *, reason: str,
                                 now: str) -> list[str]:
        flagged: list[str] = []
        rows = connection.execute(
            "SELECT DISTINCT d.disposition_id, d.incident_id FROM dispositions d "
            "JOIN incidents i ON i.incident_id=d.incident_id "
            "JOIN incident_signals s ON s.incident_id=d.incident_id "
            "JOIN observations o ON o.observation_id=s.observation_id "
            "WHERE i.status='open' AND o.sensor_id=? AND d.status IN ('effective','pending_confirmation')",
            (sensor_id,)).fetchall()
        for row in rows:
            exists = connection.execute(
                "SELECT 1 FROM disposition_reviews WHERE disposition_id=? AND required=1 "
                "AND resolved=0", (row["disposition_id"],)).fetchone()
            if exists:
                continue
            connection.execute(
                "INSERT INTO disposition_reviews(review_id,disposition_id,required,reason,"
                "resolved,created_at) VALUES(?,?,1,?,0,?)",
                (uuid.uuid4().hex, row["disposition_id"], reason, now))
            if row["incident_id"] not in flagged:
                flagged.append(row["incident_id"])
        return flagged

    def _resolve_reviews(self, connection, disposition_id: str, incident_id: str,
                         facility_id: str, now: str) -> None:
        connection.execute(
            "UPDATE disposition_reviews SET resolved=1, resolved_at=? WHERE required=1 "
            "AND resolved=0 AND disposition_id IN ("
            "SELECT disposition_id FROM dispositions WHERE incident_id=? AND facility_id=?)",
            (now, incident_id, facility_id))

    def _observation_view(self, row) -> Observation:
        return Observation(row["observation_id"], row["facility_id"], row["sensor_id"],
                           row["source"], row["metric"], row["value"], row["quality"],
                           row["observed_at"], row["received_at"],
                           json.loads(row["payload_json"]))

    def _incident_view(self, connection, row) -> IncidentView:
        signals = []
        seen: set[str] = set()
        for sig_row in connection.execute(
                "SELECT s.*, o.facility_id, o.metric, o.value, o.quality, o.observed_at, "
                "o.received_at, o.payload_json, o.sensor_id AS obs_sensor_id "
                "FROM incident_signals s "
                "JOIN observations o ON o.observation_id=s.observation_id "
                "WHERE s.incident_id=? ORDER BY o.observed_at", (row["incident_id"],)):
            if sig_row["observation_id"] in seen:
                continue
            seen.add(sig_row["observation_id"])
            match_rows = connection.execute(
                "SELECT * FROM incident_signals WHERE incident_id=? AND observation_id=?",
                (row["incident_id"], sig_row["observation_id"])).fetchall()
            signals.append(SignalView(
                sig_row["observation_id"], sig_row["facility_id"], sig_row["obs_sensor_id"],
                sig_row["source"],
                sig_row["metric"], sig_row["value"], sig_row["quality"], sig_row["observed_at"],
                sig_row["calibration_status"],
                tuple({"rule_id": m["rule_id"], "matched_level": m["matched_level"],
                       "weight": m["weight"], "qualified": bool(m["qualified"]),
                       **json.loads(m["evaluation_json"])} for m in match_rows)))
        facilities = tuple(dict(f) for f in connection.execute(
            "SELECT facility_id, role FROM incident_facilities WHERE incident_id=? "
            "ORDER BY role DESC, facility_id", (row["incident_id"],)))
        dispositions = tuple(self._disposition_view(connection, d).__dict__ for d in
                             connection.execute(
                                 "SELECT * FROM dispositions WHERE incident_id=? "
                                 "ORDER BY ordinal, decided_at", (row["incident_id"],)))
        pending = tuple(dict(r) for r in connection.execute(
            "SELECT r.review_id, r.reason, d.facility_id, d.stage FROM disposition_reviews r "
            "JOIN dispositions d ON d.disposition_id=r.disposition_id "
            "WHERE d.incident_id=? AND r.required=1 AND r.resolved=0", (row["incident_id"],)))
        return IncidentView(row["incident_id"], row["site_id"], row["status"], row["severity"],
                            row["confidence"], row["rule_version_id"], row["correlation_key"],
                            row["hypothesis"], json.loads(row["impact_json"]), row["summary"],
                            row["opened_at"], row["closed_at"], tuple(signals), facilities,
                            dispositions, pending)

    def _disposition_view(self, connection, row) -> DispositionView:
        confirmations = tuple(dict(c) for c in connection.execute(
            "SELECT confirmation_id,channel,result,opinion,evidence_ref,confirmed_by,"
            "confirmed_by_organization,created_at FROM technical_confirmations "
            "WHERE disposition_id=? ORDER BY created_at", (row["disposition_id"],)))
        review_row = connection.execute(
            "SELECT * FROM disposition_reviews WHERE disposition_id=? AND required=1 "
            "ORDER BY created_at DESC LIMIT 1", (row["disposition_id"],)).fetchone()
        review = None
        if review_row:
            review = {"reason": review_row["reason"], "resolved": bool(review_row["resolved"]),
                      "resolved_at": review_row["resolved_at"]}
        return DispositionView(row["disposition_id"], row["incident_id"], row["facility_id"],
                               row["stage"], row["ordinal"], row["status"], row["reason"],
                               row["rule_version_id"], row["plan_id"], row["basis_id"],
                               row["confidence"], json.loads(row["impact_json"]),
                               row["decided_by"], row["decided_at"], confirmations, review)
