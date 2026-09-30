"""重点路桥风险处置领域服务。

在基础服务之上实现：

- 设施拓扑、传感器与人工观测、校准状态、阈值规则版本、应急预案版本登记；
- 信号评估与归并：同一场灾害（episode 或拓扑相邻时间窗）内的桥梁位移、
  边坡含水、巡检报告归并为一个可追踪事件，并给出置信度与影响范围；
- 处置流水线：升级 → 限行 → 封闭 → 抢修 → 复检 → 开放，严格按角色与
  顺序推进，任何步骤都不能倒退；
- 重复/迟到观测不产生新信号、不倒退已发布状态；
- 规则与预案在首次生效决策时冻结快照，换版不会静默改变既有决定；
- 开放高风险设施需要两名来自相互独立机构的技术确认，且确认人与开放人分离；
- 校准失效会把引用该传感器的未结事件标记为必须重新审查。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .audit import append_event, canonical_json, digest
from .errors import ConflictError, DomainError, NotFoundError, PermissionDenied, ValidationError
from .risk_storage import (
    ACTION_ROLES,
    CORRELATION_WINDOW_HOURS,
    DEFAULT_OPEN_CONFIRMATIONS,
    DEFAULT_RESPONSE_LEVELS,
    LEVEL_INDEX,
    STATE_INDEX,
    TRANSITIONS,
    COMPARATORS,
)
from .service import DomainService

FACILITY_TYPES = frozenset({"bridge", "slope", "tunnel", "road", "culvert"})
CRITICALITIES = frozenset({"high", "normal"})


class RiskService(DomainService):
    """实现重点路桥风险登记、归并、处置与复核规则。"""

    # ------------------------------------------------------------------ 登记

    def register_facility(self, *, request_id: str, actor_id: str, facility_id: str,
                          site_id: str, facility_type: str, name: str,
                          criticality: str = "normal", payload: dict[str, Any] | None = None):
        payload = payload or {}
        body = {"actor_id": actor_id, "facility_id": facility_id, "site_id": site_id,
                "facility_type": facility_type, "name": name, "criticality": criticality,
                "payload": payload}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator")
            site = conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if site is None:
                raise NotFoundError("场所不存在")
            if actor.organization_id != site["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能在其他组织的场所登记设施")
            facility_id = self._identifier(facility_id, "facility_id")
            name = self._text(name, "name")
            if facility_type not in FACILITY_TYPES:
                raise ValidationError("facility_type 不在允许范围内")
            if criticality not in CRITICALITIES:
                raise ValidationError("criticality 必须是 high 或 normal")
            if not isinstance(payload, dict):
                raise ValidationError("payload 必须是对象")

            def create():
                try:
                    conn.execute(
                        "INSERT INTO risk_facilities(facility_id,site_id,organization_id,facility_type,"
                        "name,criticality,control_status,payload_json,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?, 'normal', ?,?,?)",
                        (facility_id, site_id, site["organization_id"], facility_type, name,
                         criticality, canonical_json(payload), actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("设施编号已经存在") from exc
                append_event(conn, actor_id=actor_id, action="risk.facility_registered",
                             resource_type="risk_facility", resource_id=facility_id,
                             detail={"site_id": site_id, "facility_type": facility_type,
                                     "name": name, "criticality": criticality},
                             occurred_at=self._now())
                return "risk_facility", facility_id, {"facility_id": facility_id}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_register_facility", payload=body, create=create)

    def register_facility_link(self, *, request_id: str, actor_id: str,
                               upstream_id: str, downstream_id: str, relation: str):
        body = {"actor_id": actor_id, "upstream_id": upstream_id,
                "downstream_id": downstream_id, "relation": relation}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator")
            upstream_id = self._identifier(upstream_id, "upstream_id")
            downstream_id = self._identifier(downstream_id, "downstream_id")
            relation = self._text(relation, "relation", 40)
            if upstream_id == downstream_id:
                raise ValidationError("设施不能与自己建立拓扑关系")
            if not conn.execute("SELECT 1 FROM risk_facilities WHERE facility_id=?",
                                (upstream_id,)).fetchone():
                raise NotFoundError("上游设施不存在")
            if not conn.execute("SELECT 1 FROM risk_facilities WHERE facility_id=?",
                                (downstream_id,)).fetchone():
                raise NotFoundError("下游设施不存在")

            def create():
                link_id = uuid.uuid4().hex
                try:
                    conn.execute(
                        "INSERT INTO risk_facility_links(link_id,upstream_id,downstream_id,relation,"
                        "created_by,created_at) VALUES(?,?,?,?,?,?)",
                        (link_id, upstream_id, downstream_id, relation, actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("拓扑关系已经存在") from exc
                append_event(conn, actor_id=actor_id, action="risk.facility_link_registered",
                             resource_type="risk_facility_link", resource_id=link_id,
                             detail={"upstream_id": upstream_id, "downstream_id": downstream_id,
                                     "relation": relation}, occurred_at=self._now())
                return "risk_facility_link", link_id, {"link_id": link_id}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_register_facility_link", payload=body, create=create)

    def register_sensor(self, *, request_id: str, actor_id: str, sensor_id: str,
                        facility_id: str, metric: str, unit: str = "",
                        calibrated_at: str | None = None):
        body = {"actor_id": actor_id, "sensor_id": sensor_id, "facility_id": facility_id,
                "metric": metric, "unit": unit, "calibrated_at": calibrated_at}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator")
            sensor_id = self._identifier(sensor_id, "sensor_id")
            facility_id = self._identifier(facility_id, "facility_id")
            metric = self._text(metric, "metric", 80)
            unit = str(unit or "")[:40]
            calibrated_at = calibrated_at or self._now()
            self._parse_ts(calibrated_at, "calibrated_at")
            if not conn.execute("SELECT 1 FROM risk_facilities WHERE facility_id=?",
                                (facility_id,)).fetchone():
                raise NotFoundError("设施不存在")

            def create():
                calibration_id = uuid.uuid4().hex
                try:
                    conn.execute(
                        "INSERT INTO risk_sensors(sensor_id,facility_id,metric,unit,calibration_status,"
                        "calibrated_at,created_by,created_at) VALUES(?,?,?,?, 'valid', ?,?,?)",
                        (sensor_id, facility_id, metric, unit, calibrated_at, actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("传感器编号已经存在") from exc
                conn.execute(
                    "INSERT INTO risk_calibrations(calibration_id,sensor_id,status,effective_at,note,"
                    "recorded_by,created_at) VALUES(?,?,'valid',?,'初始登记',?,?)",
                    (calibration_id, sensor_id, calibrated_at, actor_id, self._now()),
                )
                append_event(conn, actor_id=actor_id, action="risk.sensor_registered",
                             resource_type="risk_sensor", resource_id=sensor_id,
                             detail={"facility_id": facility_id, "metric": metric,
                                     "calibrated_at": calibrated_at}, occurred_at=self._now())
                return "risk_sensor", sensor_id, {"sensor_id": sensor_id}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_register_sensor", payload=body, create=create)

    def record_calibration(self, *, request_id: str, actor_id: str, sensor_id: str,
                           status: str, effective_at: str | None = None, note: str = ""):
        """登记校准结论；失效/恢复都会重新评估相关未结事件。"""

        body = {"actor_id": actor_id, "sensor_id": sensor_id, "status": status,
                "effective_at": effective_at, "note": note}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "reviewer")
            sensor = conn.execute("SELECT * FROM risk_sensors WHERE sensor_id=?",
                                  (sensor_id,)).fetchone()
            if sensor is None:
                raise NotFoundError("传感器不存在")
            if status not in ("valid", "failed"):
                raise ValidationError("校准状态必须是 valid 或 failed")
            effective_at = effective_at or self._now()
            self._parse_ts(effective_at, "effective_at")

            def create():
                calibration_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO risk_calibrations(calibration_id,sensor_id,status,effective_at,note,"
                    "recorded_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (calibration_id, sensor_id, status, effective_at, note[:200], actor_id, self._now()),
                )
                conn.execute("UPDATE risk_sensors SET calibration_status=?, calibrated_at=? WHERE sensor_id=?",
                             (status, effective_at, sensor_id))
                append_event(conn, actor_id=actor_id,
                             action="risk.calibration_failed" if status == "failed"
                             else "risk.calibration_restored",
                             resource_type="risk_sensor", resource_id=sensor_id,
                             detail={"effective_at": effective_at, "note": note[:200]},
                             occurred_at=self._now())
                affected = []
                # 校准失效：引用该传感器的未结事件一律转人工复核；校准恢复不自动
                # 撤销标记，必须由复核人凭证据闭环（review_event_after_calibration）。
                if status == "failed":
                    event_rows = conn.execute(
                        "SELECT DISTINCT e.event_id FROM risk_events e JOIN risk_event_signals es "
                        "ON e.event_id=es.event_id JOIN risk_signals s ON es.signal_id=s.signal_id "
                        "WHERE s.sensor_id=? AND e.state!='opened' AND e.review_required=0",
                        (sensor_id,)
                    ).fetchall()
                    for row in event_rows:
                        conn.execute("UPDATE risk_events SET review_required=1, updated_at=? WHERE event_id=?",
                                     (self._now(), row["event_id"]))
                        affected.append({"event_id": row["event_id"], "review_required": 1})
                        append_event(conn, actor_id=actor_id, action="risk.review_required",
                                     resource_type="risk_event", resource_id=row["event_id"],
                                     detail={"sensor_id": sensor_id, "calibration_status": status},
                                     occurred_at=self._now())
                return "risk_calibration", calibration_id, {
                    "calibration_id": calibration_id, "status": status, "events": affected}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_record_calibration", payload=body, create=create)

    # ------------------------------------------------------------- 规则/预案

    def register_rule_version(self, *, request_id: str, actor_id: str,
                              rule_version_id: str, rules: list[dict[str, Any]],
                              activate: bool = False):
        body = {"actor_id": actor_id, "rule_version_id": rule_version_id,
                "rules": rules, "activate": activate}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "reviewer")
            rule_version_id = self._identifier(rule_version_id, "rule_version_id")
            self._validate_rules(rules)
            content_hash = digest(rules)
            existing = conn.execute("SELECT * FROM risk_rule_versions WHERE rule_version_id=?",
                                    (rule_version_id,)).fetchone()
            if existing:
                raise ConflictError("规则版本编号已经存在（规则内容不可修改，请登记新版本）")

            def create():
                status = "active" if activate else "draft"
                if activate:
                    conn.execute("UPDATE risk_rule_versions SET status='superseded' WHERE status='active'")
                conn.execute(
                    "INSERT INTO risk_rule_versions(rule_version_id,status,rules_json,content_hash,"
                    "created_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?)",
                    (rule_version_id, status, canonical_json(rules), content_hash, actor_id,
                     self._now(), self._now() if activate else None),
                )
                append_event(conn, actor_id=actor_id,
                             action="risk.rule_version_activated" if activate
                             else "risk.rule_version_registered",
                             resource_type="risk_rule_version", resource_id=rule_version_id,
                             detail={"content_hash": content_hash, "rule_count": len(rules)},
                             occurred_at=self._now())
                return "risk_rule_version", rule_version_id, {
                    "rule_version_id": rule_version_id, "status": status,
                    "content_hash": content_hash}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_register_rule_version", payload=body, create=create)

    def activate_rule_version(self, *, request_id: str, actor_id: str, rule_version_id: str):
        body = {"actor_id": actor_id, "rule_version_id": rule_version_id}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "reviewer")
            row = conn.execute("SELECT * FROM risk_rule_versions WHERE rule_version_id=?",
                               (rule_version_id,)).fetchone()
            if row is None:
                raise NotFoundError("规则版本不存在")
            if row["status"] == "active":
                raise ConflictError("该版本已经处于激活状态")
            previous = conn.execute(
                "SELECT rule_version_id FROM risk_rule_versions WHERE status='active'"
            ).fetchone()

            def create():
                conn.execute("UPDATE risk_rule_versions SET status='superseded' WHERE status='active'")
                conn.execute(
                    "UPDATE risk_rule_versions SET status='active', activated_at=? WHERE rule_version_id=?",
                    (self._now(), rule_version_id),
                )
                append_event(conn, actor_id=actor_id, action="risk.rule_version_activated",
                             resource_type="risk_rule_version", resource_id=rule_version_id,
                             detail={"previous_version": previous["rule_version_id"] if previous else None,
                                     "content_hash": row["content_hash"]},
                             occurred_at=self._now())
                return "risk_rule_version", rule_version_id, {"rule_version_id": rule_version_id}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_activate_rule_version", payload=body, create=create)

    def register_plan_version(self, *, request_id: str, actor_id: str,
                              plan_version_id: str, scope: dict[str, Any],
                              content: dict[str, Any], activate: bool = False):
        body = {"actor_id": actor_id, "plan_version_id": plan_version_id,
                "scope": scope, "content": content, "activate": activate}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator")
            plan_version_id = self._identifier(plan_version_id, "plan_version_id")
            if not isinstance(scope, dict) or not isinstance(content, dict):
                raise ValidationError("scope 与 content 必须是对象")
            scope.setdefault("facility_ids", [])
            scope.setdefault("facility_types", [])
            if not scope["facility_ids"] and not scope["facility_types"]:
                raise ValidationError("预案适用范围不能为空")
            if conn.execute("SELECT 1 FROM risk_plan_versions WHERE plan_version_id=?",
                            (plan_version_id,)).fetchone():
                raise ConflictError("预案版本编号已经存在（预案内容不可修改，请登记新版本）")
            content_hash = digest({"scope": scope, "content": content})

            def create():
                status = "active" if activate else "draft"
                if activate:
                    conn.execute("UPDATE risk_plan_versions SET status='superseded' WHERE status='active'")
                conn.execute(
                    "INSERT INTO risk_plan_versions(plan_version_id,status,scope_json,content_json,"
                    "content_hash,created_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (plan_version_id, status, canonical_json(scope), canonical_json(content),
                     content_hash, actor_id, self._now(), self._now() if activate else None),
                )
                append_event(conn, actor_id=actor_id,
                             action="risk.plan_version_activated" if activate
                             else "risk.plan_version_registered",
                             resource_type="risk_plan_version", resource_id=plan_version_id,
                             detail={"content_hash": content_hash, "scope": scope},
                             occurred_at=self._now())
                return "risk_plan_version", plan_version_id, {
                    "plan_version_id": plan_version_id, "status": status,
                    "content_hash": content_hash}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_register_plan_version", payload=body, create=create)

    def activate_plan_version(self, *, request_id: str, actor_id: str, plan_version_id: str):
        body = {"actor_id": actor_id, "plan_version_id": plan_version_id}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator")
            row = conn.execute("SELECT * FROM risk_plan_versions WHERE plan_version_id=?",
                               (plan_version_id,)).fetchone()
            if row is None:
                raise NotFoundError("预案版本不存在")
            if row["status"] == "active":
                raise ConflictError("该版本已经处于激活状态")

            def create():
                conn.execute("UPDATE risk_plan_versions SET status='superseded' WHERE status='active'")
                conn.execute(
                    "UPDATE risk_plan_versions SET status='active', activated_at=? WHERE plan_version_id=?",
                    (self._now(), plan_version_id),
                )
                append_event(conn, actor_id=actor_id, action="risk.plan_version_activated",
                             resource_type="risk_plan_version", resource_id=plan_version_id,
                             detail={"content_hash": row["content_hash"]}, occurred_at=self._now())
                return "risk_plan_version", plan_version_id, {"plan_version_id": plan_version_id}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_activate_plan_version", payload=body, create=create)

    # --------------------------------------------------------------- 观测入口

    def ingest_observation(self, *, request_id: str, actor_id: str, facility_id: str,
                           source_kind: str, metric: str, observed_at: str,
                           value: float | int | None = None, text: str = "",
                           reported_level: str | None = None, sensor_id: str | None = None,
                           reporter_id: str | None = None, episode_id: str | None = None,
                           is_reinspection: bool = False, late: bool = False,
                           duplicate: bool = False):
        """登记一次传感器读数或人工观测，并立即完成规则评估与事件归并。

        标记 ``duplicate`` 的观测只留档，不产生信号，不影响任何处置状态；
        ``late`` 观测不能回退已开放的事件，必要时另立新事件。
        """

        body = {"actor_id": actor_id, "facility_id": facility_id, "source_kind": source_kind,
                "metric": metric, "observed_at": observed_at, "value": value, "text": text,
                "reported_level": reported_level, "sensor_id": sensor_id,
                "reporter_id": reporter_id, "episode_id": episode_id,
                "is_reinspection": is_reinspection, "late": late, "duplicate": duplicate}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            facility_id = self._identifier(facility_id, "facility_id")
            facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                    (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            metric = self._text(metric, "metric", 80)
            observed_at = self._normalize_ts(observed_at, "observed_at")
            if source_kind not in ("sensor", "manual"):
                raise ValidationError("source_kind 必须是 sensor 或 manual")
            sensor_row = None
            if source_kind == "sensor":
                if not sensor_id:
                    raise ValidationError("传感器观测必须提供 sensor_id")
                sensor_row = conn.execute("SELECT * FROM risk_sensors WHERE sensor_id=?",
                                          (sensor_id,)).fetchone()
                if sensor_row is None:
                    raise NotFoundError("传感器不存在")
                if sensor_row["facility_id"] != facility_id or sensor_row["metric"] != metric:
                    raise ValidationError("传感器与设施或监测指标不一致")
                if value is None:
                    raise ValidationError("传感器观测必须提供数值 value")
                double_value = float(value)
            else:
                if not reporter_id:
                    raise ValidationError("人工观测必须提供 reporter_id")
                if conn.execute("SELECT 1 FROM actors WHERE actor_id=? AND active=1",
                                (reporter_id,)).fetchone() is None:
                    raise NotFoundError("报告人不存在或已停用")
                double_value = float(value) if value is not None else None
            if reported_level is not None and reported_level not in LEVEL_INDEX:
                raise ValidationError("reported_level 必须是 watch/warning/danger")
            if episode_id is not None:
                episode_id = self._identifier(episode_id, "episode_id")

            def create():
                observation_id = uuid.uuid4().hex
                # 服务端去重：同一设施/来源/指标/观测时刻/读数只留档，不产生信号。
                duplicate_hit = conn.execute(
                    "SELECT observation_id FROM risk_observations WHERE facility_id=? AND metric=? "
                    "AND source_kind=? AND observed_at=? "
                    "AND IFNULL(sensor_id,'')=IFNULL(?,'') "
                    "AND IFNULL(reporter_id,'')=IFNULL(?,'') "
                    "AND IFNULL(double_value,-999999999)=IFNULL(?,-999999999)",
                    (facility_id, metric, source_kind, observed_at, sensor_id, reporter_id,
                     double_value),
                ).fetchone()
                is_duplicate = bool(duplicate) or duplicate_hit is not None
                conn.execute(
                    "INSERT INTO risk_observations(observation_id,facility_id,source_kind,sensor_id,"
                    "reporter_id,episode_id,metric,double_value,text_value,reported_level,"
                    "is_reinspection,late,duplicate,observed_at,received_at,payload_json,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (observation_id, facility_id, source_kind, sensor_id, reporter_id, episode_id,
                     metric, double_value, text[:500], reported_level,
                     1 if is_reinspection else 0, 1 if late else 0, 1 if is_duplicate else 0,
                     observed_at, self._now(), canonical_json(body), actor_id, self._now()),
                )
                append_event(conn, actor_id=actor_id, action="risk.observation_ingested",
                             resource_type="risk_observation", resource_id=observation_id,
                             detail={"facility_id": facility_id, "metric": metric,
                                     "source_kind": source_kind, "duplicate": is_duplicate,
                                     "duplicate_of": duplicate_hit["observation_id"] if duplicate_hit else None,
                                     "late": bool(late), "observed_at": observed_at,
                                     "episode_id": episode_id},
                             occurred_at=self._now())
                response: dict[str, Any] = {
                    "observation_id": observation_id, "duplicate": is_duplicate}
                if not is_duplicate and not is_reinspection:
                    signal = self._build_signal(conn, facility, observation_id, source_kind,
                                                sensor_row, reporter_id, episode_id, metric,
                                                double_value, text, reported_level, late,
                                                observed_at)
                    if signal is not None:
                        event_id, attached = self._correlate(conn, signal, facility, observed_at)
                        response.update({"signal_id": signal["signal_id"], "level": signal["level"],
                                         "tainted": bool(signal["tainted"]),
                                         "event_id": event_id, "attached": attached})
                elif is_reinspection:
                    response["reinspection_evidence"] = True
                return "risk_observation", observation_id, response

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_ingest_observation", payload=body, create=create)

    def _build_signal(self, conn, facility, observation_id, source_kind, sensor_row,
                      reporter_id, episode_id, metric, double_value, text, reported_level,
                      late, observed_at) -> dict[str, Any] | None:
        level = None
        rule_row = None
        matched: dict[str, Any] = {}
        active_rule = conn.execute(
            "SELECT * FROM risk_rule_versions WHERE status='active'"
        ).fetchone()
        if active_rule is not None and double_value is not None:
            for rule in json.loads(active_rule["rules_json"]):
                if rule.get("metric") != metric:
                    continue
                if rule.get("facility_id") and rule["facility_id"] != facility["facility_id"]:
                    continue
                if rule.get("facility_type") and rule["facility_type"] != facility["facility_type"]:
                    continue
                operator = rule.get("operator", ">=")
                if operator not in COMPARATORS:
                    continue
                thresholds = rule.get("thresholds", {})
                for candidate in ("danger", "warning", "watch"):
                    threshold = thresholds.get(candidate)
                    if threshold is None:
                        continue
                    if COMPARATORS[operator](double_value, float(threshold)):
                        level = candidate
                        rule_row = active_rule
                        matched = {"rule_id": rule.get("rule_id"), "operator": operator,
                                   "threshold": threshold, "value": double_value,
                                   "thresholds": thresholds}
                        break
                if level:
                    break
        if level is None and source_kind == "manual" and reported_level:
            level = reported_level
            matched = {"manual_report": True, "text": text[:500]}
        if level is None:
            return None
        tainted = 0
        if sensor_row is not None and sensor_row["calibration_status"] == "failed":
            tainted = 1
            matched["calibration_status"] = "failed"
        signal_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO risk_signals(signal_id,observation_id,facility_id,metric,level,source_kind,"
            "sensor_id,reporter_id,episode_id,rule_version_id,rule_content_hash,matched_json,"
            "tainted,late,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (signal_id, observation_id, facility["facility_id"], metric, level, source_kind,
             sensor_row["sensor_id"] if sensor_row else None, reporter_id, episode_id,
             rule_row["rule_version_id"] if rule_row else None,
             rule_row["content_hash"] if rule_row else None,
             canonical_json(matched), tainted, 1 if late else 0, observed_at, self._now()),
        )
        return {"signal_id": signal_id, "facility_id": facility["facility_id"], "metric": metric,
                "level": level, "source_kind": source_kind,
                "sensor_id": sensor_row["sensor_id"] if sensor_row else None,
                "reporter_id": reporter_id, "episode_id": episode_id,
                "rule_version_id": rule_row["rule_version_id"] if rule_row else None,
                "rule_content_hash": rule_row["content_hash"] if rule_row else None,
                "matched": matched, "tainted": tainted, "late": bool(late),
                "observed_at": observed_at}

    def _correlate(self, conn, signal: dict[str, Any], facility, observed_at: str):
        """把信号归并到同场灾害的未结事件；找不到则新建 detected 事件。

        同 episode_id 一律归并（同一场强降雨不受时间窗限制）；否则要求与
        事件最近信号在归并窗内且来自同一设施或拓扑相邻设施。已开放事件不
        再接收信号，迟到观测只能另立新事件，不能把状态倒退回去。
        """

        window = timedelta(hours=CORRELATION_WINDOW_HOURS)
        signal_time = self._parse_ts(observed_at, "observed_at")
        episode_id = signal["episode_id"]
        candidates = conn.execute(
            "SELECT * FROM risk_events WHERE state!='opened' ORDER BY created_at DESC"
        ).fetchall()
        chosen = None
        reason = None
        # 第一轮：同一场灾害（episode）优先，不受时间窗约束。
        if episode_id:
            for event in candidates:
                if event["episode_id"] == episode_id:
                    chosen, reason = event, "same_episode"
                    break
        # 第二轮：时间窗内的同设施或拓扑相邻设施。
        if chosen is None:
            for event in candidates:
                last = conn.execute(
                    "SELECT MAX(observed_at) AS last_at FROM risk_signals s JOIN risk_event_signals es "
                    "ON s.signal_id=es.signal_id WHERE es.event_id=?", (event["event_id"],)
                ).fetchone()["last_at"]
                if last is None or abs(signal_time - self._parse_ts(last, "observed_at")) > window:
                    continue
                facilities = self._event_facilities(conn, event["event_id"])
                if signal["facility_id"] in facilities:
                    chosen, reason = event, "same_facility"
                    break
                if self._facilities_adjacent(conn, signal["facility_id"], facilities):
                    chosen, reason = event, "adjacent_facility"
                    break
        if chosen is None:
            event_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO risk_events(event_id,episode_id,primary_facility_id,state,severity,"
                "confidence,created_by,created_at,updated_at) VALUES(?,?,?, 'detected', ?,?, ?,?,?)",
                (event_id, episode_id, facility["facility_id"], signal["level"],
                 self._confidence([signal]), "system", self._now(), self._now()),
            )
            conn.execute(
                "INSERT INTO risk_event_signals(event_id,signal_id,correlation_json,linked_at) "
                "VALUES(?,?,?,?)",
                (event_id, signal["signal_id"],
                 canonical_json({"reason": "new_event"}), self._now()),
            )
            review = self._recompute_review(conn, event_id)
            append_event(conn, actor_id="system", action="risk.event_created",
                         resource_type="risk_event", resource_id=event_id,
                         detail={"facility_id": facility["facility_id"],
                                 "severity": signal["level"], "episode_id": episode_id,
                                 "signal_id": signal["signal_id"], "review_required": review},
                         occurred_at=self._now())
            return event_id, False
        conn.execute(
            "INSERT INTO risk_event_signals(event_id,signal_id,correlation_json,linked_at) "
            "VALUES(?,?,?,?)",
            (chosen["event_id"], signal["signal_id"],
             canonical_json({"reason": reason}), self._now()),
        )
        signals = self._event_signals(conn, chosen["event_id"])
        severity = max((s["level"] for s in signals), key=lambda lv: LEVEL_INDEX[lv])
        confidence = self._confidence(signals)
        review_required = self._recompute_review(conn, chosen["event_id"])
        conn.execute(
            "UPDATE risk_events SET severity=?, confidence=?, review_required=?, updated_at=? "
            "WHERE event_id=?",
            (severity, confidence, review_required, self._now(), chosen["event_id"]),
        )
        append_event(conn, actor_id="system", action="risk.signal_correlated",
                     resource_type="risk_event", resource_id=chosen["event_id"],
                     detail={"signal_id": signal["signal_id"], "reason": reason,
                             "severity": severity, "confidence": confidence},
                     occurred_at=self._now())
        return chosen["event_id"], True

    # --------------------------------------------------------------- 处置流水线

    def decide(self, *, request_id: str, actor_id: str, event_id: str, action: str,
               note: str = ""):
        """按权限与顺序推进一个处置动作。非法顺序直接报错，状态保持不变。"""

        body = {"actor_id": actor_id, "event_id": event_id, "action": action, "note": note}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            event = self._get_event_row(conn, event_id)
            # 幂等重放优先于状态机校验：同 request_id 重放已成功的决策时，
            # 即使事件已前进到后续状态，也必须原样返回原回执而不是报顺序错误。
            replayed = self._peek_receipt(conn, request_id=request_id,
                                          action=f"risk_decide_{action}", payload=body)
            if replayed is not None:
                return replayed
            self._validate_decision(actor, event, action)

            def create():
                basis = self._decision_basis(conn, event, action, actor, note)
                decision_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO risk_decisions(decision_id,event_id,action,from_state,to_state,"
                    "basis_json,actor_id,decided_at) VALUES(?,?,?,?,?,?,?,?)",
                    (decision_id, event_id, action, basis["from_state"], basis["to_state"],
                     canonical_json(basis), actor_id, self._now()),
                )
                conn.execute("UPDATE risk_events SET state=?, updated_at=? WHERE event_id=?",
                             (basis["to_state"], self._now(), event_id))
                control = {"restrict": "restricted", "close": "closed", "open": "open"}.get(action)
                if control:
                    conn.execute(
                        "UPDATE risk_facilities SET control_status=? WHERE facility_id=?",
                        (control, event["primary_facility_id"]),
                    )
                append_event(conn, actor_id=actor_id, action=f"risk.decision_{action}",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"decision_id": decision_id, "from_state": basis["from_state"],
                                     "to_state": basis["to_state"], "basis": basis},
                             occurred_at=self._now())
                return "risk_decision", decision_id, {
                    "decision_id": decision_id, "event_id": event_id,
                    "action": action, "from_state": basis["from_state"],
                    "to_state": basis["to_state"], "basis": basis}

            return self._idempotent(conn, request_id=request_id,
                                    action=f"risk_decide_{action}", payload=body, create=create)

    def _validate_decision(self, actor, event, action: str) -> None:
        if action not in TRANSITIONS:
            raise ValidationError("未知处置动作")
        if actor.role not in ACTION_ROLES[action]:
            raise PermissionDenied(f"当前角色不能执行 {action}")
        from_state, _ = TRANSITIONS[action]
        if event["state"] != from_state:
            raise ConflictError(
                f"状态 {event['state']} 不允许执行 {action}（要求 {from_state}）")
        if event["review_required"]:
            raise ConflictError("存在校准失效导致的未完成复核，不能继续推进处置")

    def attempt(self, **kwargs):
        """尝试推进处置；被拒绝时把原因留档并返回 accepted=False 而不是抛错。

        拒绝记录写入独立事务，因此即使业务事务回滚，时间线仍能解释该次尝试。
        """

        try:
            receipt = self.decide(**kwargs)
        except DomainError as exc:
            self._record_rejection(kwargs.get("event_id", ""), kwargs.get("action", ""),
                                   kwargs.get("actor_id", ""), str(exc))
            return {"accepted": False, "reason": str(exc), "code": exc.code}
        return {"accepted": True, "receipt": receipt.__dict__}

    def _record_rejection(self, event_id: str, action: str, actor_id: str, reason: str) -> None:
        if not event_id:
            return
        with self.database.transaction(immediate=True) as conn:
            if conn.execute("SELECT 1 FROM risk_events WHERE event_id=?", (event_id,)).fetchone() is None:
                return
            conn.execute(
                "INSERT INTO risk_rejected_steps(reject_id,event_id,action,actor_id,reason,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (uuid.uuid4().hex, event_id, action, actor_id, reason[:300], self._now()),
            )
            append_event(conn, actor_id=actor_id, action="risk.decision_rejected",
                         resource_type="risk_event", resource_id=event_id,
                         detail={"action": action, "reason": reason[:300]},
                         occurred_at=self._now())

    def review_event_after_calibration(self, *, request_id: str, actor_id: str, event_id: str,
                                       failed_sensor_id: str | None, conclusion: str,
                                       evidence: dict[str, Any], note: str = ""):
        """技术复核人对校准失效影响过的未结事件重新审查并闭环。

        conclusion=valid 表示依据新证据确认告警仍然成立、解除复核标记；
        invalid 表示原告警不可信，事件保留未结并要求重新观测，不能继续封闭/开放。
        """

        body = {"actor_id": actor_id, "event_id": event_id,
                "failed_sensor_id": failed_sensor_id, "conclusion": conclusion,
                "evidence": evidence, "note": note}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "reviewer")
            event = self._get_event_row(conn, event_id)
            if not event["review_required"]:
                raise ConflictError("该事件当前没有待完成的校准复核")
            if conclusion not in ("valid", "invalid"):
                raise ValidationError("conclusion 必须是 valid 或 invalid")
            if not isinstance(evidence, dict) or not evidence:
                raise ValidationError("复核必须附带证据对象")

            def create():
                review_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO risk_reviews(review_id,event_id,failed_sensor_id,reviewer_id,"
                    "conclusion,evidence_json,note,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (review_id, event_id, failed_sensor_id, actor_id, conclusion,
                     canonical_json(evidence), note[:500], self._now()),
                )
                if conclusion == "valid":
                    conn.execute("UPDATE risk_events SET review_required=0, updated_at=? WHERE event_id=?",
                                 (self._now(), event_id))
                append_event(conn, actor_id=actor_id,
                             action="risk.calibration_review_valid" if conclusion == "valid"
                             else "risk.calibration_review_invalid",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"review_id": review_id,
                                     "failed_sensor_id": failed_sensor_id,
                                     "evidence_hash": digest(evidence)},
                             occurred_at=self._now())
                return "risk_review", review_id, {
                    "review_id": review_id, "event_id": event_id, "conclusion": conclusion,
                    "review_cleared": conclusion == "valid"}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_review_event", payload=body, create=create)

    def add_technical_confirmation(self, *, request_id: str, actor_id: str, event_id: str,
                                   evidence: dict[str, Any], opinion: str = ""):
        body = {"actor_id": actor_id, "event_id": event_id, "evidence": evidence,
                "opinion": opinion}
        with self.database.transaction(immediate=True) as conn:
            actor = self._actor(conn, actor_id)
            self._require(actor, "reviewer")
            event = self._get_event_row(conn, event_id)
            if not isinstance(evidence, dict) or not evidence:
                raise ValidationError("技术确认必须附带证据对象")
            facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                    (event["primary_facility_id"],)).fetchone()

            def create():
                confirmation_id = uuid.uuid4().hex
                try:
                    conn.execute(
                        "INSERT INTO risk_confirmations(confirmation_id,event_id,actor_id,"
                        "organization_id,role,evidence_json,opinion,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (confirmation_id, event_id, actor_id, actor.organization_id, actor.role,
                         canonical_json(evidence), opinion[:500], self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("同一技术人对同一事件只能确认一次") from exc
                append_event(conn, actor_id=actor_id, action="risk.technical_confirmation",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"confirmation_id": confirmation_id,
                                     "organization_id": actor.organization_id,
                                     "facility_criticality": facility["criticality"]},
                             occurred_at=self._now())
                needed = self._open_confirmation_quota(conn, event, facility)
                existing = conn.execute(
                    "SELECT COUNT(*) AS c FROM risk_confirmations WHERE event_id=?", (event_id,)
                ).fetchone()["c"]
                return "risk_confirmation", confirmation_id, {
                    "confirmation_id": confirmation_id, "event_id": event_id,
                    "confirmations": existing, "required": needed}

            return self._idempotent(conn, request_id=request_id,
                                    action="risk_technical_confirmation", payload=body,
                                    create=create)

    def _check_open_confirmations(self, conn, event, actor):
        facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                (event["primary_facility_id"],)).fetchone()
        needed = self._open_confirmation_quota(conn, event, facility)
        rows = conn.execute(
            "SELECT * FROM risk_confirmations WHERE event_id=? ORDER BY created_at", (event["event_id"],)
        ).fetchall()
        if len(rows) < needed:
            raise ConflictError(f"开放需要 {needed} 份独立技术确认，当前仅有 {len(rows)} 份")
        chosen = rows[:needed]
        actors = {row["actor_id"] for row in chosen}
        organizations = {row["organization_id"] for row in chosen}
        if actor.actor_id in actors:
            raise PermissionDenied("开放决策人不能同时担任技术确认人")
        if len(actors) != needed:
            raise ConflictError("技术确认必须由相互独立的技术人分别给出")
        if facility["criticality"] == "high" and len(organizations) != needed:
            raise ConflictError("高风险设施的技术确认必须来自相互独立的机构")
        return [{"actor_id": row["actor_id"], "organization_id": row["organization_id"],
                 "opinion": row["opinion"], "evidence": json.loads(row["evidence_json"])}
                for row in chosen]

    # ----------------------------------------------------------------- 查询

    def get_event(self, event_id: str) -> dict[str, Any]:
        with self.database.transaction() as conn:
            event = self._get_event_row(conn, event_id)
            return self._event_projection(conn, event)

    def list_events(self, *, episode_id: str | None = None, open_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM risk_events"
        clauses = []
        params: list[Any] = []
        if episode_id:
            clauses.append("episode_id=?")
            params.append(episode_id)
        if open_only:
            clauses.append("state!='opened'")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at"
        with self.database.transaction() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._event_projection(conn, row) for row in rows]

    def list_reviews_required(self) -> list[dict[str, Any]]:
        """校准失效后需要重新审查的未结事件。"""

        with self.database.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_events WHERE review_required=1 AND state!='opened' ORDER BY created_at"
            ).fetchall()
            return [self._event_projection(conn, row) for row in rows]
    def event_timeline(self, event_id: str) -> dict[str, Any]:
        """重放单个事件从首个信号到恢复通行的完整时间线。"""

        with self.database.transaction() as conn:
            event = self._get_event_row(conn, event_id)
            items: list[dict[str, Any]] = []
            signals = {s["signal_id"]: s for s in self._event_signals(conn, event_id)}
            facility_ids = self._event_facilities(conn, event_id)
            facility_ids.add(event["primary_facility_id"])
            placeholders = ",".join("?" for _ in facility_ids)
            # 与事件直接关联的信号观测，加上事件设施上的重复观测留档，以及
            # 主体设施上的复检证据观测。
            linked_obs = {s["observation_id"] for s in signals.values()}
            rows_all = conn.execute(
                f"SELECT * FROM risk_observations WHERE facility_id IN ({placeholders})",
                tuple(facility_ids),
            ).fetchall()
            start = min((s["observed_at"] for s in signals.values()), default=event["created_at"])
            end = event["updated_at"]
            obs_rows = []
            for row in rows_all:
                if row["observation_id"] in linked_obs:
                    obs_rows.append(row)
                elif row["is_reinspection"] and row["facility_id"] == event["primary_facility_id"]:
                    obs_rows.append(row)
                elif row["duplicate"] and start <= row["observed_at"] <= end:
                    obs_rows.append(row)
            obs_rows.sort(key=lambda row: row["observed_at"])
            seen = set()
            for row in obs_rows:
                if row["observation_id"] in seen:
                    continue
                seen.add(row["observation_id"])
                item = {"kind": "observation", "at": row["observed_at"],
                        "observation_id": row["observation_id"],
                        "facility_id": row["facility_id"], "metric": row["metric"],
                        "source_kind": row["source_kind"], "value": row["double_value"],
                        "text": row["text_value"], "duplicate": bool(row["duplicate"]),
                        "late": bool(row["late"]), "is_reinspection": bool(row["is_reinspection"])}
                for signal in signals.values():
                    if signal["observation_id"] == row["observation_id"]:
                        item["signal"] = {"signal_id": signal["signal_id"], "level": signal["level"],
                                          "tainted": bool(signal["tainted"]),
                                          "matched": signal["matched"],
                                          "rule_version_id": signal["rule_version_id"]}
                items.append(item)
            for row in conn.execute("SELECT * FROM risk_decisions WHERE event_id=? ORDER BY decided_at",
                                    (event_id,)):
                items.append({"kind": "decision", "at": row["decided_at"],
                              "decision_id": row["decision_id"], "action": row["action"],
                              "from_state": row["from_state"], "to_state": row["to_state"],
                              "actor_id": row["actor_id"], "basis": json.loads(row["basis_json"])})
            for row in conn.execute("SELECT * FROM risk_confirmations WHERE event_id=? ORDER BY created_at",
                                    (event_id,)):
                items.append({"kind": "technical_confirmation", "at": row["created_at"],
                              "confirmation_id": row["confirmation_id"], "actor_id": row["actor_id"],
                              "organization_id": row["organization_id"], "opinion": row["opinion"],
                              "evidence": json.loads(row["evidence_json"])})
            for row in conn.execute("SELECT * FROM risk_rejected_steps WHERE event_id=? ORDER BY created_at",
                                    (event_id,)):
                items.append({"kind": "rejected_attempt", "at": row["created_at"],
                              "action": row["action"], "actor_id": row["actor_id"],
                              "reason": row["reason"]})
            for row in conn.execute("SELECT * FROM risk_reviews WHERE event_id=? ORDER BY created_at",
                                    (event_id,)):
                items.append({"kind": "calibration_review", "at": row["created_at"],
                              "review_id": row["review_id"],
                              "failed_sensor_id": row["failed_sensor_id"],
                              "reviewer_id": row["reviewer_id"],
                              "conclusion": row["conclusion"], "note": row["note"],
                              "evidence": json.loads(row["evidence_json"])})
            items.sort(key=lambda item: (item["at"], item["kind"]))
            return {"event": self._event_projection(conn, event), "items": items}

    def impact_area(self, facility_id: str) -> dict[str, Any]:
        with self.database.transaction() as conn:
            facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                    (facility_id,)).fetchone()
            if facility is None:
                raise NotFoundError("设施不存在")
            return {"facility_id": facility_id, "impact": self._downstream_impact(conn, facility_id)}

    # ----------------------------------------------------------------- 内部

    def _decision_basis(self, conn, event, action, actor, note: str) -> dict[str, Any]:
        signals = self._event_signals(conn, event["event_id"])
        active_rule = conn.execute(
            "SELECT * FROM risk_rule_versions WHERE status='active'"
        ).fetchone()
        if event["rule_version_id"]:
            rule_version_id = event["rule_version_id"]
            rule_hash = event["rule_content_hash"]
        else:
            rule_version_id = active_rule["rule_version_id"] if active_rule else None
            rule_hash = active_rule["content_hash"] if active_rule else None
        plan_version_id = event["plan_version_id"]
        plan_hash = event["plan_content_hash"]
        plan_content = None
        if action == "escalate":
            plan_row = self._matching_plan(conn, event["primary_facility_id"])
            if plan_row:
                plan_version_id = plan_row["plan_version_id"]
                plan_hash = plan_row["content_hash"]
                plan_content = json.loads(plan_row["content_json"])
            conn.execute(
                "UPDATE risk_events SET rule_version_id=?, rule_content_hash=?, "
                "plan_version_id=?, plan_content_hash=? WHERE event_id=?",
                (rule_version_id, rule_hash, plan_version_id, plan_hash, event["event_id"]),
            )
        elif plan_version_id:
            plan_row = conn.execute("SELECT * FROM risk_plan_versions WHERE plan_version_id=?",
                                    (plan_version_id,)).fetchone()
            plan_content = json.loads(plan_row["content_json"]) if plan_row else None
        versions_seen = sorted({s["rule_version_id"] for s in signals if s["rule_version_id"]})
        from_state, to_state = TRANSITIONS[action]
        basis: dict[str, Any] = {
            "decided_at": self._now(),
            "from_state": from_state,
            "to_state": to_state,
            "severity": event["severity"],
            "confidence": self._confidence(signals),
            "signals": [{"signal_id": s["signal_id"], "facility_id": s["facility_id"],
                         "metric": s["metric"], "level": s["level"],
                         "source_kind": s["source_kind"], "matched": s["matched"],
                         "rule_version_id": s["rule_version_id"],
                         "rule_content_hash": s["rule_content_hash"],
                         "tainted": bool(s["tainted"]), "observed_at": s["observed_at"]}
                        for s in signals],
            "frozen_rule_version_id": rule_version_id,
            "frozen_rule_content_hash": rule_hash,
            "active_rule_version_at_decision": active_rule["rule_version_id"] if active_rule else None,
            "rule_versions_seen_in_event": versions_seen,
            "frozen_plan_version_id": plan_version_id,
            "frozen_plan_content_hash": plan_hash,
            "plan_content": plan_content,
            "note": note[:500],
        }
        if action == "open":
            basis["technical_confirmations"] = self._check_open_confirmations(conn, event, actor)
            basis["impact_area"] = self._downstream_impact(conn, event["primary_facility_id"])
        if action == "reinspect":
            repair = conn.execute(
                "SELECT decided_at FROM risk_decisions WHERE event_id=? AND action='repair' "
                "ORDER BY decided_at DESC LIMIT 1", (event["event_id"],)).fetchone()
            reinspection = conn.execute(
                "SELECT * FROM risk_observations WHERE facility_id=? AND is_reinspection=1 "
                "ORDER BY observed_at DESC LIMIT 1", (event["primary_facility_id"],)).fetchone()
            if repair is None or reinspection is None or \
                    self._parse_ts(reinspection["observed_at"], "observed_at") < \
                    self._parse_ts(repair["decided_at"], "decided_at"):
                raise ConflictError("复检前必须先完成抢修并登记抢修之后的复检观测")
            basis["reinspection"] = {"observation_id": reinspection["observation_id"],
                                     "observed_at": reinspection["observed_at"],
                                     "text": reinspection["text_value"],
                                     "reporter_id": reinspection["reporter_id"]}
        return basis

    def _matching_plan(self, conn, facility_id: str):
        facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                (facility_id,)).fetchone()
        for row in conn.execute("SELECT * FROM risk_plan_versions WHERE status='active' "
                                "ORDER BY activated_at DESC"):
            scope = json.loads(row["scope_json"])
            if facility_id in scope.get("facility_ids", []) or \
                    facility["facility_type"] in scope.get("facility_types", []):
                return row
        return None

    def _open_confirmation_quota(self, conn, event, facility) -> int:
        if event["plan_version_id"]:
            plan = conn.execute("SELECT content_json FROM risk_plan_versions WHERE plan_version_id=?",
                                (event["plan_version_id"],)).fetchone()
            if plan:
                content = json.loads(plan["content_json"])
                overrides = content.get("open_confirmations", {})
                if facility["criticality"] in overrides:
                    return int(overrides[facility["criticality"]])
        return DEFAULT_OPEN_CONFIRMATIONS[facility["criticality"]]

    def _get_event_row(self, conn, event_id: str):
        event = conn.execute("SELECT * FROM risk_events WHERE event_id=?", (event_id,)).fetchone()
        if event is None:
            raise NotFoundError("风险事件不存在")
        return event

    def _event_signals(self, conn, event_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT s.*, o.observation_id AS oid FROM risk_signals s JOIN risk_event_signals es "
            "ON s.signal_id=es.signal_id JOIN risk_observations o ON s.observation_id=o.observation_id "
            "WHERE es.event_id=? ORDER BY s.observed_at", (event_id,)
        ).fetchall()
        return [{"signal_id": row["signal_id"], "observation_id": row["oid"],
                 "facility_id": row["facility_id"], "metric": row["metric"], "level": row["level"],
                 "source_kind": row["source_kind"], "sensor_id": row["sensor_id"],
                 "reporter_id": row["reporter_id"], "rule_version_id": row["rule_version_id"],
                 "rule_content_hash": row["rule_content_hash"],
                 "matched": json.loads(row["matched_json"]), "tainted": row["tainted"],
                 "late": bool(row["late"]), "observed_at": row["observed_at"]} for row in rows]

    def _event_facilities(self, conn, event_id: str) -> set[str]:
        rows = conn.execute(
            "SELECT DISTINCT facility_id FROM risk_signals s JOIN risk_event_signals es "
            "ON s.signal_id=es.signal_id WHERE es.event_id=?", (event_id,)).fetchall()
        return {row["facility_id"] for row in rows}

    def _facilities_adjacent(self, conn, facility_id: str, known: set[str]) -> bool:
        rows = conn.execute(
            "SELECT upstream_id, downstream_id FROM risk_facility_links"
        ).fetchall()
        neighbors = set()
        for row in rows:
            if row["upstream_id"] == facility_id:
                neighbors.add(row["downstream_id"])
            if row["downstream_id"] == facility_id:
                neighbors.add(row["upstream_id"])
        return bool(neighbors & known)

    def _downstream_impact(self, conn, facility_id: str) -> list[dict[str, Any]]:
        seen: dict[str, int] = {facility_id: 0}
        frontier = [(facility_id, 0)]
        relations: dict[str, list[str]] = {}
        while frontier:
            current, distance = frontier.pop(0)
            links = conn.execute(
                "SELECT * FROM risk_facility_links WHERE upstream_id=?", (current,)
            ).fetchall()
            for row in links:
                nxt = row["downstream_id"]
                if nxt not in seen:
                    seen[nxt] = distance + 1
                    relations.setdefault(nxt, []).append(
                        f"{current} --{row['relation']}--> {nxt}")
                    frontier.append((nxt, distance + 1))
        impact = []
        for fid, distance in sorted(seen.items(), key=lambda item: (item[1], item[0])):
            facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                    (fid,)).fetchone()
            if facility is None:
                continue
            impact.append({"facility_id": fid, "name": facility["name"],
                           "facility_type": facility["facility_type"],
                           "criticality": facility["criticality"],
                           "control_status": facility["control_status"],
                           "distance": distance,
                           "reason": "事件主体" if distance == 0 else "拓扑下游",
                           "paths": relations.get(fid, [])})
        return impact

    def _event_impact(self, conn, event) -> list[dict[str, Any]]:
        """事件影响范围 = 主体设施拓扑下游 ∪ 同场灾害出现信号的设施。"""

        impact = self._downstream_impact(conn, event["primary_facility_id"])
        present = {item["facility_id"] for item in impact}
        for fid in sorted(self._event_facilities(conn, event["event_id"])):
            if fid in present:
                continue
            facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                    (fid,)).fetchone()
            if facility is None:
                continue
            impact.append({"facility_id": fid, "name": facility["name"],
                           "facility_type": facility["facility_type"],
                           "criticality": facility["criticality"],
                           "control_status": facility["control_status"],
                           "distance": None, "reason": "同场灾害信号设施", "paths": []})
            present.add(fid)
        return impact

    def _event_projection(self, conn, event) -> dict[str, Any]:
        signals = self._event_signals(conn, event["event_id"])
        facility = conn.execute("SELECT * FROM risk_facilities WHERE facility_id=?",
                                (event["primary_facility_id"],)).fetchone()
        decisions = conn.execute(
            "SELECT decision_id,action,from_state,to_state,actor_id,decided_at,basis_json "
            "FROM risk_decisions WHERE event_id=? ORDER BY decided_at", (event["event_id"],)
        ).fetchall()
        confirmations = conn.execute(
            "SELECT actor_id,organization_id,opinion,created_at FROM risk_confirmations "
            "WHERE event_id=? ORDER BY created_at", (event["event_id"],)
        ).fetchall()
        reviews = conn.execute(
            "SELECT review_id,failed_sensor_id,reviewer_id,conclusion,note,created_at "
            "FROM risk_reviews WHERE event_id=? ORDER BY created_at", (event["event_id"],)
        ).fetchall()
        response_level = DEFAULT_RESPONSE_LEVELS[event["severity"]]
        plan_row = None
        if event["plan_version_id"]:
            plan_row = conn.execute(
                "SELECT content_json FROM risk_plan_versions WHERE plan_version_id=?",
                (event["plan_version_id"],)).fetchone()
        else:
            # 升级冻结前，投影按当前适用的激活预案展示响应级别；冻结后不再随换版变化。
            plan_row = self._matching_plan(conn, event["primary_facility_id"])
        if plan_row:
            overrides = json.loads(plan_row["content_json"]).get("response_levels", {})
            response_level = int(overrides.get(event["severity"], response_level))
        return {
            "event_id": event["event_id"], "episode_id": event["episode_id"],
            "primary_facility_id": event["primary_facility_id"],
            "facility_name": facility["name"], "facility_criticality": facility["criticality"],
            "control_status": facility["control_status"], "state": event["state"],
            "severity": event["severity"], "response_level": response_level,
            "confidence": event["confidence"], "review_required": bool(event["review_required"]),
            "rule_version_id": event["rule_version_id"],
            "rule_content_hash": event["rule_content_hash"],
            "plan_version_id": event["plan_version_id"],
            "plan_content_hash": event["plan_content_hash"],
            "impact_area": self._event_impact(conn, event),
            "signals": [{"signal_id": s["signal_id"], "facility_id": s["facility_id"],
                         "metric": s["metric"], "level": s["level"],
                         "source_kind": s["source_kind"], "sensor_id": s["sensor_id"],
                         "reporter_id": s["reporter_id"], "matched": s["matched"],
                         "tainted": bool(s["tainted"]), "late": s["late"],
                         "rule_version_id": s["rule_version_id"],
                         "observed_at": s["observed_at"]} for s in signals],
            "decisions": [{"decision_id": row["decision_id"], "action": row["action"],
                           "from_state": row["from_state"], "to_state": row["to_state"],
                           "actor_id": row["actor_id"], "decided_at": row["decided_at"],
                           "basis": json.loads(row["basis_json"])} for row in decisions],
            "confirmations": [{"actor_id": row["actor_id"], "organization_id": row["organization_id"],
                               "opinion": row["opinion"], "created_at": row["created_at"]}
                              for row in confirmations],
            "calibration_reviews": [{"review_id": row["review_id"],
                                     "failed_sensor_id": row["failed_sensor_id"],
                                     "reviewer_id": row["reviewer_id"],
                                     "conclusion": row["conclusion"], "note": row["note"],
                                     "created_at": row["created_at"]} for row in reviews],
            "created_at": event["created_at"], "updated_at": event["updated_at"],
        }

    def _recompute_review(self, conn, event_id: str) -> int:
        """事件是否需要复核：单调置位。

        只要信号引用过当前校准失效的传感器就置 1；清除只能由复核人通过
        ``review_event_after_calibration`` 凭证据完成，校准恢复或新观测都不能
        静默撤销待复核标记。
        """

        existing = conn.execute("SELECT review_required FROM risk_events WHERE event_id=?",
                                (event_id,)).fetchone()["review_required"]
        if existing:
            return 1
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_signals s JOIN risk_event_signals es "
            "ON s.signal_id=es.signal_id JOIN risk_sensors se ON s.sensor_id=se.sensor_id "
            "WHERE es.event_id=? AND se.calibration_status='failed'", (event_id,)
        ).fetchone()
        required = 1 if row["c"] > 0 else 0
        if required:
            conn.execute("UPDATE risk_events SET review_required=1 WHERE event_id=?", (event_id,))
        return required

    def _confidence(self, signals: list[dict[str, Any]]) -> float:
        channels = {(s["source_kind"], s.get("sensor_id") or s.get("reporter_id") or "unknown")
                    for s in signals}
        metrics = {s["metric"] for s in signals}
        score = 0.5 + 0.15 * (len(channels) - 1) + 0.10 * (len(metrics) - 1)
        score = min(0.95, score)
        if any(s.get("tainted") for s in signals):
            score *= 0.8
        return round(score, 3)

    def _validate_rules(self, rules: Any) -> None:
        if not isinstance(rules, list) or not rules:
            raise ValidationError("rules 必须是非空数组")
        seen = set()
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValidationError("每条规则必须是对象")
            rid = str(rule.get("rule_id", "")).strip()
            if not rid or rid in seen:
                raise ValidationError("rule_id 不能为空且不能重复")
            seen.add(rid)
            if not str(rule.get("metric", "")).strip():
                raise ValidationError("规则必须声明 metric")
            if rule.get("operator", ">=") not in COMPARATORS:
                raise ValidationError("规则 operator 仅支持 >= > <= <")
            thresholds = rule.get("thresholds")
            if not isinstance(thresholds, dict) or not thresholds:
                raise ValidationError("规则必须包含 thresholds")
            for level, value in thresholds.items():
                if level not in LEVEL_INDEX:
                    raise ValidationError("阈值级别必须是 watch/warning/danger")
                float(value)

    @staticmethod
    def _parse_ts(value: str, field: str) -> datetime:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是 ISO 8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return parsed.astimezone()

    @classmethod
    def _normalize_ts(cls, value: str, field: str) -> str:
        """校验时间并归一化为 UTC ISO 文本。"""

        parsed = cls._parse_ts(value, field).astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")


# 兼容性别名：外部可直接按状态顺序读取。
STATE_ORDER = tuple(STATE_INDEX)
