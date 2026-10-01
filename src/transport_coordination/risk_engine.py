"""风险信号的判定与归并引擎。

引擎只做纯计算，所有读写由 RiskService 在事务内完成：
- 依据当前生效的规则版本把观测映射到处置等级；
- 按设施拓扑连通性与时间窗把多条信号归并为同一事件；
- 按传感器校准状态折算证据权重，合成可解释的置信度；
- 沿拓扑上下游计算措施影响范围。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

STAGES = ("heighten", "restrict", "close", "repair", "recheck", "reopen")
STAGE_ORDINALS = {stage: index + 1 for index, stage in enumerate(STAGES)}
STAGE_LABELS = {
    "heighten": "升级",
    "restrict": "限行",
    "close": "封闭",
    "repair": "抢修",
    "recheck": "复检",
    "reopen": "开放",
}
SEVERITY_ORDER = {"heighten": 1, "restrict": 2, "close": 3}
CALIBRATION_FACTOR = {"valid": 1.0, "expired": 0.5, "unverified": 0.25, "failed": 0.0}


def parse_ts(value: str | datetime) -> datetime:
    """解析 ISO 8601 时间文本为 UTC datetime。"""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return parsed.astimezone(timezone.utc)


def format_ts(value: datetime) -> str:
    """格式化为审计与存储使用的紧凑 UTC 文本。"""

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def active_version_at(connection, table: str, at: str) -> Any:
    """返回指定时间表中处于 active 状态的版本行。"""

    return connection.execute(
        f"SELECT * FROM {table} WHERE status='active' AND published_at<=? "
        "ORDER BY version DESC LIMIT 1",
        (at,),
    ).fetchone()


def active_plan(connection, facility_id: str, at: str) -> Any:
    """返回设施在指定时间生效的应急预案版本。"""

    return connection.execute(
        "SELECT * FROM plan_versions WHERE facility_id=? AND status='active' AND published_at<=? "
        "ORDER BY version DESC LIMIT 1",
        (facility_id, at),
    ).fetchone()


def calibration_at(connection, sensor_id: str, at: datetime) -> tuple[str, Any]:
    """确定传感器在观测时刻的校准状态。"""

    stamp = format_ts(at)
    row = connection.execute(
        "SELECT * FROM calibration_records WHERE sensor_id=? AND valid_from<=? "
        "ORDER BY valid_from DESC, created_at DESC LIMIT 1",
        (sensor_id, stamp),
    ).fetchone()
    if row is None:
        return "unverified", None
    status = row["status"]
    if status == "valid" and row["valid_until"] is not None and row["valid_until"] <= stamp:
        status = "expired"
    return status, row


def match_level(rule: dict[str, Any], observation: dict[str, Any], facility_type: str) -> str | None:
    """按单条规则评估观测，返回命中的处置等级；未命中返回 None。"""

    if rule.get("facility_type") and rule["facility_type"] != facility_type:
        return None
    if rule.get("metric") and rule["metric"] != observation["metric"]:
        return None
    if rule.get("source") and rule["source"] != observation["source"]:
        return None
    thresholds = rule.get("thresholds")
    if thresholds is not None:
        value = observation.get("value")
        if value is None:
            return None
        operator = rule.get("operator", ">=")
        matched: str | None = None
        for level, bound in thresholds.items():
            if level not in SEVERITY_ORDER:
                continue
            triggered = value >= bound if operator == ">=" else value <= bound
            if triggered and (matched is None or SEVERITY_ORDER[level] > SEVERITY_ORDER[matched]):
                matched = level
        return matched
    report_levels = rule.get("report_levels")
    if report_levels is not None:
        payload = observation.get("payload") or {}
        declared = payload.get("level")
        report = str(payload.get("report", ""))
        for level, keywords in report_levels.items():
            if level not in SEVERITY_ORDER:
                continue
            if declared == level or any(keyword and keyword in report for keyword in keywords):
                return level
    return None


def evaluate_observation(connection, rules_payload: dict[str, Any], observation: dict[str, Any],
                         calibration_status: str) -> list[dict[str, Any]]:
    """用整套规则评估一条观测，返回命中明细。"""

    facility = connection.execute(
        "SELECT * FROM facilities WHERE facility_id=?", (observation["facility_id"],)
    ).fetchone()
    matches: list[dict[str, Any]] = []
    for rule in rules_payload.get("rules", []):
        level = match_level(rule, observation, facility["facility_type"])
        if level is None:
            continue
        qualified = observation["source"] == "sensor" and calibration_status in (
            "failed", "unverified", "expired")
        matches.append({
            "rule_id": rule["rule_id"],
            "matched_level": level,
            "weight": float(rule.get("weight", 0.5)),
            "calibration_status": calibration_status,
            "qualified": qualified,
            "threshold": (rule.get("thresholds") or {}).get(level),
            "operator": rule.get("operator", ">="),
        })
    return matches


def facility_cluster(connection, facility_id: str) -> set[str]:
    """沿无向拓扑边求设施所在连通分量。"""

    seen = {facility_id}
    frontier = [facility_id]
    while frontier:
        current = frontier.pop()
        rows = connection.execute(
            "SELECT upstream_facility_id AS a, downstream_facility_id AS b FROM facility_links "
            "WHERE upstream_facility_id=? OR downstream_facility_id=?",
            (current, current),
        ).fetchall()
        for row in rows:
            for neighbor in (row["a"], row["b"]):
                if neighbor not in seen:
                    seen.add(neighbor)
                    frontier.append(neighbor)
    return seen


def find_incident(connection, *, site_id: str, cluster: set[str], observed_at: datetime,
                  window_minutes: int):
    """在同站点、同拓扑分量、时间窗相邻的未关闭事件中寻找归并目标。"""

    rows = connection.execute(
        "SELECT DISTINCT i.* FROM incidents i "
        "JOIN incident_facilities f ON f.incident_id=i.incident_id "
        "WHERE i.status='open' AND i.site_id=? AND f.facility_id IN (%s)" %
        ",".join("?" for _ in cluster),
        (site_id, *cluster),
    ).fetchall()
    lower = observed_at - timedelta(minutes=window_minutes)
    upper = observed_at + timedelta(minutes=window_minutes)
    for incident in rows:
        bound = connection.execute(
            "SELECT MIN(o.observed_at) AS first_at, MAX(o.observed_at) AS last_at "
            "FROM incident_signals s JOIN observations o ON o.observation_id=s.observation_id "
            "WHERE s.incident_id=?",
            (incident["incident_id"],),
        ).fetchone()
        if bound["last_at"] is None:
            continue
        first_at = parse_ts(bound["first_at"])
        last_at = parse_ts(bound["last_at"])
        if lower <= last_at and upper >= first_at:
            return incident
    return None


def synthesize(signals: list[dict[str, Any]]) -> tuple[str, float, bool]:
    """根据全部信号合成严重等级、置信度与证据是否受限。"""

    survivor = 1.0
    qualified_only = True
    severity: str | None = None
    for signal in signals:
        factor = CALIBRATION_FACTOR.get(signal["calibration_status"], 0.25)
        if signal["source"] != "sensor":
            factor = 1.0
        survivor *= 1.0 - signal["weight"] * factor
        if not signal["qualified"]:
            qualified_only = False
            level = signal["matched_level"]
            if level and (severity is None or SEVERITY_ORDER[level] > SEVERITY_ORDER[severity]):
                severity = level
    confidence = round(min(0.99, 1.0 - survivor), 4)
    if qualified_only and severity:
        severity = "heighten"
    return severity or "heighten", confidence, qualified_only


def impact_scope(connection, facility_ids: set[str], stage: str) -> dict[str, Any]:
    """沿拓扑计算措施影响范围内的设施与角色。"""

    affected: dict[str, dict[str, str]] = {}
    for facility_id in facility_ids:
        affected.setdefault(facility_id, {"facility_id": facility_id, "role": "primary",
                                          "relation": "self"})
        if stage in ("restrict", "close"):
            for row in connection.execute(
                "SELECT relation, upstream_facility_id, downstream_facility_id FROM facility_links "
                "WHERE upstream_facility_id=? OR downstream_facility_id=?",
                (facility_id, facility_id),
            ):
                if row["upstream_facility_id"] == facility_id:
                    neighbor, relation = row["downstream_facility_id"], "downstream"
                else:
                    neighbor, relation = row["upstream_facility_id"], "upstream"
                affected.setdefault(neighbor, {"facility_id": neighbor, "role": "impacted",
                                               "relation": relation})
    blocked = stage == "close"
    return {"stage": stage, "blocked": blocked,
            "facilities": [affected[key] for key in sorted(affected)]}


def utc_now_text() -> str:
    """返回当前 UTC 时间文本（极少使用，常规时间由时钟注入）。"""

    return format_ts(datetime.now(timezone.utc))
