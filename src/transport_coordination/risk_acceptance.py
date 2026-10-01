"""重点路桥风险处置服务的离线端到端验收。

重放 2026 年汛期一场强降雨从首个信号到恢复通行的完整时间线，验证：
1. 桥梁位移、边坡含水、巡检报告三类信号归并为同一个可追踪事件，
   并给出置信度与沿拓扑的影响范围；
2. 升级、限行、封闭、抢修、复检、开放按角色权限与固定顺序推进，
   重复或迟到的观测不能让处置状态倒退；
3. 高风险设施开放必须取得渠道、人员、机构相互独立的外部技术确认；
4. 阈值规则换版不会静默改变已经发布的决定，每条措施都能还原
   当时采用的阈值、预案版本、信号与校准证据；
5. 校准证书到期或校准失效后，依赖该传感器的未结事件进入复审队列，
   完成复检后才能关闭事件。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import SimulatedClock
from .risk_engine import STAGE_LABELS
from .risk_service import RiskService
from .storage import Database


def _full_disposition_chain(service, incident_id, facility_id, *, prefix: str,
                            reopen_confirmations, rejected_first: bool = False,
                            stages=("heighten", "restrict", "close", "repair", "recheck",
                                    "reopen")):
    """按固定顺序推进一个设施的处置链并登记开放技术确认。"""

    reasons = {
        "heighten": "强降雨风险信号，提升监测等级",
        "restrict": "监测值超过限行阈值，按 v1 规则与 1 号预案实施限行",
        "close": "人工巡检建议封闭且多重信号一致，值班负责人决定封闭",
        "repair": "养护单位进场抢险加固",
        "recheck": "抢险完成，工程师现场复检",
        "reopen": "复检合格，申请恢复通行",
    }
    actors = {"heighten": "operator-001", "restrict": "operator-001",
              "close": "admin-001", "repair": "engineer-001",
              "recheck": "engineer-001", "reopen": "admin-001"}
    reopen = None
    for stage in stages:
        receipt = service.advance_disposition(
            request_id=f"{prefix}-{stage}", actor_id=actors[stage], incident_id=incident_id,
            facility_id=facility_id, stage=stage, reason=reasons[stage])
        if stage == "reopen":
            reopen = receipt
    if rejected_first:
        service.add_technical_confirmation(
            request_id=f"{prefix}-confirm-a1", actor_id="operator-001",
            incident_id=incident_id, facility_id=facility_id,
            channel=reopen_confirmations[0][0], result="rejected",
            opinion="首轮复核发现裂缝仍在扩展，不同意开放",
            evidence_ref="CHK-REJECT-001", confirmed_by=reopen_confirmations[0][1],
            confirmed_by_organization=reopen_confirmations[0][2])
        reopen = service.advance_disposition(
            request_id=f"{prefix}-reopen-2", actor_id="admin-001", incident_id=incident_id,
            facility_id=facility_id, stage="reopen",
            reason="裂缝处置完成后重新申请开放")
        confirmations = reopen_confirmations
    else:
        confirmations = reopen_confirmations
    for index, (channel, person, organization, opinion, evidence) in enumerate(confirmations):
        service.add_technical_confirmation(
            request_id=f"{prefix}-confirm-b{index}", actor_id="operator-001",
            incident_id=incident_id, facility_id=facility_id, channel=channel,
            result="approved", opinion=opinion, evidence_ref=evidence,
            confirmed_by=person, confirmed_by_organization=organization)
    return reopen.resource_id


def run() -> dict[str, object]:
    """执行完整灾害时间线并返回可核验结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "risk_acceptance.sqlite3")
        clock = SimulatedClock(datetime(2026, 7, 14, 0, 0, tzinfo=timezone.utc))
        service = RiskService(database, clock)

        # ---- 组织与人员 ----
        service.register_organization(
            request_id="acc-org", actor_id="bootstrap", organization_id="org-highway",
            name="某市公路管理局")
        service.register_actor(
            request_id="acc-admin", actor_id="bootstrap", new_actor_id="admin-001",
            display_name="值班负责人", role="admin", organization_id="org-highway")
        service.register_actor(
            request_id="acc-operator", actor_id="admin-001", new_actor_id="operator-001",
            display_name="防汛值班员", role="operator", organization_id="org-highway")
        service.register_actor(
            request_id="acc-engineer", actor_id="admin-001", new_actor_id="engineer-001",
            display_name="桥隧养护工程师", role="engineer", organization_id="org-highway")
        service.register_site(
            request_id="acc-site", actor_id="admin-001", site_id="site-qinglong",
            organization_id="org-highway", name="青龙峡路网节点",
            timezone_name="Asia/Shanghai")

        # ---- 设施拓扑 ----
        service.register_facility(
            request_id="acc-bridge", actor_id="operator-001", site_id="site-qinglong",
            facility_id="bridge-qinglong", facility_type="bridge", name="青龙峡特大桥",
            kilometrage="K118+200", risk_level="high",
            attributes={"span_m": 860, "load_grade": "公路-I级"})
        service.register_facility(
            request_id="acc-slope", actor_id="operator-001", site_id="site-qinglong",
            facility_id="slope-nanan", facility_type="slope", name="南岸深挖边坡",
            kilometrage="K118+900", risk_level="normal",
            attributes={"height_m": 42, "retain": "锚杆框架"})
        service.link_facilities(
            request_id="acc-edge", actor_id="operator-001", link_id="edge-bridge-slope",
            upstream_facility_id="bridge-qinglong",
            downstream_facility_id="slope-nanan", relation="桥头紧邻边坡")

        # ---- 传感器与校准 ----
        service.register_sensor(
            request_id="acc-sensor-disp", actor_id="operator-001", sensor_id="sensor-disp",
            facility_id="bridge-qinglong", metric="displacement_mm", unit="mm",
            attributes={"position": "3号墩支座"})
        service.register_sensor(
            request_id="acc-sensor-moist", actor_id="operator-001", sensor_id="sensor-moist",
            facility_id="slope-nanan", metric="soil_moisture_pct", unit="%",
            attributes={"depth_m": 2.5})
        service.record_calibration(
            request_id="acc-cal-disp", actor_id="engineer-001", sensor_id="sensor-disp",
            calibration_id="cal-disp-2026q2", status="valid",
            valid_from="2026-04-01T00:00:00Z", valid_until="2026-08-01T00:00:00Z",
            drift=0.2, evidence_ref="CAL/CERT-2026-Q2-014",
            notes="汛期前专项校准")
        service.record_calibration(
            request_id="acc-cal-moist", actor_id="engineer-001", sensor_id="sensor-moist",
            calibration_id="cal-moist-2026q2", status="valid",
            valid_from="2026-04-01T00:00:00Z", valid_until="2026-10-01T00:00:00Z",
            evidence_ref="CAL/CERT-2026-Q2-027")

        # ---- 阈值规则 v1 与应急预案 v1 ----
        service.publish_rules(
            request_id="acc-rules-v1", actor_id="admin-001", version=1, window_minutes=180,
            rules=[
                {"rule_id": "R-BRIDGE-DISP", "facility_type": "bridge",
                 "metric": "displacement_mm", "weight": 0.6,
                 "thresholds": {"heighten": 10, "restrict": 20, "close": 35}},
                {"rule_id": "R-SLOPE-MOIST", "facility_type": "slope",
                 "metric": "soil_moisture_pct", "weight": 0.5,
                 "thresholds": {"heighten": 60, "restrict": 75, "close": 90}},
                {"rule_id": "R-INSPECTION", "source": "inspector", "weight": 0.4,
                 "report_levels": {"restrict": ["限行", "限速"],
                                   "close": ["封闭", "垮塌", "坍塌"]}},
            ])
        service.publish_plan(
            request_id="acc-plan-bridge-v1", actor_id="admin-001",
            facility_id="bridge-qinglong", version=1,
            steps=["heighten", "restrict", "close", "repair", "recheck", "reopen"])
        service.publish_plan(
            request_id="acc-plan-slope-v1", actor_id="admin-001",
            facility_id="slope-nanan", version=1,
            steps=["heighten", "restrict", "close", "repair", "recheck", "reopen"])

        # ===== 第一场强降雨：三源信号归并 =====
        clock.set_to(datetime(2026, 7, 14, 8, 0, tzinfo=timezone.utc))
        signal_bridge = service.ingest_observation(
            actor_id="operator-001", facility_id="bridge-qinglong", sensor_id="sensor-disp",
            source="sensor", metric="displacement_mm", value=22.4,
            observed_at=clock.now().isoformat(),
            payload={"position": "3号墩支座", "rainfall_mm": 86})
        clock.advance(minutes=22)
        signal_slope = service.ingest_observation(
            actor_id="operator-001", facility_id="slope-nanan", sensor_id="sensor-moist",
            source="sensor", metric="soil_moisture_pct", value=77.5,
            observed_at=clock.now().isoformat(), payload={"rainfall_mm": 91})
        clock.advance(minutes=13)
        signal_report = service.ingest_observation(
            actor_id="operator-001", facility_id="bridge-qinglong", source="inspector",
            metric="inspection_report",
            observed_at=clock.now().isoformat(),
            payload={"report": "3号墩支座位移明显，伸缩缝异响，建议封闭复核",
                     "inspector": "赵巡", "team": "桥梁巡检三班"})

        incident_id = signal_bridge["incident_id"]
        assert signal_slope["incident_id"] == incident_id
        assert signal_report["incident_id"] == incident_id
        incident = service.get_incident(incident_id)
        assert incident.severity == "close"
        initial_confidence = incident.confidence
        assert initial_confidence > 0.8

        # 迟到 3 小时、仅达升级阈值的含水观测：挂回同一事件，处置不倒退。
        service.advance_disposition(
            request_id="acc-bridge-heighten", actor_id="operator-001",
            incident_id=incident_id, facility_id="bridge-qinglong",
            stage="heighten", reason="08:00 位移 22.4mm 超过限行阈值，先行升级布控")
        service.advance_disposition(
            request_id="acc-bridge-restrict", actor_id="operator-001",
            incident_id=incident_id, facility_id="bridge-qinglong", stage="restrict",
            reason="位移持续 22.4mm（限行阈值 20mm），08:35 巡检同步预警，实施限行")
        restrict_receipt = service.get_disposition(
            service.get_incident(incident_id).dispositions[-1]["disposition_id"])
        late_signal = service.ingest_observation(
            actor_id="operator-001", facility_id="slope-nanan", sensor_id="sensor-moist",
            source="sensor", metric="soil_moisture_pct", value=61.0,
            observed_at="2026-07-14T05:10:00Z", payload={"delayed_upload": True})
        assert late_signal["incident_id"] == incident_id
        # 重复投递同一条迟到观测：幂等返回，不新增任何状态。
        duplicate_late = service.ingest_observation(
            actor_id="operator-001", facility_id="slope-nanan", sensor_id="sensor-moist",
            source="sensor", metric="soil_moisture_pct", value=61.0,
            observed_at="2026-07-14T05:10:00Z", payload={"delayed_upload": True})
        assert duplicate_late["replayed"] is True
        assert service.get_incident(incident_id).dispositions[-1]["stage"] == "restrict"

        # ===== 桥梁封闭到开放（高风险：双独立确认，首轮驳回一次） =====
        reopen_id = _full_disposition_chain(
            service, incident_id, "bridge-qinglong", prefix="acc-bridge",
            rejected_first=True,
            stages=("close", "repair", "recheck", "reopen"),
            reopen_confirmations=[
                ("bridge_load_test", "周检测", "省公路工程检测中心",
                 "荷载试验残余变形满足规范，同意开放", "CHK/LOAD-2026-0715-07"),
                ("independent_geo_radar", "吴物探", "国土资源勘测院（第三方）",
                 "地质雷达显示墩周土体密实，与管养单位无隶属关系",
             "CHK/GPR-2026-0715-11"),
            ])
        # 边坡为普通风险：一个外部确认即可开放。
        slope_reopen_id = _full_disposition_chain(
            service, incident_id, "slope-nanan", prefix="acc-slope",
            reopen_confirmations=[
                ("slope_stability_check", "郑检测", "省交通科学研究院",
                 "坡体位移收敛、排水畅通，同意开放", "CHK/SLOPE-2026-0715-03"),
            ])

        # ===== 规则换版（v2 更严格）不得改写历史限行决定 =====
        service.publish_rules(
            request_id="acc-rules-v2", actor_id="admin-001", version=2, window_minutes=120,
            rules=[
                {"rule_id": "R-BRIDGE-DISP", "facility_type": "bridge",
                 "metric": "displacement_mm", "weight": 0.8,
                 "thresholds": {"heighten": 5, "restrict": 10, "close": 20}},
                {"rule_id": "R-SLOPE-MOIST", "facility_type": "slope",
                 "metric": "soil_moisture_pct", "weight": 0.5,
                 "thresholds": {"heighten": 60, "restrict": 75, "close": 90}},
                {"rule_id": "R-INSPECTION", "source": "inspector", "weight": 0.4,
                 "report_levels": {"restrict": ["限行", "限速"],
                                   "close": ["封闭", "垮塌", "坍塌"]}},
            ])
        restrict_basis = service.decision_basis(restrict_receipt.disposition_id)
        reopen_basis = service.decision_basis(reopen_id)
        assert restrict_basis["snapshot"]["rule_version"] == 1
        assert restrict_basis["snapshot"]["rules"]["rules"][0]["thresholds"]["restrict"] == 20
        assert reopen_basis["snapshot"]["rule_version"] == 1
        assert reopen_basis["snapshot"]["plan_version"] == 1
        # 复核证据可追溯：技术确认编号、校准证书都在依据快照或确认记录中。
        reopen_view = service.get_disposition(reopen_id)
        confirmation_orgs = {c["confirmed_by_organization"] for c in reopen_view.confirmations}
        assert confirmation_orgs == {"省公路工程检测中心", "国土资源勘测院（第三方）"}
        cal_in_basis = reopen_basis["snapshot"]["calibration"]["sensor-disp"]
        assert cal_in_basis["status_at_observation"] == "valid"
        assert cal_in_basis["calibration_id"] == "cal-disp-2026q2"

        service.close_incident(
            request_id="acc-close-1", actor_id="admin-001", incident_id=incident_id,
            summary="7·14 强降雨处置完毕，桥梁与边坡恢复正常通行")
        timeline_1 = service.timeline(incident_id)

        # ===== 九月连阴雨：校准证书到期后的未结事件复审 =====
        clock.set_to(datetime(2026, 9, 16, 6, 30, tzinfo=timezone.utc))
        # 位移传感器校准证书 8 月 1 日已到期；其孤立信号不能单独支撑事件。
        lone = service.ingest_observation(
            actor_id="operator-001", facility_id="bridge-qinglong", sensor_id="sensor-disp",
            source="sensor", metric="displacement_mm", value=24.0,
            observed_at=clock.now().isoformat(), payload={"rainfall_mm": 64})
        assert lone["incident_id"] is None
        # 人工巡检独立印证后开立事件，到期传感器信号被追溯归并。
        second_report = service.ingest_observation(
            actor_id="operator-001", facility_id="bridge-qinglong", source="inspector",
            metric="inspection_report", observed_at=clock.now().isoformat(),
            payload={"report": "支座复测位移偏大，建议限行并核查传感器",
                     "inspector": "钱巡"})
        incident_two_id = second_report["incident_id"]
        assert incident_two_id is not None
        service.advance_disposition(
            request_id="acc-two-heighten", actor_id="operator-001",
            incident_id=incident_two_id, facility_id="bridge-qinglong", stage="heighten",
            reason="人工巡检发现位移异常，先升级，传感器数据待校准核查")
        service.advance_disposition(
            request_id="acc-two-restrict", actor_id="operator-001",
            incident_id=incident_two_id, facility_id="bridge-qinglong", stage="restrict",
            reason="人工与传感器方向一致，保守限行")
        review_before = service.review_queue()
        assert any(item["incident_id"] == incident_two_id for item in review_before)
        # 工程师登记校准失效，相关未结事件保持在复审队列中、不能关闭。
        service.record_calibration(
            request_id="acc-cal-fail", actor_id="engineer-001", sensor_id="sensor-disp",
            calibration_id="cal-disp-failed-0916", status="failed",
            valid_from="2026-09-16T00:00:00Z", drift=6.8,
            evidence_ref="CAL/FAIL-2026-0916-02", notes="比测超差，传感器下架")
        cannot_close = False
        try:
            service.close_incident(
                request_id="acc-close-two-early", actor_id="admin-001",
                incident_id=incident_two_id)
        except Exception:
            cannot_close = True
        assert cannot_close
        # 完成封闭-抢修-复检闭环后复审解除（复检以人工复核为准）。
        service.advance_disposition(
            request_id="acc-two-close", actor_id="admin-001",
            incident_id=incident_two_id, facility_id="bridge-qinglong", stage="close",
            reason="传感器失效且人工确认风险，封闭处治")
        service.advance_disposition(
            request_id="acc-two-repair", actor_id="engineer-001",
            incident_id=incident_two_id, facility_id="bridge-qinglong", stage="repair",
            reason="更换支座监测传感器并复位")
        service.advance_disposition(
            request_id="acc-two-recheck", actor_id="engineer-001",
            incident_id=incident_two_id, facility_id="bridge-qinglong", stage="recheck",
            reason="新传感器校准合格，人工复测位移收敛")
        review_after = service.review_queue()
        assert not any(item["incident_id"] == incident_two_id for item in review_after)
        timeline_2 = service.timeline(incident_two_id)

        audit_valid, audit_events = service.verify_audit()
        assert audit_valid

        # ---- 组装“每项措施依据”的解释视图 ----
        explanations = []
        for item in timeline_1["items"]:
            if item["kind"] != "disposition":
                continue
            basis = service.decision_basis(item["disposition_id"])
            explanations.append({
                "stage": item["stage"], "stage_label": STAGE_LABELS[item["stage"]],
                "facility_id": item["facility_id"], "decided_by": item["decided_by"],
                "rule_version": basis["snapshot"]["rule_version"],
                "plan_version": basis["snapshot"]["plan_version"],
                "confidence_at_decision": basis["snapshot"]["confidence"],
                "signal_count": len(basis["snapshot"]["signals"]),
                "reason": item["reason"],
                "thresholds_applied": [
                    {"metric": s["metric"], "matched_level": s["matched_level"],
                     "rule_id": s["evaluation"].get("rule_id"),
                     "threshold": s["evaluation"].get("threshold")}
                    for s in basis["snapshot"]["signals"]],
            })

        return {
            "status": "ok",
            "incident_one": {
                "incident_id": incident_id,
                "correlated_signals": 3,
                "severity": incident.severity,
                "confidence": initial_confidence,
                "impact_facilities": [f["facility_id"] for f in incident.facilities],
                "timeline_entries": len(timeline_1["items"]),
                "decision_explanations": explanations,
                "frozen_rule_version_after_v2": 1,
            },
            "incident_two": {
                "incident_id": incident_two_id,
                "expired_sensor_signal_held": lone["incident_id"] is None,
                "review_queue_before_recheck": [
                    item["incident_id"] for item in review_before],
                "close_blocked_until_recheck": cannot_close,
                "review_cleared_after_recheck": True,
                "timeline_entries": len(timeline_2["items"]),
            },
            "audit_valid": audit_valid,
            "audit_events": audit_events,
        }


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
