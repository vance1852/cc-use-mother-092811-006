"""重点路桥风险处置服务的离线端到端验收。

重放一场强降雨（episode=storm-2026-0925）从首个信号到恢复通行的时间线：
桥梁位移、边坡含水、巡检报告三类信号归并为同一事件，按顺序完成升级、限行、
封闭；途中传感器校准失效冻结处置，经独立机构技术复核后继续抢修、复检；
规则换版不改变既有冻结版本；高风险桥梁由两名相互独立的技术人确认后开放；
重复/迟到观测不倒退状态；并识别校准失效后需要重新审查的未结事件。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import FixedClock
from .risk_service import RiskService
from .storage import Database

START = datetime(2026, 9, 25, 1, 30, tzinfo=timezone.utc)


def run() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "risk_acceptance.sqlite3")
        clock = FixedClock(START)
        service = RiskService(database, clock)

        def tick(minutes: int = 0):
            service.clock = FixedClock(START + timedelta(minutes=minutes))
            return (START + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

        def ts(minutes: int) -> str:
            return (START + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

        # ---------------------------------------------------------- 组织与角色
        service.register_organization(request_id="org-hwy", actor_id="bootstrap",
                                      organization_id="org-hwy", name="公路管理局")
        service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin",
                               display_name="管理员", role="admin", organization_id="org-hwy")
        service.register_organization(request_id="org-qjc", actor_id="admin",
                                      organization_id="org-qjc", name="桥隧检测中心")
        service.register_actor(request_id="duty", actor_id="admin", new_actor_id="op-duty",
                               display_name="值班员", role="operator", organization_id="org-hwy")
        service.register_actor(request_id="repair", actor_id="admin", new_actor_id="op-repair",
                               display_name="抢修负责人", role="operator", organization_id="org-hwy")
        service.register_actor(request_id="rv-hwy", actor_id="admin", new_actor_id="rv-hwy",
                               display_name="公路局桥梁工程师", role="reviewer",
                               organization_id="org-hwy")
        service.register_actor(request_id="rv-qjc", actor_id="admin", new_actor_id="rv-qjc",
                               display_name="检测中心检测师", role="reviewer",
                               organization_id="org-qjc")
        service.register_actor(request_id="auditor", actor_id="admin", new_actor_id="au1",
                               display_name="审计员", role="auditor", organization_id="org-hwy")
        service.register_site(request_id="site", actor_id="admin", site_id="site-1",
                              organization_id="org-hwy", name="沿江通道",
                              timezone_name="Asia/Shanghai")

        # ------------------------------------------------------------ 设施拓扑
        service.register_facility(request_id="fac-bridge", actor_id="admin",
                                  facility_id="b-001", site_id="site-1",
                                  facility_type="bridge", name="一号高架桥",
                                  criticality="high", payload={"span_m": 320})
        service.register_facility(request_id="fac-slope", actor_id="admin",
                                  facility_id="sp-001", site_id="site-1",
                                  facility_type="slope", name="一号桥北岸边坡",
                                  criticality="normal")
        service.register_facility(request_id="fac-road", actor_id="admin",
                                  facility_id="rd-001", site_id="site-1",
                                  facility_type="road", name="沿江路K12段",
                                  criticality="normal")
        service.register_facility_link(request_id="link-sp-b", actor_id="admin",
                                       upstream_id="sp-001", downstream_id="b-001",
                                       relation="边坡邻接桥梁")
        service.register_facility_link(request_id="link-b-rd", actor_id="admin",
                                       upstream_id="b-001", downstream_id="rd-001",
                                       relation="桥梁承担路段")

        # ------------------------------------------------------------ 传感器登记
        service.register_sensor(request_id="sensor-b", actor_id="admin", sensor_id="sb-001",
                                facility_id="b-001", metric="displacement_mm", unit="mm",
                                calibrated_at=ts(-1440))
        service.register_sensor(request_id="sensor-s", actor_id="admin", sensor_id="ss-001",
                                facility_id="sp-001", metric="moisture_pct", unit="%",
                                calibrated_at=ts(-1440))

        # --------------------------------------------------- 阈值规则 v1 与预案
        rules_v1 = [
            {"rule_id": "disp", "facility_type": "bridge", "metric": "displacement_mm",
             "operator": ">=", "thresholds": {"watch": 5, "warning": 10, "danger": 20}},
            {"rule_id": "moist", "facility_type": "slope", "metric": "moisture_pct",
             "operator": ">=", "thresholds": {"watch": 60, "warning": 75, "danger": 85}},
        ]
        service.register_rule_version(request_id="rules-v1", actor_id="admin",
                                      rule_version_id="rules-v1", rules=rules_v1,
                                      activate=True)
        service.register_plan_version(
            request_id="plan-v1", actor_id="admin", plan_version_id="plan-v1",
            scope={"facility_ids": ["b-001"], "facility_types": ["bridge"]},
            content={"name": "高风险桥梁汛期预案", "response_levels": {"danger": 4},
                     "open_confirmations": {"high": 2, "normal": 1}}, activate=True)

        # ==================== 灾害发生：三类信号归并为一个事件 ==================
        tick(30)
        r1 = service.ingest_observation(request_id="obs-1", actor_id="op-duty",
                                        facility_id="b-001", source_kind="sensor",
                                        sensor_id="sb-001", metric="displacement_mm",
                                        value=22.5, observed_at=ts(30),
                                        episode_id="storm-2026-0925")
        assert r1.resource_id  # observation 回执
        # 事件号从按 episode 的事件查询获得。
        event_id = service.list_events(episode_id="storm-2026-0925")[0]["event_id"]

        tick(35)
        service.ingest_observation(request_id="obs-2", actor_id="op-duty",
                                   facility_id="b-001", source_kind="manual",
                                   reporter_id="rv-hwy", metric="visual_crack",
                                   reported_level="warning",
                                   text="巡检发现梁体斜裂缝约1.2mm", observed_at=ts(35),
                                   episode_id="storm-2026-0925")
        tick(42)
        service.ingest_observation(request_id="obs-3", actor_id="op-duty",
                                   facility_id="sp-001", source_kind="sensor",
                                   sensor_id="ss-001", metric="moisture_pct",
                                   value=88.0, observed_at=ts(42),
                                   episode_id="storm-2026-0925")

        events = service.list_events(episode_id="storm-2026-0925")
        assert len(events) == 1, "三类信号必须归并为同一事件"
        event = service.get_event(event_id)
        assert event["severity"] == "danger"
        assert event["response_level"] == 4, "预案把 danger 提升到 4 级响应"
        assert len(event["signals"]) == 3
        assert event["confidence"] >= 0.9, f"多通道多指标置信度应较高，实际 {event['confidence']}"
        impacted = {item["facility_id"] for item in event["impact_area"]}
        assert impacted == {"b-001", "sp-001", "rd-001"}, impacted

        # 重复观测：同读数同时刻再次上报，只留档，不产生信号。
        tick(45)
        duplicate = service.ingest_observation(request_id="obs-dup", actor_id="op-duty",
                                               facility_id="b-001", source_kind="sensor",
                                               sensor_id="sb-001", metric="displacement_mm",
                                               value=22.5, observed_at=ts(30),
                                               episode_id="storm-2026-0925")
        dup_response = json.loads(
            database.connection.execute(
                "SELECT response_json FROM request_receipts WHERE request_id='obs-dup'").fetchone()[0])
        assert dup_response["duplicate"] is True
        assert service.get_event(event_id)["state"] == "detected"

        # ==================== 升级 → 限行 → 封闭 ====================
        tick(50)
        service.decide(request_id="esc-1", actor_id="op-duty", event_id=event_id,
                       action="escalate", note="启动四级响应，通知值班领导")
        tick(55)
        service.decide(request_id="res-1", actor_id="op-duty", event_id=event_id,
                       action="restrict", note="限载30吨、限速20")
        tick(60)
        service.decide(request_id="cls-1", actor_id="op-duty", event_id=event_id,
                       action="close", note="位移超危险阈值，全封闭")
        # 顺序错误不能倒退/跳步：封闭后直接开放必须失败且状态不变。
        bad = service.attempt(request_id="bad-open", actor_id="op-duty", event_id=event_id,
                              action="open")
        assert bad["accepted"] is False
        assert service.get_event(event_id)["state"] == "closed"
        # 审计员无权处置。
        bad_role = service.attempt(request_id="bad-role", actor_id="au1", event_id=event_id,
                                   action="repair")
        assert bad_role["accepted"] is False

        # ============== 校准失效：处置冻结，事件进入待复核清单 ==============
        tick(120)
        cal = service.record_calibration(request_id="cal-fail", actor_id="rv-hwy",
                                         sensor_id="sb-001", status="failed",
                                         effective_at=ts(120), note="强降雨后零点漂移")
        assert any(item["event_id"] == event_id for item in json.loads(
            database.connection.execute(
                "SELECT response_json FROM request_receipts WHERE request_id='cal-fail'"
            ).fetchone()[0])["events"])
        reviews_pending = service.list_reviews_required()
        assert any(item["event_id"] == event_id for item in reviews_pending)
        blocked = service.attempt(request_id="repair-blocked", actor_id="op-repair",
                                  event_id=event_id, action="repair")
        assert blocked["accepted"] is False and "复核" in blocked["reason"]

        # 公路局工程师复核：裂缝仍在、边坡含水率独立佐证位移异常，结论有效。
        service.review_event_after_calibration(
            request_id="review-1", actor_id="rv-hwy", event_id=event_id,
            failed_sensor_id="sb-001", conclusion="valid",
            evidence={"crack_width_mm": 1.3, "independent_moisture_pct": 88.0,
                      "manual_survey_at": ts(125)},
            note="人工复测确认位移趋势真实")
        assert not service.get_event(event_id)["review_required"]

        # ==================== 抢修 → 复检 ====================
        tick(130)
        service.decide(request_id="rep-1", actor_id="op-repair", event_id=event_id,
                       action="repair", note="支座复位、裂缝注胶")
        # 没有复检证据不能进入复检完成。
        no_reinspect = service.attempt(request_id="rein-blocked", actor_id="rv-hwy",
                                       event_id=event_id, action="reinspect")
        assert no_reinspect["accepted"] is False
        tick(270)
        service.record_calibration(request_id="cal-restore", actor_id="rv-qjc",
                                   sensor_id="sb-001", status="valid",
                                   effective_at=ts(270), note="重新标定合格")
        service.ingest_observation(request_id="obs-rein", actor_id="rv-hwy",
                                   facility_id="b-001", source_kind="manual",
                                   reporter_id="rv-hwy", metric="reinspection",
                                   text="复测位移3.1mm，裂缝稳定，具备开放条件",
                                   reported_level="watch", observed_at=ts(275),
                                   is_reinspection=True, episode_id="storm-2026-0925")
        tick(280)
        service.decide(request_id="rein-1", actor_id="rv-hwy", event_id=event_id,
                       action="reinspect", note="复检合格")

        # 规则换版（放宽危险阈值到 30mm），不得静默改变已发布决定。
        rules_v2 = [
            {"rule_id": "disp", "facility_type": "bridge", "metric": "displacement_mm",
             "operator": ">=", "thresholds": {"watch": 8, "warning": 15, "danger": 30}},
            {"rule_id": "moist", "facility_type": "slope", "metric": "moisture_pct",
             "operator": ">=", "thresholds": {"watch": 60, "warning": 75, "danger": 85}},
        ]
        service.register_rule_version(request_id="rules-v2", actor_id="admin",
                                      rule_version_id="rules-v2", rules=rules_v2,
                                      activate=True)

        # ============== 相互独立的双技术确认后开放高风险桥梁 ==============
        # 只有一份确认不能开放。
        service.add_technical_confirmation(
            request_id="conf-hwy", actor_id="rv-hwy", event_id=event_id,
            evidence={"load_test": "满足汽-20", "displacement_mm": 3.1},
            opinion="结构安全，同意开放")
        one_conf = service.attempt(request_id="open-one", actor_id="op-repair",
                                   event_id=event_id, action="open")
        assert one_conf["accepted"] is False and "2 份" in one_conf["reason"]
        # 同一机构两名确认人不满足相互独立（此处用第二家检测机构）。
        service.add_technical_confirmation(
            request_id="conf-qjc", actor_id="rv-qjc", event_id=event_id,
            evidence={"report_no": "QJC-2026-0925", "conclusion": "合格"},
            opinion="第三方检测同意开放")
        # 技术确认人本人不能充当开放决策人。
        opener_is_confirmer = service.attempt(request_id="open-self", actor_id="rv-hwy",
                                              event_id=event_id, action="open")
        assert opener_is_confirmer["accepted"] is False
        tick(300)
        opened = service.decide(request_id="open-1", actor_id="op-repair",
                                event_id=event_id, action="open", note="解除封闭恢复通行")
        open_basis = opened.resource_id and json.loads(
            database.connection.execute(
                "SELECT basis_json FROM risk_decisions WHERE decision_id=?",
                (opened.resource_id,)).fetchone()[0])
        assert open_basis["frozen_rule_version_id"] == "rules-v1"
        assert open_basis["active_rule_version_at_decision"] == "rules-v2"
        assert open_basis["frozen_plan_version_id"] == "plan-v1"
        assert len(open_basis["technical_confirmations"]) == 2
        assert {c["organization_id"] for c in open_basis["technical_confirmations"]} == {
            "org-hwy", "org-qjc"}
        final = service.get_event(event_id)
        assert final["state"] == "opened"
        assert final["control_status"] == "open"

        # ============== 重复与迟到观测不能倒退处置状态 ==============
        tick(330)
        late = service.ingest_observation(request_id="obs-late", actor_id="op-duty",
                                          facility_id="b-001", source_kind="sensor",
                                          sensor_id="sb-001", metric="displacement_mm",
                                          value=21.0, observed_at=ts(20), late=True,
                                          episode_id="storm-2026-0925")
        late_resp = json.loads(database.connection.execute(
            "SELECT response_json FROM request_receipts WHERE request_id='obs-late'"
        ).fetchone()[0])
        assert late_resp["event_id"] != event_id, "迟到信号不能重新打开已开放事件"
        assert service.get_event(event_id)["state"] == "opened"

        # ==================== 时间线解释与审计校验 ====================
        timeline = service.event_timeline(event_id)
        action_sequence = [item["action"] for item in timeline["items"]
                           if item["kind"] == "decision"]
        assert action_sequence == ["escalate", "restrict", "close", "repair",
                                   "reinspect", "open"], action_sequence
        assert any(item["kind"] == "rejected_attempt" for item in timeline["items"])
        assert any(item["kind"] == "calibration_review" for item in timeline["items"])
        assert any(item.get("duplicate") for item in timeline["items"]
                   if item["kind"] == "observation")
        # 每项措施依据中都能找到当时冻结的阈值证据。
        close_basis = next(item["basis"] for item in timeline["items"]
                           if item["kind"] == "decision" and item["action"] == "close")
        assert close_basis["frozen_rule_content_hash"]
        assert any(s["matched"].get("threshold") == 20 for s in close_basis["signals"])

        valid, audit_count = service.verify_audit()
        result = {
            "status": "ok",
            "event_id": event_id,
            "events_in_episode": len(events),
            "signal_count": len(final["signals"]),
            "confidence": final["confidence"],
            "response_level": final["response_level"],
            "impact_facilities": sorted(impacted),
            "action_sequence": action_sequence,
            "state": final["state"],
            "frozen_rule_at_open": open_basis["frozen_rule_version_id"],
            "active_rule_at_open": open_basis["active_rule_version_at_decision"],
            "open_confirmations": [
                c["organization_id"] for c in open_basis["technical_confirmations"]],
            "late_observation_new_event": late_resp["event_id"],
            "reviews_required_after_calibration": [
                item["event_id"] for item in reviews_pending],
            "timeline_items": len(timeline["items"]),
            "audit_valid": valid,
            "audit_events": audit_count,
        }
        database.close()
        return result


def main() -> int:
    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
