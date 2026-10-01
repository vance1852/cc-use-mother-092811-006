"""重点路桥风险处置服务的领域规则测试。"""

import unittest
from datetime import datetime, timezone

from transport_coordination.clock import SimulatedClock
from transport_coordination.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from transport_coordination.risk_service import RiskService
from transport_coordination.storage import Database


class RiskServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = SimulatedClock(datetime(2026, 7, 14, 0, 0, tzinfo=timezone.utc))
        self.service = RiskService(self.database, self.clock)
        self._bootstrap()

    def tearDown(self):
        self.database.close()

    def _bootstrap(self):
        s = self.service
        s.register_organization(request_id="org", actor_id="bootstrap",
                                organization_id="o1", name="公路管理局")
        s.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="adm",
                         display_name="管理员", role="admin", organization_id="o1")
        s.register_actor(request_id="operator", actor_id="adm", new_actor_id="op",
                         display_name="值班员", role="operator", organization_id="o1")
        s.register_actor(request_id="engineer", actor_id="adm", new_actor_id="eng",
                         display_name="桥隧工程师", role="engineer", organization_id="o1")
        s.register_actor(request_id="reviewer", actor_id="adm", new_actor_id="rev",
                         display_name="复核员", role="reviewer", organization_id="o1")
        s.register_site(request_id="site", actor_id="op", site_id="s1", organization_id="o1",
                        name="青龙峡节点", timezone_name="Asia/Shanghai")
        s.register_facility(request_id="fb", actor_id="op", site_id="s1", facility_id="bridge1",
                            facility_type="bridge", name="青龙峡大桥", kilometrage="K12+300",
                            risk_level="high")
        s.register_facility(request_id="fs", actor_id="op", site_id="s1", facility_id="slope1",
                            facility_type="slope", name="南岸边坡", kilometrage="K12+800",
                            risk_level="normal")
        s.link_facilities(request_id="fl", actor_id="op", link_id="edge1",
                          upstream_facility_id="bridge1", downstream_facility_id="slope1",
                          relation="adjacent")
        s.register_sensor(request_id="sd", actor_id="op", sensor_id="disp", facility_id="bridge1",
                          metric="displacement_mm", unit="mm")
        s.register_sensor(request_id="sm", actor_id="op", sensor_id="moist", facility_id="slope1",
                          metric="soil_moisture_pct", unit="%")
        s.record_calibration(request_id="cd", actor_id="eng", sensor_id="disp",
                             calibration_id="cal-disp", status="valid",
                             valid_from="2026-07-01T00:00:00Z",
                             valid_until="2026-08-01T00:00:00Z", evidence_ref="CAL-1")
        s.record_calibration(request_id="cm", actor_id="eng", sensor_id="moist",
                             calibration_id="cal-moist", status="valid",
                             valid_from="2026-07-01T00:00:00Z",
                             valid_until="2026-08-01T00:00:00Z")
        s.publish_rules(request_id="rv1", actor_id="adm", version=1, window_minutes=180, rules=[
            {"rule_id": "bridge-disp", "facility_type": "bridge", "metric": "displacement_mm",
             "weight": 0.6, "thresholds": {"heighten": 10, "restrict": 20, "close": 35}},
            {"rule_id": "slope-water", "facility_type": "slope", "metric": "soil_moisture_pct",
             "weight": 0.5, "thresholds": {"heighten": 60, "restrict": 75, "close": 90}},
            {"rule_id": "inspection", "source": "inspector", "weight": 0.4,
             "report_levels": {"restrict": ["限行"], "close": ["封闭", "垮塌"]}},
        ])
        s.publish_plan(request_id="pb1", actor_id="adm", facility_id="bridge1", version=1,
                       steps=["heighten", "restrict", "close", "repair", "recheck", "reopen"])
        s.publish_plan(request_id="ps1", actor_id="adm", facility_id="slope1", version=1,
                       steps=["heighten", "restrict", "close", "repair", "recheck", "reopen"])

    def _flood_signals(self):
        self.clock.set_to(datetime(2026, 7, 14, 8, 0, tzinfo=timezone.utc))
        o1 = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", sensor_id="disp", source="sensor",
            metric="displacement_mm", value=22.0, observed_at=self.clock.now().isoformat())
        self.clock.advance(minutes=20)
        o2 = self.service.ingest_observation(
            actor_id="op", facility_id="slope1", sensor_id="moist", source="sensor",
            metric="soil_moisture_pct", value=78.0, observed_at=self.clock.now().isoformat())
        self.clock.advance(minutes=15)
        o3 = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", source="inspector",
            metric="inspection_report", payload={"report": "支座位移超限，建议封闭"},
            observed_at=self.clock.now().isoformat())
        return o1, o2, o3

    def test_three_signals_correlate_to_one_incident(self):
        o1, o2, o3 = self._flood_signals()
        self.assertEqual(o1["incident_id"], o2["incident_id"])
        self.assertEqual(o2["incident_id"], o3["incident_id"])
        incident = self.service.get_incident(o1["incident_id"])
        self.assertEqual("open", incident.status)
        self.assertEqual("close", incident.severity)
        self.assertGreater(incident.confidence, 0.8)
        facilities = {item["facility_id"]: item["role"] for item in incident.facilities}
        self.assertEqual("primary", facilities["bridge1"])
        self.assertEqual("impacted", facilities["slope1"])
        self.assertTrue(incident.impact["blocked"])

    def test_signal_below_threshold_does_not_open_incident(self):
        result = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", sensor_id="disp", source="sensor",
            metric="displacement_mm", value=3.0, observed_at="2026-07-14T08:00:00Z")
        self.assertIsNone(result["incident_id"])
        self.assertEqual([], self.service.list_open_incidents())

    def test_duplicate_observation_is_idempotent_and_changes_nothing(self):
        first = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", sensor_id="disp", source="sensor",
            metric="displacement_mm", value=22.0, observed_at="2026-07-14T08:00:00Z")
        second = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", sensor_id="disp", source="sensor",
            metric="displacement_mm", value=22.0, observed_at="2026-07-14T08:00:00Z")
        self.assertTrue(second["replayed"])
        self.assertEqual(first["observation_id"], second["observation_id"])

    def test_late_observation_attaches_without_regressing_disposition(self):
        o1, _o2, _o3 = self._flood_signals()
        incident_id = o1["incident_id"]
        self.service.advance_disposition(
            request_id="h1", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        self.service.advance_disposition(
            request_id="r1", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="restrict", reason="限行")
        late = self.service.ingest_observation(
            actor_id="op", facility_id="slope1", sensor_id="moist", source="sensor",
            metric="soil_moisture_pct", value=61.0, observed_at="2026-07-14T05:00:00Z")
        self.assertEqual(incident_id, late["incident_id"])
        current = self.service.get_incident(incident_id).dispositions
        self.assertEqual("restrict", current[-1]["stage"])
        with self.assertRaises(ConflictError):
            self.service.advance_disposition(
                request_id="back", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", stage="heighten", reason="试图倒退")

    def test_dispositions_follow_permissions_and_order(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        with self.assertRaises(PermissionDenied):
            self.service.advance_disposition(
                request_id="req-x", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", stage="close", reason="值班员无权封闭")
        self.service.advance_disposition(
            request_id="req-h", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        with self.assertRaises(ConflictError):
            self.service.advance_disposition(
                request_id="repair-first", actor_id="eng", incident_id=incident_id,
                facility_id="bridge1", stage="repair", reason="未封闭先抢修")
        self.service.advance_disposition(
            request_id="req-r", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="restrict", reason="限行")
        self.service.advance_disposition(
            request_id="req-c", actor_id="adm", incident_id=incident_id, facility_id="bridge1",
            stage="close", reason="封闭")
        with self.assertRaises(PermissionDenied):
            self.service.advance_disposition(
                request_id="repair-op", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", stage="repair", reason="值班员无权抢修")
        self.service.advance_disposition(
            request_id="rep", actor_id="eng", incident_id=incident_id, facility_id="bridge1",
            stage="repair", reason="抢修")
        self.service.advance_disposition(
            request_id="rec", actor_id="eng", incident_id=incident_id, facility_id="bridge1",
            stage="recheck", reason="复检")
        with self.assertRaises(ConflictError):
            self.service.advance_disposition(
                request_id="reopen-early", actor_id="adm", incident_id=incident_id,
                facility_id="slope1", stage="reopen", reason="边坡尚未复检")

    def test_high_risk_reopen_requires_two_independent_confirmations(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        for request_id, actor, stage, reason in [
                ("req-h2", "op", "heighten", "升级"), ("req-r2", "op", "restrict", "限行"),
                ("req-c2", "adm", "close", "封闭"), ("req-rep2", "eng", "repair", "抢修"),
                ("req-rec2", "eng", "recheck", "复检")]:
            self.service.advance_disposition(
                request_id=request_id, actor_id=actor, incident_id=incident_id,
                facility_id="bridge1", stage=stage, reason=reason)
        reopen = self.service.advance_disposition(
            request_id="ro", actor_id="adm", incident_id=incident_id, facility_id="bridge1",
            stage="reopen", reason="申请开放")
        self.assertEqual("pending_confirmation",
                         self.service.get_disposition(reopen.resource_id).status)
        # 运营方自我确认不允许。
        with self.assertRaises(ValidationError):
            self.service.add_technical_confirmation(
                request_id="self", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", channel="inspection", result="approved",
                opinion="合格", evidence_ref="E", confirmed_by="某检测员",
                confirmed_by_organization="o1")
        self.service.add_technical_confirmation(
            request_id="k1", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            channel="bridge_inspection", result="approved", opinion="结构合格",
            evidence_ref="R-1", confirmed_by="李检测", confirmed_by_organization="检测中心A")
        self.assertEqual("pending_confirmation",
                         self.service.get_disposition(reopen.resource_id).status)
        # 渠道、确认人、机构任一重复都不允许。
        with self.assertRaises(ConflictError):
            self.service.add_technical_confirmation(
                request_id="k-dup-channel", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", channel="bridge_inspection", result="approved",
                opinion="x", evidence_ref="E", confirmed_by="王检测",
                confirmed_by_organization="检测中心B")
        with self.assertRaises(ConflictError):
            self.service.add_technical_confirmation(
                request_id="k-dup-person", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", channel="load_test", result="approved",
                opinion="x", evidence_ref="E", confirmed_by="李检测",
                confirmed_by_organization="检测中心B")
        with self.assertRaises(ConflictError):
            self.service.add_technical_confirmation(
                request_id="k-dup-org", actor_id="op", incident_id=incident_id,
                facility_id="bridge1", channel="geo_radar", result="approved",
                opinion="x", evidence_ref="E", confirmed_by="陈检测",
                confirmed_by_organization="检测中心A")
        self.service.add_technical_confirmation(
            request_id="k2", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            channel="load_test", result="approved", opinion="荷载试验合格",
            evidence_ref="R-2", confirmed_by="陈检测", confirmed_by_organization="检测中心D")
        self.assertEqual("effective",
                         self.service.get_disposition(reopen.resource_id).status)

    def test_rejection_cancels_reopen_and_request_can_be_renewed(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        for request_id, actor, stage in [
                ("req-h3", "op", "heighten"), ("req-r3", "op", "restrict"), ("req-c3", "adm", "close"),
                ("req-rep3", "eng", "repair"), ("req-rec3", "eng", "recheck")]:
            self.service.advance_disposition(
                request_id=request_id, actor_id=actor, incident_id=incident_id,
                facility_id="bridge1", stage=stage, reason=stage)
        reopen = self.service.advance_disposition(
            request_id="ro", actor_id="adm", incident_id=incident_id, facility_id="bridge1",
            stage="reopen", reason="申请开放")
        self.service.add_technical_confirmation(
            request_id="k1", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            channel="bridge_inspection", result="rejected", opinion="仍有异常",
            evidence_ref="R-1", confirmed_by="李检测", confirmed_by_organization="检测中心A")
        self.assertEqual("cancelled",
                         self.service.get_disposition(reopen.resource_id).status)
        renewed = self.service.advance_disposition(
            request_id="ro2", actor_id="adm", incident_id=incident_id, facility_id="bridge1",
            stage="reopen", reason="缺陷消除后重新申请")
        self.assertNotEqual(reopen.resource_id, renewed.resource_id)

    def test_rule_revision_does_not_change_published_decisions(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        receipt = self.service.advance_disposition(
            request_id="req-r", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="restrict", reason="位移超过 v1 限行阈值 20mm")
        basis = self.service.decision_basis(receipt.resource_id)
        self.assertEqual(1, basis["snapshot"]["rule_version"])
        self.service.publish_rules(request_id="rv2", actor_id="adm", version=2, rules=[
            {"rule_id": "bridge-disp", "facility_type": "bridge", "metric": "displacement_mm",
             "weight": 0.9, "thresholds": {"heighten": 5, "restrict": 10, "close": 15}}])
        basis_after = self.service.decision_basis(receipt.resource_id)
        self.assertEqual(1, basis_after["snapshot"]["rule_version"])
        self.assertEqual(20, basis_after["snapshot"]["rules"]["rules"][0]["thresholds"]["restrict"])
        metrics = {signal["metric"] for signal in basis_after["snapshot"]["signals"]}
        self.assertIn("displacement_mm", metrics)

    def test_calibration_failure_flags_open_incident_for_review(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        self.service.advance_disposition(
            request_id="req-h", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        self.service.advance_disposition(
            request_id="req-r", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="restrict", reason="限行")
        self.assertEqual([], self.service.review_queue())
        self.service.record_calibration(
            request_id="cfail", actor_id="eng", sensor_id="disp",
            calibration_id="cal-failed", status="failed",
            valid_from="2026-07-20T00:00:00Z", evidence_ref="FAIL")
        queue = self.service.review_queue()
        self.assertEqual(1, len(queue))
        self.assertEqual(incident_id, queue[0]["incident_id"])
        with self.assertRaises(ConflictError):
            self.service.close_incident(request_id="close", actor_id="adm",
                                        incident_id=incident_id)
        # 完成复检并开放后复审解除。
        self.service.advance_disposition(
            request_id="req-c", actor_id="adm", incident_id=incident_id, facility_id="bridge1",
            stage="close", reason="封闭")
        self.service.advance_disposition(
            request_id="rep", actor_id="eng", incident_id=incident_id, facility_id="bridge1",
            stage="repair", reason="抢修")
        self.service.advance_disposition(
            request_id="rec", actor_id="eng", incident_id=incident_id, facility_id="bridge1",
            stage="recheck", reason="复检")
        self.assertEqual([], self.service.review_queue())

    def test_expired_calibration_signal_needs_corroboration(self):
        self.clock.set_to(datetime(2026, 9, 1, tzinfo=timezone.utc))
        lone = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", sensor_id="disp", source="sensor",
            metric="displacement_mm", value=25.0, observed_at=self.clock.now().isoformat())
        self.assertIsNone(lone["incident_id"])
        report = self.service.ingest_observation(
            actor_id="op", facility_id="bridge1", source="inspector",
            metric="inspection_report", payload={"report": "现场建议限行"},
            observed_at=self.clock.now().isoformat())
        self.assertIsNotNone(report["incident_id"])
        incident = self.service.get_incident(report["incident_id"])
        sensor_signal = next(s for s in incident.signals if s.source == "sensor")
        self.assertEqual("expired", sensor_signal.calibration_status)
        self.assertTrue(all(m["qualified"] for m in sensor_signal.matches))
        self.assertTrue(any(item["incident_id"] == report["incident_id"]
                            for item in self.service.review_queue()))

    def test_timeline_replays_signal_to_reopening(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        self.service.advance_disposition(
            request_id="req-h", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        timeline = self.service.timeline(incident_id)
        self.assertEqual("signal", timeline["items"][0]["kind"])
        signal = timeline["items"][0]
        self.assertEqual("restrict", signal["matched_level"])
        self.assertEqual(20, signal["threshold"])
        disposition = next(item for item in timeline["items"] if item["kind"] == "disposition")
        self.assertEqual("heighten", disposition["stage"])
        self.assertEqual(1, disposition["rule_version"])
        self.assertTrue(disposition["basis_id"])

    def test_facility_and_sensor_validation(self):
        with self.assertRaises(ValidationError):
            self.service.register_facility(
                request_id="bad", actor_id="op", site_id="s1", facility_id="f-x",
                facility_type="airport", name="x", kilometrage="K1", risk_level="normal")
        with self.assertRaises(NotFoundError):
            self.service.register_sensor(
                request_id="bad2", actor_id="op", sensor_id="sx", facility_id="missing",
                metric="m", unit="u")

    def test_replayed_disposition_request_returns_same_receipt(self):
        incident_id = self._flood_signals()[0]["incident_id"]
        first = self.service.advance_disposition(
            request_id="req-h", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        second = self.service.advance_disposition(
            request_id="req-h", actor_id="op", incident_id=incident_id, facility_id="bridge1",
            stage="heighten", reason="升级")
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)

    def test_audit_chain_covers_risk_actions(self):
        self._flood_signals()
        valid, count = self.service.verify_audit()
        self.assertTrue(valid)
        self.assertGreater(count, 10)


if __name__ == "__main__":
    unittest.main()
