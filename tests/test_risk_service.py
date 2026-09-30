import unittest
from datetime import datetime, timedelta, timezone

from transport_coordination.clock import FixedClock
from transport_coordination.errors import ConflictError, PermissionDenied
from transport_coordination.risk_service import RiskService
from transport_coordination.storage import Database

START = datetime(2026, 9, 25, 1, 30, tzinfo=timezone.utc)


def t(minutes: int) -> str:
    return (START + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


class RiskTestBase(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = RiskService(self.database, FixedClock(START))
        s = self.service
        s.register_organization(request_id="org-h", actor_id="bootstrap",
                                organization_id="org-h", name="公路局")
        s.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin",
                         display_name="管理员", role="admin", organization_id="org-h")
        s.register_organization(request_id="org-t", actor_id="admin",
                                organization_id="org-t", name="检测中心")
        s.register_actor(request_id="op", actor_id="admin", new_actor_id="op1",
                         display_name="值班员", role="operator", organization_id="org-h")
        s.register_actor(request_id="rv-h", actor_id="admin", new_actor_id="rv-h",
                         display_name="局工程师", role="reviewer", organization_id="org-h")
        s.register_actor(request_id="rv-t", actor_id="admin", new_actor_id="rv-t",
                         display_name="检测师", role="reviewer", organization_id="org-t")
        s.register_actor(request_id="au", actor_id="admin", new_actor_id="au1",
                         display_name="审计员", role="auditor", organization_id="org-h")
        s.register_site(request_id="site", actor_id="admin", site_id="site-1",
                        organization_id="org-h", name="沿江通道", timezone_name="Asia/Shanghai")
        s.register_facility(request_id="fb", actor_id="admin", facility_id="b1",
                            site_id="site-1", facility_type="bridge", name="一号桥",
                            criticality="high")
        s.register_facility(request_id="fs", actor_id="admin", facility_id="s1",
                            site_id="site-1", facility_type="slope", name="边坡")
        s.register_facility(request_id="fr", actor_id="admin", facility_id="r1",
                            site_id="site-1", facility_type="road", name="路段")
        s.register_facility_link(request_id="lk1", actor_id="admin", upstream_id="s1",
                                 downstream_id="b1", relation="邻接")
        s.register_facility_link(request_id="lk2", actor_id="admin", upstream_id="b1",
                                 downstream_id="r1", relation="承担")
        s.register_sensor(request_id="sb", actor_id="admin", sensor_id="sb1",
                          facility_id="b1", metric="disp", calibrated_at=t(-60))
        s.register_sensor(request_id="ss", actor_id="admin", sensor_id="ss1",
                          facility_id="s1", metric="moist", calibrated_at=t(-60))
        s.register_rule_version(request_id="rv1", actor_id="admin", rule_version_id="rules-1",
                                rules=[
                                    {"rule_id": "rd", "facility_type": "bridge", "metric": "disp",
                                     "thresholds": {"watch": 5, "warning": 10, "danger": 20}},
                                    {"rule_id": "rm", "facility_type": "slope", "metric": "moist",
                                     "thresholds": {"watch": 60, "warning": 75, "danger": 85}},
                                ], activate=True)

    def tearDown(self):
        self.database.close()

    def storm_signals(self):
        s = self.service
        s.ingest_observation(request_id="o1", actor_id="op1", facility_id="b1",
                             source_kind="sensor", sensor_id="sb1", metric="disp",
                             value=22.0, observed_at=t(1), episode_id="storm")
        s.ingest_observation(request_id="o2", actor_id="op1", facility_id="b1",
                             source_kind="manual", reporter_id="rv-h", metric="crack",
                             reported_level="warning", text="斜裂缝", observed_at=t(2),
                             episode_id="storm")
        s.ingest_observation(request_id="o3", actor_id="op1", facility_id="s1",
                             source_kind="sensor", sensor_id="ss1", metric="moist",
                             value=88.0, observed_at=t(3), episode_id="storm")
        return s.list_events(episode_id="storm")[0]["event_id"]


class CorrelationTest(RiskTestBase):
    def test_three_signals_merge_with_confidence_and_impact(self):
        event_id = self.storm_signals()
        event = self.service.get_event(event_id)
        self.assertEqual("detected", event["state"])
        self.assertEqual("danger", event["severity"])
        self.assertEqual(3, len(event["signals"]))
        self.assertGreaterEqual(event["confidence"], 0.9)
        facilities = {item["facility_id"] for item in event["impact_area"]}
        self.assertEqual({"b1", "s1", "r1"}, facilities)
        road = next(item for item in event["impact_area"] if item["facility_id"] == "r1")
        self.assertEqual(1, road["distance"])

    def test_unrelated_signals_create_separate_events(self):
        s = self.service
        s.register_facility(request_id="ft", actor_id="admin", facility_id="t1",
                            site_id="site-1", facility_type="tunnel", name="远端隧道")
        s.ingest_observation(request_id="o1", actor_id="op1", facility_id="b1",
                             source_kind="sensor", sensor_id="sb1", metric="disp",
                             value=22.0, observed_at=t(1))
        s.ingest_observation(request_id="o2", actor_id="op1", facility_id="t1",
                             source_kind="manual", reporter_id="rv-h", metric="patrol",
                             reported_level="warning", text="渗水", observed_at=t(2))
        self.assertEqual(2, len(s.list_events()))

    def test_same_facility_within_window_correlates_without_episode(self):
        s = self.service
        s.ingest_observation(request_id="o1", actor_id="op1", facility_id="b1",
                             source_kind="sensor", sensor_id="sb1", metric="disp",
                             value=22.0, observed_at=t(1))
        s.ingest_observation(request_id="o2", actor_id="op1", facility_id="b1",
                             source_kind="sensor", sensor_id="sb1", metric="disp",
                             value=23.0, observed_at=t(20))
        self.assertEqual(1, len(s.list_events()))

    def test_observation_below_threshold_creates_no_signal(self):
        s = self.service
        receipt = s.ingest_observation(request_id="o1", actor_id="op1", facility_id="b1",
                                      source_kind="sensor", sensor_id="sb1", metric="disp",
                                      value=1.0, observed_at=t(1))
        self.assertNotIn("signal_id", receipt.response or {})
        self.assertEqual(0, len(s.list_events()))


class DisposalTest(RiskTestBase):
    def drive_to_closed(self, event_id):
        s = self.service
        s.decide(request_id="d1", actor_id="op1", event_id=event_id, action="escalate")
        s.decide(request_id="d2", actor_id="op1", event_id=event_id, action="restrict")
        s.decide(request_id="d3", actor_id="op1", event_id=event_id, action="close")

    def test_state_machine_must_advance_in_order(self):
        event_id = self.storm_signals()
        with self.assertRaises(ConflictError):
            self.service.decide(request_id="xx", actor_id="op1", event_id=event_id,
                                action="close")
        self.assertEqual("detected", self.service.get_event(event_id)["state"])
        self.drive_to_closed(event_id)
        self.assertEqual("closed", self.service.get_event(event_id)["state"])
        self.assertEqual("closed",
                         self.database.connection.execute(
                             "SELECT control_status FROM risk_facilities WHERE facility_id='b1'"
                         ).fetchone()[0])

    def test_cannot_go_backwards(self):
        event_id = self.storm_signals()
        self.drive_to_closed(event_id)
        with self.assertRaises(ConflictError):
            self.service.decide(request_id="back", actor_id="op1", event_id=event_id,
                                action="restrict")
        self.assertEqual("closed", self.service.get_event(event_id)["state"])

    def test_roles_are_enforced_and_rejection_is_recorded(self):
        event_id = self.storm_signals()
        result = self.service.attempt(request_id="a1", actor_id="au1",
                                      event_id=event_id, action="escalate")
        self.assertFalse(result["accepted"])
        timeline = self.service.event_timeline(event_id)
        self.assertTrue(any(i["kind"] == "rejected_attempt" for i in timeline["items"]))
        with self.assertRaises(PermissionDenied):
            self.service.decide(request_id="a2", actor_id="rv-h", event_id=event_id,
                                action="escalate")

    def test_reinspect_requires_post_repair_observation(self):
        event_id = self.storm_signals()
        s = self.service
        self.drive_to_closed(event_id)
        s.decide(request_id="rep", actor_id="op1", event_id=event_id, action="repair")
        blocked = s.attempt(request_id="bb", actor_id="rv-h", event_id=event_id,
                            action="reinspect")
        self.assertFalse(blocked["accepted"])
        s.ingest_observation(request_id="rein", actor_id="rv-h", facility_id="b1",
                             source_kind="manual", reporter_id="rv-h", metric="reinspection",
                             text="复测合格", reported_level="watch", observed_at=t(40),
                             is_reinspection=True)
        s.decide(request_id="ri", actor_id="rv-h", event_id=event_id, action="reinspect")
        self.assertEqual("reinspected", s.get_event(event_id)["state"])

    def test_reinspection_observation_does_not_create_signal(self):
        event_id = self.storm_signals()
        before = len(self.service.get_event(event_id)["signals"])
        self.service.ingest_observation(
            request_id="rein", actor_id="rv-h", facility_id="b1", source_kind="manual",
            reporter_id="rv-h", metric="reinspection", text="复测",
            reported_level="danger", observed_at=t(40), is_reinspection=True)
        self.assertEqual(before, len(self.service.get_event(event_id)["signals"]))


class RuleFreezeTest(RiskTestBase):
    def test_rule_change_does_not_alter_published_decisions(self):
        event_id = self.storm_signals()
        s = self.service
        s.decide(request_id="esc", actor_id="op1", event_id=event_id, action="escalate")
        s.register_rule_version(request_id="rv2", actor_id="admin", rule_version_id="rules-2",
                                rules=[{"rule_id": "rd", "metric": "disp",
                                        "thresholds": {"watch": 1, "warning": 2, "danger": 30}}],
                                activate=True)
        s.decide(request_id="res", actor_id="op1", event_id=event_id, action="restrict")
        close = s.decide(request_id="cls", actor_id="op1", event_id=event_id, action="close")
        basis = close.response["basis"]
        self.assertEqual("rules-1", basis["frozen_rule_version_id"])
        self.assertEqual("rules-2", basis["active_rule_version_at_decision"])
        danger_signal = next(x for x in basis["signals"] if x["metric"] == "disp")
        self.assertEqual(20, danger_signal["matched"]["threshold"])

    def test_rule_versions_are_immutable(self):
        with self.assertRaises(ConflictError):
            self.service.register_rule_version(
                request_id="rv1dup", actor_id="admin", rule_version_id="rules-1",
                rules=[{"rule_id": "rd", "metric": "disp", "thresholds": {"danger": 99}}])


class DuplicateLateTest(RiskTestBase):
    def _full_open(self, event_id):
        s = self.service
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        s.decide(request_id="rr", actor_id="op1", event_id=event_id, action="restrict")
        s.decide(request_id="cc", actor_id="op1", event_id=event_id, action="close")
        s.decide(request_id="rp", actor_id="op1", event_id=event_id, action="repair")
        s.ingest_observation(request_id="reins", actor_id="rv-h", facility_id="b1",
                             source_kind="manual", reporter_id="rv-h", metric="reinspection",
                             text="合格", reported_level="watch", observed_at=t(50),
                             is_reinspection=True)
        s.decide(request_id="ri", actor_id="rv-h", event_id=event_id, action="reinspect")
        s.add_technical_confirmation(request_id="c1", actor_id="rv-h", event_id=event_id,
                                     evidence={"report": "ok"}, opinion="同意")
        s.add_technical_confirmation(request_id="c2", actor_id="rv-t", event_id=event_id,
                                     evidence={"report": "ok"}, opinion="同意")
        s.decide(request_id="dec-open", actor_id="op1", event_id=event_id, action="open")

    def test_duplicate_observation_is_archived_not_signaled(self):
        event_id = self.storm_signals()
        receipt = self.service.ingest_observation(
            request_id="dup", actor_id="op1", facility_id="b1", source_kind="sensor",
            sensor_id="sb1", metric="disp", value=22.0, observed_at=t(1), episode_id="storm")
        self.assertTrue(receipt.response.get("duplicate"))
        self.assertEqual(3, len(self.service.get_event(event_id)["signals"]))
        self.assertEqual("detected", self.service.get_event(event_id)["state"])

    def test_late_signal_after_open_starts_new_event(self):
        event_id = self.storm_signals()
        self._full_open(event_id)
        self.service.ingest_observation(
            request_id="late", actor_id="op1", facility_id="b1", source_kind="sensor",
            sensor_id="sb1", metric="disp", value=21.0, observed_at=t(0),
            late=True, episode_id="storm")
        events = self.service.list_events()
        self.assertEqual(2, len(events))
        states = {event["event_id"]: event["state"] for event in events}
        self.assertEqual("opened", states[event_id])
        self.assertIn("detected", states.values())


class CalibrationReviewTest(RiskTestBase):
    def test_calibration_failure_freezes_disposal_and_lists_review(self):
        event_id = self.storm_signals()
        s = self.service
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        s.decide(request_id="rr", actor_id="op1", event_id=event_id, action="restrict")
        s.decide(request_id="cc", actor_id="op1", event_id=event_id, action="close")
        s.record_calibration(request_id="cf", actor_id="rv-h", sensor_id="sb1",
                             status="failed", effective_at=t(10))
        pending = s.list_reviews_required()
        self.assertEqual(event_id, pending[0]["event_id"])
        blocked = s.attempt(request_id="bb", actor_id="op1", event_id=event_id, action="repair")
        self.assertFalse(blocked["accepted"])

    def test_reviewer_evidence_clears_flag_invalid_keeps_it(self):
        event_id = self.storm_signals()
        s = self.service
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        s.record_calibration(request_id="cf", actor_id="rv-h", sensor_id="sb1",
                             status="failed", effective_at=t(10))
        s.review_event_after_calibration(
            request_id="rv", actor_id="rv-t", event_id=event_id, failed_sensor_id="sb1",
            conclusion="invalid", evidence={"note": "证据不足"})
        self.assertTrue(s.get_event(event_id)["review_required"])
        s.review_event_after_calibration(
            request_id="rv2", actor_id="rv-t", event_id=event_id, failed_sensor_id="sb1",
            conclusion="valid", evidence={"manual_survey_mm": 21.5, "at": t(12)})
        self.assertFalse(s.get_event(event_id)["state"] == "opened")
        self.assertFalse(s.get_event(event_id)["review_required"])

    def test_calibration_restore_does_not_auto_clear_review(self):
        event_id = self.storm_signals()
        s = self.service
        s.record_calibration(request_id="cf", actor_id="rv-h", sensor_id="sb1",
                             status="failed", effective_at=t(10))
        s.record_calibration(request_id="cr", actor_id="rv-h", sensor_id="sb1",
                             status="valid", effective_at=t(20))
        self.assertEqual(1, len(s.list_reviews_required()))
        with self.assertRaises(PermissionDenied):
            s.review_event_after_calibration(
                request_id="op-rev", actor_id="op1", event_id=event_id,
                failed_sensor_id="sb1", conclusion="valid", evidence={"x": 1})


class OpenConfirmationTest(RiskTestBase):
    def _to_reinspected(self, event_id):
        s = self.service
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        s.decide(request_id="rr", actor_id="op1", event_id=event_id, action="restrict")
        s.decide(request_id="cc", actor_id="op1", event_id=event_id, action="close")
        s.decide(request_id="rp", actor_id="op1", event_id=event_id, action="repair")
        s.ingest_observation(request_id="reins", actor_id="rv-h", facility_id="b1",
                             source_kind="manual", reporter_id="rv-h", metric="reinspection",
                             text="合格", reported_level="watch", observed_at=t(50),
                             is_reinspection=True)
        s.decide(request_id="ri", actor_id="rv-h", event_id=event_id, action="reinspect")

    def test_high_risk_needs_two_independent_confirmations(self):
        event_id = self.storm_signals()
        s = self.service
        self._to_reinspected(event_id)
        s.add_technical_confirmation(request_id="k1", actor_id="rv-h", event_id=event_id,
                                     evidence={"a": 1}, opinion="同意")
        one = s.attempt(request_id="dec-open-1", actor_id="op1", event_id=event_id, action="open")
        self.assertFalse(one["accepted"])
        s.add_technical_confirmation(request_id="k2", actor_id="rv-t", event_id=event_id,
                                     evidence={"b": 2}, opinion="同意")
        opener = s.attempt(request_id="dec-open-2", actor_id="rv-h", event_id=event_id, action="open")
        self.assertFalse(opener["accepted"])
        s.decide(request_id="dec-open-3", actor_id="op1", event_id=event_id, action="open")
        self.assertEqual("opened", s.get_event(event_id)["state"])

    def test_same_reviewer_cannot_confirm_twice(self):
        event_id = self.storm_signals()
        s = self.service
        self._to_reinspected(event_id)
        s.add_technical_confirmation(request_id="k1", actor_id="rv-h", event_id=event_id,
                                     evidence={"a": 1})
        with self.assertRaises(ConflictError):
            s.add_technical_confirmation(request_id="k2", actor_id="rv-h", event_id=event_id,
                                         evidence={"a": 2})

    def test_normal_facility_needs_one_confirmation(self):
        s = self.service
        s.ingest_observation(request_id="o1", actor_id="op1", facility_id="s1",
                             source_kind="sensor", sensor_id="ss1", metric="moist",
                             value=88.0, observed_at=t(1))
        event_id = s.list_events()[0]["event_id"]
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        s.decide(request_id="rr", actor_id="op1", event_id=event_id, action="restrict")
        s.decide(request_id="cc", actor_id="op1", event_id=event_id, action="close")
        s.decide(request_id="rp", actor_id="op1", event_id=event_id, action="repair")
        s.ingest_observation(request_id="reins", actor_id="rv-h", facility_id="s1",
                             source_kind="manual", reporter_id="rv-h", metric="reinspection",
                             text="合格", reported_level="watch", observed_at=t(50),
                             is_reinspection=True)
        s.decide(request_id="ri", actor_id="rv-h", event_id=event_id, action="reinspect")
        s.add_technical_confirmation(request_id="k1", actor_id="rv-h", event_id=event_id,
                                     evidence={"a": 1})
        s.decide(request_id="dec-open", actor_id="op1", event_id=event_id, action="open")
        self.assertEqual("opened", s.get_event(event_id)["state"])


class TimelineTest(RiskTestBase):
    def test_timeline_explains_every_measure(self):
        event_id = self.storm_signals()
        s = self.service
        s.decide(request_id="ee", actor_id="op1", event_id=event_id, action="escalate")
        timeline = s.event_timeline(event_id)
        observations = [i for i in timeline["items"] if i["kind"] == "observation"]
        self.assertEqual(3, len(observations))
        decision = next(i for i in timeline["items"] if i["kind"] == "decision")
        self.assertIn("frozen_rule_content_hash", decision["basis"])
        self.assertTrue(s.verify_audit()[0])


if __name__ == "__main__":
    unittest.main()
