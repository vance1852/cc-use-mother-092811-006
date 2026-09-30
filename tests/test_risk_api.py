import unittest
from datetime import datetime, timezone

from transport_coordination.api import route
from transport_coordination.clock import FixedClock
from transport_coordination.risk_service import RiskService
from transport_coordination.storage import Database

START = "2026-09-25T01:30:00Z"


class RiskApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = RiskService(self.database,
                                   FixedClock(datetime(2026, 9, 25, 1, 30, tzinfo=timezone.utc)))
        s = self.service
        s.register_organization(request_id="org", actor_id="bootstrap",
                                organization_id="org-h", name="公路局")
        s.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin",
                         display_name="管理员", role="admin", organization_id="org-h")
        s.register_actor(request_id="op", actor_id="admin", new_actor_id="op1",
                         display_name="值班员", role="operator", organization_id="org-h")
        s.register_actor(request_id="rv", actor_id="admin", new_actor_id="rv1",
                         display_name="工程师", role="reviewer", organization_id="org-h")
        s.register_site(request_id="site", actor_id="admin", site_id="site-1",
                        organization_id="org-h", name="节点", timezone_name="Asia/Shanghai")
        s.register_facility(request_id="fb", actor_id="admin", facility_id="b1",
                            site_id="site-1", facility_type="bridge", name="一号桥",
                            criticality="high")
        s.register_sensor(request_id="sb", actor_id="admin", sensor_id="sb1",
                          facility_id="b1", metric="disp", calibrated_at=START)
        s.register_rule_version(request_id="rv1", actor_id="admin", rule_version_id="rules-1",
                                rules=[{"rule_id": "rd", "metric": "disp",
                                        "thresholds": {"danger": 20}}], activate=True)

    def tearDown(self):
        self.database.close()

    def post(self, path, body, actor="op1"):
        return route(self.service, "POST", path, body, {"X-Actor-Id": actor})

    def get(self, path, actor="op1"):
        return route(self.service, "GET", path, {}, {"X-Actor-Id": actor})

    def test_ingest_and_event_lifecycle_over_http(self):
        status, body = self.post("/risk/observations", {
            "request_id": "o1", "facility_id": "b1", "source_kind": "sensor",
            "sensor_id": "sb1", "metric": "disp", "value": 22.0,
            "observed_at": START, "episode_id": "storm"})
        self.assertEqual(201, status)
        self.assertIn("event_id", body)

        status, events = self.get("/risk/events?episode_id=storm")
        self.assertEqual(200, status)
        event_id = events["items"][0]["event_id"]

        status, body = self.post(f"/risk/events/{event_id}/decisions",
                                 {"request_id": "e1", "action": "escalate"})
        self.assertEqual(201, status)
        self.assertEqual("escalated", body["to_state"])

        status, body = self.post(f"/risk/events/{event_id}/decisions",
                                 {"request_id": "e1", "action": "escalate"})
        self.assertEqual(200, status, body)
        self.assertTrue(body["replayed"])

        status, body = self.post(f"/risk/events/{event_id}/attempts",
                                 {"request_id": "x1", "action": "open"})
        self.assertEqual(200, status)
        self.assertFalse(body["accepted"])

        status, timeline = self.get(f"/risk/events/{event_id}/timeline")
        self.assertEqual(200, status)
        self.assertGreaterEqual(len(timeline["items"]), 2)

    def test_review_required_endpoint(self):
        self.post("/risk/observations", {
            "request_id": "o1", "facility_id": "b1", "source_kind": "sensor",
            "sensor_id": "sb1", "metric": "disp", "value": 22.0, "observed_at": START})
        status, body = self.post("/risk/calibrations", {
            "request_id": "cf", "sensor_id": "sb1", "status": "failed",
            "effective_at": "2026-09-25T02:00:00Z"}, actor="rv1")
        self.assertEqual(201, status)
        status, body = self.get("/risk/events?review_required=true")
        self.assertEqual(200, status)
        self.assertEqual(1, len(body["items"]))

    def test_permission_denied_over_http(self):
        status, body = self.post("/risk/facilities", {
            "request_id": "f", "facility_id": "b9", "site_id": "site-1",
            "facility_type": "bridge", "name": "桥"}, actor="rv1")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", body["error"])

    def test_impact_endpoint(self):
        self.service.register_facility(
            request_id="fr", actor_id="admin", facility_id="r1", site_id="site-1",
            facility_type="road", name="路段")
        self.service.register_facility_link(
            request_id="lk", actor_id="admin", upstream_id="b1", downstream_id="r1",
            relation="承担")
        status, body = self.get("/risk/facilities/b1/impact")
        self.assertEqual(200, status)
        self.assertEqual({"b1", "r1"}, {item["facility_id"] for item in body["impact"]})

    def test_health_still_reports_chain(self):
        status, body = route(self.service, "GET", "/health", None)
        self.assertEqual(200, status)
        self.assertTrue(body["audit_valid"])


if __name__ == "__main__":
    unittest.main()
