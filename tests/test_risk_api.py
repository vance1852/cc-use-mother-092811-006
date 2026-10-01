"""重点路桥风险处置服务的 HTTP 路由测试。"""

import unittest
from datetime import datetime, timezone

from transport_coordination.api import route
from transport_coordination.clock import SimulatedClock
from transport_coordination.risk_service import RiskService
from transport_coordination.storage import Database


def headers(actor: str) -> dict[str, str]:
    return {"X-Actor-Id": actor}


class RiskApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = SimulatedClock(datetime(2026, 7, 14, 8, 0, tzinfo=timezone.utc))
        self.service = RiskService(self.database, self.clock)
        self._bootstrap()

    def tearDown(self):
        self.database.close()

    def _post(self, path, body, actor="op"):
        return route(self.service, "POST", path, body, headers(actor))

    def _get(self, path, actor="op"):
        return route(self.service, "GET", path, None, headers(actor))

    def _bootstrap(self):
        self._post("/organizations", {"request_id": "org", "organization_id": "o1",
                                      "name": "公路局"}, "bootstrap")
        self._post("/actors", {"request_id": "adm", "new_actor_id": "adm",
                               "display_name": "管理员", "role": "admin",
                               "organization_id": "o1"}, "bootstrap")
        self._post("/actors", {"request_id": "op", "new_actor_id": "op",
                               "display_name": "值班员", "role": "operator",
                               "organization_id": "o1"}, "adm")
        self._post("/actors", {"request_id": "eng", "new_actor_id": "eng",
                               "display_name": "工程师", "role": "engineer",
                               "organization_id": "o1"}, "adm")
        self._post("/actors", {"request_id": "rev", "new_actor_id": "rev",
                               "display_name": "复核员", "role": "reviewer",
                               "organization_id": "o1"}, "adm")
        self._post("/sites", {"request_id": "site", "site_id": "s1", "organization_id": "o1",
                              "name": "节点", "timezone_name": "Asia/Shanghai"}, "op")
        status, _ = self._post("/facilities", {
            "request_id": "fb", "site_id": "s1", "facility_id": "bridge1",
            "facility_type": "bridge", "name": "大桥", "kilometrage": "K1",
            "risk_level": "high"})
        self.assertEqual(201, status)
        self.assertEqual(201, self._post("/sensors", {
            "request_id": "ss", "sensor_id": "disp", "facility_id": "bridge1",
            "metric": "displacement_mm", "unit": "mm"})[0])
        self.assertEqual(201, self._post("/calibrations", {
            "request_id": "cc", "sensor_id": "disp", "calibration_id": "cal1",
            "status": "valid", "valid_from": "2026-07-01T00:00:00Z",
            "valid_until": "2026-08-01T00:00:00Z"}, "eng")[0])
        self.assertEqual(201, self._post("/rule-versions", {
            "request_id": "rv", "version": 1, "window_minutes": 180, "rules": [
                {"rule_id": "rd", "facility_type": "bridge", "metric": "displacement_mm",
                 "weight": 0.6, "thresholds": {"heighten": 10, "restrict": 20, "close": 35}},
                {"rule_id": "ri", "source": "inspector", "weight": 0.4,
                 "report_levels": {"close": ["封闭"]}}]}, "adm")[0])
        self.assertEqual(201, self._post("/plan-versions", {
            "request_id": "pv", "facility_id": "bridge1", "version": 1,
            "steps": ["heighten", "restrict", "close", "repair", "recheck", "reopen"]},
            "adm")[0])

    def test_health_reports_risk_tables_via_audit(self):
        status, payload = self._get("/health")
        self.assertEqual(200, status)
        self.assertEqual("ok", payload["status"])

    def test_observation_to_disposition_flow_over_http(self):
        status, payload = self._post("/observations", {
            "facility_id": "bridge1", "sensor_id": "disp", "source": "sensor",
            "metric": "displacement_mm", "value": 22.0,
            "observed_at": "2026-07-14T08:00:00Z"})
        self.assertEqual(201, status)
        incident_id = payload["incident_id"]
        self.assertTrue(incident_id)

        status, payload = self._get(f"/incidents/{incident_id}")
        self.assertEqual(200, status)
        self.assertEqual("restrict", payload["severity"])

        status, payload = self._get("/incidents?site_id=s1")
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))

        status, payload = self._post(f"/incidents/{incident_id}/dispositions", {
            "request_id": "dh", "facility_id": "bridge1", "stage": "heighten",
            "reason": "升级"})
        self.assertEqual(201, status)
        status, payload = self._post(f"/incidents/{incident_id}/dispositions", {
            "request_id": "dr", "facility_id": "bridge1", "stage": "restrict",
            "reason": "限行"})
        self.assertEqual(201, status)

        status, payload = self._get(f"/incidents/{incident_id}/timeline")
        self.assertEqual(200, status)
        self.assertEqual("signal", payload["items"][0]["kind"])
        disposition = next(item for item in payload["items"] if item["kind"] == "disposition")

        status, payload = self._get(f"/dispositions/{disposition['disposition_id']}/basis")
        self.assertEqual(200, status)
        self.assertEqual(1, payload["snapshot"]["rule_version"])

    def test_high_risk_reopen_waits_for_two_confirmations(self):
        _, payload = self._post("/observations", {
            "facility_id": "bridge1", "source": "inspector",
            "metric": "inspection_report", "payload": {"report": "建议封闭"},
            "observed_at": "2026-07-14T08:00:00Z"})
        incident_id = payload["incident_id"]
        for request_id, actor, stage in [
                ("h", "op", "heighten"), ("r", "op", "restrict"), ("c", "adm", "close"),
                ("rep", "eng", "repair"), ("rec", "eng", "recheck")]:
            status, _ = self._post(f"/incidents/{incident_id}/dispositions", {
                "request_id": f"req-{request_id}", "facility_id": "bridge1",
                "stage": stage, "reason": stage}, actor)
            self.assertEqual(201, status)
        status, reopen = self._post(f"/incidents/{incident_id}/dispositions", {
            "request_id": "req-ro", "facility_id": "bridge1", "stage": "reopen",
            "reason": "开放"}, "adm")
        self.assertEqual(201, status)
        status, payload = self._post(f"/incidents/{incident_id}/confirmations", {
            "request_id": "k1", "facility_id": "bridge1", "channel": "load_test",
            "result": "approved", "opinion": "合格", "evidence_ref": "E1",
            "confirmed_by": "周检测", "confirmed_by_organization": "检测中心A"})
        self.assertEqual(201, status)
        _, pending = self._get(f"/incidents/{incident_id}")
        reopen_row = next(d for d in pending["dispositions"] if d["stage"] == "reopen"
                          and d["status"] == "pending_confirmation")
        self.assertEqual(1, len(reopen_row["confirmations"]))
        status, payload = self._get("/reviews")
        self.assertEqual(200, status)
        self.assertEqual([], payload["items"])

    def test_permission_failure_is_reported_as_domain_error(self):
        _, payload = self._post("/observations", {
            "facility_id": "bridge1", "sensor_id": "disp", "source": "sensor",
            "metric": "displacement_mm", "value": 22.0,
            "observed_at": "2026-07-14T08:00:00Z"})
        incident_id = payload["incident_id"]
        status, payload = self._post(f"/incidents/{incident_id}/dispositions", {
            "request_id": "forbidden", "facility_id": "bridge1", "stage": "heighten",
            "reason": "x"}, "rev")
        # 复核员不能执行升级阶段。
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_unknown_route_still_404(self):
        status, payload = route(self.service, "GET", "/no-such-path", None, {})
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])


if __name__ == "__main__":
    unittest.main()
