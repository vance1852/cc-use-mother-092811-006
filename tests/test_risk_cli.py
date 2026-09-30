import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from transport_coordination.clock import FixedClock
from transport_coordination.risk_cli import replay_scenario, render_timeline
from transport_coordination.risk_service import RiskService
from transport_coordination.storage import Database

START = datetime(2026, 9, 25, 1, 30, tzinfo=timezone.utc)


class CliReplayTest(unittest.TestCase):
    def test_replay_scenario_runs_steps_and_timeline_renders(self):
        database = Database()
        service = RiskService(database, FixedClock(START))
        service.register_organization(request_id="org-h", actor_id="bootstrap",
                                      organization_id="org-h", name="公路局")
        service.register_actor(request_id="adm", actor_id="bootstrap", new_actor_id="admin",
                               display_name="管", role="admin", organization_id="org-h")
        service.register_actor(request_id="op", actor_id="admin", new_actor_id="op1",
                               display_name="值班", role="operator", organization_id="org-h")
        service.register_site(request_id="site", actor_id="admin", site_id="s1",
                              organization_id="org-h", name="通道", timezone_name="Asia/Shanghai")
        service.register_facility(request_id="fac", actor_id="admin", facility_id="b1",
                                  site_id="s1", facility_type="bridge", name="一号桥",
                                  criticality="normal")
        service.register_sensor(request_id="sen", actor_id="admin", sensor_id="sb1",
                                facility_id="b1", metric="disp",
                                calibrated_at="2026-09-24T01:30:00Z")
        service.register_rule_version(request_id="rul", actor_id="admin", rule_version_id="v1",
                                      rules=[{"rule_id": "rd", "metric": "disp",
                                              "thresholds": {"danger": 20}}], activate=True)
        service.ingest_observation(
            request_id="obs", actor_id="op1", facility_id="b1", source_kind="sensor",
            sensor_id="sb1", metric="disp", value=22.0,
            observed_at="2026-09-25T01:31:00Z", episode_id="storm")
        event_id = service.list_events()[0]["event_id"]

        with tempfile.TemporaryDirectory() as directory:
            scenario = {
                "name": "升级并限行",
                "steps": [
                    {"name": "升级", "method": "decide",
                     "payload": {"request_id": "esc", "event_id": event_id, "action": "escalate"}},
                    {"name": "限行", "method": "decide",
                     "payload": {"request_id": "res", "event_id": event_id, "action": "restrict"}},
                    {"name": "越序尝试", "method": "attempt",
                     "payload": {"request_id": "bad", "event_id": event_id, "action": "open"}},
                ],
            }
            path = Path(directory) / "scenario.json"
            path.write_text(json.dumps(scenario), encoding="utf-8")
            result = replay_scenario(service, str(path), default_actor="op1")
        self.assertEqual("升级并限行", result["scenario"])
        self.assertTrue(result["steps"][0]["result"]["replayed"] is False)
        self.assertFalse(result["steps"][2]["result"]["accepted"])
        self.assertEqual("restricted", service.get_event(event_id)["state"])

        rendered = render_timeline(service.event_timeline(event_id))
        text = "\n".join(rendered["explanation"])
        self.assertIn("escalate", text)
        self.assertIn("被拒绝尝试", text)
        database.close()


if __name__ == "__main__":
    unittest.main()
