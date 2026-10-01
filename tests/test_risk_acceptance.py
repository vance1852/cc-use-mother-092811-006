"""重点路桥风险处置离线验收测试。"""

import unittest

from transport_coordination.risk_acceptance import run


class RiskAcceptanceTest(unittest.TestCase):
    def test_disaster_timeline_replay(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        first = result["incident_one"]
        self.assertEqual(3, first["correlated_signals"])
        self.assertEqual("close", first["severity"])
        self.assertGreater(first["confidence"], 0.8)
        self.assertIn("bridge-qinglong", first["impact_facilities"])
        self.assertGreaterEqual(first["timeline_entries"], 15)
        # 每条处置都解释了规则版本、预案版本和阈值依据。
        for explanation in first["decision_explanations"]:
            self.assertEqual(1, explanation["rule_version"])
            self.assertEqual(1, explanation["plan_version"])
            self.assertTrue(explanation["thresholds_applied"])
        second = result["incident_two"]
        self.assertTrue(second["expired_sensor_signal_held"])
        self.assertTrue(second["close_blocked_until_recheck"])
        self.assertTrue(second["review_cleared_after_recheck"])
        self.assertIn(second["incident_id"], second["review_queue_before_recheck"])


if __name__ == "__main__":
    unittest.main()
