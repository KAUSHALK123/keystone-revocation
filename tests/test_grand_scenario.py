"""Unit test wrapper executing the Phase 1.2 23-step Grand Failure Scenario."""
import unittest

from quantumvault.testing.phase_1_2_scenarios import Phase12GrandScenario


class TestGrandScenario(unittest.TestCase):
    def test_complete_23_step_grand_scenario(self):
        """Execute the complete 23-step headless adversarial security resilience scenario."""
        scenario = Phase12GrandScenario()
        result = scenario.run()

        # Ensure all 23 steps passed
        for step in result.step_details:
            self.assertEqual(
                step["status"], "PASS",
                f"Step {step['step']} ({step['title']}) failed: {step.get('details')}"
            )

        self.assertEqual(result.steps_passed, 23)
        self.assertTrue(result.success)
        self.assertGreater(result.execution_time_ms, 0.0)


if __name__ == "__main__":
    unittest.main()
