"""Unit test executing the 40-step combined failure scenario."""
import unittest

from quantumvault.testing.phase_1_3_combined_scenario import Phase13CombinedScenario


class TestPhase13CombinedScenario(unittest.TestCase):
    def test_forty_step_combined_scenario(self):
        scenario = Phase13CombinedScenario()
        res = scenario.run()
        self.assertTrue(res.success)
        self.assertEqual(res.steps_passed, 40)
        self.assertEqual(res.total_steps, 40)


if __name__ == "__main__":
    unittest.main()
