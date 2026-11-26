"""Unit test executing all registered security laboratory scenarios."""
import unittest

from quantumvault.testing.lab import SecurityLab


class TestSecurityLaboratory(unittest.TestCase):
    def test_all_laboratory_scenarios(self):
        lab = SecurityLab()
        self.assertGreaterEqual(len(lab.scenarios), 34)
        results = lab.run_all()
        self.assertEqual(results["failed"], 0, f"Failed scenarios: {[s for s in results['scenarios'] if s['status'] != 'PASS']}")
        self.assertEqual(results["passed"], len(lab.scenarios))


if __name__ == "__main__":
    unittest.main()
