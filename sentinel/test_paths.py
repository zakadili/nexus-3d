"""Unit tests: run python3 -m unittest discover -s sentinel -p 'test_*.py'."""
import unittest
from main import DATA, Scenario, analyze, edge_key

class TestPaths(unittest.TestCase):
    def test_baseline_path(self):
        r = analyze(DATA, Scenario())
        self.assertTrue(r["reachable"])
        self.assertEqual(r["path"], ["internet", "web", "ws", "alice", "admins", "dc"])

    def test_remove_critical_edge(self):
        r = analyze(DATA, Scenario(disabled_edges=["admins->dc"]))
        self.assertFalse(r["reachable"])

    def test_remove_unrelated_edge(self):
        r = analyze(DATA, Scenario(disabled_edges=["api->db"]))
        self.assertTrue(r["reachable"])

    def test_unknown_node(self):
        with self.assertRaises(ValueError):
            analyze(DATA, Scenario(source="missing"))

if __name__ == "__main__":
    unittest.main()
