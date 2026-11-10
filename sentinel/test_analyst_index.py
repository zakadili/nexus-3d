"""Regression checks for the CC0-only browser index and future-only KEV diffs."""
import json
from pathlib import Path
import tempfile
import unittest

from sentinel import analyst_index as idx
from sentinel import intelligence_pipeline as p


class AnalystIndexTests(unittest.TestCase):
    def setUp(self):
        self.geo=p.GeoDB([["8.8.8.0","8.8.8.255","US"],
                          ["1.1.1.0","1.1.1.255","AU"]])

    def test_license_gated_feodo_only(self):
        shards=idx.build_ip_index({
            "8.8.8.8":{"feodo","ipsum"},
            "1.1.1.1":{"blocklistde"},
            "127.0.0.1":{"feodo"}
        },self.geo,"2026-11-10T00:00:00Z")
        self.assertEqual(list(shards),["8"])
        self.assertEqual(shards["8"]["records"][0]["country"],"US")
        self.assertEqual(shards["8"]["records"][0]["sources"],["feodo"])
        self.assertIsNone(shards["8"]["records"][0]["first_seen"])

    def test_empty_index(self):
        self.assertEqual(idx.build_ip_index({},self.geo,"now"),{})

    def test_malformed_index(self):
        with self.assertRaises(ValueError):
            idx.build_ip_index(None,self.geo,"now")

    def test_clean_kev(self):
        catalog=idx.clean_kev({"vulnerabilities":[
            {"cveID":"CVE-2026-12345","vendorProject":"ExampleVendor","dueDate":"2026-12-30"},
            {"cveID":"CVE-2026-12345"},
            {"cveID":"not-a-cve"}
        ]},"now")
        self.assertEqual(len(catalog["records"]),1)
        self.assertEqual(catalog["records"][0]["product"],None)

    def test_empty_kev(self):
        self.assertEqual(idx.clean_kev({"vulnerabilities":[]},"now")["records"],[])

    def test_malformed_kev(self):
        with self.assertRaises(ValueError):
            idx.clean_kev({"vulnerabilities":"oops"},"now")

    def test_missing_history_is_unavailable(self):
        result=idx.snapshot_diff({"kev_ids":["CVE-2026-12345"]},None)
        self.assertEqual(result["status"],"unavailable")

    def test_exact_kev_history(self):
        result=idx.snapshot_diff({"kev_ids":["CVE-2026-12345","CVE-2026-9999"]},
                                 {"kev_ids":["CVE-2026-12345"]})
        self.assertEqual(result["added"],["CVE-2026-9999"])
        self.assertEqual(result["removed"],[])

    def test_write_and_prune_stale_shards(self):
        with tempfile.TemporaryDirectory() as root:
            folder=Path(root)/"index"
            folder.mkdir()
            (folder/"99.json").write_text("{}")
            manifest=idx.write_static_index(folder,
                idx.build_ip_index({"8.8.8.8":{"feodo"}},self.geo,"now"))
            self.assertFalse((folder/"99.json").exists())
            self.assertTrue((folder/"8.json").exists())
            self.assertEqual(manifest["total_records"],1)
            self.assertEqual(json.loads((folder/"manifest.json").read_text())["schema"],1)


if __name__=="__main__":
    unittest.main()
