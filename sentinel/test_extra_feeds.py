"""Offline parser tests: normal, empty, malformed and unavailable provider. No requests sent."""
import gzip
import json
import unittest
from unittest.mock import patch
from sentinel import extra_feeds as x
from sentinel import intelligence_pipeline as p


class SupplementaryFeedTests(unittest.TestCase):
    def setUp(self):
        self.geo = p.GeoDB([["8.8.8.0", "8.8.8.255", "US"],
                            ["1.1.1.0", "1.1.1.255", "AU"]])

    def test_urlhaus_normal_and_country_limit(self):
        data = b"# exported: today\n# id,dateadded,url,tags\n1,now,http://8.8.8.8/a,botnet\n2,now,https://domain.example/a,other\n"
        result = x.parse_urlhaus(data, self.geo)
        self.assertEqual(result["total_urls"], 2)
        self.assertEqual(result["countries"], {"US": 1})
        self.assertEqual(result["unmapped_url_count"], 1)

    def test_urlhaus_empty(self):
        self.assertEqual(x.parse_urlhaus(b"id,dateadded,url,tags\n", self.geo)["total_urls"], 0)

    def test_urlhaus_malformed(self):
        with self.assertRaises(ValueError):
            x.parse_urlhaus(b"not,a,urlhaus,table\n", self.geo)

    def test_urlhaus_source_down_and_no_key(self):
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": ""}):
            data, health = x.collect_urlhaus(self.geo)
        self.assertIsNone(data)
        self.assertEqual(health["status"], "unavailable")
        self.assertEqual(health["reason"], "no key configured")
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": "test"}):
            with patch.object(x, "fetch_bytes", side_effect=OSError("provider down")):
                data, health = x.collect_urlhaus(self.geo)
        self.assertIsNone(data)
        self.assertEqual(health["status"], "unavailable")

    def test_threatfox_normal_with_non_ip_iocs(self):
        result = x.parse_threatfox({"query_status":"ok","data":[
          {"ioc":"8.8.8.8:443","ioc_type":"ip:port","malware_printable":"TestFamily","tags":["test"]},
          {"ioc":"bad.example","ioc_type":"domain","malware":"TestFamily","tags":["test"]}]}, self.geo)
        self.assertEqual(result["total_iocs"], 2)
        self.assertEqual(result["countries"], {"US": 1})
        self.assertEqual(result["top_malware"][0]["count"], 2)

    def test_threatfox_empty(self):
        self.assertEqual(x.parse_threatfox({"query_status":"no_result","data":None}, self.geo)["total_iocs"], 0)

    def test_threatfox_malformed(self):
        with self.assertRaises(ValueError):
            x.parse_threatfox({"query_status":"ok","data":"not a list"}, self.geo)

    def test_threatfox_source_down_and_no_key(self):
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": ""}):
            data, h = x.collect_threatfox(self.geo)
        self.assertIsNone(data)
        self.assertIn("no key", h["reason"])
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": "test"}):
            with patch.object(x, "fetch_bytes", side_effect=TimeoutError):
                data, h = x.collect_threatfox(self.geo)
        self.assertIsNone(data)
        self.assertEqual(h["status"], "unavailable")

    def test_asn_normal_range_and_counts(self):
        raw = gzip.compress(b"8.8.8.0\t8.8.8.255\t15169\tUS\tGoogle LLC\n1.1.1.0\t1.1.1.255\t13335\tAU\tCloudflare\n")
        db = x.parse_asn_gzip(raw)
        result = x.summarize_asns({"US":["8.8.8.8"],"AU":["1.1.1.1"]}, db)
        self.assertEqual(result["matched_ips"], 2)
        self.assertEqual(result["countries"]["US"][0]["asn"], 15169)

    def test_asn_empty(self):
        with self.assertRaisesRegex(ValueError, "Empty"):
            x.parse_asn_gzip(gzip.compress(b""))

    def test_asn_malformed(self):
        with self.assertRaises(Exception):
            x.parse_asn_gzip(b"invalid gzip")

    def test_asn_source_down(self):
        with patch.object(x, "fetch_bytes", side_effect=OSError("down")):
            data, h = x.collect_asns({"US":["8.8.8.8"]})
        self.assertIsNone(data)
        self.assertEqual(h["status"], "unavailable")

    def test_ioda_normal(self):
        result=x.parse_ioda({"data":[{"entityType":"country","entityCode":"US","from":1760000000,"until":1760003600,"datasource":"bgp"},
                                     {"location":"country/AU","start":1760000001,"duration":600,"datasource":"ping-slash24"}]})
        self.assertEqual(result["countries"], {"AU":1,"US":1})
        self.assertEqual(len(result["events"]), 2)

    def test_ioda_empty(self):
        self.assertEqual(x.parse_ioda({"data":[]})["events"], [])

    def test_ioda_malformed(self):
        with self.assertRaises(ValueError):
            x.parse_ioda({"data":{"wrong":"shape"}})

    def test_ioda_source_down(self):
        with patch.object(x, "fetch_bytes", side_effect=TimeoutError):
            data, h=x.collect_ioda()
        self.assertIsNone(data)
        self.assertEqual(h["status"], "unavailable")

    def test_health_is_separate_from_counts(self):
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": ""}):
            with patch.object(x, "fetch_bytes", side_effect=OSError("all other sources down")):
                result=x.collect_all(self.geo, {"US":["8.8.8.8"]})
        self.assertTrue(all(h["status"]=="unavailable" for h in result["source_health"]))
        self.assertTrue(all(value is None for value in result["feeds"].values()))


if __name__ == "__main__":
    unittest.main()
