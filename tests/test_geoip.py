"""Unit tests for geoip.py and the attacker-feed aggregation.

Offline by construction: GeoIP is built from a tiny in-memory range table, and
the aggregator is fed synthetic feed data. No network, no DB-IP download.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from geoip import GeoIP                              # noqa: E402
import attacker_feeds as af                          # noqa: E402


def _mini_geo():
    """A GeoIP over three hand-built ranges, so lookups are deterministic."""
    csv = "\n".join([
        "1.0.0.0,1.255.255.255,US",
        "2.0.0.0,2.255.255.255,CN",
        "77.88.8.0,77.88.8.255,RU",
    ])
    v4, v6 = GeoIP._parse(csv)
    return GeoIP(v4, v6)


class TestGeoIPLookup(unittest.TestCase):
    def setUp(self):
        self.geo = _mini_geo()

    def test_known_ip_resolves(self):
        self.assertEqual(self.geo.country("1.2.3.4"), "US")
        self.assertEqual(self.geo.country("2.2.2.2"), "CN")
        self.assertEqual(self.geo.country("77.88.8.8"), "RU")

    def test_range_boundaries_inclusive(self):
        self.assertEqual(self.geo.country("1.0.0.0"), "US")        # first
        self.assertEqual(self.geo.country("1.255.255.255"), "US")  # last
        self.assertEqual(self.geo.country("77.88.8.255"), "RU")

    def test_gap_between_ranges_is_unknown(self):
        # 3.x.x.x falls in no range.
        self.assertIsNone(self.geo.country("3.3.3.3"))

    def test_private_and_invalid_are_none(self):
        for ip in ("192.168.1.1", "10.0.0.1", "127.0.0.1", "not-an-ip", ""):
            self.assertIsNone(self.geo.country(ip), ip)

    def test_zz_rows_are_dropped(self):
        v4, _ = GeoIP._parse("0.0.0.0,0.255.255.255,ZZ\n5.0.0.0,5.0.0.255,FR")
        geo = GeoIP(v4, [])
        self.assertIsNone(geo.country("0.0.0.1"))
        self.assertEqual(geo.country("5.0.0.1"), "FR")

    def test_country_name_falls_back_to_code(self):
        self.assertEqual(GeoIP.country_name("US"), "United States")
        self.assertEqual(GeoIP.country_name("ZK"), "ZK")   # unknown code
        self.assertEqual(GeoIP.country_name(None), "Unknown")

    def test_ipv6_lookup(self):
        # 2400:cb00::/32 is a real routable block (documentation ranges like
        # 2001:db8:: are flagged private and correctly rejected).
        v4, v6 = GeoIP._parse("2400:cb00::,2400:cb00:ffff:ffff:ffff:ffff:ffff:ffff,JP")
        geo = GeoIP(v4, v6)
        self.assertEqual(geo.country("2400:cb00::1"), "JP")


class TestIpExtraction(unittest.TestCase):
    def test_bare_ip_lines(self):
        text = "1.2.3.4\n5.6.7.8\n# comment\n\n"
        self.assertEqual(af._extract_ips(text), ["1.2.3.4", "5.6.7.8"])

    def test_pipe_delimited_dataplane_rows(self):
        # dataplane rows are: asn | asn-name | ip | lastseen | category
        text = "4134 | CHINANET | 1.2.3.4 | 2026-08-25 | sshpwauth\n"
        self.assertEqual(af._extract_ips(text), ["1.2.3.4"])

    def test_private_ips_excluded(self):
        text = "192.168.0.1\n10.1.1.1\n8.8.8.8\n127.0.0.1"
        self.assertEqual(af._extract_ips(text), ["8.8.8.8"])

    def test_max_rows_cap(self):
        text = "\n".join(f"1.1.1.{i}" for i in range(1, 20))
        self.assertEqual(len(af._extract_ips(text, max_rows=5)), 5)


class TestAggregation(unittest.TestCase):
    def test_aggregate_counts_by_country_and_category(self):
        geo = _mini_geo()
        # Two US scanners, one CN scanner, one CN intruder.
        ip_categories = {
            "1.1.1.1": {af.SCANNER},
            "1.1.1.2": {af.SCANNER},
            "2.2.2.1": {af.SCANNER},
            "2.2.2.2": {af.INTRUDER},
        }
        summary = af._aggregate(ip_categories, {}, [], geo)
        self.assertEqual(summary["distinct_ips"], 4)
        self.assertEqual(summary["geolocated"], 4)
        self.assertEqual(summary["totals"][af.SCANNER], 3)
        self.assertEqual(summary["totals"][af.INTRUDER], 1)
        by_cc = {c["cc"]: c for c in summary["countries"]}
        self.assertEqual(by_cc["US"]["by_category"][af.SCANNER], 2)
        self.assertEqual(by_cc["CN"]["total"], 2)

    def test_ranking_is_by_total_desc(self):
        geo = _mini_geo()
        ip_categories = {f"2.0.0.{i}": {af.SCANNER} for i in range(5)}   # CN x5
        ip_categories["1.1.1.1"] = {af.SCANNER}                          # US x1
        summary = af._aggregate(ip_categories, {}, [], geo)
        self.assertEqual(summary["countries"][0]["cc"], "CN")
        self.assertEqual(summary["countries"][0]["rank"], 1)
        self.assertEqual(summary["countries"][1]["cc"], "US")

    def test_no_ip_leaks_into_summary(self):
        """The whole point: no raw address may appear in the published summary."""
        import json
        geo = _mini_geo()
        ip_categories = {"1.1.1.1": {af.SCANNER}, "2.2.2.2": {af.INTRUDER}}
        blob = json.dumps(af._aggregate(ip_categories, {}, [], geo))
        self.assertNotIn("1.1.1.1", blob)
        self.assertNotIn("2.2.2.2", blob)

    def test_confidence_counts_multi_feed_ips(self):
        geo = _mini_geo()
        ip_categories = {"1.1.1.1": {af.SCANNER}, "2.2.2.2": {af.INTRUDER}}
        confidence = {"1.1.1.1": 2, "2.2.2.2": 1}    # only the first is >= 2
        summary = af._aggregate(ip_categories, confidence, [], geo)
        self.assertEqual(summary["high_confidence_ips"], 1)

    def test_unlocatable_ip_counted_but_not_mapped(self):
        geo = _mini_geo()
        ip_categories = {"3.3.3.3": {af.SCANNER}}     # in no range
        summary = af._aggregate(ip_categories, {}, [], geo)
        self.assertEqual(summary["distinct_ips"], 1)
        self.assertEqual(summary["geolocated"], 0)
        self.assertEqual(summary["countries"], [])


if __name__ == "__main__":
    unittest.main()
