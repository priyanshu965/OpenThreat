"""Tests for exposure.py, attack_surface.py and the sector benchmark.

Offline: network calls are stubbed. These pin the safety properties as much as
the parsing — a CASM feature that leaks credentials or probes hosts would be a
much worse bug than one that miscounts.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import exposure as ex                                  # noqa: E402
import attack_surface as asf                           # noqa: E402
import darkweb as dw                                   # noqa: E402


class TestDomainValidation(unittest.TestCase):
    """Domains build cache filenames and URLs, so they are validated hard."""

    def test_plain_domains(self):
        self.assertEqual(ex.valid_domain("example.com"), "example.com")
        self.assertEqual(ex.valid_domain("  Example.CO.UK "), "example.co.uk")
        self.assertEqual(ex.valid_domain("sub.example.com"), "sub.example.com")

    def test_url_and_email_forms_are_reduced(self):
        self.assertEqual(ex.valid_domain("https://example.com/a/b"), "example.com")
        self.assertEqual(ex.valid_domain("user@example.com"), "example.com")

    def test_hostile_input_rejected(self):
        for bad in ("../etc/passwd", "not a domain", "exa mple.com", "-bad.com",
                    "bad-.com", "", None, "localhost", "a" * 300 + ".com",
                    "javascript:alert(1)"):
            self.assertIsNone(ex.valid_domain(bad), repr(bad))

    def test_output_is_always_a_clean_domain(self):
        """The property that matters is not rejection but that whatever comes
        back is safe to put in a URL and a cache filename. A path suffix is
        stripped the same way it is for a full URL, so the traversal cannot
        survive into either."""
        for value in ("example.com/../../x", "https://example.com/../../etc/passwd",
                      "example.com/..%2f..%2fx", "example.com?q=1#frag"):
            out = ex.valid_domain(value)
            if out is None:
                continue
            for bad in ("/", "\\", "..", "?", "#", ":"):
                self.assertNotIn(bad, out, f"{value!r} -> {out!r}")
            self.assertRegex(out, r"^[a-z0-9.-]+$")


class TestExposureParsing(unittest.TestCase):
    def setUp(self):
        self._orig = ex._fetch_json
        ex._fetch_json = lambda name, url, ttl: {
            "total": 431, "employees": 6, "users": 400, "third_parties": 25,
            "totalUrls": 900, "last_employee_compromised": "2026-08-13T00:00:00Z",
            "last_user_compromised": "2026-08-20T00:00:00Z",
            # Fields we must NOT propagate even if the API returns them.
            "data": {"employees": [{"password": "hunter2", "user": "a@b.com"}]},
            "credentials": ["secret"],
        }

    def tearDown(self):
        ex._fetch_json = self._orig

    def test_counts_parsed(self):
        r = ex.check_domain_exposure("example.com")
        self.assertEqual(r["employees"], 6)
        self.assertEqual(r["users"], 400)
        self.assertEqual(r["third_parties"], 25)
        self.assertEqual(r["last_employee_compromised"], "2026-08-13")

    def test_no_credentials_are_carried_through(self):
        """We take counts. Passwords must never enter our data model."""
        import json
        blob = json.dumps(ex.check_domain_exposure("example.com"))
        for leak in ("hunter2", "password", "credentials", "a@b.com"):
            self.assertNotIn(leak, blob, f"{leak!r} leaked into exposure output")

    def test_malformed_domain_refused_before_any_fetch(self):
        called = []
        ex._fetch_json = lambda *a, **k: called.append(1)
        self.assertIsNone(ex.check_domain_exposure("../../etc/passwd"))
        self.assertEqual(called, [], "a fetch was attempted for a bad domain")

    def test_build_exposure_totals(self):
        agg = ex.build_exposure(["a.com", "b.com"])
        self.assertEqual(agg["totals"]["employees"], 12)
        self.assertEqual(len(agg["domains"]), 2)


class TestBreachCatalogue(unittest.TestCase):
    def setUp(self):
        self._orig = ex._fetch_json
        ex._fetch_json = lambda name, url, ttl: [
            {"Title": "Old", "BreachDate": "2020-01-01", "AddedDate": "2020-02-01",
             "PwnCount": 100, "DataClasses": ["Email addresses"], "IsVerified": True},
            {"Title": "New", "BreachDate": "2026-08-01", "AddedDate": "2026-08-20",
             "PwnCount": 900, "DataClasses": ["Passwords", "Email addresses"],
             "IsVerified": True},
        ]

    def tearDown(self):
        ex._fetch_json = self._orig

    def test_sorted_newest_added_first(self):
        c = ex.build_breach_catalogue()
        self.assertEqual(c["recent"][0]["name"], "New")

    def test_totals(self):
        c = ex.build_breach_catalogue()
        self.assertEqual(c["total_breaches"], 2)
        self.assertEqual(c["total_accounts"], 1000)


class TestAttackSurface(unittest.TestCase):
    def setUp(self):
        self._orig = asf._cached_fetch
        import json
        asf._cached_fetch = lambda name, ttl, raw: json.dumps([
            {"name_value": "www.example.com\ndev.example.com",
             "issuer_name": 'C=US, O=Let\'s Encrypt, CN=R3'},
            {"name_value": "*.staging.example.com",
             "issuer_name": "C=US, O=DigiCert Inc"},
            {"name_value": "evil.attacker.net", "issuer_name": "O=Other"},
            {"name_value": "vpn.example.com", "issuer_name": "O=DigiCert Inc"},
        ])

    def tearDown(self):
        asf._cached_fetch = self._orig

    def test_hostnames_extracted_and_wildcards_stripped(self):
        r = asf.discover_subdomains("example.com")
        self.assertIn("staging.example.com", r["sample"])
        self.assertIn("www.example.com", r["sample"])

    def test_out_of_scope_hosts_excluded(self):
        """A cert can list unrelated names; only our domain belongs here."""
        r = asf.discover_subdomains("example.com")
        self.assertNotIn("evil.attacker.net", r["sample"])

    def test_shadow_it_flagged(self):
        r = asf.discover_subdomains("example.com")
        self.assertIn("dev.example.com", r["noteworthy"])
        self.assertIn("vpn.example.com", r["noteworthy"])
        self.assertNotIn("www.example.com", r["noteworthy"])

    def test_issuers_counted(self):
        names = [i["issuer"] for i in asf.discover_subdomains("example.com")["issuers"]]
        self.assertIn("DigiCert Inc", names)

    def test_malformed_domain_refused(self):
        self.assertIsNone(asf.discover_subdomains("../etc/passwd"))

    def test_note_states_no_probing(self):
        """This must never be mistaken for a scanner."""
        out = asf.build_attack_surface(["example.com"])
        self.assertIn("does not probe", out["note"].lower())


class TestSectorBenchmark(unittest.TestCase):
    def _index(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc).date()
        recent = (today - timedelta(days=10)).isoformat()
        older = (today - timedelta(days=120)).isoformat()
        return {"victims": [
            {"v": "A", "g": "x", "d": recent, "c": "US", "s": "Healthcare"},
            {"v": "B", "g": "x", "d": recent, "c": "US", "s": "Healthcare"},
            {"v": "C", "g": "x", "d": recent, "c": "GB", "s": "Manufacturing"},
            {"v": "D", "g": "x", "d": older, "c": "US", "s": "Healthcare"},
        ]}

    def test_direction_and_change(self):
        b = dw.build_sector_benchmark(self._index())
        by = {s["sector"]: s for s in b["sectors"]}
        self.assertEqual(by["Healthcare"]["current"], 2)
        self.assertEqual(by["Healthcare"]["previous"], 1)
        self.assertEqual(by["Healthcare"]["change_pct"], 100)
        self.assertEqual(by["Healthcare"]["direction"], "up")

    def test_no_baseline_is_new_not_a_fake_percentage(self):
        """Dividing by a zero baseline would invent a number."""
        by = {s["sector"]: s for s in dw.build_sector_benchmark(self._index())["sectors"]}
        self.assertIsNone(by["Manufacturing"]["change_pct"])
        self.assertEqual(by["Manufacturing"]["direction"], "new")

    def test_country_rollup(self):
        b = dw.build_sector_benchmark(self._index())
        self.assertEqual(b["top_countries"][0]["cc"], "US")

    def test_empty_index(self):
        self.assertIsNone(dw.build_sector_benchmark({"victims": []}))


class TestWatchAlerts(unittest.TestCase):
    def setUp(self):
        import webhook_post
        self.wp = webhook_post
        self.match = {"v": "Acme Corp", "g": "qilin", "d": "2026-08-25",
                      "c": "US", "s": "Manufacturing"}

    def test_payload_names_the_term_and_victim(self):
        import json
        for kind in ("slack", "discord", "telegram"):
            blob = json.dumps(self.wp.build_watch_payload("Acme", [self.match], kind))
            self.assertIn("Acme", blob, kind)
            self.assertIn("qilin", blob, kind)

    def test_payload_carries_the_claim_caveat(self):
        """A leak-site listing is a claim; the alert must say so."""
        import json
        for kind in ("slack", "discord", "telegram"):
            blob = json.dumps(self.wp.build_watch_payload("Acme", [self.match], kind))
            self.assertIn("claim", blob.lower(), kind)

    def test_dedup_key_is_stable_and_specific(self):
        k1 = self.wp._watch_key("Acme", self.match)
        k2 = self.wp._watch_key("acme", dict(self.match))
        self.assertEqual(k1, k2)
        other = dict(self.match, v="Different Co")
        self.assertNotEqual(k1, self.wp._watch_key("Acme", other))

    def test_no_hits_sends_nothing(self):
        class Cfg:
            webhook_url = "https://example.invalid/hook"
            webhook_type = "slack"
        self.assertEqual(self.wp.send_watch_alerts({"darkweb_watch": []}, Cfg), 0)

    def test_no_webhook_configured_sends_nothing(self):
        class Cfg:
            webhook_url = ""
            webhook_type = "slack"
        out = {"darkweb_watch": [{"term": "Acme", "matches": [self.match]}]}
        self.assertEqual(self.wp.send_watch_alerts(out, Cfg), 0)


if __name__ == "__main__":
    unittest.main()
