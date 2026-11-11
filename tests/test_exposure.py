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


class TestOwnEstateNotPublished(unittest.TestCase):
    """Own-estate findings must not reach the public site by default.

    The dashboard deploys to a public URL. An inventory of your own
    dev/staging/vpn hostnames plus credential-exposure counts is exactly the
    reconnaissance an attacker would otherwise have to perform, so publishing
    it would hand that over. Industry-wide data (sector benchmark, public
    breach catalogue) is not sensitive and always publishes.
    """

    def _write(self, tmp, publish):
        import exports
        from config import CONFIG
        old = CONFIG.publish_own_estate
        try:
            CONFIG.publish_own_estate = publish
            exports.write_exports({
                "last_updated": "2026-08-25T00:00:00Z", "items": [],
                "exposure": {"domains": [{"domain": "example.com", "employees": 3,
                                          "users": 1, "third_parties": 0, "total": 4}],
                             "totals": {"employees": 3, "users": 1, "third_parties": 0}},
                "attack_surface": {"domains": [{"domain": "example.com", "hostnames": 2,
                                                "sample": ["vpn.example.com"],
                                                "noteworthy": ["vpn.example.com"]}],
                                   "total_hostnames": 2},
                "sector_benchmark": {"sectors": [], "current_total": 0, "previous_total": 0},
                "breach_catalogue": {"recent": [], "total_breaches": 0, "total_accounts": 0},
            }, tmp / "exports")
            return tmp / "api"
        finally:
            CONFIG.publish_own_estate = old

    def test_withheld_by_default(self):
        import tempfile
        from pathlib import Path
        api = self._write(Path(tempfile.mkdtemp()), False)
        self.assertFalse((api / "exposure.json").exists(),
                         "exposure.json was published to the public site")
        self.assertFalse((api / "attack_surface.json").exists(),
                         "attack_surface.json was published to the public site")

    def test_industry_wide_data_still_publishes(self):
        import tempfile
        from pathlib import Path
        api = self._write(Path(tempfile.mkdtemp()), False)
        self.assertTrue((api / "sector_benchmark.json").exists())
        self.assertTrue((api / "breaches.json").exists())

    def test_opt_in_publishes(self):
        import tempfile
        from pathlib import Path
        api = self._write(Path(tempfile.mkdtemp()), True)
        self.assertTrue((api / "exposure.json").exists())
        self.assertTrue((api / "attack_surface.json").exists())

    def test_no_hostname_leaks_into_published_files(self):
        """Belt and braces: no own-estate hostname may appear in ANY published
        artefact when publishing is off."""
        import tempfile
        from pathlib import Path
        api = self._write(Path(tempfile.mkdtemp()), False)
        for f in api.glob("*.json"):
            text = f.read_text(encoding="utf-8")
            self.assertNotIn("vpn.example.com", text, f"leaked into {f.name}")


class TestSilenceIsNeverAmbiguous(unittest.TestCase):
    """A monitoring check that finds nothing must look different from one that
    never ran. The reverse — an outage reading as "all clear" — is the failure
    mode that actually hurts."""

    @staticmethod
    def _logger_name(mod):
        lg = getattr(mod.log, "logger", mod.log)
        return lg.name

    def setUp(self):
        # Names and findings only reach the log on a private run; these tests
        # are about what such a run says. TestPublicLogsNameNothing covers the
        # default.
        self._detail = ex.CONFIG.own_estate_in_logs
        ex.CONFIG.own_estate_in_logs = True

    def tearDown(self):
        ex.CONFIG.own_estate_in_logs = self._detail

    def test_exposure_reports_even_when_clean(self):
        import logging
        orig = ex._fetch_json
        ex._fetch_json = lambda name, url, ttl: {
            "total": 0, "employees": 0, "users": 0, "third_parties": 0}
        try:
            with self.assertLogs(self._logger_name(ex), level=logging.INFO) as cm:
                ex.build_exposure(["clean.com"])
            self.assertTrue(any("checked 1 domain" in m for m in cm.output),
                            "a clean result produced no log line")
        finally:
            ex._fetch_json = orig

    def test_exposure_names_domains_that_returned_nothing(self):
        import logging
        orig = ex._fetch_json
        ex._fetch_json = lambda name, url, ttl: None
        try:
            with self.assertLogs(self._logger_name(ex), level=logging.WARNING) as cm:
                ex.build_exposure(["broken.com"])
            self.assertTrue(any("broken.com" in m for m in cm.output))
        finally:
            ex._fetch_json = orig

    def test_attack_surface_flags_an_outage_rather_than_implying_clean(self):
        import logging
        orig = asf._cached_fetch
        asf._cached_fetch = lambda name, ttl, raw: None
        try:
            with self.assertLogs(self._logger_name(asf), level=logging.WARNING) as cm:
                asf.build_attack_surface(["example.com"])
            joined = " ".join(cm.output)
            self.assertIn("example.com", joined)
            self.assertIn("outage", joined.lower())
        finally:
            asf._cached_fetch = orig

    def test_shadow_it_hosts_are_logged_individually(self):
        import json
        import logging
        orig = asf._cached_fetch
        asf._cached_fetch = lambda name, ttl, raw: json.dumps([
            {"name_value": "dev.example.com", "issuer_name": "O=X"}])
        try:
            with self.assertLogs(self._logger_name(asf), level=logging.WARNING) as cm:
                asf.build_attack_surface(["example.com"])
            self.assertTrue(any("SHADOW IT" in m and "dev.example.com" in m
                                for m in cm.output))
        finally:
            asf._cached_fetch = orig


class TestPublicLogsNameNothing(unittest.TestCase):
    """On a public repository the Actions log is public. By default the log
    may say that a check ran and how many names it covered - never which names,
    and never what was found."""

    SECRETS = ("example.com", "dev.example.com", "Acme")

    def setUp(self):
        self._detail = ex.CONFIG.own_estate_in_logs
        ex.CONFIG.own_estate_in_logs = False
        self._watch = dw.CONFIG.darkweb_watch

    def tearDown(self):
        ex.CONFIG.own_estate_in_logs = self._detail
        dw.CONFIG.darkweb_watch = self._watch

    @staticmethod
    def _logger_name(mod):
        return getattr(mod.log, "logger", mod.log).name

    def _assert_clean(self, output):
        joined = " ".join(output)
        for secret in self.SECRETS:
            self.assertNotIn(secret, joined)

    def test_off_by_default(self):
        from config import Config
        self.assertFalse(Config().own_estate_in_logs)

    def test_exposure_log_carries_no_domain_or_count(self):
        import logging
        orig = ex._fetch_json
        ex._fetch_json = lambda name, url, ttl: {
            "total": 31, "employees": 11, "users": 19, "third_parties": 1}
        try:
            with self.assertLogs(self._logger_name(ex), level=logging.INFO) as cm:
                ex.build_exposure(["example.com"])
        finally:
            ex._fetch_json = orig
        self._assert_clean(cm.output)
        self.assertNotIn("11", " ".join(cm.output))
        # …but it must still be visibly a result, not silence.
        self.assertTrue(any("checked 1 domain" in m for m in cm.output))

    def test_attack_surface_log_carries_no_hostname(self):
        import json
        import logging
        orig = asf._cached_fetch
        asf._cached_fetch = lambda name, ttl, raw: json.dumps([
            {"name_value": "dev.example.com", "issuer_name": "O=X"}])
        try:
            with self.assertLogs(self._logger_name(asf), level=logging.INFO) as cm:
                asf.build_attack_surface(["example.com"])
        finally:
            asf._cached_fetch = orig
        self._assert_clean(cm.output)
        self.assertTrue(any("enumerated 1 domain" in m for m in cm.output))

    def test_an_outage_is_still_reported_without_the_name(self):
        import logging
        orig = asf._cached_fetch
        asf._cached_fetch = lambda name, ttl, raw: None
        try:
            with self.assertLogs(self._logger_name(asf), level=logging.WARNING) as cm:
                asf.build_attack_surface(["example.com"])
        finally:
            asf._cached_fetch = orig
        self._assert_clean(cm.output)
        self.assertIn("outage", " ".join(cm.output).lower())

    def test_watchlist_hit_does_not_log_the_term(self):
        import logging
        dw.CONFIG.darkweb_watch = "Acme"
        index = {"victims": [{"v": "Acme Corp", "g": "qilin", "d": "2026-08-25"}]}
        with self.assertNoLogs(self._logger_name(dw), level=logging.WARNING):
            hits = dw.check_watchlist(index)
        self.assertEqual(len(hits), 1)


class TestOwnEstateStaysOutOfTheFeed(unittest.TestCase):
    """intel.json is the public feed, and every daily archive is a copy of it.
    PUBLISH_OWN_ESTATE=0 used to withhold the per-view API files while the same
    findings shipped in the main payload."""

    FEED = {
        "items": [{"title": "x"}],
        "exposure": {"domains": [{"domain": "example.com", "employees": 3}]},
        "attack_surface": {"domains": [{"domain": "example.com",
                                        "noteworthy": ["vpn.example.com"]}]},
        "darkweb_watch": [{"term": "Acme", "count": 1}],
    }

    def setUp(self):
        import fetch_intel
        self.fi = fetch_intel
        self._publish = fetch_intel.CONFIG.publish_own_estate

    def tearDown(self):
        self.fi.CONFIG.publish_own_estate = self._publish

    def test_feed_carries_no_estate_data_by_default(self):
        import json
        self.fi.CONFIG.publish_own_estate = False
        public, private = self.fi.split_own_estate(dict(self.FEED))
        blob = json.dumps(public)
        for secret in ("example.com", "vpn.example.com", "Acme"):
            self.assertNotIn(secret, blob)
        # The shape is unchanged, so the dashboard needs no special case.
        self.assertEqual(set(public), set(self.FEED))
        self.assertEqual(public["darkweb_watch"], [])
        self.assertEqual(public["items"], self.FEED["items"])
        self.assertEqual(set(private), {"exposure", "attack_surface", "darkweb_watch"})

    def test_explicit_opt_in_still_publishes(self):
        self.fi.CONFIG.publish_own_estate = True
        public, _ = self.fi.split_own_estate(dict(self.FEED))
        self.assertEqual(public["exposure"], self.FEED["exposure"])

    def test_private_file_is_removed_when_there_is_nothing_to_report(self):
        import tempfile
        from pathlib import Path as P
        old = self.fi.CONFIG.own_estate_path
        with tempfile.TemporaryDirectory() as tmp:
            self.fi.CONFIG.own_estate_path = P(tmp) / ".own_estate.json"
            try:
                self.fi.write_own_estate({"exposure": {"domains": []}})
                self.assertTrue(self.fi.CONFIG.own_estate_path.exists())
                self.fi.write_own_estate({})
                self.assertFalse(self.fi.CONFIG.own_estate_path.exists())
            finally:
                self.fi.CONFIG.own_estate_path = old

    def test_private_file_is_never_tracked_or_published(self):
        root = Path(__file__).resolve().parent.parent
        self.assertIn("data/.own_estate.json", (root / ".gitignore").read_text(encoding="utf-8"))
        workflow = (root / ".github/workflows/update.yml").read_text(encoding="utf-8")
        assemble = workflow.split("name: Assemble site", 1)[1].split("name: Upload Pages artifact", 1)[0]
        self.assertNotIn(".own_estate.json", assemble)


class TestEstateReport(unittest.TestCase):
    OUTPUT = {
        "exposure": {"domains": [{"domain": "example.com", "employees": 3,
                                  "users": 1, "third_parties": 0}]},
        "attack_surface": {"domains": [{"domain": "example.com", "hostnames": 12,
                                        "noteworthy": ["<!channel>.example.com"]}]},
    }

    def setUp(self):
        import webhook_post
        self.wp = webhook_post

    def test_report_names_the_findings_for_every_destination(self):
        import json
        for kind in ("slack", "discord", "telegram", "email", "generic"):
            blob = json.dumps(self.wp.build_estate_payload(self.OUTPUT, kind))
            self.assertIn("example.com", blob, kind)
            self.assertIn("3 employee", blob, kind)

    def test_nothing_to_report_sends_nothing(self):
        self.assertIsNone(self.wp.build_estate_payload({"exposure": None}, "slack"))
        self.assertFalse(self.wp.send_estate_report({}, object()))

    def test_hostnames_are_escaped(self):
        """Certificate names are attacker-influenced: anyone can get a
        certificate issued for a hostname under a domain they control."""
        import json
        blob = json.dumps(self.wp.build_estate_payload(self.OUTPUT, "slack"))
        self.assertNotIn("<!channel>", blob)

    def test_an_unchanged_report_is_sent_once(self):
        import tempfile
        from pathlib import Path as P
        from types import SimpleNamespace
        sent = []
        orig = self.wp._post_with_retry
        self.wp._post_with_retry = lambda url, payload, retries=3: sent.append(payload) or True
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = SimpleNamespace(webhook_url="https://hooks.example/x", webhook_type="slack",
                                      alert_state_path=P(tmp) / "state.json",
                                      alert_retry_count=1, alert_state_ttl_days=14)
                self.assertTrue(self.wp.send_estate_report(self.OUTPUT, cfg))
                self.assertFalse(self.wp.send_estate_report(self.OUTPUT, cfg))
                changed = {"exposure": {"domains": [{"domain": "example.com", "employees": 4}]}}
                self.assertTrue(self.wp.send_estate_report(changed, cfg))
        finally:
            self.wp._post_with_retry = orig
        self.assertEqual(len(sent), 2)
