"""Unit tests for CyberWatch pipeline helpers.

These import the REAL implementations from scripts/fetch_intel.py.

The previous version of this file re-implemented extract_cve_id, infer_severity,
infer_category, extract_iocs and compute_priority inside the test module and
then tested those copies, so all 30 tests passed while exercising zero lines of
production code — including a verbatim copy of the `rce`-substring bug that
mislabelled 31% of all `critical` items.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import fetch_intel as fi                                     # noqa: E402
from mitre_ttps import map_ttps                              # noqa: E402


class TestCveExtraction(unittest.TestCase):
    def test_standard_cve(self):
        self.assertEqual(fi.extract_cve_id("CVE-2024-1234 found in the wild"), "CVE-2024-1234")

    def test_lowercase_is_normalised(self):
        self.assertEqual(fi.extract_cve_id("see cve-2023-49113"), "CVE-2023-49113")

    def test_no_cve(self):
        self.assertIsNone(fi.extract_cve_id("No vulnerability here"))

    def test_multiple_cves_returns_first(self):
        self.assertEqual(fi.extract_cve_id("CVE-2024-1111 and CVE-2024-2222"), "CVE-2024-1111")


class TestSeverityInference(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(fi.infer_severity("critical rce vulnerability"), "critical")
        self.assertEqual(fi.infer_severity("zero-day exploit released"), "critical")
        self.assertEqual(fi.infer_severity("actively exploited in the wild"), "critical")

    def test_high(self):
        self.assertEqual(fi.infer_severity("privilege escalation in kernel"), "high")
        self.assertEqual(fi.infer_severity("data breach at major corp"), "high")

    def test_medium(self):
        self.assertEqual(fi.infer_severity("xss vulnerability in plugin"), "medium")

    def test_low(self):
        self.assertEqual(fi.infer_severity("informational guide released"), "low")

    def test_default(self):
        self.assertEqual(fi.infer_severity("something random here"), "medium")

    # ── Regression: whole-token matching ────────────────────────────────────
    # "rce" is a substring of source / force / resource / Salesforce, and the
    # original `kw in text` form made all of them `critical`. Measured against
    # a real run: 16 of 51 critical items were false for exactly this reason,
    # and ALERT_SEVERITIES defaults to `critical`, so they were paged out.
    def test_rce_does_not_match_inside_other_words(self):
        for text in ("Salesforce data exposure",
                     "a resource leak causes a crash",
                     "this enforcement action was taken",
                     "brute force login attempts observed"):
            self.assertNotEqual(fi.infer_severity(text), "critical",
                                f"false critical on: {text!r}")

    def test_rce_still_matches_as_a_word(self):
        self.assertEqual(fi.infer_severity("Critical RCE in Apache Struts"), "critical")
        self.assertEqual(fi.infer_severity("unauthenticated rce, patch now"), "critical")

    def test_apt_does_not_match_adapter(self):
        self.assertNotEqual(fi.infer_severity("network adapter driver update"), "high")


class TestCategoryInference(unittest.TestCase):
    def test_cve_category(self):
        self.assertEqual(fi.infer_category("CVE-2024-1234 in Apache"), "cve")
        self.assertEqual(fi.infer_category("new vulnerability in nginx"), "cve")

    def test_incident_category(self):
        self.assertEqual(fi.infer_category("data breach at company"), "incident")

    def test_advisory_category(self):
        self.assertEqual(fi.infer_category("cisa advisory released"), "advisory")

    def test_news_default(self):
        self.assertEqual(fi.infer_category("something else entirely"), "news")


class TestIocExtraction(unittest.TestCase):
    """IOCs are only extracted from sources that actually publish indicators."""

    def test_ioc_feed_yields_indicators(self):
        result = fi.extract_iocs("malicious IP 203.0.113.45 seen", source="URLhaus")
        self.assertIn("203.0.113.45", result.get("ipv4", []))

    def test_hashes_from_ioc_feed(self):
        result = fi.extract_iocs("hash: d41d8cd98f00b204e9800998ecf8427e", source="ThreatFox")
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result.get("md5", []))

    def test_private_ips_filtered(self):
        result = fi.extract_iocs("internal host 192.168.1.1 and 10.0.0.5", source="URLhaus")
        self.assertEqual(result.get("ipv4", []), [])

    # ── Regression: the STIX bundle used to publish these ───────────────────
    def test_news_prose_yields_no_network_indicators(self):
        text = "Contact steve.traylen@cern.ch about the redhat.com advisory at isc.sans.edu"
        result = fi.extract_iocs(text, source="Fedora")
        self.assertNotIn("domain", result)
        self.assertNotIn("email", result,
                         "maintainer emails must never be exported as indicators")

    def test_infrastructure_domains_rejected(self):
        result = fi.extract_iocs("see github.com and gmail.com", source="URLhaus")
        self.assertEqual(result.get("domain", []), [])

    def test_code_identifiers_rejected(self):
        result = fi.extract_iocs("in handlers.ts we call req.query and ops.dispatch",
                                 source="URLhaus")
        self.assertEqual(result.get("domain", []), [])

    def test_own_url_host_excluded(self):
        result = fi.extract_iocs("read more at https://malbearlabs.com/post",
                                 source="AlienVault OTX",
                                 own_url="https://malbearlabs.com/post")
        self.assertEqual(result.get("domain", []), [])

    def test_defanged_text_is_treated_as_indicators(self):
        result = fi.extract_iocs("C2 at evil-domain[.]tld and hxxp://bad[.]example",
                                 source="The Hacker News")
        self.assertIn("evil-domain.tld", result.get("domain", []))

    def test_cve_extracted_from_any_source(self):
        result = fi.extract_iocs("affects CVE-2024-3094", source="Krebs on Security")
        self.assertIn("CVE-2024-3094", result.get("cve", []))

    def test_empty(self):
        self.assertEqual(fi.extract_iocs(""), {})


class TestThreatFoxIocTyping(unittest.TestCase):
    """ThreatFox reports the indicator type; the code used to ignore it and
    re-derive the type from the string's shape instead."""

    def test_bare_ip_is_an_ip_not_a_domain(self):
        """The old shape test required a ':port' suffix to take the IPv4
        branch, so a bare address fell through and was published as a domain."""
        self.assertEqual(fi._threatfox_ioc("185.220.101.5", "ip:port"),
                         {"ipv4": ["185.220.101.5"]})

    def test_ip_port_is_split(self):
        self.assertEqual(fi._threatfox_ioc("185.220.101.5:8080", "ip:port"),
                         {"ipv4": ["185.220.101.5"]})

    def test_hashes_are_typed(self):
        """Hashes matched no branch at all and fell through to the prose
        extractor."""
        sha = "a" * 64
        self.assertEqual(fi._threatfox_ioc(sha, "sha256_hash"), {"sha256": [sha]})
        self.assertEqual(fi._threatfox_ioc("b" * 32, "md5_hash"), {"md5": ["b" * 32]})

    def test_domain_is_lowercased(self):
        self.assertEqual(fi._threatfox_ioc("EVIL.Example", "domain"),
                         {"domain": ["evil.example"]})

    def test_url_is_preserved_verbatim(self):
        url = "http://evil.example/Payload.BIN"
        self.assertEqual(fi._threatfox_ioc(url, "url"), {"url": [url]})

    def test_unknown_type_falls_back_to_the_shared_extractor(self):
        self.assertIsInstance(fi._threatfox_ioc("1.2.3.4", "something_new"), dict)


class TestPriorityScoring(unittest.TestCase):
    def test_urgent_kev(self):
        result = fi.compute_priority({"cvss_score": 5.0, "epss_score": 0.1, "cisa_kev": True})
        self.assertGreaterEqual(result["score"], 90)
        self.assertEqual(result["label"], "urgent")

    def test_none_on_no_signal(self):
        self.assertIsNone(fi.compute_priority({"title": "just news"}))

    def test_rationale_includes_kev(self):
        result = fi.compute_priority({"cisa_kev": True})
        self.assertIn("CISA KEV", result["rationale"])
        self.assertEqual(result["score"], 90.0)

    def test_score_is_bounded(self):
        result = fi.compute_priority({"cvss_score": 10.0, "epss_score": 1.0, "cisa_kev": True,
                                      "has_poc": True, "ssvc_exploitation": "active",
                                      "ssvc_automatable": "yes",
                                      "ssvc_technical_impact": "total"})
        self.assertLessEqual(result["score"], 100.0)

    def test_ssvc_active_escalates(self):
        base = fi.compute_priority({"cvss_score": 6.0})
        ssvc = fi.compute_priority({"cvss_score": 6.0, "ssvc_exploitation": "active"})
        self.assertGreater(ssvc["score"], base["score"])
        self.assertEqual(ssvc["label"], "urgent")

    def test_every_scored_item_gets_an_action(self):
        for label in ("urgent", "elevated", "moderate", "low"):
            self.assertIn(label, fi._ACTION_BY_LABEL)
        result = fi.compute_priority({"cvss_score": 9.8, "cisa_kev": True})
        self.assertEqual(result["action"], "Patch now")

    def test_config_weights_are_honoured(self):
        """The old utils.compute_priority hardcoded 40/40/20, silently ignoring
        the documented PRIORITY_* environment overrides."""
        result = fi.compute_priority({"cvss_score": 10.0})
        self.assertAlmostEqual(result["score"], fi.CONFIG.priority_cvss_weight, places=1)

    def test_poc_is_a_bonus_not_a_floor(self):
        """A PoC used to floor the score at 70, which forced every low-impact
        item with a scaffold repo on GitHub into "Patch this week" and tied
        them all at an identical score."""
        low = fi.compute_priority({"cvss_score": 3.1, "has_poc": True})
        self.assertLess(low["score"], 70.0)
        self.assertNotEqual(low["action"], "Patch this week")

    def test_poc_still_raises_the_score(self):
        without = fi.compute_priority({"cvss_score": 7.5})
        with_poc = fi.compute_priority({"cvss_score": 7.5, "has_poc": True})
        self.assertGreater(with_poc["score"], without["score"])
        self.assertIn("Public PoC", with_poc["rationale"])

    def test_poc_scores_still_rank_against_each_other(self):
        """The floor collapsed ordering; different impacts must now differ."""
        weak   = fi.compute_priority({"cvss_score": 4.0, "has_poc": True})
        strong = fi.compute_priority({"cvss_score": 9.5, "has_poc": True})
        self.assertGreater(strong["score"], weak["score"])

    def test_kev_floor_is_retained(self):
        """KEV keeps its floor — confirmed exploitation outranks any CVSS."""
        self.assertGreaterEqual(
            fi.compute_priority({"cvss_score": 2.0, "cisa_kev": True})["score"], 90.0)


class TestEnrichmentBudget(unittest.TestCase):
    """select_enrichment_candidates() splits the AI allowance.

    Ranking purely on priority_score sent all 40 slots to CVEs; in a typical
    run 167 of 241 items have no score at all and so were never enriched.
    """

    def _items(self):
        scored = [{"title": f"cve {n}", "priority_score": float(n), "severity": "high",
                   "published": "2026-08-20"} for n in range(60)]
        unscored = [{"title": f"news {n}", "priority_score": None,
                     "severity": "critical" if n < 5 else "low",
                     "published": f"2026-08-{(n % 28) + 1:02d}"} for n in range(60)]
        return scored + unscored

    def test_unscored_items_get_slots(self):
        picked = fi.select_enrichment_candidates(self._items())
        self.assertTrue(any(i.get("priority_score") is None for i in picked),
                        "no budget reached unscored items")

    def test_budgets_are_respected(self):
        picked = fi.select_enrichment_candidates(self._items())
        scored = [i for i in picked if i.get("priority_score") is not None]
        unscored = [i for i in picked if i.get("priority_score") is None]
        self.assertEqual(len(scored), fi.AI_ENRICH_LIMIT)
        self.assertEqual(len(unscored), fi.CONFIG.ai_enrich_unscored_limit)

    def test_scored_slice_is_highest_priority_first(self):
        picked = fi.select_enrichment_candidates(self._items())
        scores = [i["priority_score"] for i in picked if i.get("priority_score") is not None]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_unscored_slice_prefers_severity_then_recency(self):
        picked = fi.select_enrichment_candidates(self._items())
        unscored = [i for i in picked if i.get("priority_score") is None]
        self.assertEqual(unscored[0]["severity"], "critical")


class TestAiCache(unittest.TestCase):
    """Enrichment is cached across runs, so the hourly pipeline stops paying
    for the same items 24 times a day."""

    def test_roundtrip_applies_cached_fields(self):
        source = {"cve_id": "CVE-2026-0001", "title": "x",
                  "ai_summary": "a real analysis", "why_it_matters": "act today",
                  "vendors": ["acme"], "products": ["widget"],
                  "ai_confidence": 0.9, "ai_provider": "gemini", "ai_model": "m"}
        cache = {}
        fi._cache_enrichment(cache, source)
        self.assertIn(fi.item_key(source), cache)

        target = {"cve_id": "CVE-2026-0001", "title": "x", "ai_provider": "rule"}
        self.assertTrue(fi._apply_cached_enrichment(target, cache[fi.item_key(source)]))
        self.assertEqual(target["ai_summary"], "a real analysis")
        self.assertEqual(target["ai_provider"], "gemini")

    def test_rule_defaults_are_not_cached(self):
        """Caching a rule-based item would permanently starve it of a real
        model call, because the cache hit marks it already enriched."""
        cache = {}
        fi._cache_enrichment(cache, {"cve_id": "CVE-2026-0002", "ai_provider": "rule"})
        self.assertEqual(cache, {})

    def test_cache_key_matches_item_identity(self):
        """The cache is keyed on item_key(), so the same story arriving from a
        different source still hits."""
        a = {"cve_id": "CVE-2026-0003", "source": "NVD"}
        b = {"cve_id": "cve-2026-0003", "source": "The Hacker News"}
        self.assertEqual(fi.item_key(a), fi.item_key(b))


class TestTtpMapping(unittest.TestCase):
    def test_real_technique_matches(self):
        self.assertIn("T1190", [t["id"] for t in map_ttps("Critical RCE in Apache Struts")])

    def test_substring_false_positives_gone(self):
        for text in ("Salesforce data exposure",
                     "a resource leak causes a crash",
                     "authentication failure logged"):
            self.assertEqual(map_ttps(text), [], f"false TTP on: {text!r}")

    def test_capped(self):
        self.assertLessEqual(len(map_ttps("phishing ransomware powershell wmi " * 30)), 10)


class TestDeduplication(unittest.TestCase):
    def test_identical_urls_collapse(self):
        items = [{"title": "A", "url": "https://x.test/a", "source": "S1"},
                 {"title": "B", "url": "https://x.test/a/", "source": "S2"}]
        self.assertEqual(len(fi.deduplicate(items)), 1)

    def test_tracking_params_ignored(self):
        items = [{"title": "A", "url": "https://x.test/a", "source": "S1"},
                 {"title": "B", "url": "https://x.test/a?utm_source=rss", "source": "S2"}]
        self.assertEqual(len(fi.deduplicate(items)), 1)

    def test_distinct_stories_survive(self):
        items = [{"title": "Fortinet RCE patched", "url": "https://x.test/1", "source": "S"},
                 {"title": "Cisco DoS disclosed", "url": "https://x.test/2", "source": "S"}]
        self.assertEqual(len(fi.deduplicate(items)), 2)

    def test_source_authority_ranking(self):
        self.assertGreater(fi._source_rank("NVD"), fi._source_rank("Reddit/netsec"))

    def test_authoritative_copy_survives(self):
        """Regression: the pipeline sorted on ``-_source_rank(...)`` with
        ``reverse=True``. The two negations cancelled, so the LEAST
        authoritative copy sorted first and "first occurrence wins" dedup kept
        the blog rewrite while discarding the NVD record.

        The old test only compared two _source_rank() return values, which
        stayed true the whole time the pipeline was doing the opposite.
        """
        items = [
            {"title": "Foo RCE flaw", "url": "https://news.test/foo",
             "source": "The Hacker News", "published": "2026-08-20T10:00:00+00:00"},
            {"title": "Foo RCE flaw", "url": "https://nvd.test/foo",
             "source": "NVD", "published": "2026-08-20T09:00:00+00:00"},
        ]
        survivors = fi.deduplicate(fi.sort_for_dedup(items))
        self.assertEqual(len(survivors), 1)
        self.assertEqual(survivors[0]["source"], "NVD")

    def test_sort_puts_highest_authority_first(self):
        items = [{"source": "Reddit/netsec", "published": "2026-08-20"},
                 {"source": "NVD", "published": "2026-08-20"},
                 {"source": "CISA", "published": "2026-08-19"}]
        self.assertEqual([i["source"] for i in fi.sort_for_dedup(items)],
                         ["NVD", "CISA", "Reddit/netsec"])

    def test_newest_wins_within_one_source(self):
        items = [{"source": "NVD", "title": "old", "published": "2026-08-01"},
                 {"source": "NVD", "title": "new", "published": "2026-08-20"}]
        self.assertEqual(fi.sort_for_dedup(items)[0]["title"], "new")


class TestCleanHtml(unittest.TestCase):
    def test_strips_tags(self):
        self.assertEqual(fi.clean_html("<p>hello <b>world</b></p>"), "hello world")

    def test_preserves_prose_with_angle_brackets(self):
        """`<[^>]+>` used to delete everything from a bare '<' to the next '>',
        silently truncating code snippets in advisory text."""
        out = fi.clean_html("Crash when if (a < b) and x > y")
        self.assertIn("a < b", out)
        self.assertIn("x > y", out)


class TestSourceHealth(unittest.TestCase):
    def test_fresh_items_have_low_median_age(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.assertLess(fi._median_age_days([{"published": now}] * 3), 1)

    def test_undated_items_return_none(self):
        self.assertIsNone(fi._median_age_days([{"title": "x"}]))

    def test_stale_feed_detected(self):
        """Regression: Threatpost returned 10 items every hour and reported
        'ok' while serving its 2022 archive."""
        old = [{"published": "2022-08-31T00:00:00+00:00"}] * 5
        self.assertGreater(fi._median_age_days(old), fi.CONFIG.source_stale_days)


if __name__ == "__main__":
    unittest.main()
