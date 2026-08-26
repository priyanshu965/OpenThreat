"""
Tests for the v4 research and entity modules.

The bias here is toward END-TO-END assertions rather than unit tests of each
half. This project has twice shipped a fully green suite alongside a wrong
published artifact — a provenance hint that classify_provenance() silently
discarded, and a frontend module that was never spliced in at all. Both were
integration gaps that per-half unit tests could not see. So where a value has
to travel from one function into a published field, the test follows it the
whole way.
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import backtest as bt                       # noqa: E402
import campaigns as camp                    # noqa: E402
import entity_graph as eg                   # noqa: E402
import exploit_lag as lag                   # noqa: E402
import exports                              # noqa: E402
import fetch_intel as fi                    # noqa: E402
import sigma_rules as sig                   # noqa: E402
import source_reliability as sr             # noqa: E402
import timeline as tl                       # noqa: E402


def _day(offset_days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=offset_days)).strftime("%Y-%m-%d")


def _write_archive(root: Path, days: dict) -> Path:
    archive = root / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    for date_str, items in days.items():
        (archive / f"{date_str}.json").write_text(
            json.dumps({"last_updated": f"{date_str}T00:00:00+00:00", "items": items}),
            encoding="utf-8")
    return archive


# ═══════════════════════════════════════════════════════════════════════════
class TestPriorityComponents(unittest.TestCase):
    """The score breakdown is only useful if it reaches the published item.

    compute_priority() returned `components` correctly while main() copied
    five named fields and dropped it, so the dashboard's score breakdown had
    nothing to render. The unit test passed; the artifact was wrong. This
    checks the arithmetic AND that the field survives the copy in main().
    """

    def test_components_sum_to_the_score(self):
        for item in (
            {"cvss_score": 7.5, "epss_score": 0.02},
            {"cvss_score": 9.8, "epss_score": 0.42, "cisa_kev": True, "has_poc": True},
            {"cvss_score": 6.5, "cisa_kev": True},
            {"cvss_score": 9.9, "epss_score": 0.97, "cisa_kev": True, "has_poc": True,
             "ssvc_exploitation": "active", "ssvc_automatable": "yes",
             "ssvc_technical_impact": "total"},
        ):
            result = fi.compute_priority(item)
            total = sum(c["points"] for c in result["components"])
            self.assertAlmostEqual(
                total, result["score"], places=1,
                msg=f"components do not sum to the score for {item}")

    def test_floor_is_shown_as_its_own_term(self):
        result = fi.compute_priority({"cvss_score": 6.5, "cisa_kev": True})
        labels = [c["label"] for c in result["components"]]
        self.assertIn("Confirmed-exploitation floor", labels,
                      "the KEV floor added 43 points invisibly")

    def test_cap_is_shown_as_its_own_term(self):
        result = fi.compute_priority({
            "cvss_score": 10.0, "epss_score": 1.0, "cisa_kev": True, "has_poc": True,
            "ssvc_exploitation": "active", "ssvc_automatable": "yes",
            "ssvc_technical_impact": "total"})
        self.assertEqual(result["score"], 100.0)
        self.assertIn("Capped at 100", [c["label"] for c in result["components"]])

    def test_main_copies_components_onto_the_item(self):
        """Guards the exact gap that shipped: the field must be in the copy list."""
        source = (PROJECT_ROOT / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        self.assertIn('item["priority_components"] = priority["components"]', source,
                      "compute_priority emits components but main() does not "
                      "copy them onto the item, so nothing is published")


# ═══════════════════════════════════════════════════════════════════════════
class TestBacktest(unittest.TestCase):
    """The experiment is only meaningful if it cannot cheat."""

    def test_cves_already_in_kev_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = _write_archive(root, {
                _day(60): [
                    {"cve_id": "CVE-2020-1111", "priority_score": 95, "cisa_kev": True},
                    {"cve_id": "CVE-2020-2222", "priority_score": 60},
                ],
            })
            kev = {
                "CVE-2020-1111": {"added": _day(90)},     # listed BEFORE we scored it
                "CVE-2020-2222": {"added": _day(50)},     # listed after — a real prediction
            }
            cohort = bt.collect_cohort(archive, kev)
            by_cve = {row["cve"]: row for row in cohort}
            self.assertTrue(by_cve["CVE-2020-1111"]["already_kev"],
                            "a CVE already in KEV when scored must not be predictable")
            self.assertFalse(by_cve["CVE-2020-2222"]["already_kev"])

    def test_recent_cves_are_censored_not_counted_as_misses(self):
        row = {"scored_on": _day(3), "kev_added": ""}
        self.assertIsNone(bt._label(row, horizon_days=30),
                          "a CVE scored 3 days ago has not had its chance yet")
        old = {"scored_on": _day(90), "kev_added": ""}
        self.assertIs(bt._label(old, horizon_days=30), False)

    def test_listing_inside_the_horizon_is_a_hit(self):
        row = {"scored_on": _day(60), "kev_added": _day(45)}
        self.assertIs(bt._label(row, horizon_days=30), True)

    def test_listing_outside_the_horizon_is_not_a_hit(self):
        row = {"scored_on": _day(120), "kev_added": _day(40)}
        self.assertIs(bt._label(row, horizon_days=30), False)

    def test_confusion_matrix_arithmetic(self):
        rows = [(95, True), (80, False), (75, True), (30, False), (20, True)]
        result = bt._confusion(rows, 70)
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]),
                         (2, 1, 1, 1))
        self.assertAlmostEqual(result["precision"], 2 / 3, places=3)
        self.assertAlmostEqual(result["recall"], 2 / 3, places=3)

    def test_average_precision_rewards_a_perfect_ranking(self):
        perfect = [(100, True), (90, True), (10, False), (5, False)]
        inverted = [(100, False), (90, False), (10, True), (5, True)]
        self.assertEqual(bt._average_precision(perfect), 1.0)
        self.assertLess(bt._average_precision(inverted), 0.6)

    def test_blend_never_awards_kev_points(self):
        """Cohort rows were not in KEV when scored, so a KEV term would be
        inventing points the live scorer did not give them."""
        row = {"cvss": 10.0, "epss": 1.0, "ssvc": "", "has_poc": False,
               "automatable": False, "total_impact": False}
        self.assertAlmostEqual(bt._blend(row, 40, 40), 80.0, places=1)

    def test_thin_archive_says_so_rather_than_inventing_a_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = _write_archive(Path(tmp), {
                _day(40): [{"cve_id": "CVE-2020-3333", "priority_score": 50}],
            })
            out = bt.build_backtest(archive, {"CVE-2020-3333": {"added": ""}})
            self.assertTrue(out["insufficient_data"])
            self.assertIn("Not enough history", out["verdict"])


# ═══════════════════════════════════════════════════════════════════════════
class TestSourceReliability(unittest.TestCase):
    """Coverage and early warning are different questions."""

    def _build(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = _write_archive(Path(tmp), {
                _day(60): [
                    {"cve_id": "CVE-2021-1000", "source": "Early Feed", "priority_score": 70},
                ],
                _day(40): [
                    {"cve_id": "CVE-2021-1000", "source": "Late Feed", "priority_score": 70},
                ],
            })
            kev = {"CVE-2021-1000": {"added": _day(45)}}
            return sr.build_source_reliability(archive, kev)

    def test_a_source_reporting_after_the_listing_gets_no_early_warning_credit(self):
        out = self._build()
        rows = {r["source"]: r for r in out["sources"]}
        self.assertEqual(rows["Early Feed"]["ahead_hits"], 1,
                         "carried the CVE 15 days before CISA listed it")
        self.assertEqual(rows["Late Feed"]["ahead_hits"], 0,
                         "reported it 5 days AFTER the listing — that is not a forecast")

    def test_coverage_still_credits_the_late_source(self):
        out = self._build()
        rows = {r["source"]: r for r in out["sources"]}
        self.assertEqual(rows["Late Feed"]["kev_hits"], 1,
                         "coverage is a real, separate measure")

    def test_first_mover_requires_being_first_and_early(self):
        out = self._build()
        rows = {r["source"]: r for r in out["sources"]}
        self.assertEqual(rows["Early Feed"]["first_mover_hits"], 1)
        self.assertEqual(rows["Late Feed"]["first_mover_hits"], 0)

    def test_noise_counts_items_with_nothing_enrichable(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = _write_archive(Path(tmp), {
                _day(10): [
                    {"source": "Noisy", "title": "a headline"},
                    {"source": "Noisy", "title": "another"},
                    {"source": "Noisy", "cve_id": "CVE-2021-9999", "priority_score": 10},
                ],
            })
            out = sr.build_source_reliability(archive, {"CVE-2021-9999": {"added": ""}})
            row = next(r for r in out["sources"] if r["source"] == "Noisy")
            self.assertEqual(row["noise_items"], 2)
            self.assertAlmostEqual(row["noise_ratio"], 2 / 3, places=2)


# ═══════════════════════════════════════════════════════════════════════════
class TestExploitLag(unittest.TestCase):

    def test_cve_ids_are_validated_before_reaching_a_url(self):
        """The id comes from a third-party catalogue and builds a request path."""
        self.assertIsNone(lag._fetch_published("CVE-../../etc/passwd"))
        self.assertIsNone(lag._fetch_published("not-a-cve"))
        self.assertIsNone(lag._fetch_published(""))

    def test_day_parses_the_shapes_the_apis_actually_return(self):
        for value in ("2026-01-15", "2026-01-15T10:22:00Z", "2026-01-15T10:22:00+00:00"):
            parsed = lag._day(value)
            self.assertIsNotNone(parsed, value)
            self.assertEqual(parsed.date().isoformat(), "2026-01-15")
        self.assertIsNone(lag._day(""))
        self.assertIsNone(lag._day("nonsense"))

    def test_summary_reports_a_distribution_not_just_a_mean(self):
        summary = lag._summary([1, 2, 3, 4, 100])
        self.assertEqual(summary["median"], 3)
        self.assertEqual(summary["n"], 5)
        self.assertEqual(summary["max"], 100)
        self.assertLess(summary["median"], summary["mean"],
                        "one 100-day outlier must not become the headline")

    def test_thin_data_reports_coverage_instead_of_a_number(self):
        out = lag.build_exploit_lag({"CVE-2099-0001": {"added": "2026-01-01"}})
        self.assertTrue(out.get("insufficient_data"))
        self.assertIn("coverage_pct", out)


# ═══════════════════════════════════════════════════════════════════════════
class TestCampaigns(unittest.TestCase):

    @staticmethod
    def _item(title, actor=None, malware=None, tech=None, sector=None,
              source="S", days_ago=1):
        return {
            "title": title, "source": source,
            "published": (datetime.now(timezone.utc)
                          - timedelta(days=days_ago)).isoformat(),
            "threat_actors": [actor] if actor else [],
            "malware": [malware] if malware else [],
            "ttps": [{"id": t} for t in (tech or [])],
            "sector": sector,
        }

    def test_shared_actor_forms_a_cluster(self):
        items = [self._item(f"story {i}", actor="APT99", source=f"S{i}")
                 for i in range(3)]
        out = camp.build_campaigns(items, window_days=14, min_items=3)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["campaigns"][0]["anchor"], "APT99")

    def test_technique_and_sector_overlap_alone_never_creates_a_cluster(self):
        """Rule 3 must be extension-only. Unconstrained it merges half the feed:
        T1566 and 'corporate' co-occur constantly and mean nothing together."""
        items = [self._item(f"story {i}", tech=["T1566"], sector="corporate",
                            source=f"S{i}") for i in range(6)]
        out = camp.build_campaigns(items, window_days=14, min_items=3)
        self.assertIsNone(out, "technique+sector overlap invented a campaign")

    def test_technique_and_sector_overlap_can_extend_an_anchored_cluster(self):
        items = [self._item(f"anchored {i}", actor="APT99", tech=["T1486"],
                            sector="healthcare", source=f"S{i}") for i in range(3)]
        items.append(self._item("unanchored", tech=["T1486"], sector="healthcare",
                                source="S9"))
        out = camp.build_campaigns(items, window_days=14, min_items=3)
        self.assertEqual(out["campaigns"][0]["extended_items"], 1)
        self.assertEqual(out["campaigns"][0]["items"], 4)

    def test_confidence_counts_sources_not_rows(self):
        """Five rows from one feed is one observation repeated."""
        same = [self._item(f"s{i}", actor="APT98", source="OneFeed") for i in range(5)]
        out = camp.build_campaigns(same, window_days=14, min_items=3)
        self.assertEqual(out["campaigns"][0]["confidence"], "low")

    def test_items_outside_the_window_are_not_clustered(self):
        items = [self._item(f"s{i}", actor="APT97", source=f"S{i}", days_ago=1)
                 for i in range(2)]
        items.append(self._item("old", actor="APT97", source="S9", days_ago=90))
        out = camp.build_campaigns(items, window_days=14, min_items=3)
        self.assertIsNone(out, "a 90-day-old item joined a 14-day window")


# ═══════════════════════════════════════════════════════════════════════════
class TestEntityGraph(unittest.TestCase):

    def test_actor_case_variants_are_collapsed(self):
        """Leak-site fetchers hand us the crew's own spelling, so one run
        carried Qilin, qilin, SafePay and safepay as four distinct actors and
        split every count that keys on the name."""
        items = [
            {"threat_actors": ["Qilin"]},
            {"threat_actors": ["qilin"]},
            {"threat_actors": ["SafePay", "safepay"]},
        ]
        eg.canonical_actor_names(items)
        self.assertEqual(items[0]["threat_actors"], ["Qilin"])
        self.assertEqual(items[1]["threat_actors"], ["Qilin"])
        self.assertEqual(items[2]["threat_actors"], ["SafePay"],
                         "within one item the variants must also collapse")

    def test_ordinary_english_words_are_not_treated_as_malware(self):
        """ATT&CK ships tools named Expand, Route, Chaos and Embargo. Matching
        them against prose tagged a shipping-embargo story as ransomware."""
        kb = {"software": {
            "Embargo": {"aliases": [], "techniques": [], "actors": []},
            "Chaos": {"aliases": [], "techniques": [], "actors": []},
            "QakBot": {"aliases": ["Qbot"], "techniques": [], "actors": []},
        }}
        matcher, lookup = eg.build_software_matcher(kb)
        text = "The trade embargo caused chaos for shipping, and QakBot spread."
        found = eg.detect_software(text, matcher, lookup)
        self.assertEqual(found, ["QakBot"])

    def test_family_names_that_are_ordinary_words_are_refused(self):
        """Found by reading the published graph, not by guessing.

        Malpedia carries families literally called Global, Payload, Crisis and
        Globe. Every one fired against ordinary security prose — 'Global' alone
        matched 11 items in a single run, more than every real family combined.
        A missed family is a gap; a wrong one is a false claim about who is
        behind an incident, so ambiguous names are dropped.
        """
        kb = {"software": {name: {"aliases": [], "techniques": [], "actors": []}
                           for name in ("Global", "Payload", "Crisis", "Globe",
                                        "Phoenix", "Emotet")}}
        matcher, lookup = eg.build_software_matcher(kb)
        text = ("A global payload delivery crisis hit the phoenix project "
                "across the globe, and Emotet was involved.")
        self.assertEqual(eg.detect_software(text, matcher, lookup), ["Emotet"])

    def test_matching_is_whole_token(self):
        kb = {"software": {"Emotet": {"aliases": [], "techniques": [], "actors": []}}}
        matcher, lookup = eg.build_software_matcher(kb)
        self.assertEqual(eg.detect_software("emotethreatxyz", matcher, lookup), [])
        self.assertEqual(eg.detect_software("Emotet returned.", matcher, lookup), ["Emotet"])

    def test_known_and_observed_edges_stay_distinguishable(self):
        """Presenting co-occurrence as if MITRE asserted it would be the most
        misleading thing this view could do."""
        kb = {
            "actors": {"APT99": {"aliases": [], "techniques": ["T1071"],
                                 "software": ["Widget"], "url": ""}},
            "software": {"Widget": {"aliases": [], "techniques": ["T1071"],
                                    "actors": ["APT99"], "kind": "malware", "url": ""}},
            "technique_names": {"T1071": "Application Layer Protocol"},
        }
        items = [{"threat_actors": ["APT99"], "malware": ["Widget"],
                  "ttps": [{"id": "T1071"}], "sector": "government",
                  "title": "x"}]
        graph = eg.build_entity_graph(items, kb)
        origins = {e["origin"] for e in graph["edges"]}
        self.assertEqual(origins, {"attack", "observed"})
        targets = [e for e in graph["edges"] if e["kind"] == "targets"]
        self.assertTrue(all(e["origin"] == "observed" for e in targets),
                        "ATT&CK does not assert sector targeting; we observed it")

    def test_aliases_resolve_a_feed_name_onto_the_attack_name(self):
        kb = {
            "actors": {"Sandworm Team": {"aliases": ["Voodoo Bear"],
                                         "techniques": [], "software": [], "url": ""}},
            "software": {}, "technique_names": {},
        }
        graph = eg.build_entity_graph(
            [{"threat_actors": ["Voodoo Bear"], "ttps": [], "title": "x"}], kb)
        labels = [n["label"] for n in graph["nodes"] if n["type"] == "actor"]
        self.assertEqual(labels, ["Sandworm Team"])


# ═══════════════════════════════════════════════════════════════════════════
class TestSigmaRules(unittest.TestCase):

    RULE = """title: Suspicious Thing
id: 11111111-2222-3333-4444-555555555555
related:
    - id: 99999999-9999-9999-9999-999999999999
      type: obsolete
status: stable
description: Detects a suspicious thing.
tags:
    - attack.execution
    - attack.t1059.001
level: high
"""

    def test_parser_takes_the_rule_id_not_the_related_id(self):
        rule = sig._parse_rule(self.RULE, "rules/windows/process_creation/x.yml")
        self.assertEqual(rule["id"], "11111111-2222-3333-4444-555555555555")

    def test_parser_extracts_techniques_level_and_logsource(self):
        rule = sig._parse_rule(self.RULE, "rules/windows/process_creation/x.yml")
        self.assertEqual(rule["techniques"], ["T1059.001"])
        self.assertEqual(rule["level"], "high")
        self.assertEqual(rule["logsource"], "windows / process_creation")

    def test_rules_without_attack_tags_are_skipped(self):
        self.assertIsNone(sig._parse_rule("title: No tags\nlevel: low\n", "rules/x.yml"))

    def test_parent_technique_inherits_its_subtechniques_rule_count(self):
        """A rule tagged attack.t1059.001 detects an instance of T1059."""
        index = {"by_technique": {"T1059.001": [{"title": "r"}]},
                 "totals": {"T1059.001": 4}}
        items = [{"ttps": [{"id": "T1059"}]}]
        sig.annotate_detections(items, index)
        self.assertEqual(items[0]["detection_rule_count"], 4)

    def test_items_with_no_covered_technique_get_no_field(self):
        index = {"by_technique": {"T1059": [{"title": "r"}]}, "totals": {"T1059": 1}}
        items = [{"ttps": [{"id": "T9999"}]}]
        sig.annotate_detections(items, index)
        self.assertNotIn("detection_rule_count", items[0])


# ═══════════════════════════════════════════════════════════════════════════
class TestTimeline(unittest.TestCase):

    def test_slim_item_drops_the_bulk_and_keeps_the_verdict(self):
        item = {
            "title": "T", "description": "x" * 900, "priority_score": 91,
            "priority_label": "urgent", "action": "Patch now", "cisa_kev": True,
            "ttps": [{"id": "T1059", "name": "Command Interpreter",
                      "tactic": "Execution", "tactic_id": "TA0002"}],
            "iocs": {"ipv4": ["1.2.3.4"] * 50},
            "source_health": {"junk": True},
        }
        slim = tl.slim_item(item)
        self.assertEqual(slim["priority_label"], "urgent")
        self.assertEqual(slim["ttps"], ["T1059"], "TTP objects reduce to ids")
        self.assertLessEqual(len(slim["description"]), 220)
        self.assertNotIn("iocs", slim)
        self.assertNotIn("source_health", slim)

    def test_verify_archive_finds_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = _write_archive(Path(tmp), {
                "2026-01-01": [], "2026-01-02": [], "2026-01-05": [],
            })
            health = tl.verify_archive(archive)
            self.assertFalse(health["contiguous"])
            self.assertEqual(health["missing"], ["2026-01-03", "2026-01-04"])
            self.assertEqual(health["days"], 3)
            self.assertEqual(health["span_days"], 5)

    def test_verify_archive_on_a_complete_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = _write_archive(Path(tmp), {"2026-01-01": [], "2026-01-02": []})
            self.assertTrue(tl.verify_archive(archive)["contiguous"])

    def test_publish_writes_a_day_file_and_an_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = _write_archive(root, {
                "2026-01-01": [{"title": "a", "priority_label": "urgent",
                                "priority_score": 95, "cisa_kev": True}],
            })
            out = tl.publish_timeline(archive, root / "api")
            self.assertEqual(out["days"], 1)
            self.assertTrue((root / "api" / "day" / "2026-01-01.json").exists())
            row = out["timeline"][0]
            self.assertEqual(row["urgent"], 1)
            self.assertEqual(row["kev"], 1)
            self.assertTrue(row["sha256"], "no integrity digest recorded")

    def test_days_outside_retention_are_pruned_from_the_published_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = _write_archive(root, {"2026-01-02": []})
            stale = root / "api" / "day"
            stale.mkdir(parents=True)
            (stale / "2020-01-01.json").write_text("{}", encoding="utf-8")
            tl.publish_timeline(archive, root / "api")
            self.assertFalse((stale / "2020-01-01.json").exists())


# ═══════════════════════════════════════════════════════════════════════════
class TestMispExport(unittest.TestCase):

    OUTPUT = {
        "last_updated": "2026-08-25T12:00:00+00:00",
        "brief": {"headline": "A quiet day."},
        "items": [
            {"title": "Bad IP", "source": "URLhaus", "cve_id": None,
             "iocs": {"ipv4": ["203.0.113.9"]}, "published": "2026-08-25"},
            {"title": "News story", "source": "Krebs on Security",
             "iocs": {"domain": ["example.com"]}, "published": "2026-08-25"},
            {"title": "Exploited bug", "source": "NVD", "cve_id": "CVE-2026-1234",
             "cisa_kev": True, "iocs": {}, "published": "2026-08-25",
             "threat_actors": ["APT99"], "ttps": [{"id": "T1059"}]},
        ],
    }

    def _event(self, tmp):
        rows = list(exports._iter_iocs(self.OUTPUT["items"]))
        path = Path(tmp) / "misp_event.json"
        exports._write_misp(self.OUTPUT, rows, path, self.OUTPUT["last_updated"])
        return json.loads(path.read_text(encoding="utf-8"))["Event"]

    def test_every_attribute_has_a_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = self._event(tmp)
            self.assertTrue(event["Attribute"])
            for attr in event["Attribute"]:
                self.assertTrue(attr["value"], f"empty value: {attr}")

    def test_only_indicator_feeds_are_marked_to_ids(self):
        """to_ids says 'safe to turn into a detection rule'. A hash mentioned
        in a news article is context; pushing it into an IDS is how false
        positives reach someone's SOC."""
        with tempfile.TemporaryDirectory() as tmp:
            event = self._event(tmp)
            by_value = {a["value"]: a for a in event["Attribute"]}
            self.assertTrue(by_value["203.0.113.9"]["to_ids"])
            self.assertNotIn("example.com", by_value,
                             "prose from a news article is not a threat feed")

    def test_exploited_cves_ride_along_as_vulnerability_attributes(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = self._event(tmp)
            vulns = [a for a in event["Attribute"] if a["type"] == "vulnerability"]
            self.assertEqual([v["value"] for v in vulns], ["CVE-2026-1234"])
            self.assertFalse(vulns[0]["to_ids"])

    def test_event_is_deterministic_so_reimport_updates_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self._event(tmp)
            second = self._event(tmp)
            self.assertEqual(first["uuid"], second["uuid"])
            self.assertEqual([a["uuid"] for a in first["Attribute"]],
                             [a["uuid"] for a in second["Attribute"]])

    def test_actors_and_techniques_become_galaxy_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = self._event(tmp)
            names = [t["name"] for t in event["Tag"]]
            self.assertIn("tlp:clear", names)
            self.assertIn('misp-galaxy:threat-actor="APT99"', names)
            self.assertIn("mitre-attack-pattern:T1059", names)


# ═══════════════════════════════════════════════════════════════════════════
class TestFetchlibIsShared(unittest.TestCase):
    """The satellite modules used to import the session and cache from
    fetch_intel inside a try/except that could never succeed, so they all ran
    with caching disabled and re-downloaded everything on all 24 daily runs."""

    def test_no_module_reaches_back_into_fetch_intel_for_the_session(self):
        # Real import statements only. Several modules mention the old pattern
        # in a comment explaining why it was removed, and matching those would
        # make this test fail on its own documentation.
        offenders = []
        for path in (PROJECT_ROOT / "scripts").glob("*.py"):
            if path.name in ("fetch_intel.py", "fetchlib.py"):
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith(("from fetch_intel import", "import fetch_intel")):
                    offenders.append(f"{path.name}: {stripped}")
        self.assertEqual(offenders, [],
                         "these import from fetch_intel, which re-executes it as "
                         "a second module under `python scripts/fetch_intel.py`")

    def test_cache_helpers_are_the_same_objects(self):
        import fetchlib
        self.assertIs(fi._cached_fetch, fetchlib.cached_fetch)
        self.assertIs(fi._SESSION, fetchlib.SESSION)


if __name__ == "__main__":
    unittest.main()
