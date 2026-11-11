"""
OPENTHREAT — tests/test_feed_quality.py
=======================================
What happens to the feed after it is collected: which copies are the same
story, which sources are allowed to be slow, what the first screen is painted
from, and what the machine-readable exports carry.

Every one of these was added in response to something that went wrong on a
real run, and the docstrings say what.
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import dedup                                                 # noqa: E402
import exports                                               # noqa: E402
import feedutil                                              # noqa: E402
import fetch_intel as fi                                     # noqa: E402
import probe_feeds                                           # noqa: E402
import scoring                                               # noqa: E402
import sources                                               # noqa: E402
import stories                                               # noqa: E402
import timeline                                              # noqa: E402
from config import CONFIG                                    # noqa: E402


def _days_ago(n: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _news(title, source, days=0.0, **extra):
    return {"title": title, "description": "", "url": f"https://{source.lower()}.example/{abs(hash(title))}",
            "source": source, "category": "news", "provenance": "journalism",
            "published": _days_ago(days), **extra}


class TestCanonicalUrl(unittest.TestCase):
    def test_tracking_parameters_are_dropped(self):
        self.assertEqual(dedup._canonical_url("https://www.Example.com/a/?utm_source=rss&fbclid=1#top"),
                         "example.com/a")

    def test_pages_addressed_by_parameter_stay_distinct(self):
        """Every CERT-In advisory shares one path. Stripping the whole query
        collapsed ten of them to a single URL and nine were dropped."""
        base = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE="
        a, b = dedup._canonical_url(base + "CIVN-2026-0545"), dedup._canonical_url(base + "CIVN-2026-0544")
        self.assertNotEqual(a, b)
        items = [{"title": f"note {n}", "url": base + n, "source": "CERT-In"}
                 for n in ("CIVN-2026-0545", "CIVN-2026-0544")]
        self.assertEqual(len(dedup.deduplicate(items)), 2)

    def test_parameter_order_does_not_split_a_page(self):
        self.assertEqual(dedup._canonical_url("https://x.org/p?b=2&a=1"),
                         dedup._canonical_url("https://x.org/p?a=1&b=2"))

    def test_the_dashboard_uses_the_same_rule(self):
        """itemKey() in the browser must agree, or dismissing one CERT-In
        item dismisses all of them."""
        app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        block = app.split("function canonicalUrl(url)", 1)[1].split("function itemKey", 1)[0]
        self.assertIn("TRACKING_PARAM", block)
        self.assertNotIn(".split('?')[0]", block)


class TestEntryDate(unittest.TestCase):
    def test_parsed_struct_wins(self):
        stamp = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc).timetuple()
        self.assertEqual(feedutil.entry_date({"published_parsed": stamp}), "2026-11-01T12:00:00+00:00")

    def test_updated_is_used_when_published_is_missing(self):
        stamp = datetime(2026, 10, 2, tzinfo=timezone.utc).timetuple()
        self.assertTrue(feedutil.entry_date({"updated_parsed": stamp}).startswith("2026-10-02"))

    def test_a_date_feedparser_cannot_read_is_still_read(self):
        """CrowdStrike's feed. feedparser returns the string and no struct, so
        every item used to be stamped with the time of the run."""
        got = feedutil.entry_date({"published": "Nov 10, 2026 00:00:00-0600", "published_parsed": None})
        self.assertEqual(got, "2026-11-10T06:00:00+00:00")

    def test_no_date_is_none_not_now(self):
        self.assertIsNone(feedutil.entry_date({"title": "undated"}))
        self.assertIsNone(feedutil.entry_date({"published": "sometime last week"}))


class TestSlowSources(unittest.TestCase):
    def test_slow_sources_get_the_longer_limit(self):
        slow = next(s["name"] for s in sources.RSS_SOURCES if s.get("cadence") == "slow")
        fast = next(s["name"] for s in sources.RSS_SOURCES if s.get("cadence") != "slow")
        self.assertEqual(sources.stale_after_days(slow), CONFIG.source_slow_stale_days)
        self.assertEqual(sources.stale_after_days(fast), CONFIG.source_stale_days)
        self.assertEqual(sources.stale_after_days("NVD"), CONFIG.source_stale_days)

    def test_only_recent_posts_are_taken(self):
        items = [{"title": "new", "published": _days_ago(3)},
                 {"title": "old", "published": _days_ago(CONFIG.slow_source_window_days + 40)}]
        self.assertEqual([i["title"] for i in sources.recent_only(items)], ["new"])

    def test_a_quiet_blog_keeps_its_newest_post(self):
        """Otherwise a feed with nothing recent reads as empty, and the
        health check loses the age it needs to call it stale."""
        items = [{"title": "older", "published": _days_ago(400)},
                 {"title": "newest", "published": _days_ago(200)}]
        self.assertEqual([i["title"] for i in sources.recent_only(items)], ["newest"])
        self.assertEqual(sources.recent_only([]), [])

    def test_a_slow_source_is_not_reported_stale(self):
        slow = next(s["name"] for s in sources.RSS_SOURCES if s.get("cadence") == "slow")
        health = {}
        sources.run_source(slow, lambda: [{"published": _days_ago(90)}], health)
        self.assertEqual(health[slow]["status"], "ok")
        sources.run_source(slow, lambda: [{"published": _days_ago(500)}], health)
        self.assertEqual(health[slow]["status"], "stale")


class TestCertIn(unittest.TestCase):
    PAGE = '''
    <li><a href="/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0545"><span class="verblue2">
      CERT-In Vulnerability Note CIVN-2026-0545</span></a></li></td></tr>
    <tr><td><span class="DateContent"> &nbsp;&nbsp;(November
      10, 2026) </span></td></tr>
    <tr><td><DIV style="height:30px"><span style="padding-left:15px">Authentication Bypass Vulnerability in OpenSSH</span></DIV>
    <li><a href="/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0058"> <span>CERT-In Advisory CIAD-2026-0058</span></a></li>
    <span class="contentTD,DateContent">&nbsp; (November 04, 2026) </span>
    <DIV><span style="padding-left: 20px">Attacks on <b>BFSI</b> Entities</span></DIV>
    '''

    def test_rows_are_parsed_with_their_own_date_and_title(self):
        rows = sources.parse_cert_in(self.PAGE)
        self.assertEqual([r["title"] for r in rows],
                         ["CIVN-2026-0545: Authentication Bypass Vulnerability in OpenSSH",
                          "CIAD-2026-0058: Attacks on BFSI Entities"])
        self.assertTrue(rows[0]["published"].startswith("2026-11-10"))
        self.assertTrue(rows[1]["published"].startswith("2026-11-04"))
        self.assertTrue(rows[0]["url"].endswith("VLCODE=CIVN-2026-0545"))
        self.assertTrue(all(r["url"].startswith("https://www.cert-in.org.in/") for r in rows))

    def test_a_page_with_no_rows_is_empty_not_an_error(self):
        self.assertEqual(sources.parse_cert_in("<html>maintenance</html>"), [])
        self.assertEqual(sources.parse_cert_in(""), [])


class TestHackerNewsFilter(unittest.TestCase):
    def test_security_headlines_pass(self):
        for title in ("OpenSSH 10.6p2 fixes a critical vulnerability", "Queens library hit by ransomware",
                      "CVE-2026-1234: RCE in MS Paint", "Notion customer data leaked"):
            self.assertTrue(sources._HN_TITLE.search(title), title)

    def test_the_site_name_does_not_count_as_a_match(self):
        """'Hacker News' contains 'hack'. A story about the site is not a
        security story."""
        for title in ("Going back two years on Hacker News", "Search for everyone", "Show HN: a satellite tracker"):
            self.assertFalse(sources._HN_TITLE.search(title), title)


class TestStories(unittest.TestCase):
    def test_same_cve_from_different_sources_is_one_story(self):
        items = [
            {"title": "CVE-2026-1111", "cve_id": "CVE-2026-1111", "source": "NVD", "provenance": "government",
             "priority_label": "urgent", "priority_score": 95, "published": _days_ago(2)},
            _news("PHP flaw CVE-2026-1111 under attack", "Bleeping Computer"),
            _news("Unrelated ransomware case in Ohio", "The Record"),
        ]
        summary = stories.cluster_stories(items)
        self.assertEqual(summary, {"stories": 1, "items_folded": 1, "largest": 2})
        self.assertEqual(items[0]["story_id"], items[1]["story_id"])
        self.assertTrue(items[0].get("story_lead"))        # the one with a verdict leads
        self.assertNotIn("story_lead", items[1])
        self.assertEqual(items[0]["story_sources"], 2)
        self.assertNotIn("story_id", items[2])

    def test_a_roundup_does_not_weld_stories_together(self):
        """A Patch Tuesday summary names dozens of CVEs. Linking through it
        would merge every one of those stories into a single card."""
        roundup = _news("Patch Tuesday: CVE-2026-1 CVE-2026-2 CVE-2026-3 CVE-2026-4".replace("-1 ", "-1001 ")
                        .replace("-2 ", "-1002 ").replace("-3 ", "-1003 ").replace("-4", "-1004"), "Rapid7")
        a = _news("Outlook bug CVE-2026-1001 exploited", "Dark Reading")
        b = _news("Kernel bug CVE-2026-1002 patched", "SecurityWeek")
        stories.cluster_stories([roundup, a, b])
        self.assertNotIn("story_id", a)
        self.assertNotIn("story_id", b)

    def test_similar_headlines_from_different_outlets_are_one_story(self):
        a = _news("France blames Iran for supermarket fridge hack", "The Register")
        b = _news("France Blames Iran for the Supermarket Fridge Attacks", "Security Affairs")
        stories.cluster_stories([a, b])
        self.assertEqual(a["story_id"], b["story_id"])

    def test_templated_titles_from_one_source_stay_apart(self):
        a = _news("Multiple Vulnerabilities in Drupal Core Modules Today", "CERT-In")
        b = _news("Multiple Vulnerabilities in Drupal Core Products Today", "CERT-In")
        stories.cluster_stories([a, b])
        self.assertNotIn("story_id", a)

    def test_old_coverage_is_not_folded_into_a_new_story(self):
        a = _news("Acme Widget database exposed online again", "HackRead", days=0)
        b = _news("Acme Widget database exposed online again", "CyberScoop", days=stories.WINDOW_DAYS + 3)
        stories.cluster_stories([a, b])
        self.assertNotIn("story_id", a)

    def test_indicator_rows_are_never_title_matched(self):
        a = {"title": "Malware sample abc def ghi", "source": "MalwareBazaar", "provenance": "automated-feed"}
        b = {"title": "Malware sample abc def ghi", "source": "ThreatFox", "provenance": "automated-feed"}
        stories.cluster_stories([a, b])
        self.assertNotIn("story_id", a)

    def test_rerunning_clears_the_previous_grouping(self):
        a = _news("France blames Iran for supermarket fridge hack", "The Register")
        a.update(story_id="stale", story_size=9, story_lead=True)
        stories.cluster_stories([a])
        self.assertNotIn("story_id", a)
        self.assertNotIn("story_lead", a)


class TestEpssTrend(unittest.TestCase):
    BASE = {"cve_id": "CVE-2026-1", "cvss_score": 7.0, "epss_score": 0.30}

    def test_a_rising_cve_scores_higher_and_says_why(self):
        flat = scoring.compute_priority(dict(self.BASE))
        rising = scoring.compute_priority({**self.BASE, "epss_delta": 0.25, "epss_rising": True})
        self.assertAlmostEqual(rising["score"] - flat["score"], CONFIG.priority_epss_rising_bonus, places=1)
        self.assertIn("EPSS rising", rising["rationale"])
        self.assertTrue(any(c["label"] == "EPSS rising" for c in rising["components"]))
        self.assertNotIn("EPSS rising", flat["rationale"])

    def test_the_dated_corpus_url_is_derived_from_the_current_one(self):
        src = (PROJECT_ROOT / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        self.assertIn('base.replace("-current.", f"-{day}.")', src)
        self.assertIn("-current.", fi._EPSS_BULK_URL)

    def test_a_cve_with_no_earlier_score_is_not_called_rising(self):
        """It is new, which the feed already says. 'Up 30 points from
        nothing' would flag every freshly published CVE."""
        src = (PROJECT_ROOT / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        self.assertIn("if cve not in previous:", src)


class TestFeedHead(unittest.TestCase):
    def _feed(self):
        items = [{"title": f"n{i}", "severity": "high", "published": _days_ago(i / 10)} for i in range(300)]
        items += [{"title": "low", "priority_label": "low", "priority_score": 5, "severity": "low"},
                  {"title": "urgent", "priority_label": "urgent", "priority_score": 96, "severity": "critical"},
                  {"title": "urgent2", "priority_label": "urgent", "priority_score": 99, "severity": "critical"}]
        return {"last_updated": "x", "brief": {"headline": "h"}, "items": items}

    def test_verdicts_lead_in_the_order_the_dashboard_sorts_them(self):
        head = fi.build_feed_head(self._feed())
        self.assertEqual([i["title"] for i in head["items"][:3]], ["urgent2", "urgent", "low"])
        self.assertEqual(len(head["items"]), CONFIG.feed_head_items)
        self.assertEqual(head["items"][3]["title"], "n0")       # then the newest of the rest

    def test_counts_describe_the_whole_feed_not_the_head(self):
        head = fi.build_feed_head(self._feed())
        self.assertTrue(head["partial"])
        self.assertEqual(head["head_counts"],
                         {"total": 303, "urgent": 2, "critical": 2, "high": 300, "verdicts": 3})
        self.assertEqual(head["brief"], {"headline": "h"})

    def test_the_head_is_deployed_and_the_page_reads_it(self):
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        self.assertIn("cp data/feed-head.json", workflow)
        app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        self.assertIn("'data/feed-head.json'", app)
        self.assertEqual(CONFIG.feed_head_path.name, "feed-head.json")


class TestProbe(unittest.TestCase):
    NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)

    def _feed(self, *dates):
        entries = "".join(f"<item><title>t</title><link>https://x.example/{i}</link>"
                          f"{'<pubDate>' + d + '</pubDate>' if d else ''}</item>"
                          for i, d in enumerate(dates))
        return f'<?xml version="1.0"?><rss version="2.0"><channel><title>f</title>{entries}</channel></rss>'

    def test_verdicts(self):
        cases = [
            ((200, self._feed("Tue, 10 Nov 2026 00:00:00 GMT")), "ok"),
            ((200, self._feed("Tue, 10 Nov 2026 00:00:00 GMT", "Mon, 01 Jun 2026 00:00:00 GMT",
                              "Fri, 01 May 2026 00:00:00 GMT")), "slow"),
            ((200, self._feed("Wed, 01 Jan 2020 00:00:00 GMT")), "dormant"),
            ((200, self._feed("", "")), "undated"),
            ((200, "<html>not a feed</html>"), "empty"),
            ((403, ""), "blocked"),
            ((None, "ConnectTimeout"), "unreachable"),
        ]
        for (status, text), expected in cases:
            self.assertEqual(probe_feeds.classify(status, text, self.NOW)[0], expected, expected)

    def test_the_waiting_list_parses_and_is_https(self):
        rows = probe_feeds.read_candidates(PROJECT_ROOT / "scripts" / "feed_candidates.txt")
        self.assertTrue(rows)
        configured = {s["url"] for s in sources.RSS_SOURCES}
        for name, url in rows:
            self.assertTrue(url.startswith("https://"), name)
            self.assertNotIn(url, configured, f"{name} is configured and still on the waiting list")

    def test_the_health_workflow_runs_it_and_files_one_issue(self):
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "source-health.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/probe_feeds.py --configured --strict", workflow)
        self.assertIn("gh issue list", workflow)


class TestExports(unittest.TestCase):
    ITEMS = [
        {"title": "Bad bug", "description": "desc", "cve_id": "CVE-2026-7", "source": "NVD",
         "url": "https://nvd.example/7", "category": "cve", "priority_label": "urgent",
         "priority_score": 97.0, "action": "Patch now", "cvss_score": 9.8, "epss_score": 0.9,
         "cisa_kev": True, "epss_rising": True, "published": "2026-11-10T00:00:00+00:00"},
        {"title": "C2 server", "source": "ThreatFox", "cve_id": "CVE-2026-7", "category": "news",
         "iocs": {"ipv4": ["203.0.113.9"]}, "published": "2026-11-10T00:00:00+00:00"},
        {"title": "Breach at Acme", "source": "The Record", "url": "javascript:alert(1)",
         "category": "incident", "published": "2026-11-09T00:00:00+00:00"},
    ]

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _bundle(self):
        rows = list(exports._iter_iocs(self.ITEMS))
        count = exports._write_stix(rows, self.tmp / "stix.json", "2026-11-11T03:05:19.761991+00:00", self.ITEMS)
        return count, json.loads((self.tmp / "stix.json").read_text(encoding="utf-8"))["objects"]

    def test_the_bundle_carries_a_vulnerability_per_cve_linked_to_its_indicators(self):
        count, objects = self._bundle()
        self.assertEqual(count, 1)                       # indicators only, as the caller logs it
        vulns = [o for o in objects if o["type"] == "vulnerability"]
        self.assertEqual([v["name"] for v in vulns], ["CVE-2026-7"])
        self.assertIn("cisa-kev", vulns[0]["labels"])
        self.assertIn("epss-rising", vulns[0]["labels"])
        self.assertIn("Patch now", vulns[0]["description"])
        self.assertEqual(vulns[0]["external_references"][0], {"source_name": "cve", "external_id": "CVE-2026-7"})
        rel = [o for o in objects if o["type"] == "relationship"]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0]["target_ref"], vulns[0]["id"])
        self.assertEqual(rel[0]["relationship_type"], "indicates")

    def test_no_custom_properties_and_spec_timestamps(self):
        _, objects = self._bundle()
        for obj in objects:
            self.assertFalse([k for k in obj if k.startswith("x_")], obj["type"])
            for key in ("created", "modified", "valid_from"):
                if key in obj:
                    self.assertRegex(obj[key], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_ids_are_stable_across_runs(self):
        first = [o["id"] for o in self._bundle()[1]]
        self.assertEqual(first, [o["id"] for o in self._bundle()[1]])

    def test_filtered_feeds_hold_only_what_they_name(self):
        names = exports.write_filtered_feeds({"last_updated": "2026-11-11T00:00:00+00:00",
                                              "items": self.ITEMS}, self.tmp)
        self.assertEqual(sorted(names), sorted(f"feed-{n}.xml" for n in exports.FILTERED_FEEDS))
        read = lambda n: (self.tmp / f"feed-{n}.xml").read_text(encoding="utf-8")  # noqa: E731
        for name in ("urgent", "exploited", "rising", "cve"):
            self.assertEqual(read(name).count("<item>"), 1, name)
            self.assertIn("Bad bug", read(name))
        self.assertIn("Breach at Acme", read("incident"))
        self.assertNotIn("javascript:", read("incident"))
        self.assertEqual(read("advisory").count("<item>"), 0)
        self.assertIn("<title>OpenThreat: patch now</title>", read("urgent"))


class TestHistorySearch(unittest.TestCase):
    def test_one_row_per_item_with_first_and_last_day(self):
        tmp = Path(tempfile.mkdtemp())
        day = lambda date, items: (tmp / f"{date}.json").write_text(json.dumps({"items": items}))  # noqa: E731
        ivanti = {"title": "Ivanti bug", "url": "https://x.example/i", "source": "Rapid7", "cve_id": "CVE-2026-9"}
        day("2026-08-14", [ivanti, {"title": "Gone tomorrow", "url": "https://x.example/g", "source": "A"}])
        day("2026-08-15", [{**ivanti, "priority_label": "urgent"}])
        (tmp / "notes.json").write_text("{}")             # not a day file
        index = timeline.build_search_index(tmp, {"items": [{"title": "Live", "url": "https://x.example/l"}]})
        self.assertEqual(index["columns"], list(timeline.SEARCH_COLUMNS))
        self.assertEqual(index["count"], 3)
        self.assertEqual(index["days"], 3)
        rows = {r[0]: r for r in index["rows"]}
        self.assertEqual(rows["Ivanti bug"][3:], ["CVE-2026-9", "urgent", "2026-08-14", "2026-08-15"])
        self.assertEqual(rows["Gone tomorrow"][5:], ["2026-08-14", "2026-08-14"])
        self.assertEqual(index["rows"][0][0], "Live")      # newest first
        self.assertEqual(index["from"], "2026-08-14")


class TestDockerSmokeTestIsWired(unittest.TestCase):
    def test_ci_runs_it(self):
        ci = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("bash tests/docker_smoke.sh", ci)
        script = (PROJECT_ROOT / "tests" / "docker_smoke.sh").read_text(encoding="utf-8")
        for needle in ("--target frontend", "--target fetcher", "/.git/config", "X-Frame-Options"):
            self.assertIn(needle, script)

    def test_private_data_is_kept_out_of_the_build_context(self):
        ignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("data/.own_estate.json", ignore)


if __name__ == "__main__":
    unittest.main()
