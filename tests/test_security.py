"""Security regression tests.

These pin fixes for issues found in a review of the whole project. Each one
fails if the corresponding hardening is removed.
"""

import json
import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import fetch_intel as fi                                # noqa: E402


class TestCachePathTraversal(unittest.TestCase):
    """Cache filenames are partly built from values that arrive over the
    network, so the path helper must not let one escape the cache directory."""

    def test_traversal_is_neutralised(self):
        for hostile in ("../../../../etc/passwd",
                        "..\\..\\windows\\system32\\config\\sam",
                        "ssvc_CVE-../../secret.json",
                        "/etc/shadow"):
            path = fi._cache_path(hostile)
            self.assertTrue(
                str(path.resolve()).startswith(str(fi._CACHE_DIR.resolve())),
                f"{hostile!r} escaped the cache dir: {path}")

    def test_separators_do_not_survive(self):
        name = fi._safe_cache_name("a/b\\c..d")
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)

    def test_leading_dots_stripped(self):
        self.assertFalse(fi._safe_cache_name("...hidden").startswith("."))

    def test_ordinary_names_survive_readably(self):
        self.assertEqual(fi._safe_cache_name("ssvc_CVE-2026-12345.json"),
                         "ssvc_CVE-2026-12345.json")

    def test_empty_name_still_yields_a_path(self):
        self.assertTrue(fi._safe_cache_name("///"))


class TestCveValidation(unittest.TestCase):
    """`startswith("CVE-")` is not validation. Several fetchers take cve_id
    straight from a third-party API response, and that value builds a cache
    filename."""

    def test_wellformed_ids_pass(self):
        self.assertEqual(fi.valid_cve_id("CVE-2026-12345"), "CVE-2026-12345")
        self.assertEqual(fi.valid_cve_id("cve-2026-1234"), "CVE-2026-1234")
        self.assertEqual(fi.valid_cve_id("  CVE-2026-1234  "), "CVE-2026-1234")

    def test_traversal_shaped_ids_are_rejected(self):
        for hostile in ("CVE-../../../../etc/passwd",
                        "CVE-2026-1234/../../evil",
                        "CVE-abc-defg",
                        "CVE-2026-12345.json",
                        "../CVE-2026-1234"):
            self.assertIsNone(fi.valid_cve_id(hostile), hostile)

    def test_empty_and_none(self):
        for v in (None, "", "   ", 0, []):
            self.assertIsNone(fi.valid_cve_id(v))

    def test_hostile_cve_cannot_reach_the_cache_dir(self):
        """End to end: even if a feed smuggled one through, the path is safe."""
        hostile = "CVE-../../../../tmp/evil"
        self.assertIsNone(fi.valid_cve_id(hostile))
        path = fi._cache_path(f"ssvc_{hostile}.json")
        self.assertTrue(str(path.resolve()).startswith(str(fi._CACHE_DIR.resolve())))


class TestNoDangerousSinksInFrontend(unittest.TestCase):
    """The dashboard renders attacker-controlled feed text. It must not have an
    HTML-injection sink, and links must be scheme-checked."""

    @classmethod
    def setUpClass(cls):
        # app.js AND every module under js/. Views have been moving out of
        # app.js into their own files; a check that only read app.js would
        # cover less of the frontend with every one that left.
        cls.sources = {p.relative_to(PROJECT_ROOT).as_posix(): p.read_text(encoding="utf-8")
                       for p in [PROJECT_ROOT / "app.js", *sorted((PROJECT_ROOT / "js").glob("*.js"))]}
        cls.app = "\n".join(cls.sources.values())

    def test_no_html_injection_sinks(self):
        for name, text in self.sources.items():
            # Strip comments: several modules explain in prose that they do
            # NOT use innerHTML, and that sentence is not a sink.
            code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            code = re.sub(r"(?m)^\s*//.*$", "", code)
            for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                         "document.write", "eval(", "new Function("):
                self.assertNotIn(sink, code, f"{sink} reintroduced in {name}")

    def test_safe_url_rejects_dangerous_schemes(self):
        """Mirror of safeUrl()'s contract, asserted against its source."""
        self.assertIn("function safeUrl", self.app)
        # It must anchor on http(s) rather than blocklisting javascript:.
        self.assertRegex(self.app, r"\^\\\?https\?:\\\/\\\/|\^https\?:")

    def test_external_links_carry_noopener(self):
        opens = self.app.count("target = '_blank'")
        noopener = self.app.count("rel = 'noopener noreferrer'")
        self.assertGreaterEqual(noopener, opens,
                                "a target=_blank link is missing rel=noopener")


class TestContentSecurityPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
        m = re.search(r'Content-Security-Policy"\s+content="([^"]+)"', cls.html)
        cls.csp = m.group(1) if m else ""

    def test_csp_present(self):
        self.assertTrue(self.csp, "no CSP meta tag")

    def test_scripts_are_self_only(self):
        m = re.search(r"script-src ([^;]+)", self.csp)
        self.assertTrue(m, "no script-src directive")
        directive = m.group(1)
        self.assertNotIn("'unsafe-inline'", directive)
        self.assertNotIn("'unsafe-eval'", directive)
        self.assertNotIn("*", directive)

    def test_object_and_base_locked_down(self):
        self.assertIn("object-src 'none'", self.csp)
        self.assertIn("base-uri 'self'", self.csp)
        self.assertIn("form-action 'none'", self.csp)

    def test_no_inline_event_handlers(self):
        self.assertNotRegex(self.html, r'\son[a-z]+="')


class TestNoPersonalPhoneNumberPublished(unittest.TestCase):
    """The about page is published to a public site. The CV's mobile number is
    deliberately not on it."""

    def test_phone_absent_from_shipped_files(self):
        shipped = [PROJECT_ROOT / n for n in ("app.js", "index.html", "README.md")]
        # The profile itself lives in js/about.js now, so the modules are
        # where this check matters most.
        shipped += sorted((PROJECT_ROOT / "js").glob("*.js"))
        for path in shipped:
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("9650493485", text, f"phone number leaked in {path.name}")


class TestAlertPayloadsEscapeFeedText(unittest.TestCase):
    """Alert text comes from feeds anyone can post to, and leak-site victim
    names are written by the adversary. Each chat platform treats some of it as
    markup, so unescaped it can ping a channel, swap a link or break delivery."""

    HOSTILE = "<!channel> [free money](https://evil.example) *_`x` <https://evil.example|click>"

    def setUp(self):
        import webhook_post
        self.wp = webhook_post
        self.item = {"title": self.HOSTILE, "description": self.HOSTILE,
                     "url": "https://example.com/a", "severity": "critical",
                     "action": self.HOSTILE, "priority_score": 90}

    def test_slack_cannot_ping_or_inject_a_link(self):
        blob = json.dumps(self.wp.build_payload([self.item], "slack", 1), ensure_ascii=False)
        self.assertNotIn("<!channel>", blob)
        self.assertNotIn("<https://evil.example|", blob)
        self.assertIn("&lt;!channel&gt;", blob)

    def test_discord_disables_mentions_and_masked_links(self):
        for payload in (self.wp.build_payload([self.item], "discord", 1),
                        self.wp.build_watch_payload("Acme", [{"v": self.HOSTILE}], "discord"),
                        self.wp.build_digest_payload({"items": [self.item]}, "discord")):
            self.assertEqual(payload["allowed_mentions"], {"parse": []})
            self.assertNotIn("[free money](https://evil.example)",
                             json.dumps(payload, ensure_ascii=False))

    def test_telegram_markup_is_always_balanced(self):
        """One stray * or [ makes the Bot API reject the whole message, which
        is a way to silence the alert for the item that carried it."""
        text = self.wp.build_payload([self.item], "telegram", 1)["text"]
        # Exactly one link, and it is the item's own URL - not one smuggled in
        # through the title.
        self.assertEqual(text.count("["), 1)
        self.assertEqual(text.count("]("), 1)
        self.assertIn("](https://example.com/a)", text)
        self.assertEqual(text.count("*") % 2, 0)
        self.assertNotIn("`", text)

    def test_only_http_links_reach_an_alert(self):
        for bad in ("javascript:alert(1)", "slack://open", "data:text/html,x",
                    " java\tscript:alert(1)", "", None):
            self.assertEqual(self.wp._link(bad), "", repr(bad))
        self.assertEqual(self.wp._link("https://a.example/x?y=1"), "https://a.example/x?y=1")

    def test_a_url_cannot_close_the_link_it_sits_in(self):
        link = self.wp._link("https://a.example/x>|<!channel>)(")
        for ch in "<>|()":
            self.assertNotIn(ch, link)

    def test_a_bad_url_drops_the_link_not_the_alert(self):
        item = dict(self.item, title="Plain title", url="javascript:alert(1)")
        slack = json.dumps(self.wp.build_payload([item], "slack", 1))
        self.assertIn("Plain title", slack)
        self.assertNotIn("javascript:", slack)
        self.assertIsNone(self.wp.build_payload([item], "discord", 1)["embeds"][0]["url"])

    def test_watch_alert_escapes_adversary_written_fields(self):
        match = {"v": "<!channel> Acme", "g": "<@U123>", "d": "2026-08-25"}
        blob = json.dumps(self.wp.build_watch_payload("Acme", [match], "slack"))
        self.assertNotIn("<!channel>", blob)
        self.assertNotIn("<@U123>", blob)


class TestClickjackingDefences(unittest.TestCase):
    def test_hosted_site_refuses_to_be_framed(self):
        """GitHub Pages cannot send a frame-ancestors header, so the script
        guard is the only defence there - and it must run before anything
        else in the first script the page loads."""
        app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("window.top !== window.self", app)
        self.assertLess(app.index("refuseFraming"), app.index("const DATA_URL"))
        first_script = re.search(r'<script src="([^"?]+)', html).group(1)
        self.assertEqual(first_script, "app.js")

    def test_nginx_locations_do_not_drop_the_security_headers(self):
        """nginx does not merge add_header across levels: a location with its
        own add_header loses every inherited one."""
        conf = (PROJECT_ROOT / "nginx.conf").read_text(encoding="utf-8")
        for block in re.findall(r"location[^{]*\{([^}]*)\}", conf):
            if "add_header" not in block:
                continue
            for header in ("X-Content-Type-Options", "X-Frame-Options",
                           "Referrer-Policy", "frame-ancestors"):
                self.assertIn(header, block, block.strip().splitlines()[0])


class TestExportsCannotCarryAPayload(unittest.TestCase):
    """Exports leave the browser's protections behind: a CSV is opened in a
    spreadsheet and feed.xml in a feed reader, and each has its own way of
    turning data into behaviour."""

    def setUp(self):
        import exports
        self.exports = exports

    def test_csv_cells_cannot_be_formulas(self):
        for payload in ("=HYPERLINK(\"http://evil.example\",\"x\")", "+1+1", "-2+3",
                        "@SUM(A1)", "\t=1+1", "\r=1+1"):
            self.assertTrue(self.exports._csv_cell(payload).startswith("'"), payload)
        for harmless in ("example.com", "198.51.100.7", "CVE-2026-1234", "", None):
            self.assertEqual(self.exports._csv_cell(harmless), str(harmless or ""))

    def test_browser_csv_export_neutralises_formulas_too(self):
        app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        block = app.split("function exportCsv()", 1)[1][:900]
        self.assertIn("/^[=+\\-@\\t\\r]/", block)

    def test_rss_export_links_are_http_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.xml"
            self.exports._write_rss({"last_updated": "2026-11-10T00:00:00+00:00", "items": [
                {"title": "bad", "url": "javascript:alert(1)", "severity": "high"},
                {"title": "good", "url": "https://example.com/a", "severity": "high"},
            ]}, path)
            xml = path.read_text(encoding="utf-8")
        self.assertNotIn("<link>javascript:", xml)
        self.assertIn("<link>https://example.com/a</link>", xml)


class TestSourceListIsSound(unittest.TestCase):
    def test_every_feed_is_https_named_once_and_classified(self):
        """A feed over plain http can be rewritten in transit; a duplicated
        name merges two sources' health into one; an unclassified source
        silently takes the default provenance."""
        import provenance
        names = [s["name"] for s in fi.RSS_SOURCES]
        self.assertEqual(len(names), len(set(names)))
        for source in fi.RSS_SOURCES:
            self.assertTrue(source["url"].startswith("https://"), source["name"])
            self.assertIn(source["name"], provenance._SOURCE_PROVENANCE, source["name"])
        self.assertGreaterEqual(len(fi.RSS_SOURCES) + len(fi.API_SOURCES), 100)

    def test_no_third_party_actions(self):
        """Every action must be GitHub's own, so the repository can refuse
        anything else outright."""
        for path in sorted((PROJECT_ROOT / ".github" / "workflows").glob("*.yml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                m = re.match(r"\s*-?\s*uses:\s*(\S+)", line)
                if m:
                    self.assertTrue(m.group(1).startswith("actions/"), f"{path.name}: {m.group(1)}")


if __name__ == "__main__":
    unittest.main()
