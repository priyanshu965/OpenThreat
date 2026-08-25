"""Security regression tests.

These pin fixes for issues found in a review of the whole project. Each one
fails if the corresponding hardening is removed.
"""

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
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")

    def test_no_html_injection_sinks(self):
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                     "document.write", "eval(", "new Function("):
            self.assertNotIn(sink, self.app, f"{sink} reintroduced in app.js")

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
        for name in ("app.js", "index.html", "README.md"):
            text = (PROJECT_ROOT / name).read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("9650493485", text, f"phone number leaked in {name}")


if __name__ == "__main__":
    unittest.main()
