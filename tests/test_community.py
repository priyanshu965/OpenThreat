"""
OPENTHREAT — tests/test_community.py
====================================
Contact, disclosure and identity plumbing.

The failure modes pinned here are all quiet ones:

  * A security.txt whose Expires date has passed still serves a 200. RFC 9116
    says consumers should ignore it, so the file becomes decorative without
    anything reporting an error.
  * A mailto: built by string concatenation will happily carry a newline,
    which is header injection in a mail client.
  * The RSS channel link shipped as "https://github.com/" for the project's
    whole life, because nothing ever asserted it pointed at the feed's site.
"""

import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import wellknown  # noqa: E402


class TestSecurityTxt(unittest.TestCase):

    def setUp(self):
        self.body = wellknown.build_security_txt()

    def test_mandatory_fields_present(self):
        """RFC 9116: Contact and Expires are the only required fields, and a
        file missing either is invalid rather than merely incomplete."""
        for field in ("Contact:", "Expires:", "Canonical:", "Policy:"):
            self.assertIn(field, self.body)

    def test_expires_is_in_the_future(self):
        raw = re.search(r"^Expires: (.+)$", self.body, re.M).group(1)
        when = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertGreater(when, datetime.now(timezone.utc),
                           "security.txt is born expired")

    def test_contact_is_a_mailto_uri(self):
        """Bare addresses are common and wrong: the field takes a URI."""
        contact = re.search(r"^Contact: (.+)$", self.body, re.M).group(1)
        self.assertTrue(contact.startswith("mailto:"), contact)
        self.assertIn("@", contact)

    def test_is_ascii(self):
        self.body.encode("ascii")

    def test_writes_lf_only(self):
        """A CR would reach a strict parser as part of the field value."""
        with tempfile.TemporaryDirectory() as tmp:
            path = wellknown.write_wellknown(Path(tmp))
            self.assertIsNotNone(path)
            self.assertNotIn(b"\r", path.read_bytes())

    def test_skipped_when_no_address_configured(self):
        original = wellknown.CONFIG.contact_email
        try:
            wellknown.CONFIG.contact_email = ""
            with tempfile.TemporaryDirectory() as tmp:
                self.assertIsNone(wellknown.write_wellknown(Path(tmp)))
        finally:
            wellknown.CONFIG.contact_email = original


class TestSafeMailto(unittest.TestCase):
    """safeUrl() allows http(s) only, because every URL it sees came from a
    third-party feed. safeMailto() is the separate, narrower helper — these
    assertions are on its source, since there is no JS runtime here."""

    @classmethod
    def setUpClass(cls):
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.comm = (PROJECT_ROOT / "js" / "community.js").read_text(encoding="utf-8")

    @staticmethod
    def _body(src, name):
        """The function body only. Slicing to the closing brace matters: the
        comment that FOLLOWS safeUrl discusses mailto at length, and matching
        against that would make these assertions vacuous."""
        return src.split("function " + name, 1)[1].split("\n}", 1)[0]

    def test_safe_url_still_rejects_non_http(self):
        body = self._body(self.app, "safeUrl")
        self.assertIn(r"^https?:\/\/", body)
        self.assertNotIn("mailto", body)

    def test_safe_mailto_validates_and_encodes(self):
        body = self._body(self.app, "safeMailto")
        self.assertIn("encodeURIComponent", body)
        # The address pattern must exclude whitespace, which is what stops a
        # CR or LF reaching the mail client as an extra header.
        self.assertIn(r"[^\s@", body)
        self.assertIn("return ''", body)

    def test_community_never_hand_builds_a_mailto(self):
        self.assertNotIn("'mailto:' +", self.comm)

    def test_no_unsafe_sink_in_community(self):
        self.assertNotRegex(self.comm, r"\.(innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", self.comm)


class TestContactViewIsRegistered(unittest.TestCase):
    """A view needs four separate registrations to work. Miss one and the
    route silently does nothing — no error, just a blank screen."""

    @classmethod
    def setUpClass(cls):
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")

    def test_in_views(self):
        self.assertIn("'contact'", self.app.split("const VIEWS = [", 1)[1].split("];", 1)[0])

    def test_in_view_nodes(self):
        self.assertIn("'contact-view'", self.app.split("const VIEW_NODES = [", 1)[1].split("];", 1)[0])

    def test_has_a_route(self):
        self.assertIn("case 'contact':", self.app)

    def test_has_a_container(self):
        self.assertIn('id="contact-view"', self.html)

    def test_module_is_loaded_and_defines_the_view(self):
        self.assertIn("js/community.js", self.html)
        comm = (PROJECT_ROOT / "js" / "community.js").read_text(encoding="utf-8")
        self.assertRegex(comm, r"function showContactView\b")

    def test_footer_link_is_a_button_not_an_inline_handler(self):
        """The CSP has no 'unsafe-inline', so an onclick= would be dead code."""
        self.assertIn('id="contact-open"', self.html)
        self.assertNotRegex(self.html, r'\son[a-z]+="')
        self.assertIn("initContactLink", self.app)

    def test_contact_does_not_persist_as_a_landing_view(self):
        """Reopening the dashboard onto Contact is landing on leftovers."""
        block = self.app.split("const TRANSIENT_VIEWS", 1)[1][:120]
        self.assertIn("'contact'", block)


class TestExportIdentity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "scripts" / "exports.py").read_text(encoding="utf-8")

    def test_rss_channel_link_is_not_the_placeholder(self):
        self.assertNotIn("<link>https://github.com/</link>", self.src)
        self.assertIn("managingEditor", self.src)

    def test_stix_bundle_carries_an_identity(self):
        self.assertIn('"type": "identity"', self.src)
        self.assertIn("created_by_ref", self.src)

    def test_identity_is_not_counted_as_an_indicator(self):
        """_write_stix returns an INDICATOR count that the caller logs."""
        block = self.src.split("def _write_stix", 1)[1]
        self.assertIn("return len(objects) - 1", block)


if __name__ == "__main__":
    unittest.main()
