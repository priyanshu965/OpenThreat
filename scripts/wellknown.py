"""
OPENTHREAT — wellknown.py
=========================
Generates `/.well-known/security.txt` (RFC 9116).

WHY THIS IS GENERATED AND NOT COMMITTED
---------------------------------------
RFC 9116 makes `Expires` mandatory and tells consumers to treat the file as
invalid once that date has passed. A committed file is therefore a file that
silently stops being valid on a date nobody has written down — and the failure
is invisible, because a stale security.txt still serves a 200.

Regenerating it on every run means the expiry is always `security_txt_months`
away from a real deployment, and the file cannot rot.

WHAT IT IS FOR
--------------
This site publishes vulnerability and breach information about other people.
Publishing a way to report a vulnerability *in this site* is the other half of
that, and it is the difference between a research project and a megaphone.

The address is deliberately public. It will be scraped; that is the cost of
having one, and it is worth paying.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fetchlib import CONFIG, log


def _expires(months: int) -> str:
    """RFC 9116 wants an ISO 8601 instant. Months are approximated as 30 days:
    the field only has to be a truthful upper bound, not a calendar date."""
    when = datetime.now(timezone.utc) + timedelta(days=30 * max(1, months))
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_security_txt() -> str:
    site = str(CONFIG.dashboard_url or "").rstrip("/")
    email = str(CONFIG.contact_email or "").strip()
    lines = [
        "# OpenThreat security contact",
        "#",
        "# This file is regenerated on every deployment, so Expires is never",
        "# stale. See scripts/wellknown.py for why that matters.",
        "",
        f"Contact: mailto:{email}",
        f"Expires: {_expires(CONFIG.security_txt_months)}",
        "Preferred-Languages: en",
        f"Canonical: {site}/.well-known/security.txt",
        f"Policy: {CONFIG.repo_url}/blob/main/SECURITY.md",
        "",
        "# Scope",
        "#   In scope:     this site, its published JSON API, and the pipeline",
        "#                 that builds them.",
        "#   Out of scope: the 43 upstream sources this project reads. Report",
        "#                 those to their own owners.",
        "#",
        "# There is no server and no user account here: the site is static and",
        "# stores nothing about visitors. Reports about data exposed BY the",
        "# published output are in scope and are taken seriously.",
        "",
    ]
    return "\n".join(lines)


def write_wellknown(out_dir: Path) -> Path | None:
    """Write security.txt under `out_dir`, returning the path written."""
    email = str(CONFIG.contact_email or "").strip()
    if "@" not in email:
        log.warning("  No CONTACT_EMAIL set — skipping security.txt")
        return None
    target = Path(out_dir) / "security.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    # Newline-terminated, LF, ASCII. Parsers are strict and this file is small.
    target.write_text(build_security_txt(), encoding="utf-8", newline="\n")
    log.info(f"  security.txt -> {target}")
    return target


if __name__ == "__main__":
    print(build_security_txt())
