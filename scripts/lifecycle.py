"""
OPENTHREAT — lifecycle.py
=========================
Software lifecycle: what is out of support, and what shipped recently.

WHY THIS IS IN THE PIPELINE AND NOT THE BROWSER
------------------------------------------------
Both upstreams are keyless and CORS-open, so the page COULD call them
directly. It should not:

  * endoflife.date is one request per product. A useful board covers 30+
    products, which is 30+ requests per visitor per page load, repeated for
    every visitor, to answer a question whose answer changes weekly.
  * The GitHub API is 60 requests per hour per IP unauthenticated. A visitor
    behind a corporate NAT would share that budget with their whole office and
    see an empty board with no explanation. Authenticated in Actions it is
    5,000/hour, and the result is one cached file.

So it is fetched once per run and published as static JSON. That is the same
reasoning that puts the rest of the pipeline where it is; TOOLS is the browser
because its input arrives after the pipeline has finished, and this input does
not.

WHAT "END OF LIFE" MEANS HERE
-----------------------------
A cycle is out of support when its support or EOL date has passed. That is a
statement about the VENDOR, not about you: running an EOL release is a risk
decision, not automatically a vulnerability. The board reports the date and
lets the reader decide, and it never says "vulnerable".
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

import os

from fetchlib import CONFIG, SESSION, cached_derive, http_text, log, now_utc

_EOL_API = "https://endoflife.date/api/{product}.json"
_GH_RELEASES = "https://api.github.com/repos/{repo}/releases/latest"

# Products worth a board for a security audience: the things that sit on the
# edge, hold the data, or run the builds. Deliberately not "every product
# endoflife.date knows about" -- an unreadable board is not a board.
_PRODUCTS = [
    "windows", "windows-server", "ubuntu", "debian", "rhel", "centos",
    "alpine", "amazon-linux",
    "python", "nodejs", "go", "php", "ruby", "dotnet",
    # "java" is not a slug -- the JDK is listed per distributor.
    # These four 404 and were removed after probing the API:
    #   java, openssh, sonicos, exchange
    "eclipse-temurin", "oracle-jdk",
    "postgresql", "mysql", "mariadb", "mongodb", "redis", "elasticsearch",
    "nginx", "apache", "tomcat", "openssl",
    "kubernetes", "docker-engine", "terraform", "ansible",
    "django", "rails", "laravel", "spring-framework", "angular", "react",
    "wordpress", "drupal", "jenkins", "gitlab", "grafana",
    "vmware-esxi", "fortios", "sharepoint",
]

# Security tooling whose releases matter operationally: if your detection
# content is a version behind, you are missing coverage that exists.
_REPOS = [
    "SigmaHQ/sigma", "redcanaryco/atomic-red-team", "MISP/MISP",
    "OISF/suricata", "Velocidex/velociraptor", "Neo23x0/Loki",
    "mitre-attack/attack-stix-data", "elastic/detection-rules",
    "wazuh/wazuh", "TheHive-Project/TheHive", "cortexproject/cortex",
    "OWASP/CheatSheetSeries", "projectdiscovery/nuclei",
    "projectdiscovery/nuclei-templates", "rapid7/metasploit-framework",
]


def _parse_date(value) -> date | None:
    """endoflife.date uses `false` for 'not announced' and `true` for
    'already ended', alongside real ISO dates. All three arrive in the same
    field, so a naive parse silently treats a boolean as no date at all."""
    if value is True or value is False or value is None:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _cycle_state(cycle: dict, today: date) -> tuple[str, str, int | None]:
    """(state, the date it turns on, days until/since). States are
    `eol`, `extended`, `security-only`, `supported`, `unknown`.

    `extended` exists because leaving it out produces a confidently wrong
    board. Debian 12's `eol` is 2026-07-11 and its `extendedSupport` runs to
    2028-06-30: reading only `eol` reports one of the most widely deployed
    server distributions in the world as out of support while it still has two
    years of security updates. Ubuntu LTS with ESM is the same shape. A reader
    acting on that would schedule an upgrade that is not due, which is a
    cheaper mistake than the reverse but still a wrong answer stated firmly.
    """
    eol_raw = cycle.get("eol")
    support_raw = cycle.get("support")
    extended_raw = cycle.get("extendedSupport")

    # `eol: true` means it has already ended and no date was recorded. That is
    # a real answer, and dropping it because it will not parse as a date would
    # silently mark dead releases as supported.
    if eol_raw is True:
        return "eol", "", None
    eol = _parse_date(eol_raw)
    support = _parse_date(support_raw)
    extended = _parse_date(extended_raw)

    if eol and eol <= today:
        # Past normal EOL, but paid or long-term support may still run.
        if extended and extended > today:
            return "extended", extended.isoformat(), (extended - today).days
        return "eol", eol.isoformat(), (today - eol).days
    if support and support <= today:
        return "security-only", (eol.isoformat() if eol else ""), (
            (eol - today).days if eol else None)
    if eol:
        return "supported", eol.isoformat(), (eol - today).days
    if support_raw is True or support:
        return "supported", "", None
    return "unknown", "", None


def _fetch_products(today: date) -> list[dict]:
    rows = []
    for product in _PRODUCTS:
        text, err = http_text(_EOL_API.format(product=product),
                              timeout=CONFIG.request_timeout)
        if err or not text:
            log.info(f"  endoflife.date: {product} unavailable ({err})")
            continue
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001
            log.info(f"  endoflife.date: {product} did not parse as JSON")
            continue
        if not isinstance(data, list):
            continue
        cycles = []
        for cycle in data[:CONFIG.lifecycle_cycles_per_product]:
            if not isinstance(cycle, dict):
                continue
            state, turns, days = _cycle_state(cycle, today)
            cycles.append({
                "cycle": str(cycle.get("cycle", "")),
                "latest": str(cycle.get("latest", "") or ""),
                "released": str(cycle.get("releaseDate", "") or "")[:10],
                "state": state,
                "eol": turns,
                "days": days,
                "lts": bool(cycle.get("lts")),
            })
        if cycles:
            rows.append({
                "product": product,
                "url": f"https://endoflife.date/{product}",
                "cycles": cycles,
                "eol_count": sum(1 for c in cycles if c["state"] == "eol"),
            })
    return rows


def _fetch_releases() -> list[dict]:
    """Latest release per repo.

    Authenticated when GITHUB_TOKEN is present, which it is in Actions. The
    unauthenticated limit is 60/hour per IP and this list is 15 repos, so an
    unauthenticated run works but shares a budget with everything else on the
    runner.
    """
    headers = {"Accept": "application/vnd.github+json"}
    # GITHUB_TOKEN is injected by Actions; absent locally, which is fine.
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    rows = []
    for repo in _REPOS:
        try:
            resp = SESSION.get(_GH_RELEASES.format(repo=repo), headers=headers,
                               timeout=CONFIG.request_timeout)
            if resp.status_code == 404:
                continue  # repo publishes tags, not releases
            if resp.status_code == 403:
                log.warning("  GitHub releases: rate limited, stopping early")
                break
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            log.info(f"  GitHub releases: {repo} unavailable ({str(e)[:80]})")
            continue
        published = str(data.get("published_at") or "")[:10]
        rows.append({
            "repo": repo,
            "name": str(data.get("name") or data.get("tag_name") or "")[:120],
            "tag": str(data.get("tag_name") or "")[:80],
            "published": published,
            "url": str(data.get("html_url") or ""),
            "prerelease": bool(data.get("prerelease")),
            # Release notes are the author's prose and can be long. The board
            # links out; it does not reproduce them.
            "age_days": _age_days(published),
        })
    rows.sort(key=lambda r: r.get("published") or "", reverse=True)
    return rows


def _age_days(iso: str) -> int | None:
    parsed = _parse_date(iso)
    if not parsed:
        return None
    return (datetime.now(timezone.utc).date() - parsed).days


def _derive() -> dict | None:
    today = datetime.now(timezone.utc).date()
    log.info(f"  Lifecycle: {len(_PRODUCTS)} products, {len(_REPOS)} repos...")

    products = _fetch_products(today)
    releases = _fetch_releases()
    if not products and not releases:
        return None

    eol_products = sum(1 for p in products if p["eol_count"])
    log.info(f"  Lifecycle: {len(products)} products "
             f"({eol_products} with an EOL cycle), {len(releases)} releases")
    return {
        "built": now_utc(),
        "as_of": today.isoformat(),
        "products": products,
        "releases": releases,
        "counts": {
            "products": len(products),
            "products_with_eol": eol_products,
            "releases": len(releases),
        },
        # Reported so a partial fetch is visible rather than looking like a
        # shorter list of products.
        "complete": len(products) == len(_PRODUCTS) and len(releases) > 0,
        "sources": ["https://endoflife.date", "https://api.github.com"],
    }


def load_lifecycle(force: bool = False) -> dict | None:
    if not CONFIG.enable_lifecycle:
        return None
    ttl = 0 if force else CONFIG.lifecycle_ttl_hours
    return cached_derive("lifecycle.json", ttl, _derive)


if __name__ == "__main__":
    result = load_lifecycle(force=True)
    print(json.dumps(result.get("counts") if result else {}, indent=2))
