"""
OPENTHREAT — iocs.py
==================
Indicator extraction: IPs, domains, hashes and URLs pulled out of item text,
with the denylists that keep prose from being mistaken for indicators.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel.IOC_PATTERNS` and the like keep working.
"""

import re




# ── IOC Extraction Engine ─────────────────────────────────────────────────────
# Previously this ran over EVERY item's prose, so the STIX/CSV exports ended up
# publishing gmail.com, redhat.com, cern.ch, `req.query`, `handlers.ts` and two
# named maintainers' work email addresses as `indicator_types: malicious-activity`.
# Essentially 100% false positives, plus a PII leak in a public repo.
#
# Two changes fix it:
#   1. Only sources that actually publish IOCs are scanned (IOC_SOURCES).
#   2. Everything else must clear a plausibility bar: defanged notation, a real
#      public suffix, and not the article's own host.

IOC_PATTERNS = {
    'sha256': re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])'),
    'sha1':   re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])'),
    'md5':    re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])'),
    'ipv4':   re.compile(r'(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b'),
    'url':    re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.I),
    'cve':    re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
    'cidr':   re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![0-9])'),
    'email':  re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
}

# Sources whose payloads ARE indicator feeds. Only these get network/file IOC
# extraction; everything else contributes CVE ids only.
IOC_SOURCES = {
    "URLhaus", "ThreatFox", "Feodo Tracker", "Spamhaus", "MalwareBazaar",
    "AbuseIPDB", "PhishTank", "AlienVault OTX",
}

# Never treat these as indicators: infrastructure, source hosts, and the
# vendors whose advisories we ingest.
_DOMAIN_DENYLIST = {
    "github.com", "githubusercontent.com", "gmail.com", "google.com", "twitter.com",
    "x.com", "linkedin.com", "youtube.com", "facebook.com", "microsoft.com",
    "redhat.com", "cern.ch", "cisa.gov", "nist.gov", "mitre.org", "apache.org",
    "debian.org", "ubuntu.com", "fedoraproject.org", "gentoo.org", "archlinux.org",
    "kernel.org", "python.org", "npmjs.com", "docker.com", "amazon.com", "aws.amazon.com",
    "oracle.com", "vmware.com", "broadcom.com", "cloudflare.com", "wordpress.org",
    "sans.edu", "isc.sans.edu", "abuse.ch", "virustotal.com", "first.org",
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com", "reddit.com",
    "securityweek.com", "darkreading.com", "welivesecurity.com", "talosintelligence.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "grahamcluley.com",
    "therecord.media", "cybersecuritynews.com", "zerodayinitiative.com", "example.com",
}

# Source-code and filename shapes the domain regex loves: `req.query`,
# `handlers.ts`, `ops.dispatch`, `security.txt`, `countid.substring`.
_CODE_TLD_DENYLIST = {
    "ts", "js", "py", "go", "rs", "rb", "sh", "md", "txt", "json", "yml", "yaml",
    "xml", "html", "css", "c", "h", "cpp", "java", "php", "sql", "log", "cfg",
    "conf", "ini", "toml", "lock", "map", "min", "test", "spec", "config",
    "query", "params", "body", "data", "value", "length", "push", "pop", "get",
    "set", "add", "remove", "dispatch", "dequeue", "substring", "insecure",
    "exe", "dll", "dat", "bin", "tmp", "bak", "old", "new", "local", "internal",
}

_DEFANG_HINT = re.compile(r"\[\.\]|\(\.\)|hxxp|\[at\]|\[:\]", re.IGNORECASE)


def _plausible_domain(value: str, own_host: str = "") -> bool:
    """Reject code identifiers, filenames, infrastructure and the item's own host."""
    v = value.strip().lower().rstrip(".")
    if "." not in v or len(v) < 4 or len(v) > 253:
        return False
    tld = v.rsplit(".", 1)[-1]
    if tld in _CODE_TLD_DENYLIST or not tld.isalpha() or len(tld) < 2:
        return False
    if v in _DOMAIN_DENYLIST:
        return False
    # Registrable-domain check against the denylist ("mail.google.com" -> "google.com").
    parts = v.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _DOMAIN_DENYLIST:
        return False
    if own_host and (v == own_host or own_host.endswith("." + v) or v.endswith("." + own_host)):
        return False
    return True


def _is_private_ip(value: str) -> bool:
    try:
        parts = [int(p) for p in value.split(".")]
    except ValueError:
        return True
    if len(parts) != 4:
        return True
    a, b = parts[0], parts[1]
    return (a in (0, 10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 169 and b == 254) or a >= 224)


def extract_iocs(text: str, source: str = "", own_url: str = "") -> dict[str, list[str]]:
    """Extract indicators from text.

    `source` gates network/file indicators: only feeds that publish IOCs get
    them. Any source may still contribute CVE ids, which are unambiguous.
    """
    if not text:
        return {}

    defanged = bool(_DEFANG_HINT.search(text))
    clean = (text.replace('[.]', '.').replace('(.)', '.')
                 .replace('hxxps', 'https').replace('hxxp', 'http')
                 .replace('[at]', '@').replace('[:]', ':'))

    own_host = ""
    if own_url:
        m = re.match(r'https?://([^/:]+)', own_url.strip().lower())
        if m:
            own_host = m.group(1).removeprefix("www.")

    result: dict[str, list[str]] = {}
    # CVE ids are safe from any source.
    types = ["cve"]
    # Network/file indicators only from IOC feeds, or when the text is defanged
    # (defanging is the author explicitly signalling "this is an indicator").
    if source in IOC_SOURCES or defanged:
        types += ["sha256", "sha1", "md5", "ipv4", "cidr", "url", "domain", "email"]

    for ioc_type in types:
        pattern = IOC_PATTERNS[ioc_type]
        seen: set[str] = set()
        unique: list[str] = []
        for match in pattern.findall(clean):
            value = match.strip().lower().rstrip('.,;)')
            if not value or len(value) <= 2 or value in seen:
                continue
            if ioc_type == 'ipv4' and _is_private_ip(value):
                continue
            if ioc_type == 'domain' and not _plausible_domain(value, own_host):
                continue
            if ioc_type == 'url' and own_host and own_host in value:
                continue
            if ioc_type == 'email':
                # Only from indicator feeds, never scraped from advisory metadata
                # (that is how maintainers' addresses ended up in the STIX bundle).
                if source not in IOC_SOURCES:
                    continue
            if ioc_type == 'cve':
                value = value.upper()
            seen.add(value)
            unique.append(value)
            if len(unique) >= 50:
                break
        if unique:
            result[ioc_type] = unique
    return result
