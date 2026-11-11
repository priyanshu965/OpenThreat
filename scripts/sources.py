"""
OPENTHREAT — sources.py
=====================
The sources themselves: the RSS feed list, every API fetcher, and the
runner that records each one's health.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel.RSS_SOURCES` and the like keep working.
"""

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

from fetchlib import (
    CONFIG,
    log,
    SESSION as _SESSION,
    cache_path as _cache_path,
    cached_fetch as _cached_fetch,
)
from classify import extract_cve_id, infer_category, infer_severity, valid_cve_id
from feedutil import clean_html, entry_date, make_request, make_request_text, now_utc, parse_date
from iocs import extract_iocs
from scoring import cvss_to_severity

# Optional, like every satellite module: without darkweb.py the leak-site
# source is simply absent from API_SOURCES.
try:
    from darkweb import fetch_leak_site_posts
except Exception:
    fetch_leak_site_posts = None

ABUSEIPDB_KEY = CONFIG.abuseipdb_api_key
HEADERS = {"User-Agent": CONFIG.http_user_agent}
MAX_ITEMS_PER_SOURCE = CONFIG.max_items_per_source
MB_API_KEY = CONFIG.mb_api_key
NVD_LOOKBACK_DAYS = CONFIG.nvd_lookback_days
OTX_API_KEY = CONFIG.otx_api_key
PHISHTANK_KEY = CONFIG.phishtank_api_key
REQUEST_TIMEOUT = CONFIG.request_timeout
THREATFOX_API_KEY = CONFIG.threatfox_api_key
URLHAUS_API_KEY = CONFIG.urlhaus_api_key


# ── RSS Feed Sources ───────────────────────────────────────────────────────────
RSS_SOURCES = [
    {"name": "CISA",             "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "advisory", "severity": "high"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",            "category": "news",     "severity": "medium"},
    {"name": "Bleeping Computer","url": "https://www.bleepingcomputer.com/feed/",                 "category": "news",     "severity": "medium"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",                      "category": "news",     "severity": "medium"},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml",                  "category": "news",     "severity": "low"},
    {"name": "TheRecord Media",  "url": "https://therecord.media/feed",                           "category": "news",     "severity": "high"},
    {"name": "Dark Reading",     "url": "https://www.darkreading.com/rss.xml",                    "category": "news",     "severity": "medium"},
    {"name": "SecurityWeek",     "url": "https://www.securityweek.com/feed/",                     "category": "news",     "severity": "medium"},
    {"name": "Cisco Talos",      "url": "https://blog.talosintelligence.com/feed",                "category": "news",     "severity": "high"},
    {"name": "Unit 42",          "url": "https://feeds.feedburner.com/Unit42",                    "category": "news",     "severity": "high"},
    {"name": "Graham Cluley",    "url": "https://grahamcluley.com/feed/",                         "category": "news",     "severity": "medium"},
    {"name": "ESET WeLiveSecurity","url": "https://welivesecurity.com/feed/",                     "category": "news",     "severity": "medium"},
    # ── Vendor threat-research blogs ────────────────────────────────────────
    # Added because the geopolitical view is only as good as actor detection,
    # and these are the sources that actually NAME groups (APT41, Volt Typhoon,
    # Sandworm) rather than describing incidents generically. All are free,
    # keyless, public RSS; verified live before adding.
    {"name": "Securelist",       "url": "https://securelist.com/feed/",                          "category": "news",     "severity": "medium"},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/",             "category": "news",     "severity": "medium"},
    {"name": "Microsoft Security",   "url": "https://www.microsoft.com/en-us/security/blog/feed/", "category": "news",   "severity": "medium"},
    {"name": "SentinelOne",      "url": "https://www.sentinelone.com/blog/feed/",                "category": "news",     "severity": "medium"},
    {"name": "Malwarebytes",     "url": "https://www.malwarebytes.com/blog/feed/index.xml",      "category": "news",     "severity": "medium"},
    {"name": "Recorded Future",  "url": "https://www.recordedfuture.com/feed",                   "category": "news",     "severity": "medium"},
    {"name": "CyberSecurity News","url": "https://cybersecuritynews.com/feed/",                   "category": "news",     "severity": "medium"},
    # ── Wider news coverage ─────────────────────────────────────────────────
    # The original list leaned on a handful of outlets, so a story none of
    # them ran simply did not exist here. These broaden it by beat: general
    # security news, policy (CyberScoop), breaches (DataBreaches.net), ICS
    # (Industrial Cyber) and long-form (Ars, WIRED). Every feed below was
    # checked before it was added: live, parses cleanly, newest-first, and a
    # median item age well inside SOURCE_STALE_DAYS. Good blogs that post a few
    # times a year (Project Zero, watchTowr, PortSwigger) were left out for
    # that reason - they would sit permanently flagged as stale.
    {"name": "Security Affairs",                      "url": "https://securityaffairs.com/feed",                                                  "category": "news",     "severity": "medium"},
    {"name": "The Register",                          "url": "https://www.theregister.com/security/headlines.atom",                               "category": "news",     "severity": "medium"},
    {"name": "Ars Technica",                          "url": "https://arstechnica.com/security/feed/",                                            "category": "news",     "severity": "medium"},
    {"name": "CyberScoop",                            "url": "https://cyberscoop.com/feed/",                                                      "category": "news",     "severity": "medium"},
    {"name": "Help Net Security",                     "url": "https://www.helpnetsecurity.com/feed/",                                             "category": "news",     "severity": "medium"},
    {"name": "Infosecurity Magazine",                 "url": "https://www.infosecurity-magazine.com/rss/news/",                                   "category": "news",     "severity": "medium"},
    {"name": "HackRead",                              "url": "https://hackread.com/feed/",                                                        "category": "news",     "severity": "medium"},
    {"name": "CSO Online",                            "url": "https://www.csoonline.com/feed/",                                                   "category": "news",     "severity": "medium"},
    {"name": "WIRED Security",                        "url": "https://www.wired.com/feed/category/security/latest/rss",                           "category": "news",     "severity": "medium"},
    {"name": "TechCrunch Security",                   "url": "https://techcrunch.com/category/security/feed/",                                    "category": "news",     "severity": "medium"},
    {"name": "DataBreaches.net",                      "url": "https://databreaches.net/feed/",                                                    "category": "news",     "severity": "medium"},
    {"name": "Industrial Cyber",                      "url": "https://industrialcyber.co/feed/",                                                  "category": "news",     "severity": "medium"},
    {"name": "The Cyber Express",                     "url": "https://thecyberexpress.com/feed/",                                                 "category": "news",     "severity": "medium"},
    {"name": "Schneier on Security",                  "url": "https://www.schneier.com/feed/atom/",                                               "category": "news",     "severity": "low"},
    # ── More research teams ─────────────────────────────────────────────────
    # First-hand telemetry on what is being exploited now. Rapid7, Huntress and
    # Horizon3 in particular tend to publish on a vulnerability the day it
    # starts being used, ahead of the news cycle.
    {"name": "Rapid7",                                "url": "https://blog.rapid7.com/rss/",                                                      "category": "news",     "severity": "high"},
    {"name": "Huntress",                              "url": "https://www.huntress.com/blog/rss.xml",                                             "category": "news",     "severity": "high"},
    {"name": "Horizon3",                              "url": "https://horizon3.ai/feed/",                                                         "category": "news",     "severity": "high"},
    {"name": "Sophos X-Ops",                          "url": "https://news.sophos.com/en-us/category/threat-research/feed/",                      "category": "news",     "severity": "high"},
    {"name": "Tenable",                               "url": "https://www.tenable.com/blog/feed",                                                 "category": "news",     "severity": "medium"},
    {"name": "Qualys",                                "url": "https://blog.qualys.com/feed",                                                      "category": "news",     "severity": "medium"},
    {"name": "Wiz",                                   "url": "https://www.wiz.io/feed/rss.xml",                                                   "category": "news",     "severity": "medium"},
    {"name": "ANY.RUN",                               "url": "https://any.run/cybersecurity-blog/feed/",                                          "category": "news",     "severity": "medium"},
    {"name": "Cloudflare",                            "url": "https://blog.cloudflare.com/tag/security/rss/",                                     "category": "news",     "severity": "medium"},
    {"name": "Datadog Security Labs",                 "url": "https://securitylabs.datadoghq.com/rss/feed.xml",                                   "category": "news",     "severity": "medium"},
    {"name": "Citizen Lab",                           "url": "https://citizenlab.ca/feed/",                                                       "category": "news",     "severity": "medium"},
    # ── Official and vendor advisories ──────────────────────────────────────
    {"name": "Canadian Centre for Cyber Security",    "url": "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en",        "category": "advisory", "severity": "high"},
    {"name": "Ubuntu",                                "url": "https://ubuntu.com/security/notices/rss.xml",                                       "category": "advisory", "severity": "medium"},
    {"name": "Full Disclosure",                       "url": "https://seclists.org/rss/fulldisclosure.rss",                                       "category": "advisory", "severity": "medium"},
    # ── Second sweep ────────────────────────────────────────────────────────
    # ~230 candidate feeds were probed with this pipeline's own client; these
    # are the ones that answered, parsed, dated their entries and had a median
    # item age inside SOURCE_STALE_DAYS. Well-known names that are absent
    # failed one of those: no feed any more (Mandiant, SC Media, Decipher),
    # blocked (Trellix, Trend Micro, Security Boulevard), undated entries
    # (BankInfoSecurity). Cybernews, SecurityOnline and Exploit-DB answer a
    # desktop but refuse or time out GitHub's runners, which is where this
    # actually runs; they wait in feed_candidates.txt, probed daily.
    {"name": "GBHackers",                              "url": "https://gbhackers.com/feed/",                                                              "category": "news",     "severity": "medium"},
    {"name": "Cyber Press",                            "url": "https://cyberpress.org/feed/",                                                             "category": "news",     "severity": "medium"},
    {"name": "The420",                                 "url": "https://the420.in/feed/",                                                                  "category": "news",     "severity": "medium"},
    {"name": "ET CISO",                                "url": "https://ciso.economictimes.indiatimes.com/rss/topstories",                                 "category": "news",     "severity": "medium"},
    {"name": "IT Security Guru",                       "url": "https://www.itsecurityguru.org/feed/",                                                     "category": "news",     "severity": "medium"},
    {"name": "Nextgov",                                "url": "https://www.nextgov.com/rss/cybersecurity/",                                               "category": "news",     "severity": "medium"},
    {"name": "Risky Business",                         "url": "https://news.risky.biz/rss/",                                                              "category": "news",     "severity": "medium"},
    {"name": "Have I Been Pwned",                      "url": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches",                                "category": "news",     "severity": "medium"},
    {"name": "Lobsters",                               "url": "https://lobste.rs/t/security.rss",                                                         "category": "news",     "severity": "medium"},
    # Research teams
    {"name": "Elastic Security Labs",                  "url": "https://www.elastic.co/security-labs/rss/feed.xml",                                        "category": "news",     "severity": "medium"},
    {"name": "Symantec",                               "url": "https://sed-cms.broadcom.com/rss/v1/blogs/rss.xml",                                        "category": "news",     "severity": "medium"},
    {"name": "Zscaler ThreatLabz",                     "url": "https://www.zscaler.com/blogs/feeds/security-research",                                    "category": "news",     "severity": "medium"},
    {"name": "Sekoia",                                 "url": "https://blog.sekoia.io/feed/",                                                             "category": "news",     "severity": "medium"},
    {"name": "Bitdefender",                            "url": "https://www.bitdefender.com/blog/api/rss/hotforsecurity/",                                 "category": "news",     "severity": "medium"},
    {"name": "AhnLab ASEC",                            "url": "https://asec.ahnlab.com/en/feed/",                                                         "category": "news",     "severity": "medium"},
    {"name": "Cyble",                                  "url": "https://cyble.com/feed/",                                                                  "category": "news",     "severity": "medium"},
    {"name": "SOCRadar",                               "url": "https://socradar.io/feed/",                                                                "category": "news",     "severity": "medium"},
    {"name": "VulnCheck",                              "url": "https://www.vulncheck.com/feed/blog/atom.xml",                                             "category": "news",     "severity": "medium"},
    {"name": "Censys",                                 "url": "https://censys.com/feed/",                                                                 "category": "news",     "severity": "medium"},
    {"name": "Eclypsium",                              "url": "https://eclypsium.com/feed/",                                                              "category": "news",     "severity": "medium"},
    {"name": "ReversingLabs",                          "url": "https://www.reversinglabs.com/blog/rss.xml",                                               "category": "news",     "severity": "medium"},
    {"name": "Socket",                                 "url": "https://socket.dev/api/blog/feed.atom",                                                    "category": "news",     "severity": "medium"},
    {"name": "Wordfence",                              "url": "https://www.wordfence.com/feed/",                                                          "category": "news",     "severity": "medium"},
    {"name": "SpecterOps",                             "url": "https://specterops.io/feed/",                                                              "category": "news",     "severity": "medium"},
    # Government, vendor PSIRTs, and disclosure lists
    {"name": "UK NCSC",                                "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",                               "category": "advisory", "severity": "medium"},
    {"name": "CERT/CC",                                "url": "https://www.kb.cert.org/vuls/atomfeed/",                                                   "category": "advisory", "severity": "high"},
    {"name": "HKCERT",                                 "url": "https://www.hkcert.org/getrss/security-bulletin",                                          "category": "advisory", "severity": "medium"},
    {"name": "Fortinet PSIRT",                         "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",                                     "category": "advisory", "severity": "high"},
    {"name": "Siemens ProductCERT",                    "url": "https://cert-portal.siemens.com/productcert/rss/advisories.atom",                          "category": "advisory", "severity": "medium"},
    {"name": "Synology",                               "url": "https://www.synology.com/api/rssfeed/security/en-global",                                  "category": "advisory", "severity": "medium"},
    {"name": "Splunk",                                 "url": "https://advisory.splunk.com/feed.xml",                                                     "category": "advisory", "severity": "medium"},
    {"name": "Chrome Releases",                        "url": "https://chromereleases.googleblog.com/feeds/posts/default",                                "category": "advisory", "severity": "medium"},
    {"name": "oss-security",                           "url": "https://seclists.org/rss/oss-sec.rss",                                                     "category": "advisory", "severity": "medium"},
    # ── Slow but early ──────────────────────────────────────────────────────
    # The teams that publish a zero-day write-up before the news cycle has a
    # name for it post a few times a quarter, so the 30-day staleness rule
    # kept every one of them out. `cadence: slow` holds a feed to
    # SOURCE_SLOW_STALE_DAYS and takes only what it published inside
    # SLOW_SOURCE_WINDOW_DAYS. All were probed from a GitHub runner first.
    {"name": "Google Threat Intelligence",             "url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",                              "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Volexity",                               "url": "https://www.volexity.com/feed/",                                                           "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "watchTowr Labs",                         "url": "https://labs.watchtowr.com/rss/",                                                          "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Project Zero",                           "url": "https://projectzero.google/feed.xml",                                                      "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "The DFIR Report",                        "url": "https://thedfirreport.com/feed/",                                                          "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Proofpoint",                             "url": "https://www.proofpoint.com/us/threat-insight-blog.xml",                                    "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "GreyNoise",                              "url": "https://www.greynoise.io/blog/rss.xml",                                                    "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "PortSwigger Research",                   "url": "https://portswigger.net/research/rss",                                                     "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "FortiGuard Labs",                        "url": "https://feeds.fortinet.com/fortinet/blog/threat-research",                                 "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Trail of Bits",                          "url": "https://blog.trailofbits.com/feed/",                                                       "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Binarly",                                "url": "https://www.binarly.io/blog/rss.xml",                                                      "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Bitdefender Labs",                       "url": "https://www.bitdefender.com/blog/api/rss/labs/",                                           "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "XLab",                                   "url": "https://blog.xlab.qianxin.com/rss/",                                                       "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "CERT-EU",                                "url": "https://cert.europa.eu/publications/security-advisories-rss",                              "category": "advisory", "severity": "medium", "cadence": "slow"},
    {"name": "Zero Day",                               "url": "https://www.zetter-zeroday.com/rss/",                                                      "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Objective-See",                          "url": "https://objective-see.org/rss.xml",                                                        "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "DoublePulsar",                           "url": "https://doublepulsar.com/feed",                                                            "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "Red Canary",                             "url": "https://redcanary.com/blog/feed/",                                                         "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "GitHub Security",                        "url": "https://github.blog/security/feed/",                                                       "category": "news",     "severity": "medium", "cadence": "slow"},
    {"name": "JPCERT/CC",                              "url": "https://blogs.jpcert.or.jp/en/atom.xml",                                                   "category": "advisory", "severity": "medium", "cadence": "slow"},
    {"name": "tl;dr sec",                              "url": "https://tldrsec.com/feed.xml",                                                             "category": "news",     "severity": "medium", "cadence": "slow"},
    # Vendor PSIRTs that only speak when there is something to patch
    {"name": "Ivanti",                                 "url": "https://www.ivanti.com/blog/topics/security-advisory/rss",                                 "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "GitLab",                                 "url": "https://about.gitlab.com/security-releases.xml",                                           "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "Jenkins",                                "url": "https://www.jenkins.io/security/advisories/rss.xml",                                       "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "Node.js",                                "url": "https://nodejs.org/en/feed/vulnerability.xml",                                             "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "Kubernetes",                             "url": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml",          "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "Drupal",                                 "url": "https://www.drupal.org/security/rss.xml",                                                  "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "WordPress",                              "url": "https://wordpress.org/news/category/security/feed/",                                       "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "Oracle",                                 "url": "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml",      "category": "advisory", "severity": "high", "cadence": "slow"},
    {"name": "QNAP",                                   "url": "https://www.qnap.com/en/security-advisory/feed",                                           "category": "advisory", "severity": "high", "cadence": "slow"},
    # Answered the runner on the second sweep
    {"name": "CrowdStrike",                            "url": "https://www.crowdstrike.com/en-us/blog/feed/",                                             "category": "news",     "severity": "medium"},
    {"name": "Troy Hunt",                              "url": "https://www.troyhunt.com/rss/",                                                            "category": "news",     "severity": "medium"},
    {"name": "Security Boulevard",                     "url": "https://securityboulevard.com/feed/",                                                      "category": "news",     "severity": "medium"},
]


# ── RSS Fetcher ───────────────────────────────────────────────────────────────

# Per-feed ETag / Last-Modified store, so hourly runs can send a conditional
# request instead of re-downloading unchanged feeds 24x/day. Most of these
# feeds publish a handful of times daily; several have already started 403ing
# aggressive clients (GBHackers spent months out of RSS_SOURCES for exactly
# that reason), so this is politeness as much as speed.
_FEED_META: dict[str, dict] = {}
_FEED_META_LOCK = threading.Lock()


def _load_feed_meta() -> None:
    global _FEED_META
    try:
        if CONFIG.feed_meta_path.exists():
            _FEED_META = json.loads(CONFIG.feed_meta_path.read_text(encoding="utf-8"))
    except Exception:
        _FEED_META = {}


def _save_feed_meta() -> None:
    try:
        CONFIG.feed_meta_path.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.feed_meta_path.write_text(json.dumps(_FEED_META, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning(f"Could not persist feed metadata: {e}")


def recent_only(items: list[dict]) -> list[dict]:
    """What a slow-cadence source published inside the window, newest first.

    The newest post is always kept, however old, so a quiet research blog
    still reports its real age to the health check instead of reading as an
    empty feed.
    """
    if not items:
        return items
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=CONFIG.slow_source_window_days)).isoformat()
    ordered = sorted(items, key=lambda i: str(i.get("published") or ""), reverse=True)
    return [i for i in ordered if str(i.get("published") or "") >= cutoff] or ordered[:1]


def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']}")
    items = []
    url = source["url"]
    hdrs = {**HEADERS, **source.get("headers", {})}
    with _FEED_META_LOCK:
        meta = dict(_FEED_META.get(url, {}))
    if meta.get("etag"):
        hdrs["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        hdrs["If-Modified-Since"] = meta["last_modified"]

    try:
        resp = _SESSION.get(url, headers=hdrs, timeout=15)
        if resp.status_code == 304:
            log.info(f"  {source['name']}: 304 Not Modified — reusing last snapshot")
            return _replay_cached_feed(url)
        resp.raise_for_status()
        with _FEED_META_LOCK:
            _FEED_META[url] = {
                "etag": resp.headers.get("ETag", ""),
                "last_modified": resp.headers.get("Last-Modified", ""),
                "checked": now_utc(),
            }
        feed = feedparser.parse(resp.text)
        if feed.bozo and not feed.entries:
            log.warning(f"Feed error {source['name']}")
            return items
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link = entry.get("link", "")
            description = ""
            if hasattr(entry, "summary"):
                description = clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description = clean_html(entry.content[0].get("value", ""))
            description = description.strip()[:999]
            pub_date = entry_date(entry) or now_utc()
            severity = infer_severity(title + " " + description, source["severity"])
            category = infer_category(title + " " + description, source["category"])
            text = title + " " + description
            items.append({
                "title": title, "description": description, "url": link,
                "cve_id": extract_cve_id(text), "source": source["name"],
                "category": category, "severity": severity, "cvss_score": None,
                "published": pub_date,
            })
    except Exception as e:
        log.error(f"Unexpected error {source['name']}: {e}")
    if source.get("cadence") == "slow":
        items = recent_only(items)
    if items:
        _store_cached_feed(source["url"], items)
    log.info(f"  Got {len(items)} items from {source['name']}")
    return items


def _feed_cache_path(url: str) -> Path:
    # A cache filename, not a security control.
    digest = hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()[:16]
    return _cache_path(f"feed_{digest}.json")


def _store_cached_feed(url: str, items: list[dict]) -> None:
    try:
        _feed_cache_path(url).write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _replay_cached_feed(url: str) -> list[dict]:
    try:
        path = _feed_cache_path(url)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

# ── NVD CVE Fetcher ───────────────────────────────────────────────────────────

def fetch_nvd_cves() -> list[dict]:
    log.info("Fetching CVEs from NVD API...")
    items = []
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)
    nvd_params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }
    if CONFIG.nvd_api_key:
        nvd_params["apiKey"] = CONFIG.nvd_api_key
    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params=nvd_params)
    if not data:
        return items
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description.")[:400]
        cvss_score = None
        severity = "medium"
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            ml = cve.get("metrics", {}).get(mk, [])
            if ml:
                cvss_score = ml[0].get("cvssData", {}).get("baseScore")
                severity = cvss_to_severity(cvss_score)
                break
        # Affected vendor/product pairs from CPE criteria — powers the
        # dashboard's "my stack" watchlist matching.
        products = set()
        for conf in cve.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    parts = (match.get("criteria") or "").split(":")
                    if len(parts) > 4:  # cpe:2.3:a:vendor:product:...
                        products.add(f"{parts[3]}/{parts[4]}")
        items.append({
            "title": f"{cve_id}: {description[:80]}...", "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "cve_id": valid_cve_id(cve_id),
            "source": "NVD", "category": "cve", "severity": severity,
            "cvss_score": cvss_score, "published": parse_date(cve.get("published", "")),
            "affected_products": sorted(products)[:8],
        })
    log.info(f"  Got {len(items)} CVEs from NVD")
    return items

# ── Reddit r/netsec Fetcher ───────────────────────────────────────────────────

def fetch_reddit_netsec() -> list[dict]:
    log.info("Fetching Reddit r/netsec...")
    items = []
    try:
        resp = requests.get("https://www.reddit.com/r/netsec/.rss",
                             headers={**HEADERS, "User-Agent": f"{CONFIG.http_user_agent} (macOS; rv:1.0)"},
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc or f"Reddit (score: {entry.get('slash_comments', '')})",
                "url": link, "cve_id": extract_cve_id(title),
                "source": "Reddit/netsec", "category": infer_category(title, "news"),
                "severity": infer_severity(title, "low"), "cvss_score": None, "published": pub,
            })
    except Exception as e:
        log.warning(f"Reddit r/netsec failed: {e}")
    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items

# ── Hacker News (Algolia search API) ──────────────────────────────────────────
# hnrss.org, the RSS front end, does not answer GitHub's runners. This is the
# API that site is itself built on, queried directly. Search there is AND-only,
# so each term is its own request and the results are merged.

_HN_TERMS = ("vulnerability", "exploit", "CVE", "ransomware", "malware",
             "breach", "zero-day", "backdoor", "hacked", "security")
_HN_MIN_POINTS = 100
_HN_TITLE = re.compile(
    r"vulnerab|exploit|\bCVE\b|CVE-\d|ransomware|malware|breach|zero.?day|0.?day|backdoor"
    r"|\bhack(?:ed|ing)\b|\bhackers\b|\bRCE\b|phishing|spyware|botnet|supply.chain|security (?:flaw|bug|hole|advisory|incident)"
    r"|leak(?:ed|s)?\b|stolen|compromis", re.I)


def fetch_hacker_news() -> list[dict]:
    log.info("Fetching Hacker News security stories...")
    seen: dict[str, dict] = {}
    since = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp())
    for term in _HN_TERMS:
        data = make_request(
            "https://hn.algolia.com/api/v1/search_by_date",
            params={"query": term, "tags": "story", "hitsPerPage": 20,
                    "restrictSearchableAttributes": "title",
                    "numericFilters": f"points>={_HN_MIN_POINTS},created_at_i>{since}"})
        for hit in (data or {}).get("hits", []):
            story_id = str(hit.get("objectID") or "")
            title = (hit.get("title") or "").strip()
            # The API matches loosely (typos, prefixes, the linked page), so
            # a title has to earn its place here as well.
            if not story_id or not title or story_id in seen or not _HN_TITLE.search(title):
                continue
            discussion = f"https://news.ycombinator.com/item?id={story_id}"
            seen[story_id] = {
                "title": title,
                "description": f"{hit.get('points', 0)} points and "
                               f"{hit.get('num_comments', 0)} comments on Hacker News. "
                               f"Discussion: {discussion}",
                "url": hit.get("url") or discussion,
                "cve_id": extract_cve_id(title),
                "source": "Hacker News", "category": infer_category(title, "news"),
                "severity": infer_severity(title, "low"), "cvss_score": None,
                "published": parse_date(hit.get("created_at") or ""),
                "_points": int(hit.get("points") or 0),
            }
    # The most-discussed stories of the week, not merely the latest ten.
    items = sorted(seen.values(), key=lambda i: i["_points"], reverse=True)[:MAX_ITEMS_PER_SOURCE]
    for item in items:
        item.pop("_points", None)
    log.info(f"  Got {len(items)} stories from Hacker News")
    return items


# ── CERT-In (listing pages; the agency publishes no feed) ─────────────────────
# India's national CERT lists advisories (CIAD) and vulnerability notes (CIVN)
# on two server-rendered pages per year. Each row is a code, a date in
# brackets and a one-line title, which is everything a feed item needs.

_CERT_IN_BASE = "https://www.cert-in.org.in/s2cMainServlet"
_CERT_IN_ROW = re.compile(
    r'href="(?P<path>/s2cMainServlet\?pageid=[A-Z0-9]+&(?:amp;)?VLCODE=(?P<code>CI(?:AD|VN)-\d{4}-\d+))"'
    r'.*?\(\s*(?P<date>[A-Z][a-z]+\s+\d{1,2},\s+\d{4})\s*\)'
    r'.*?padding-left:\s*\d+px">(?P<title>.*?)</span>', re.S)


def parse_cert_in(html_text: str) -> list[dict]:
    """Rows of one CERT-In listing page, in page order (newest first)."""
    items = []
    for row in _CERT_IN_ROW.finditer(html_text or ""):
        code = row.group("code")
        title = clean_html(row.group("title")).strip()
        try:
            published = datetime.strptime(" ".join(row.group("date").split()), "%B %d, %Y") \
                .replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
        if not title:
            continue
        kind = "Advisory" if code.startswith("CIAD") else "Vulnerability Note"
        text = f"{code}: {title}"
        items.append({
            "title": text,
            "description": f"CERT-In {kind} {code}. {title}",
            "url": "https://www.cert-in.org.in" + row.group("path").replace("&amp;", "&"),
            "cve_id": extract_cve_id(title), "source": "CERT-In", "category": "advisory",
            "severity": infer_severity(title, "high" if kind == "Advisory" else "medium"),
            "cvss_score": None, "published": published,
        })
    return items


def fetch_cert_in() -> list[dict]:
    log.info("Fetching CERT-In advisories and vulnerability notes...")
    year = datetime.now(timezone.utc).year
    items: list[dict] = []
    for page in ("PUBADVLIST02", "VLNLIST02"):
        rows: list[dict] = []
        # January has almost nothing listed under the new year yet.
        for y in (year, year - 1):
            text = make_request_text(f"{_CERT_IN_BASE}?pageid={page}&year={y}")
            rows += parse_cert_in(text or "")
            if len(rows) >= MAX_ITEMS_PER_SOURCE:
                break
        items += rows[:MAX_ITEMS_PER_SOURCE]
    items.sort(key=lambda i: i["published"], reverse=True)
    log.info(f"  Got {len(items)} from CERT-In")
    return items[:MAX_ITEMS_PER_SOURCE]


# ── AlienVault OTX Fetcher (API key) ──────────────────────────────────────────

def fetch_otx_pulse() -> list[dict]:
    if not OTX_API_KEY:
        raise SourceDisabled("needs OTX_API_KEY")
    log.info("Fetching AlienVault OTX pulses...")
    items = []
    data = make_request("https://otx.alienvault.com/api/v1/pulses/subscribed",
                        headers={**HEADERS, "X-OTX-API-KEY": OTX_API_KEY},
                        params={"limit": MAX_ITEMS_PER_SOURCE})
    if not data:
        return items
    for pulse in data.get("results", []):
        name = pulse.get("name", "Untitled")
        description = (pulse.get("description") or "")[:400]
        items.append({
            "title": name, "description": description,
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
            "cve_id": None, "source": "AlienVault OTX", "category": "incident",
            "severity": infer_severity(name + " " + description, "medium"),
            "cvss_score": None, "published": parse_date(pulse.get("created", now_utc())),
        })
    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items

# ── URLhaus Fetcher (keyless) ─────────────────────────────────────────────────

class SourceDisabled(Exception):
    """A source that cannot run as configured - in practice, a missing API key.

    Raised instead of returning [] so the health report can tell "switched off"
    from "returned nothing". Both used to read as `empty`, which made a source
    nobody had given a key to look exactly like one that had broken.
    """


def fetch_urlhaus() -> list[dict]:
    """Recent malware URLs from URLhaus.

    abuse.ch retired every keyless download (csv_recent and its siblings now
    answer 410 Gone) in favour of the authenticated API. The key is free and is
    the same one MalwareBazaar and ThreatFox use - see ABUSECH_AUTH_KEY.
    """
    if not URLHAUS_API_KEY:
        raise SourceDisabled("needs ABUSECH_AUTH_KEY")
    log.info("Fetching URLhaus malware URLs...")
    items = []
    try:
        resp = requests.get(
            f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{MAX_ITEMS_PER_SOURCE}/",
            headers={**HEADERS, "Auth-Key": URLHAUS_API_KEY}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            log.warning(f"URLhaus answered {data.get('query_status')!r}")
            return items
        for row in (data.get("urls") or [])[:MAX_ITEMS_PER_SOURCE]:
            url = row.get("url") or ""
            if not url:
                continue
            threat = row.get("threat") or "malware"
            tags = ", ".join(row.get("tags") or [])
            host = row.get("host") or (url.split("/")[2] if "//" in url else "unknown")
            items.append({
                "title": f"URLhaus: {host} serving {threat}",
                "description": f"Malicious URL: {url[:200]} | Tags: {tags}",
                "url": url, "cve_id": None, "source": "URLhaus",
                "category": "incident", "severity": infer_severity(threat + " " + tags, "high"),
                "cvss_score": None, "published": parse_date(row.get("date_added") or ""),
                "iocs": {"url": [url]}
            })
    except Exception as e:
        log.warning(f"URLhaus request failed: {e}")
    log.info(f"  Got {len(items)} URLs from URLhaus")
    return items

# ── Spamhaus DROP Fetcher (keyless) ──────────────────────────────────────────

def fetch_spamhaus_drop() -> list[dict]:
    log.info("Fetching Spamhaus DROP list...")
    items = []
    text = make_request_text("https://www.spamhaus.org/drop/drop.txt")
    if not text:
        return items
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith(";") or ";" not in line:
            continue
        parts = line.split(";", 1)
        cidr = parts[0].strip()
        description = parts[1].strip() if len(parts) > 1 else "Spamhaus DROP"
        if not cidr:
            continue
        items.append({
            "title": f"Spamhaus DROP: {cidr}",
            "description": f"Malicious IP range: {cidr} — {description[:200]}",
            "url": "https://www.spamhaus.org/drop/", "cve_id": None,
            "source": "Spamhaus", "category": "advisory", "severity": "medium",
            "cvss_score": None, "published": now_utc(),
            "iocs": {"cidr": [cidr]},
        })
        if len(items) >= MAX_ITEMS_PER_SOURCE:
            break
    log.info(f"  Got {len(items)} IP ranges from Spamhaus")
    return items

# ── Feodo Tracker Fetcher (keyless) ───────────────────────────────────────────

# ── AbuseIPDB Fetcher (API key) ──────────────────────────────────────────────

def fetch_abuseipdb() -> list[dict]:
    if not ABUSEIPDB_KEY:
        raise SourceDisabled("needs ABUSEIPDB_API_KEY")
    log.info("Fetching AbuseIPDB blacklist...")
    items = []
    data = make_request(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={**HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"confidenceMinimum": 90, "limit": MAX_ITEMS_PER_SOURCE}
    )
    if not data:
        return items
    for entry in data.get("data", []):
        ip = entry.get("ipAddress", "")
        confidence = entry.get("abuseConfidenceScore", 0)
        country = entry.get("countryCode", "")
        domain = entry.get("domain", "")
        desc_parts = [f"IP: {ip}", f"Confidence: {confidence}%"]
        if country:
            desc_parts.append(f"Country: {country}")
        if domain:
            desc_parts.append(f"Domain: {domain}")
        items.append({
            "title": f"AbuseIPDB: {ip} ({confidence}% confidence)",
            "description": " | ".join(desc_parts),
            "url": f"https://www.abuseipdb.com/check/{ip}",
            "cve_id": None, "source": "AbuseIPDB", "category": "incident",
            "severity": "high" if confidence >= 90 else "medium",
            "cvss_score": None, "published": now_utc(),
            "iocs": {"ipv4": [ip]},
        })
    log.info(f"  Got {len(items)} IPs from AbuseIPDB")
    return items

# ── PhishTank Fetcher (API key) ──────────────────────────────────────────────

def fetch_phishtank() -> list[dict]:
    if not PHISHTANK_KEY:
        raise SourceDisabled("needs PHISHTANK_API_KEY")
    log.info("Fetching PhishTank phishing URLs...")
    items = []
    data = make_request(f"http://data.phishtank.com/data/{PHISHTANK_KEY}/online-valid.json")
    if not data:
        return items
    for entry in data[:MAX_ITEMS_PER_SOURCE]:
        phish_url = entry.get("url", "")
        phish_detail = entry.get("phish_detail_url", "")
        target = entry.get("target", "")
        verified = entry.get("verified", False)
        submission_time = entry.get("submission_time", "")
        description = f"Phishing URL: {phish_url[:200]}"
        if target:
            description += f" | Target: {target}"
        description += f" | Verified: {verified}"
        items.append({
            "title": f"PhishTank: {target or 'phishing'} page at {phish_url[:60]}...",
            "description": description,
            "url": phish_detail or phish_url, "cve_id": None,
            "source": "PhishTank", "category": "incident", "severity": "medium",
            "cvss_score": None, "published": parse_date(submission_time),
            "iocs": {"url": [phish_url]},
        })
    log.info(f"  Got {len(items)} phishing URLs from PhishTank")
    return items

# ── MalwareBazaar Fetcher (keyless) ──────────────────────────────────────────

def fetch_malwarebazaar() -> list[dict]:
    if not MB_API_KEY:
        raise SourceDisabled("needs ABUSECH_AUTH_KEY")
    log.info("Fetching MalwareBazaar recent samples...")
    items = []
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            headers={**HEADERS, "Auth-Key": MB_API_KEY}, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", [])[:MAX_ITEMS_PER_SOURCE]:
            sha256 = entry.get("sha256_hash", "")
            md5 = entry.get("md5_hash", "")
            file_name = entry.get("file_name", "unknown")
            file_type = entry.get("file_type", "")
            signature = entry.get("signature", "")
            first_seen = entry.get("first_seen", "")
            tags = entry.get("tags", [])
            tag_str = ", ".join(tags[:5]) if tags else ""
            desc = f"SHA256: {sha256[:20]}... | MD5: {md5} | Type: {file_type} | Tags: {tag_str}"
            if signature:
                desc += f" | Malware: {signature}"
            items.append({
                "title": f"MalwareBazaar: {file_name} ({signature or file_type})",
                "description": desc,
                "url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                "cve_id": None, "source": "MalwareBazaar",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(first_seen),
                "iocs": {"sha256": [sha256], "md5": [md5]} if md5 else {"sha256": [sha256]},
            })
    except Exception as e:
        log.warning(f"MalwareBazaar failed: {e}")
    log.info(f"  Got {len(items)} samples from MalwareBazaar")
    return items

# ── ThreatFox Fetcher (keyless) ──────────────────────────────────────────────

# ThreatFox states the indicator type explicitly. The previous code ignored
# that field and re-derived the type from the string's shape, which was both
# redundant and wrong: the IPv4 branch required a ":port" suffix, so a bare
# address fell through to the domain branch and was published as a *domain*,
# and hashes matched no branch at all.
_THREATFOX_TYPE_MAP = {
    "ip:port": "ipv4", "ip": "ipv4",
    "domain": "domain", "url": "url", "email": "email",
    "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256",
}


def _threatfox_ioc(ioc: str, ioc_type: str) -> dict[str, list[str]]:
    """Bucket one ThreatFox indicator using the type the API reports."""
    kind = _THREATFOX_TYPE_MAP.get((ioc_type or "").strip().lower())
    if not kind or not ioc:
        # Unknown type: fall back to the shared extractor rather than guessing.
        return extract_iocs(ioc, source="ThreatFox")
    value = ioc.rsplit(":", 1)[0] if kind == "ipv4" and ioc.count(":") == 1 else ioc
    return {kind: [value.lower() if kind in ("domain", "email") else value]}


def fetch_sslbl() -> list[dict]:
    """abuse.ch SSL Certificate Blacklist: SHA1 fingerprints of certs seen on
    malware C2 infrastructure. Listed in awesome-threat-intelligence; free, no
    key. The listing reason names the malware family, which is what makes these
    worth carrying alongside the IOC itself."""
    log.info("Fetching abuse.ch SSL Blacklist...")
    items = []
    try:
        resp = _SESSION.get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        rows = [ln for ln in resp.text.splitlines()
                if ln and not ln.startswith("#")]
        # The file is newest-first, so the head is the most recent listings.
        for line in rows[:MAX_ITEMS_PER_SOURCE]:
            parts = line.split(",")
            if len(parts) < 3:
                continue
            listed, sha1, reason = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if len(sha1) != 40:
                continue
            items.append({
                "title": f"SSLBL: {reason} certificate",
                "description": (f"abuse.ch listed an SSL certificate used by "
                                f"{reason} infrastructure. SHA1: {sha1}"),
                "url": f"https://sslbl.abuse.ch/ssl-certificates/sha1/{sha1}/",
                "cve_id": None, "source": "SSL Blacklist",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(listed),
                "iocs": {"sha1": [sha1]},
            })
    except Exception as e:
        log.warning(f"SSL Blacklist failed: {e}")
    log.info(f"  Got {len(items)} certificates from SSL Blacklist")
    return items


def fetch_threatfox() -> list[dict]:
    if not THREATFOX_API_KEY:
        raise SourceDisabled("needs ABUSECH_AUTH_KEY")
    log.info("Fetching ThreatFox recent IOCs...")
    items = []
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "recent", "limit": MAX_ITEMS_PER_SOURCE},
            headers={**HEADERS, "Auth-Key": THREATFOX_API_KEY}, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", [])[:MAX_ITEMS_PER_SOURCE]:
            ioc = entry.get("ioc", "")
            ioc_type = entry.get("ioc_type", "")
            malware = entry.get("malware", "")
            threat = entry.get("threat_type", "")
            first_seen = entry.get("first_seen", "")
            reference = entry.get("reference", "")
            malware_printable = entry.get("malware_printable", "")
            desc = f"IOC: {ioc} | Type: {malware_printable or malware} | Threat: {threat}"
            iocs = _threatfox_ioc(ioc, ioc_type)
            items.append({
                "title": f"ThreatFox: {ioc[:60]} ({malware_printable or malware})",
                "description": desc,
                "url": reference or f"https://threatfox.abuse.ch/browse/{ioc}/",
                "cve_id": None, "source": "ThreatFox",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(first_seen),
                "iocs": iocs,
            })
    except Exception as e:
        log.warning(f"ThreatFox failed: {e}")
    log.info(f"  Got {len(items)} IOCs from ThreatFox")
    return items

# ── Generic RSS source fetcher ────────────────────────────────────────────────

_RSS_SOURCE_CONFIG: list[dict] = [
    {"name": "MSRC",          "url": "https://api.msrc.microsoft.com/update-guide/rss",                                   "severity": "high"},
    {"name": "Debian",        "url": "https://www.debian.org/security/dsa-long",                                          "severity": "medium"},
    {"name": "VMware",        "url": "https://www.broadcom.com/support/security/advisories/json",                         "severity": "high"},
]

def _fetch_rss_source(name: str, url: str, default_severity: str, extra_headers: dict | None = None) -> list[dict]:
    """Generic RSS feed parser. ``extra_headers`` override defaults for
    sources that need a different User-Agent (e.g. to bypass 403)."""
    hdrs = {**HEADERS, **(extra_headers or {})}
    try:
        resp = requests.get(url, headers=hdrs, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        items = []
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", f"{name} Advisory")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            # Some feeds (Debian's RDF among them) date entries with dc:date,
            # which feedparser exposes as `updated`. Without the fallback
            # parse_date() answers "now", so every item looks brand new on
            # every run and the staleness check can never fire.
            pub = entry_date(entry) or now_utc()
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc),
                "source": name, "category": "advisory",
                "severity": infer_severity(title, default_severity),
                "cvss_score": None, "published": pub,
            })
        return items
    except Exception as e:
        log.warning(f"{name} failed: {e}")
        return []

# ── MSRC Fetcher (RSS) ───────────────────────────────────────────────────────

def fetch_msrc() -> list[dict]:
    return _fetch_rss_source("MSRC", "https://api.msrc.microsoft.com/update-guide/rss", "high")

# ── Fedora Bodhi Fetcher ────────────────────────────────────────────────────

def fetch_fedora() -> list[dict]:
    log.info("Fetching Fedora updates...")
    items = []
    try:
        data = make_request("https://bodhi.fedoraproject.org/updates/?limit=10&status=stable&type=security")
        if data:
            for update in data.get("updates", [])[:MAX_ITEMS_PER_SOURCE]:
                update_id = update.get("updateid") or update.get("alias") or ""
                title = update.get("title", update_id or "Fedora Update")
                # title is space-separated build names; show first build + ID
                first_build = title.split(" ")[0] if " " in title else title
                desc = update.get("notes", "")[:400]
                pub = parse_date(update.get("date_submitted", ""))
                items.append({
                    "title": f"Fedora: {first_build[:80]} ({update_id})",
                    "description": clean_html(desc) or "Fedora security update",
                    "url": update.get("url") or f"https://bodhi.fedoraproject.org/updates/{update_id}",
                    "cve_id": extract_cve_id(title + " " + desc), "source": "Fedora",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                })
    except Exception as e:
        log.warning(f"Fedora Bodhi failed: {e}")

    # Fallback: Bodhi is behind Anubis PoW and may block us at any time.
    # The HyperKitty package-announce list still ships plain RSS.
    if not items:
        log.info("  Bodhi returned nothing — falling back to package-announce RSS")
        fallback = _fetch_rss_source(
            "Fedora",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/feed/",
            "medium",
        )
        # Prefer security-looking entries; take the rest only if needed.
        sec = [i for i in fallback if "security" in (i["title"] + i["description"]).lower()
               or i.get("cve_id")]
        items = (sec + [i for i in fallback if i not in sec])[:MAX_ITEMS_PER_SOURCE]

    log.info(f"  Got {len(items)} from Fedora")
    return items

# ── Arch Linux Security Fetcher ─────────────────────────────────────────────

def fetch_archlinux() -> list[dict]:
    log.info("Fetching Arch Linux issues...")
    items = []
    try:
        data = make_request("https://security.archlinux.org/issues.json")
        if data:
            for issue in data[:MAX_ITEMS_PER_SOURCE]:
                title = issue.get("title", issue.get("id", "Arch Issue"))
                cve = issue.get("cve", [])
                cve_id = cve[0] if cve else None
                pub = parse_date(issue.get("created_at", ""))
                items.append({
                    "title": f"Arch Linux: {title[:120]}",
                    "description": f"Type: {issue.get('issue_type','')} | Severity: {issue.get('severity','')} | Package: {issue.get('package','')}",
                    "url": f"https://security.archlinux.org/{issue.get('id','')}",
                    "cve_id": valid_cve_id(cve_id), "source": "Arch Linux",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                })
    except Exception as e:
        log.warning(f"Arch Linux failed: {e}")
    log.info(f"  Got {len(items)} from Arch Linux")
    return items

# ── Amazon Linux Fetcher ───────────────────────────────────────────────────

def fetch_amazon_linux() -> list[dict]:
    log.info("Fetching Amazon Linux advisories...")
    items = []
    try:
        for feed_url in ["https://alas.aws.amazon.com/alas.rss",
                         "https://alas.aws.amazon.com/AL2/alas.rss",
                         "https://alas.aws.amazon.com/AL2023/alas.rss"]:
            try:
                resp = requests.get(feed_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)
                for entry in feed.entries[:MAX_ITEMS_PER_SOURCE // 2]:
                    title = entry.get("title", "Amazon Linux Advisory")
                    link = entry.get("link", "")
                    desc = clean_html(entry.get("summary", ""))[:400]
                    pub = parse_date(entry.get("published_parsed"))
                    items.append({
                        "title": title, "description": desc, "url": link,
                        "cve_id": extract_cve_id(title + " " + desc), "source": "Amazon Linux",
                        "category": "advisory", "severity": infer_severity(title, "medium"),
                        "cvss_score": None, "published": pub,
                    })
            except Exception:
                continue  # try next Amazon Linux feed version
    except Exception as e:
        log.warning(f"Amazon Linux failed: {e}")
    log.info(f"  Got {len(items)} from Amazon Linux")
    return items

# ── CentOS Announce Fetcher ────────────────────────────────────────────────

# Three sources were replaced here, each for a different kind of death:
#   CentOS Stream blog - alive but silent (median item 332 days old); Debian's
#                        advisory feed fills the same role and posts daily.
#   Mitre CWE          - the endpoint 404'd, and when it worked it listed the
#                        first ten weaknesses of a static catalogue stamped
#                        with today's date. That was never news.
#   Feodo Tracker      - five C2 hosts, last seen eight months ago. The
#                        botnets it tracked were taken down.
# Cisco and Palo Alto publish advisories for exactly the edge devices that
# dominate CISA KEV, which is what this feed is for.

def fetch_debian() -> list[dict]:
    return _fetch_rss_source("Debian", "https://www.debian.org/security/dsa-long", "medium")

def fetch_cisco() -> list[dict]:
    return _fetch_rss_source(
        "Cisco PSIRT",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "high")

def fetch_paloalto() -> list[dict]:
    return _fetch_rss_source("Palo Alto Networks",
                             "https://security.paloaltonetworks.com/rss.xml", "high")

# ── VMware / Broadcom Security Fetcher ────────────────────────────────────

def fetch_vmware() -> list[dict]:
    log.info("Fetching Broadcom (VMware) security advisories...")
    items = []
    try:
        resp = requests.post(
            "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList",
            json={"pageNumber": 0, "pageSize": MAX_ITEMS_PER_SOURCE, "searchVal": "",
                  "segment": "VC", "sortInfo": {"column": "", "order": ""}},
            headers={**HEADERS, "accept": "application/json", "content-type": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        for adv in (data.get("data", {}).get("list", []) if isinstance(data, dict) else data)[:MAX_ITEMS_PER_SOURCE]:
            title = adv.get("title", adv.get("name", "VMware Advisory"))
            desc = adv.get("description", adv.get("synopsis", ""))[:400]
            cve_id = extract_cve_id(title + " " + desc)
            pub = parse_date(adv.get("publishedDate", adv.get("releaseDate", "")))
            items.append({
                "title": f"VMware: {title[:150]}",
                "description": desc,
                "url": adv.get("url", adv.get("link", "https://support.broadcom.com/web/ecx/security-advisory?segment=VC")),
                "cve_id": valid_cve_id(cve_id), "source": "VMware",
                "category": "advisory", "severity": infer_severity(title, "high"),
                "cvss_score": None, "published": pub,
            })
    except Exception as e:
        log.warning(f"VMware failed: {e}")
    log.info(f"  Got {len(items)} from VMware")
    return items

# ── GitHub Security Advisories (GHSA) Fetcher ────────────────────────────────

def fetch_ghsa() -> list[dict]:
    """GitHub's global advisory database — best-in-class OSS vuln coverage.
    Keyless (60 req/h) or authenticated via GITHUB_TOKEN (5000 req/h)."""
    log.info("Fetching GitHub Security Advisories...")
    items = []
    headers = {**HEADERS, "Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        resp = requests.get(
            "https://api.github.com/advisories",
            params={"per_page": MAX_ITEMS_PER_SOURCE, "sort": "published", "direction": "desc"},
            headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for adv in resp.json()[:MAX_ITEMS_PER_SOURCE]:
            summary = adv.get("summary", "GitHub Advisory")
            desc = clean_html(adv.get("description", ""))[:400]
            sev = (adv.get("severity") or "medium").lower()
            if sev == "moderate":
                sev = "medium"
            cvss = (adv.get("cvss") or {}).get("score")
            # Affected packages → stack-profile matching signal.
            packages = []
            for v in adv.get("vulnerabilities", []) or []:
                pkg = (v.get("package") or {})
                if pkg.get("name"):
                    packages.append(f"{pkg.get('ecosystem', '')}/{pkg['name']}".strip("/"))
            items.append({
                "title": f"GHSA: {summary[:150]}",
                "description": desc or summary,
                "url": adv.get("html_url", ""),
                "cve_id": valid_cve_id(adv.get("cve_id")),
                "source": "GitHub Advisories", "category": "cve",
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "cvss_score": cvss,
                "published": parse_date(adv.get("published_at", "")),
                "affected_products": packages[:8],
            })
    except Exception as e:
        log.warning(f"GHSA failed: {e}")
    log.info(f"  Got {len(items)} from GitHub Advisories")
    return items

# ── PoC-in-GitHub Fetcher ─────────────────────────────────────────────────────
# nomi-sec/PoC-in-GitHub tracks public exploit PoCs. The motikan2010 API serves
# it as JSON. Used two ways: (1) recent PoC drops as feed items, (2) a CVE→PoC
# map that feeds the exploitability score (has_poc flag).

def _fetch_recent_pocs() -> list[dict]:
    cached = _cached_fetch("pocs.json", 6, _fetch_pocs_raw)
    if not cached:
        return []
    try:
        return json.loads(cached)
    except Exception:
        return []

def _fetch_pocs_raw() -> tuple[str | None, str | None]:
    try:
        resp = requests.get(
            "https://poc-in-github.motikan2010.net/api/v1/",
            params={"sort": "created_at", "limit": 100},
            headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return json.dumps(resp.json().get("pocs", [])), None
    except Exception as e:
        return None, str(e)

def build_poc_map() -> dict[str, str]:
    """CVE ID → PoC repo URL for recently-published public exploits."""
    poc_map = {}
    for poc in _fetch_recent_pocs():
        cve = (poc.get("cve_id") or "").upper()
        if cve.startswith("CVE-") and cve not in poc_map:
            poc_map[cve] = poc.get("html_url", "")
    return poc_map

def fetch_poc_github() -> list[dict]:
    log.info("Fetching PoC-in-GitHub recent exploits...")
    items = []
    for poc in _fetch_recent_pocs()[:MAX_ITEMS_PER_SOURCE]:
        cve = (poc.get("cve_id") or "").upper()
        name = poc.get("name", cve or "PoC")
        desc = (poc.get("description") or poc.get("vuln_description") or "")[:400]
        stars = poc.get("stargazers_count", "0")
        items.append({
            "title": f"PoC released: {cve or name}",
            "description": desc or f"Public proof-of-concept exploit published on GitHub ({stars}★).",
            "url": poc.get("html_url", ""),
            "cve_id": valid_cve_id(cve),
            "source": "PoC-in-GitHub", "category": "cve", "severity": "high",
            "cvss_score": None,
            "published": parse_date((poc.get("created_at") or "").replace(" ", "T")),
            "iocs": {},
            "has_poc": True,
        })
    log.info(f"  Got {len(items)} from PoC-in-GitHub")
    return items

# ── Zero Day Initiative (ZDI) Fetcher ─────────────────────────────────────────

def fetch_zdi() -> list[dict]:
    """ZDI advisories — often ahead of vendor announcements. Two feeds:
    published advisories and upcoming (unpatched, high-signal)."""
    items = []
    for feed_name, url in [("published", "https://www.zerodayinitiative.com/rss/published/"),
                           ("upcoming",  "https://www.zerodayinitiative.com/rss/upcoming/")]:
        got = _fetch_rss_source("ZDI", url, "high")
        for item in got[:MAX_ITEMS_PER_SOURCE // 2]:
            if feed_name == "upcoming":
                item["title"] = f"[0-day queue] {item['title']}"
            item["category"] = "cve"
            items.append(item)
    log.info(f"  Got {len(items)} from ZDI")
    return items

# ── Ransomware.live Fetcher ───────────────────────────────────────────────────

def fetch_ransomware_live() -> list[dict]:
    log.info("Fetching Ransomware.live recent victims...")
    items = []
    try:
        resp = requests.get("https://api.ransomware.live/v2/recentvictims",
                            headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for victim in resp.json()[:MAX_ITEMS_PER_SOURCE]:
            group = victim.get("group_name", victim.get("group", "unknown group"))
            name = victim.get("victim", victim.get("post_title", "Unknown victim"))
            country = victim.get("country", "")
            activity = victim.get("activity", "")
            desc_parts = [f"Ransomware group '{group}' claimed victim: {name}."]
            if country:
                desc_parts.append(f"Country: {country}.")
            if activity and activity != "Not Found":
                desc_parts.append(f"Sector: {activity}.")
            when = victim.get("attackdate", victim.get("discovered", ""))
            items.append({
                "title": f"Ransomware: {group} claims {name[:80]}",
                "description": " ".join(desc_parts),
                "url": victim.get("url") or f"https://www.ransomware.live/group/{group}",
                "cve_id": None, "source": "Ransomware.live",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(when),
                "iocs": {},
                "threat_actors_hint": [group] if group else [],
                "sector_hint": activity if activity and activity != "Not Found" else None,
            })
    except Exception as e:
        log.warning(f"Ransomware.live failed: {e}")
    log.info(f"  Got {len(items)} from Ransomware.live")
    return items


# ── Source orchestration ──────────────────────────────────────────────────────

# Non-RSS fetchers, run in order. Each entry is (display-name, callable).
API_SOURCES = [
    ("NVD",            fetch_nvd_cves),
    ("Reddit/netsec",  fetch_reddit_netsec),
    ("Hacker News",    fetch_hacker_news),
    ("CERT-In",        fetch_cert_in),
    ("AlienVault OTX", fetch_otx_pulse),
    ("URLhaus",        fetch_urlhaus),
    ("Spamhaus",       fetch_spamhaus_drop),
    ("Palo Alto Networks", fetch_paloalto),
    ("AbuseIPDB",      fetch_abuseipdb),
    ("PhishTank",      fetch_phishtank),
    ("MalwareBazaar",  fetch_malwarebazaar),
    ("ThreatFox",      fetch_threatfox),
    ("SSL Blacklist",  fetch_sslbl),
    ("MSRC",           fetch_msrc),
    ("Fedora",         fetch_fedora),
    ("Arch Linux",     fetch_archlinux),
    ("Amazon Linux",   fetch_amazon_linux),
    ("Debian",         fetch_debian),
    ("Cisco PSIRT",    fetch_cisco),
    ("VMware",         fetch_vmware),
    ("GitHub Advisories", fetch_ghsa),
    ("PoC-in-GitHub",  fetch_poc_github),
    ("ZDI",            fetch_zdi),
    ("Ransomware.live", fetch_ransomware_live),
]

if fetch_leak_site_posts:
    API_SOURCES.append(("RansomLook", fetch_leak_site_posts))

def _median_age_days(items: list[dict]) -> float | None:
    """Median age of an item batch, in days. None when nothing parses."""
    now = datetime.now(timezone.utc)
    ages = []
    for item in items:
        raw = item.get("published")
        if not raw:
            continue
        try:
            published = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        ages.append((now - published).total_seconds() / 86400.0)
    if not ages:
        return None
    ages.sort()
    mid = len(ages) // 2
    return round(ages[mid] if len(ages) % 2 else (ages[mid - 1] + ages[mid]) / 2, 1)


def stale_after_days(name: str) -> int:
    """How old a source's median item may be before it is reported stale."""
    if any(s["name"] == name and s.get("cadence") == "slow" for s in RSS_SOURCES):
        return CONFIG.source_slow_stale_days
    return CONFIG.source_stale_days


def run_source(name: str, fetcher, health: dict) -> list[dict]:
    """
    Invoke a single fetcher, capturing timing + outcome into ``health`` so a
    silently-dead feed becomes visible in the output instead of just vanishing.
    Never raises — a broken source can't abort the run.

    Health is FRESHNESS-aware, not just count-aware. The previous version set
    `ok` whenever a fetcher returned anything, so Threatpost — shut down in
    2023, still serving its 2022 archive — reported green every single hour.
    A feed whose median item is older than CONFIG.source_stale_days is `stale`.
    """
    started = time.monotonic()
    try:
        items = fetcher() or []
        elapsed = round(time.monotonic() - started, 2)
        median_age = _median_age_days(items)
        if not items:
            status = "empty"
        elif median_age is not None and median_age > stale_after_days(name):
            status = "stale"
            log.warning(f"Source '{name}' is STALE — median item age {median_age:.0f} days")
        else:
            status = "ok"
        health[name] = {"status": status, "count": len(items), "elapsed_s": elapsed,
                        "median_age_days": median_age, "error": None}
        return items
    except SourceDisabled as e:
        log.info(f"Source '{name}' is switched off: {e}")
        health[name] = {"status": "disabled", "count": 0, "elapsed_s": 0.0,
                        "median_age_days": None, "error": str(e)[:200]}
        return []
    except Exception as e:
        elapsed = round(time.monotonic() - started, 2)
        log.error(f"Source '{name}' failed: {e}")
        health[name] = {"status": "error", "count": 0, "elapsed_s": elapsed,
                        "median_age_days": None, "error": str(e)[:200]}
        return []
