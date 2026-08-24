"""
CYBERWATCH — geoip.py
=====================
Offline IP → country lookup, for the attacker map.

Uses the DB-IP Country Lite database (CC BY 4.0, no key), which ships the whole
world as one CSV of ``start_ip,end_ip,country_code`` rows. We download that file
on a slow cadence and look everything up locally — the exact same shape as the
EPSS corpus in fetch_intel.py, and for the same reason: the attacker feeds carry
hundreds of thousands of IPs per run, so a per-address API would be rate-limited
into uselessness. One monthly file, binary-searched in memory, has no such cap
and works offline.

Attribution obligation: DB-IP Country Lite is CC BY 4.0. "IP Geolocation by
DB-IP (https://db-ip.com)" must appear wherever the data is surfaced.

Usage:
    from geoip import GeoIP
    geo = GeoIP.load()           # downloads/caches the DB, builds the index
    geo.country("8.8.8.8")       # -> "US"  (or None if unknown/private)
    geo.country_name("US")       # -> "United States"
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import time
from datetime import datetime, timezone

from config import CONFIG

try:
    # Reuse the pipeline's pooled, retrying session when imported alongside it.
    from fetch_intel import _SESSION, _cached_fetch, log
except Exception:  # pragma: no cover - standalone use (tests, CLI)
    import logging
    import requests
    log = logging.getLogger("cyberwatch.geoip")
    _SESSION = requests.Session()
    _cached_fetch = None


# DB-IP publishes one file per month at a predictable URL. The current month can
# lag by a day or two around the turn of the month, so we fall back to the
# previous month rather than failing.
_DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"

# Minimal ISO-3166 alpha-2 → name map, covering what the country list on the map
# actually needs. Unknown codes fall through to the code itself.
_COUNTRY_NAMES = {
    "US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
    "NL": "Netherlands", "FR": "France", "GB": "United Kingdom", "IN": "India",
    "BR": "Brazil", "KR": "South Korea", "JP": "Japan", "VN": "Vietnam",
    "ID": "Indonesia", "IR": "Iran", "UA": "Ukraine", "SG": "Singapore",
    "CA": "Canada", "TW": "Taiwan", "TR": "Turkey", "IT": "Italy",
    "ES": "Spain", "PL": "Poland", "TH": "Thailand", "HK": "Hong Kong",
    "RO": "Romania", "MX": "Mexico", "AU": "Australia", "PH": "Philippines",
    "SE": "Sweden", "BG": "Bulgaria", "AR": "Argentina", "ZA": "South Africa",
    "CO": "Colombia", "PK": "Pakistan", "BD": "Bangladesh", "EG": "Egypt",
    "MY": "Malaysia", "NG": "Nigeria", "IL": "Israel", "CZ": "Czechia",
    "FI": "Finland", "CH": "Switzerland", "AT": "Austria", "BE": "Belgium",
    "DK": "Denmark", "NO": "Norway", "IE": "Ireland", "PT": "Portugal",
    "GR": "Greece", "HU": "Hungary", "KZ": "Kazakhstan", "SA": "Saudi Arabia",
    "AE": "United Arab Emirates", "CL": "Chile", "PE": "Peru", "VE": "Venezuela",
    "MA": "Morocco", "KE": "Kenya", "LT": "Lithuania", "LV": "Latvia",
    "EE": "Estonia", "RS": "Serbia", "SK": "Slovakia", "SI": "Slovenia",
    "HR": "Croatia", "MD": "Moldova", "BY": "Belarus", "GE": "Georgia",
    "AM": "Armenia", "AZ": "Azerbaijan", "UZ": "Uzbekistan", "LK": "Sri Lanka",
    "NP": "Nepal", "MM": "Myanmar", "KH": "Cambodia", "LA": "Laos",
    "EC": "Ecuador", "BO": "Bolivia", "PY": "Paraguay", "UY": "Uruguay",
    "DO": "Dominican Republic", "GT": "Guatemala", "CR": "Costa Rica",
    "PA": "Panama", "IQ": "Iraq", "JO": "Jordan", "LB": "Lebanon",
    "KW": "Kuwait", "QA": "Qatar", "OM": "Oman", "BH": "Bahrain",
    "TN": "Tunisia", "DZ": "Algeria", "LY": "Libya", "SD": "Sudan",
    "ET": "Ethiopia", "TZ": "Tanzania", "UG": "Uganda", "GH": "Ghana",
    "CI": "Côte d'Ivoire", "CM": "Cameroon", "AO": "Angola", "MZ": "Mozambique",
    "ZM": "Zambia", "ZW": "Zimbabwe", "MG": "Madagascar", "LU": "Luxembourg",
    "IS": "Iceland", "MT": "Malta", "CY": "Cyprus", "MK": "North Macedonia",
    "AL": "Albania", "BA": "Bosnia and Herzegovina", "ME": "Montenegro",
    "XK": "Kosovo", "MN": "Mongolia", "BN": "Brunei", "TL": "Timor-Leste",
    "FJ": "Fiji", "PG": "Papua New Guinea", "NZ": "New Zealand",
}


def _current_month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _previous_month() -> str:
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month - 1
    if month == 0:
        year, month = year - 1, 12
    return f"{year:04d}-{month:02d}"


class GeoIP:
    """In-memory IP → country index, built from the DB-IP Country Lite CSV.

    Ranges are stored as two parallel structures — one for IPv4, one for IPv6 —
    each a list of (start_int, end_int, country_code) sorted by start, plus a
    separate list of just the start ints so ``bisect`` can find the candidate
    range in O(log n). The attacker feeds are ~99% IPv4, but v6 is handled the
    same way rather than dropped.
    """

    def __init__(self, v4: list[tuple[int, int, str]],
                 v6: list[tuple[int, int, str]]):
        self._v4 = v4
        self._v4_starts = [r[0] for r in v4]
        self._v6 = v6
        self._v6_starts = [r[0] for r in v6]

    # ── construction ────────────────────────────────────────────────────────
    @classmethod
    def load(cls) -> "GeoIP | None":
        """Download (or reuse the cached) DB and build the index. Returns None
        if the database could not be obtained, so the caller degrades to
        "country unknown" rather than crashing the run."""
        csv_text = cls._fetch_csv()
        if not csv_text:
            log.warning("GeoIP: no database available; countries will be unknown")
            return None
        v4, v6 = cls._parse(csv_text)
        if not v4 and not v6:
            log.warning("GeoIP: database parsed to zero ranges")
            return None
        log.info(f"GeoIP: indexed {len(v4)} IPv4 + {len(v6)} IPv6 ranges")
        return cls(v4, v6)

    @classmethod
    def _fetch_csv(cls) -> str | None:
        # 30-day TTL: the file is monthly, so anything fresher is wasted work.
        ttl = CONFIG.geoip_ttl_hours
        if _cached_fetch is not None:
            return _cached_fetch("dbip_country.csv", ttl, cls._download_raw)
        # Standalone fallback (no pipeline cache helper available).
        content, _ = cls._download_raw()
        return content

    @classmethod
    def _download_raw(cls) -> tuple[str | None, str | None]:
        last = None
        for month in (_current_month(), _previous_month()):
            url = _DBIP_URL.format(month=month)
            try:
                resp = _SESSION.get(url, timeout=CONFIG.request_timeout)
                resp.raise_for_status()
                text = gzip.decompress(resp.content).decode("utf-8", "replace")
                if text.strip():
                    return text, None
            except Exception as e:
                last = f"{url}: {e}"
                continue
        return None, last or "all DB-IP endpoints failed"

    @staticmethod
    def _parse(csv_text: str) -> tuple[list, list]:
        v4: list[tuple[int, int, str]] = []
        v6: list[tuple[int, int, str]] = []
        for line in csv_text.splitlines():
            parts = line.split(",")
            if len(parts) != 3:
                continue
            start_s, end_s, cc = parts[0].strip(), parts[1].strip(), parts[2].strip().upper()
            if not cc or cc == "ZZ":          # ZZ = unknown/reserved in DB-IP
                continue
            try:
                start = ipaddress.ip_address(start_s)
                end = ipaddress.ip_address(end_s)
            except ValueError:
                continue
            if start.version == 4:
                v4.append((int(start), int(end), cc))
            else:
                v6.append((int(start), int(end), cc))
        v4.sort(key=lambda r: r[0])
        v6.sort(key=lambda r: r[0])
        return v4, v6

    # ── lookup ──────────────────────────────────────────────────────────────
    def country(self, ip: str) -> str | None:
        """ISO alpha-2 country code for an IP, or None if unknown or private."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
            return None
        n = int(addr)
        if addr.version == 4:
            ranges, starts = self._v4, self._v4_starts
        else:
            ranges, starts = self._v6, self._v6_starts
        # bisect_right - 1 gives the last range whose start <= n; then confirm n
        # actually falls inside that range (gaps between ranges are possible).
        i = bisect.bisect_right(starts, n) - 1
        if i < 0:
            return None
        start, end, cc = ranges[i]
        return cc if start <= n <= end else None

    @staticmethod
    def country_name(code: str | None) -> str:
        if not code:
            return "Unknown"
        return _COUNTRY_NAMES.get(code.upper(), code.upper())


if __name__ == "__main__":
    # Smoke test / manual check.
    import sys
    t0 = time.time()
    geo = GeoIP.load()
    if geo is None:
        print("GeoIP database unavailable")
        sys.exit(1)
    print(f"loaded in {time.time() - t0:.1f}s")
    for ip in sys.argv[1:] or ["8.8.8.8", "1.1.1.1", "77.88.8.8", "192.168.1.1"]:
        cc = geo.country(ip)
        print(f"  {ip:20} -> {cc or '??'}  {GeoIP.country_name(cc)}")
