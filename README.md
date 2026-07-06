# CyberWatch

A free, cybersecurity threat intelligence dashboard that aggregates CVEs, 
advisories, incidents, and news from multiple sources into a single clean
interface. Updates itself every day via GitHub Actions.

---

## 📡 Data Sources

| Source | Type | API Key? |
|---|---|---|
| NVD (NIST) | Latest CVEs | No |
| CISA Alerts | US Gov Advisories | No |
| The Hacker News | Cybersecurity News | No |
| Bleeping Computer | Incidents & Breaches | No |
| Krebs on Security | Investigative News | No |
| SANS ISC | Threat Diaries | No |
| Reddit r/netsec | Community Intel | No |
| AlienVault OTX | Threat Pulses | Yes |
| TheRecord Media | New | No |

---

## 📁 Project Structure

```
.
├── .github/
│   └── workflows/
│       └── update.yml          ← GitHub Actions: runs daily at 06:00 UTC
├── scripts/
│   ├── fetch_intel.py          ← Fetches all sources → data/intel.json
│   └── mitre_ttps.py           ← Full MITRE ATT&CK database (504 entries)
├── data/
│   └── intel.json              ← Auto-generated daily (committed by bot)
├── index.html                  ← Dashboard UI
├── style.css                   ← Dark terminal theme
├── app.js                      ← Renders feed, matrix, search/filter
└── README.md
```

## 🔧 Customization

**Add a new RSS source:** Edit `RSS_SOURCES` in `scripts/fetch_intel.py`

```python
{
    "name":     "Dark Reading",
    "url":      "https://www.darkreading.com/rss.xml",
    "category": "news",
    "severity": "medium",
},
```

**Change update schedule:** Edit the cron in `.github/workflows/update.yml`

```yaml
- cron: '0 6 * * *'   # 06:00 UTC daily
- cron: '0 */6 * * *' # every 6 hours
- cron: '0 6 * * 1'   # every Monday
```

🗺️ MITRE ATT&CK Coverage
The scripts/mitre_ttps.py module contains:

14 tactics (full Enterprise matrix)
191 parent techniques
313 sub-techniques
~2,800 keywords for automatic detection

Every article is scanned at fetch time. Matched techniques appear as
blue T#### pills on each card. Click any pill to filter the feed.
The ⬛ ATT&CK MATRIX tab shows a heatmap across all 14 tactics.

---

## 💡 Tips

- The dashboard works even if some sources fail — it uses whatever data was fetched
- The `data/intel.json` file is committed to the repo so GitHub Pages can serve it
- API keys are stored as GitHub Secrets — they are never visible in the repo
- All sources used are completely free with no rate limit issues at this scale

---
