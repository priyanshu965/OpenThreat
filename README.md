# OpenThreat

A self-updating threat intelligence dashboard. Live at **[openthreat.in](https://openthreat.in/)**.

## What it is

OpenThreat collects CVEs, security advisories, incident reports and attack indicators from 138
public sources, scores each item on how likely it is to be exploited, and publishes the result as
a static website. It also links items to threat actors, malware and ATT&CK techniques, and ships
detection rules for them.

There is no server, database or backend. Everything is static files on GitHub Pages.

## How it works

Roughly every hour, a GitHub Actions job runs the Python pipeline in `scripts/`:

1. **Collect** — fetch the RSS and JSON feeds.
2. **Clean** — remove duplicates, keeping the most authoritative copy of each item.
3. **Enrich** — add EPSS, CISA KEV, SSVC, public-PoC and MITRE ATT&CK data.
4. **Score** — give each item a 0–100 priority and an action band (patch now, this week, next
   cycle, monitor).
5. **Publish** — write JSON into `data/` and deploy the site.

The site itself (`index.html`, `app.js`, `js/`) is plain JavaScript that reads those JSON files in
the browser. The Tools tab (passive recon, IOC lookup, password check) also runs entirely in the
browser, using public keyless services.

## Run it locally

```bash
pip install -r requirements.txt
python scripts/fetch_intel.py        # build the data
python -m http.server 8765           # then open http://localhost:8765
```

API keys are optional. Settings live in [`scripts/config.py`](scripts/config.py) and can be
overridden with environment variables.

```bash
python -m unittest discover -s tests   # run the tests
```

## More

- [docs/design-notes.md](docs/design-notes.md) — why each part works the way it does
- [docs/external-scheduler.md](docs/external-scheduler.md) — make the hourly run reliable
- [SECURITY.md](SECURITY.md) — how to report a vulnerability

MIT licensed. ATT&CK data © MITRE · malware families © [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) ·
detection rules © [SigmaHQ](https://github.com/SigmaHQ/sigma) · IP geolocation by
[DB-IP](https://db-ip.com) (CC BY 4.0)
