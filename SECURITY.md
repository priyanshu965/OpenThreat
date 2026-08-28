# Security Policy

OpenThreat publishes vulnerability and breach information about other
organisations. Publishing a way to report a vulnerability *in OpenThreat* is
the other half of that.

## Reporting

**priyanshu@openthreat.in**, or a
[private security advisory](https://github.com/priyanshu965/OpenThreat/security/advisories/new)
on GitHub if you would rather it stay on-platform.

Please include what you did, what you expected, and what happened instead. A
proof of concept is welcome and never required.

You will get an acknowledgement. This is a one-person project, so "quickly" is
best effort rather than a commitment — say so in your report if you are working
to a disclosure deadline and I will tell you honestly whether I can meet it.

## Scope

**In scope**

- `openthreat.in` and everything it serves
- The published JSON API under `data/`
- The GitHub Actions pipeline in `scripts/` and `.github/workflows/`
- Anything in the published output that should not be there — see below

**Out of scope**

- The 43 upstream sources this project reads. Report those to their owners.
- Missing rate limits on third-party APIs the browser calls directly. Those
  requests come from the visitor's own browser and IP, by design.
- Reports that a published CVE, IOC or leak-site claim is inaccurate. That is
  upstream data, and it is labelled as such. Interesting, but not a
  vulnerability.

## What matters most here

This project has no server, no database and no user accounts, so the usual
web-application classes mostly do not apply. The failure modes that would
actually hurt are:

1. **Data that should not have been published.** The pipeline monitors the
   maintainer's own estate — credential exposure, subdomain inventory,
   attack surface — and that output is excluded from the public site by
   default (`PUBLISH_OWN_ESTATE=0`) and asserted out of the published state
   archive in CI. If you find any of it on the live site, that is the highest
   severity report this project can receive.
2. **Cross-site scripting.** Every string on screen came from one of 43
   third-party feeds, or from Telegram channels run by threat actors. The
   frontend builds nodes with `textContent`, CI rejects `innerHTML` and inline
   handlers outright, and the CSP has no `unsafe-inline`. A way around any of
   that is a real finding.
3. **A widened CSP or a leaked key.** No API key ever reaches the browser. CI
   fails if `connect-src` grows to reach a model API.
4. **Supply chain.** A dependency or GitHub Action that could alter what gets
   published.

## Safe harbour

Test against your own data. Do not access, modify or exfiltrate anyone else's,
do not degrade the service for others, and do not run automated scanning that
amounts to a denial of service against this site or its upstreams. Research
conducted in good faith under those limits is welcome, and I will not pursue
it.

## No bounty

There is no money. There is credit in the release notes if you want it, and a
genuine thank you either way.
