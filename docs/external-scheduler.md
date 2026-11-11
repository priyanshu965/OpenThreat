# A reliable hourly run

GitHub's `schedule` trigger is best-effort. On a busy day it starts runs late and drops some
entirely; this project has measured gaps of two to eleven hours. The workflow asks four times an
hour to soften that, but it cannot make GitHub fire.

What does work is starting the run from outside. `update.yml` accepts a manual dispatch, and a
dispatch is never dropped. Any service that can send one HTTP request an hour will do.

## 1. Create a token

GitHub → Settings → Developer settings → **Fine-grained personal access tokens** → Generate new.

- **Repository access:** only `priyanshu965/OpenThreat`
- **Permissions:** Actions → **Read and write**. Nothing else.
- **Expiration:** up to a year. Put the date in your calendar; the runs stop when it lapses.

The token can start workflows in this one repository and can do nothing else.

## 2. Schedule the request

With [cron-job.org](https://cron-job.org) (free), create a job:

| Field | Value |
|---|---|
| URL | `https://api.github.com/repos/priyanshu965/OpenThreat/actions/workflows/update.yml/dispatches` |
| Schedule | every hour, at a minute other than 0 (for example `17 * * * *`) |
| Method | `POST` |
| Header | `Authorization: Bearer <your token>` |
| Header | `Accept: application/vnd.github+json` |
| Header | `X-GitHub-Api-Version: 2022-11-28` |
| Body | `{"ref":"main"}` |

A `204 No Content` response means the run was queued. Turn on the service's failure notification
so an expired token is noticed.

To test it from a terminal first:

```bash
curl -i -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/priyanshu965/OpenThreat/actions/workflows/update.yml/dispatches \
  -d '{"ref":"main"}'
```

## 3. Nothing to change in the repository

The built-in schedule stays on as a fallback. Its attempts check how old the published feed is and
skip themselves when it is under 50 minutes (`UPDATE_MIN_INTERVAL_MINUTES`), so an external hourly
trigger and the internal schedule do not double up.
