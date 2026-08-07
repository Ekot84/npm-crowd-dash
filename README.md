# npm-crowd-dash

A small dashboard that shows CrowdSec bans (and AppSec/WAF blocks) — IP,
reason/scenario, source, country/AS, time issued, expiry — without having to
run `cscli decision list` or dig through the CrowdSec console.

Polls CrowdSec's own LAPI directly (`/v1/decisions/stream` + `/v1/alerts`),
keeps a local history in SQLite (CrowdSec forgets a decision once it
expires — this doesn't), and serves an auto-refreshing table via
FastAPI + HTMX (single container, no JS build step).

## 1. Create CrowdSec credentials

Run these **on the CrowdSec container** (e.g. `docker exec -it crowdsec cscli ...`):

```bash
# Bouncer key — read access to active decisions
cscli bouncers add dashboard-reader
# → copy the printed API key into CROWDSEC_BOUNCER_KEY

# Machine account — read access to alerts (scenario message, country/AS context)
cscli machines add dashboard-reader --auto
# → copy the printed machine_id / password into CROWDSEC_MACHINE_ID / CROWDSEC_MACHINE_PASSWORD
```

## 2. Configure

Copy `.env.example` to `.env` (or edit `docker-compose.yml` directly) and fill in:

- `CROWDSEC_LAPI_URL` — **LAN IP**, not `127.0.0.1`, if CrowdSec runs in a
  separate container/network (e.g. `http://192.168.1.10:8301`, matching
  whatever port your CrowdSec container's LAPI is mapped to)
- `CROWDSEC_BOUNCER_KEY`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD` — from step 1

## 3. Run

```bash
docker compose up -d --build
```

Then open `http://<host>:8000`.

On Unraid without Compose: build the image once (`docker build -t
npm-crowd-dash .`), then add it as a container manually via "Add Container",
using the same env vars and a `/data` volume mapping as in `docker-compose.yml`.

## Notes

- AppSec/WAF blocks (e.g. from `crowdsecurity/appsec-virtual-patching`) are
  detected automatically — the app flags a ban as `appsec` vs `crowdsec` based
  on whether the scenario name contains `appsec`/`vpatch`. If your AppSec
  scenarios use different naming, adjust `_source_type()` in `app/poller.py`.
- Rows are never deleted, only marked expired/revoked, so you can still see
  what was banned last week even after CrowdSec has forgotten it.
- `GET /api/bans` returns the same data as JSON if you want to script against it.
