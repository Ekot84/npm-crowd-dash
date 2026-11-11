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

## Abuse reports

Reports automatically look up the dashboard's current public IPv4 address via
HTTPS to api.ipify.org when prepared and sent. This follows changes to your
public IP without editing container settings. If lookup fails, reports still
work but omit the address. This is the current outgoing address, not a record
of the address at the time of older attacks. If the dashboard uses a VPN or a
different connection from the attacked server, set `REPORT_PUBLIC_IP` to override
the lookup (IPv4 or IPv6). With Unraid, add it as a container variable.

Reporting an abusive IP to its network's abuse contact is always a manual,
reviewed step — nothing is ever emailed automatically. Two ways to do it:

- The "Prepare abuse report" button on an IP's history (Stats page) does an
  RDAP lookup and builds a pre-filled `mailto:` link for you to send from
  your own mail client. Quick, but untracked — it doesn't remember whether
  you already reported that IP.
- The **Reports** page lists every repeat offender (banned
  `REPEAT_OFFENDER_THRESHOLD`+ times) that doesn't have a successfully sent
  report on file yet. Click "Review & send" on an IP to see the RDAP-looked-up
  recipient and pre-filled report text, edit either if needed, and send it
  for real over SMTP — right from the dashboard. Once a report sends
  successfully it's recorded and that IP drops off the pending list for
  good, so the same IP is never reported twice by mistake. A failed send
  (SMTP down, wrong recipient, etc.) is recorded too, so it stays visible in
  the history and can be retried, but doesn't block anything.

Sending from the Reports page needs SMTP configured: set `SMTP_HOST`,
`SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (and optionally `SMTP_PORT`, see
`.env.example`), or fill in the same fields on the **Settings** page — which
also has a "Send test email" button that tries the credentials currently
typed in (saved or not), so you can confirm they work before relying on
them. Anything saved on Settings overrides the env vars; leave it untouched
and the env vars apply as-is. Note there's no login on this dashboard, so
anyone who can reach it on your network can see/change these settings and
send reports — fine on a private LAN, worth keeping in mind if you ever
expose it further.

A password saved via the Settings page is encrypted before it's written to
SQLite (not stored as plain text in the database), but that requires an
encryption key: set `SETTINGS_SECRET_KEY` (see `.env.example` for how to
generate one) before saving one there. There's no auto-generated fallback
key — a key that's created and stored automatically next to the database
would just travel along with it in any backup or copy of `/data`, defeating
the point. If `SETTINGS_SECRET_KEY` isn't set, the rest of the dashboard
still starts and works normally; the Settings page shows the SMTP password
field disabled with an explanation, and refuses to save a new password
until the key is configured. Setting it is a one-time step — generate the
key, set the env var, restart the container.

## Notes

- AppSec/WAF blocks (e.g. from `crowdsecurity/appsec-virtual-patching`) are
  detected automatically — the app flags a ban as `appsec` vs `crowdsec` based
  on whether the scenario name contains `appsec`/`vpatch`. If your AppSec
  scenarios use different naming, adjust `_source_type()` in `app/poller.py`.
- Rows are never deleted, only marked expired/revoked, so you can still see
  what was banned last week even after CrowdSec has forgotten it.
- `GET /api/bans` returns the same data as JSON if you want to script against it.
