# npm-crowd-dash

A small dashboard that shows CrowdSec bans (and AppSec/WAF blocks) — IP,
reason/scenario, source, country/AS, time issued, expiry — without having to
run `cscli decision list` or dig through the CrowdSec console.

Polls CrowdSec's own LAPI directly (`/v1/decisions/stream` + `/v1/alerts`),
keeps a local history in SQLite (CrowdSec forgets a decision once it
expires — this doesn't), and serves an auto-refreshing table via
FastAPI + HTMX (single container, no JS build step).

## What's in it

- **Stats**: totals, bans by country, source (CrowdSec vs AppSec), scenario/rule,
  hosting provider (AS), and **Repeat offenders**: IPs banned more than once,
  with a time-period filter, a ready-to-paste `cscli` command for a long ban,
  and an optional AbuseIPDB score.
- **Bans**: the full ban history (active and expired), filterable. IPs with a
  cached AbuseIPDB result get a small score badge (or **WL**) next to the IP.
- **Reports**: a queue of repeat offenders to report to their network's abuse
  contact (reviewed and sent by you), the report history, and the list of
  **escalated bans** this dashboard has pushed to CrowdSec.
- **Settings**: Reports queue age, AbuseIPDB lookups and auto-ban, and SMTP.

Every column header on **Repeat offenders** and the **Reports** queue is
clickable to sort (click again to reverse). Sorting is done server-side, so it
covers all pages and survives the automatic refresh.

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

A prebuilt image (amd64 + arm64) is published on every push to `main`:
`ghcr.io/ekot84/npm-crowd-dash:latest`.

**Docker Compose**, building from source:

```bash
docker compose up -d --build
```

To use the prebuilt image instead, replace `build: .` / `image:` in
`docker-compose.yml` with `image: ghcr.io/ekot84/npm-crowd-dash:latest` and run
`docker compose pull && docker compose up -d`.

**Unraid:** install from the template in `unraid-template/`, which uses the
prebuilt image. To update, go to **Docker** → click the container →
**Force update**. Your data in `/data` is kept.

Then open `http://<host>:8000`.

## Abuse reports

The **Reports** queue lists repeat offenders seen recently, most recent first
by default. IPs whose latest ban is older than `REPORT_MAX_AGE_DAYS` (default
30, `0` = no limit, also changeable under **Settings → Reports**) are hidden
because they have most likely moved on. They're only hidden: if the IP comes
back, it's listed again with its full ban count.

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

## Repeat-offender escalation (optional, off by default)

Pushes a long ban to CrowdSec once an IP reaches a number of local bans,
instead of letting it come back every time its short ban runs out:

```env
REPEAT_OFFENDER_ESCALATION_ENABLED=true
REPEAT_OFFENDER_ESCALATION_THRESHOLD=8     # local bans before escalating
REPEAT_OFFENDER_ESCALATION_DURATION=8760h  # ban length (Go duration, 8760h = 1 year)
```

It uses the machine login from step 1 to add the decision, so no Docker socket
is needed. Escalated bans show up under **Escalated bans** on the Reports page.
Once a ban expires, an IP that comes back can be escalated again. Test it with
a short duration first: once on, it acts on real IPs automatically.

## AbuseIPDB scores (optional)

The dashboard can show each repeat offender's [AbuseIPDB](https://www.abuseipdb.com)
confidence score, a sortable **AbuseIPDB** column on Stats → Repeat offenders
and on the Reports page. The score links to the IP's AbuseIPDB page. This is
informational only: nothing is banned or reported automatically.

### 1. Get an API key

1. Create a free account at <https://www.abuseipdb.com/register>.
2. Go to **Account → API** (<https://www.abuseipdb.com/account/api>) and click
   **Create Key**. Give it any name, e.g. `npm-crowd-dash`.
3. Copy the key. Treat it like a password and don't commit it to git.

### 2. Add it to the container

**Docker Compose / `.env`:**

```env
ABUSEIPDB_API_KEY=your-key-here
```

Then `docker compose up -d` to restart with the new variable.

**Unraid (existing container):** an installed container doesn't pick up new
fields from the template, so add the variable by hand:

1. **Docker** tab → click the container → **Edit**.
2. At the bottom: **Add another Path, Port, Variable or Device**.
3. Config Type **Variable**, Name `AbuseIPDB API Key`, Key `ABUSEIPDB_API_KEY`,
   Value = your key. Set **Mask** to *Yes* so it's hidden in the UI.
4. **Add**, then **Apply**. The container restarts with the key.

New installs from the template in `unraid-template/` already have the
**AbuseIPDB API Key** field. Just fill it in.

### 3. Check that it works

Open **Settings**. The **AbuseIPDB** panel shows an on/off switch, how many
lookups have been used today, and any pause or error, such as a rejected key.
Scores start appearing within a few poll cycles for IPs that have reached
`REPEAT_OFFENDER_THRESHOLD` bans. To stop lookups without removing the key,
untick the switch and Save. Already-cached scores stay visible.

### How it stays inside the free tier

The free plan allows 1,000 checks per day. The dashboard keeps well below that:

- **Only repeat offenders are looked up:** IPs banned
  `REPEAT_OFFENDER_THRESHOLD`+ times locally. Community-blocklist (CAPI)
  entries and private/LAN addresses are never sent.
- **Every answer is cached per IP.** A cached IP is only looked up again once
  the cache is older than `ABUSEIPDB_CACHE_DAYS` **and** the IP has been
  banned again since. An IP that never comes back is checked once.
- **Daily budget:** lookups stop at `ABUSEIPDB_DAILY_LIMIT` per UTC day.
  AbuseIPDB's own remaining-quota header is honored too, and a `429 Too Many
  Requests` pauses all lookups until AbuseIPDB's reset time.
- Lookups run in small background batches, so a slow or unreachable AbuseIPDB
  never delays the CrowdSec poller.

| Variable | Default | What it does |
|---|---|---|
| `ABUSEIPDB_API_KEY` | *(empty = off)* | Your AbuseIPDB API key |
| `ABUSEIPDB_CACHE_DAYS` | `7` | How long a cached score is reused before a re-check (only if banned again) |
| `ABUSEIPDB_DAILY_LIMIT` | `900` | Max lookups per UTC day; leaves headroom for manual checks on the website |

### Auto-ban by AbuseIPDB score (optional, off by default)

With lookups on, the dashboard can also push a **time-limited** ban to
CrowdSec for IPs that are both bad locally and known bad elsewhere. Turn it
on under **Settings → AbuseIPDB → Auto-ban**. An IP is banned when **all** of
these hold:

- its AbuseIPDB score is at least the minimum (default **75 %**), **or** it
  has at least the minimum number of distinct AbuseIPDB reporters in the last
  90 days (default **50**, `0` = off),
- it isn't in a range AbuseIPDB has whitelisted, unless **Also ban IPs in
  ranges AbuseIPDB has whitelisted** is ticked (see below),
- it has at least the minimum number of local bans (default **3**). Normal
  CrowdSec scenarios and AppSec bans both count; community-blocklist
  entries don't,
- it isn't already under a ban escalated by this dashboard.

**Whitelisted ranges.** AbuseIPDB whitelists some shared hosting ranges and
forces their score to **0 %**, however many people report them. A real example:
a scanner on such a range had 766 reports from 232 reporters and still showed
0 %. The dashboard shows these as a grey **WL · N rep.** badge instead of a green
0 %, so they don't look harmless. They're never auto-banned unless you tick the
whitelist option. Then the reporter count, together with your own local bans,
decides.

The ban is a regular CrowdSec decision (scenario
`npm-crowd-dash/abuseipdb-escalation`, default **30 days**), so every bouncer,
e.g. NPMplus, blocks the IP for everything. When it expires and the IP comes
back and gets banned locally again, it can be escalated again. Every escalation
is listed under **Escalated bans** on the Reports page. To undo one early:
`cscli decisions delete --ip <ip>`.

The Settings page values override these env defaults:
`ABUSEIPDB_BAN_ENABLED` (`false`), `ABUSEIPDB_BAN_MIN_SCORE` (`75`),
`ABUSEIPDB_BAN_MIN_BANS` (`3`), `ABUSEIPDB_BAN_DAYS` (`30`),
`ABUSEIPDB_BAN_MIN_REPORTERS` (`50`), `ABUSEIPDB_BAN_IGNORE_WHITELIST` (`false`).


## Configuration reference

All settings are environment variables. The ones marked **UI** can also be
changed on the Settings page, and a value saved there wins over the env var.

| Variable | Default | |
|---|---|---|
| `CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` | CrowdSec LAPI, use the LAN IP |
| `CROWDSEC_BOUNCER_KEY` | *(required)* | From `cscli bouncers add` |
| `CROWDSEC_MACHINE_ID` / `CROWDSEC_MACHINE_PASSWORD` | *(required)* | From `cscli machines add` |
| `POLL_INTERVAL_SECONDS` | `15` | How often the LAPI is polled |
| `DB_PATH` | `/data/dashboard.db` | SQLite database |
| `RETENTION_DAYS` | `90` | Expired bans older than this are pruned |
| `REPEAT_OFFENDER_THRESHOLD` | `3` | Bans before an IP is flagged, reportable and looked up on AbuseIPDB |
| `COUNTRY_BAN_THRESHOLD` | `10` | Bans before a country is flagged |
| `TZ` | `Europe/Stockholm` | Timezone for timestamps |
| `REPORT_PUBLIC_IP` | *(auto-detected)* | Your public IP in abuse reports |
| `REPORT_MAX_AGE_DAYS` | `30` | **UI.** Hide report candidates not seen for this long (`0` = never) |
| `REPEAT_OFFENDER_ESCALATION_ENABLED` | `false` | Long ban after N local bans |
| `REPEAT_OFFENDER_ESCALATION_THRESHOLD` | `8` | N for the above |
| `REPEAT_OFFENDER_ESCALATION_DURATION` | `8760h` | Length of that ban |
| `ABUSEIPDB_API_KEY` | *(empty = off)* | AbuseIPDB key. Lookups can be switched off in the **UI** |
| `ABUSEIPDB_CACHE_DAYS` | `7` | Reuse a cached score this long |
| `ABUSEIPDB_DAILY_LIMIT` | `900` | Max lookups per UTC day |
| `ABUSEIPDB_BAN_ENABLED` | `false` | **UI.** AbuseIPDB auto-ban |
| `ABUSEIPDB_BAN_MIN_SCORE` | `75` | **UI.** Minimum score for auto-ban |
| `ABUSEIPDB_BAN_MIN_BANS` | `3` | **UI.** Minimum local bans for auto-ban |
| `ABUSEIPDB_BAN_DAYS` | `30` | **UI.** Auto-ban length |
| `ABUSEIPDB_BAN_MIN_REPORTERS` | `50` | **UI.** Or: minimum distinct AbuseIPDB reporters (`0` = off) |
| `ABUSEIPDB_BAN_IGNORE_WHITELIST` | `false` | **UI.** Also auto-ban IPs in AbuseIPDB-whitelisted ranges |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | — / `587` | **UI.** Sending abuse reports |
| `SETTINGS_SECRET_KEY` | *(empty)* | Needed to save an SMTP password in the UI |

## Notes

- AppSec/WAF blocks (e.g. from `crowdsecurity/appsec-virtual-patching`) are
  detected automatically — the app flags a ban as `appsec` vs `crowdsec` based
  on whether the scenario name contains `appsec`/`vpatch`. If your AppSec
  scenarios use different naming, adjust `_source_type()` in `app/poller.py`.
- Rows are never deleted, only marked expired/revoked, so you can still see
  what was banned last week even after CrowdSec has forgotten it.
- `GET /api/bans` returns the same data as JSON if you want to script against it.
