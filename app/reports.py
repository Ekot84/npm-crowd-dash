"""Builds the plain-text abuse report and mailto link shared by the quick
"Prepare abuse report" mailto button on the Stats page and the tracked,
review-before-send flow on the Reports page (main.py) — one report format,
whether it ends up in the user's own mail client or is sent straight over
SMTP after being reviewed.

Also builds the X-ARF machine-readable attachment (see build_xarf_report)
that main.py's /reports/send route attaches alongside that same
human-written body. Several hosting providers' abuse mailboxes (e.g.
DigitalOcean's) run automated tooling that only auto-processes reports
carrying either an X-ARF attachment or fail2ban's template — a plain
freeform email just gets an auto-reply pointing at their webform instead.
The X-ARF part is always regenerated from the current ban summary at send
time rather than being editable text, since it has to stay well-formed for
whatever's parsing it on the other end; only the human-readable body above
is meant to be reviewed/edited before sending."""

import time
from urllib.parse import quote

from .config import settings


def fmt_ts(ts: int | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def build_report_text(ip: str, summary: dict) -> str:
    activity = summary.get("reason_message") or summary.get("scenario") or "n/a"
    lines = [
        "Hello,",
        "",
        "Our automated intrusion-prevention system (CrowdSec) has repeatedly",
        "detected malicious activity from this IP address, hosted on your network:",
        "",
        f"IP address: {ip}",
        *([f"Target public IP address (our server): {settings.report_public_ip}"]
          if settings.report_public_ip else []),
        f"Autonomous system: {summary.get('as_name') or 'unknown'}",
        f"Country (GeoIP): {summary.get('country') or 'unknown'}",
        f"Times banned: {summary['times_banned']}",
        f"First detected: {fmt_ts(summary['first_seen'])}",
        f"Last detected: {fmt_ts(summary['last_seen'])}",
        f"Most recent detected activity: {activity}",
        "",
        "We would appreciate it if you could investigate this IP/customer and",
        "take appropriate action.",
        "",
        "Thank you.",
    ]
    return "\n".join(lines)


def build_subject(ip: str) -> str:
    return f"Abuse report - repeated malicious activity from {ip}"


def build_mailto_href(ip: str, abuse_email: str, report_text: str) -> str:
    return f"mailto:{abuse_email}?subject={quote(build_subject(ip))}&body={quote(report_text)}"


def build_xarf_report(ip: str, summary: dict, now_ts: int | None = None) -> str:
    """Builds the machine-readable X-ARF "PLAIN" report body (a flat
    key: value block, per the format https://x-arf.org and fail2ban's own
    xarf-login-attack action both use — this is deliberately the older
    plain-text X-ARF shape rather than the newer JSON one, since it's the
    shape abuse desks that recognize "reports submitted from tools such as
    fail2ban" are already built to parse).

    Report-Type is fixed to "login-attack": CrowdSec's own default
    collections are overwhelmingly brute-force/login-abuse scenarios (ssh,
    http auth, etc.), and login-attack is the one schema fail2ban itself
    ships and the one abuse desks are most likely to actually recognize —
    a better bet than inventing a non-standard type for the occasional
    scenario (e.g. a port scan) that isn't a perfect fit."""
    now = int(now_ts if now_ts is not None else time.time())
    date_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    service = summary.get("scenario") or "unspecified"
    lines = [
        f"Report-ID: {now}@npm-crowd-dash",
        "Category: abuse",
        "Report-Type: login-attack",
        f"Service: {service}",
        "Version: 0.2",
        "User-Agent: npm-crowd-dash",
        f"Date: {date_str}",
        "Source-Type: ip-address",
        f"Source: {ip}",
        *([f"Destination: {settings.report_public_ip}"]
          if settings.report_public_ip else []),
        "Schema-URL: http://www.x-arf.org/schema/abuse_login-attack_0.1.2.json",
        f"Occurrences: {summary['times_banned']}",
        "TLP: green",
    ]
    return "\n".join(lines) + "\n"
