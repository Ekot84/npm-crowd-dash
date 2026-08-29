"""Builds the plain-text abuse report and mailto link shared by the manual
"Prepare abuse report" button (main.py) and the automatic SMTP sender
(poller.py, when AUTO_ABUSE_REPORT is enabled) — one report format, whether
it ends up in the user's mail client or sent straight over SMTP."""

import time
from urllib.parse import quote


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
