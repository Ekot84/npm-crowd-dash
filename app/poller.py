import asyncio
import json
import logging
import re
import time
import uuid
from datetime import datetime

import httpx

from . import db
from .config import settings
from .crowdsec_client import CrowdSecClient

log = logging.getLogger("poller")

_PURGE_INTERVAL_SECONDS = 24 * 60 * 60

# Poll health, read by main.py to show a "last synced" indicator in the UI.
last_poll_at: float | None = None
last_poll_ok: bool = False
last_poll_error: str | None = None


def get_status() -> dict:
    return {
        "last_poll_at": last_poll_at,
        "last_poll_ok": last_poll_ok,
        "last_poll_error": last_poll_error,
    }

_GO_DURATION_RE = re.compile(r"([\d.]+)(h|ms|us|ns|m|s)")
_GO_DURATION_UNIT_SECONDS = {
    "h": 3600,
    "m": 60,
    "s": 1,
    "ms": 1e-3,
    "us": 1e-6,
    "ns": 1e-9,
}


def _parse_iso(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _parse_go_duration_seconds(duration: str | None) -> float | None:
    """CrowdSec's /v1/decisions(/stream) has no 'until' field, only a Go-style
    duration string like '3h59m9.481933644s' — parse that instead."""
    if not duration:
        return None
    matches = _GO_DURATION_RE.findall(duration)
    if not matches:
        return None
    total = sum(float(value) * _GO_DURATION_UNIT_SECONDS[unit] for value, unit in matches)
    return -total if duration.strip().startswith("-") else total


def _meta_dict(meta_list) -> dict:
    return {m.get("key"): m.get("value") for m in (meta_list or [])}


def _extract_reason(alert: dict) -> tuple[str | None, str | None]:
    """Prefer concrete request detail (URI + matched rule) over CrowdSec's
    generic 'Ip x performed scenario y (N events)' alert message.

    Returns (human-readable reason, matched rule id(s)) — the rule id is kept
    separate from the free-text reason so stats can group AppSec bans by the
    specific vpatch rule that fired, not just the generic 'appsec-vpatch'
    collection name every AppSec decision shares."""
    meta = _meta_dict(alert.get("meta"))

    uris = rules = None
    try:
        if meta.get("target_uri"):
            uris = json.loads(meta["target_uri"])
        if meta.get("rules"):
            rules = json.loads(meta["rules"])
    except (json.JSONDecodeError, TypeError):
        pass

    if uris:
        text = ", ".join(uris)
        # Sort so the same rule combination always groups together in stats
        # regardless of the order CrowdSec happens to report them in.
        rule_str = ", ".join(sorted(rules)) if rules else None
        return (f"{text} (rule: {rule_str})" if rule_str else text, rule_str)

    # Non-AppSec scenarios don't populate the alert-level meta above —
    # fall back to the first event's own meta.
    events = alert.get("events") or []
    if events:
        ev_meta = _meta_dict(events[0].get("meta"))
        path = ev_meta.get("target_uri") or ev_meta.get("http_path") or ev_meta.get("uri")
        rule = ev_meta.get("rule_name")
        if path:
            return (f"{path} (rule: {rule})" if rule else path, rule)

    return (alert.get("message"), None)


# AS-name substrings for major cloud/hosting providers. A lot of automated
# scan/bot traffic comes from a handful of these regardless of which country
# the AS happens to be registered in, so "this IP is in country X" and "this
# IP is on cloud host Y" are two different signals — conflating them would
# make a country's ban count look like a real geographic pattern when it's
# really just one hosting provider's IP range. Edit this list as you notice
# more providers showing up in your own `as_name` data.
_CLOUD_PROVIDER_AS_KEYWORDS = [
    "AMAZON", "AWS", "MICROSOFT", "AZURE", "GOOGLE", "DIGITALOCEAN",
    "HETZNER", "OVH", "LINODE", "AKAMAI", "VULTR", "CHOOPA",
    "THE CONSTANT COMPANY", "ALIBABA", "TENCENT", "ORACLE", "CLOUDFLARE",
    "SCALEWAY", "CONTABO", "LEASEWEB", "M247", "DATACAMP", "COLOCROSSING",
    "PSYCHZ", "G-CORE", "FRANTECH", "BUYVM", "UPCLOUD", "IONOS", "FASTLY",
]


def _is_cloud_host(as_name: str | None) -> bool:
    if not as_name:
        return False
    upper = as_name.upper()
    return any(keyword in upper for keyword in _CLOUD_PROVIDER_AS_KEYWORDS)


def _source_type(scenario: str | None) -> str:
    s = (scenario or "").lower()
    if "appsec" in s or "vpatch" in s:
        return "appsec"
    return "crowdsec"


def _decision_id(decision: dict) -> str:
    raw_id = decision.get("id")
    if raw_id is not None:
        return str(raw_id)
    # Fallback if CrowdSec ever omits id: derive a key from scope+value+day.
    # The day bucket keeps a later, separate ban of the same IP from colliding
    # with (and silently overwriting) an earlier one — bans are what we want to
    # count per IP, so distinct ban instances must get distinct rows. Trade-off:
    # if a single decision without an id somehow lived past midnight and got
    # re-sent (e.g. app restart), it'd wrongly be treated as a new ban instead
    # of updating the old row. Accepted since CrowdSec always sends a real id
    # in practice — this path is a defensive fallback, not the common case.
    today = time.strftime("%Y-%m-%d", time.gmtime())
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{decision.get('scope')}:{decision.get('value')}:{today}"))


# Decisions with these origins (or no origin at all) were actually observed
# by this CrowdSec instance, so there's a real local alert to fetch context
# from. Anything else — "CAPI" (the shared community blocklist), "lists"
# (subscribed third-party blocklists), "cscli" (manually added) — was never
# seen locally, so an alert lookup for them always comes back empty. Confirmed
# 2026-08-01: a ~6000-decision "http:scan" burst turned out to be a one-time
# CAPI bulk sync, not a real attack, and every sampled row had origin=CAPI.
_LOCAL_ALERT_ORIGINS = {None, "crowdsec"}


async def _handle_new_decision(client: CrowdSecClient, decision: dict) -> None:
    ip = decision.get("value")
    scenario = decision.get("scenario")
    origin = decision.get("origin")
    country = None
    as_name = None
    reason_message = None
    matched_rule = None
    created_at = int(time.time())

    if ip and origin in _LOCAL_ALERT_ORIGINS:
        try:
            alert = await client.get_latest_alert_for_ip(ip)
        except Exception:
            log.exception("failed to fetch alert context for %s", ip)
            alert = None
        if alert:
            reason_message, matched_rule = _extract_reason(alert)
            source = alert.get("source") or {}
            country = source.get("cn")
            as_name = source.get("as_name")
            if not as_name and source.get("as_number") not in (None, "0", 0):
                as_name = f"AS{source['as_number']}"
            parsed_created = _parse_iso(alert.get("created_at"))
            if parsed_created:
                created_at = parsed_created

    expires_at = _parse_iso(decision.get("until"))
    if expires_at is None:
        duration_seconds = _parse_go_duration_seconds(decision.get("duration"))
        if duration_seconds is not None:
            expires_at = created_at + int(duration_seconds)

    row = {
        "id": _decision_id(decision),
        "ip": ip,
        "scope": decision.get("scope"),
        "value": decision.get("value"),
        "scenario": scenario,
        "reason_message": reason_message,
        "matched_rule": matched_rule,
        "country": country,
        "as_name": as_name,
        "is_cloud_host": int(_is_cloud_host(as_name)),
        "origin": origin,
        "source_type": _source_type(scenario),
        "duration": decision.get("duration"),
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked_at": None,
    }
    db.upsert_ban(row)

    if settings.repeat_offender_escalation_enabled and ip and origin in _LOCAL_ALERT_ORIGINS:
        await _maybe_escalate(client, ip)


async def _maybe_escalate(client: CrowdSecClient, ip: str) -> None:
    """Once a repeat local offender's ban count reaches the configured
    threshold, push a long-duration ban straight to CrowdSec instead of
    waiting for the normal short duration to lapse and the same IP to come
    back and earn another one. Fires at most once per IP (guarded by
    db.has_sent_escalation) — later local bans against an already-escalated
    IP don't re-trigger this, they just accumulate under an IP that's
    already on a long ban. A failed push is retried the next time this IP
    earns another local ban, not immediately, since bans for the same IP
    are usually spaced well apart."""
    count = db.local_ban_count(ip)
    if count < settings.repeat_offender_escalation_threshold:
        return
    if db.has_sent_escalation(ip):
        return
    duration = settings.repeat_offender_escalation_duration
    try:
        await client.add_manual_ban(ip, duration=duration, reason=f"{count} local bans")
    except Exception:
        log.exception("failed to push escalation ban for %s", ip)
        db.record_escalation(ip, times_banned=count, duration=duration, status="failed")
        return
    db.record_escalation(ip, times_banned=count, duration=duration, status="sent")
    log.info("escalated repeat offender %s (%d local bans) to a %s ban", ip, count, duration)


_MAX_CONCURRENT_ALERT_LOOKUPS = 10


async def poll_once(client: CrowdSecClient) -> None:
    stream = await client.get_decisions_stream()

    # CAPI (community blocklist)/lists/cscli decisions were never observed
    # locally, so there's nothing to track here beyond their sheer volume —
    # the community blocklist sync can dump thousands of entries at once.
    # Drop them before doing any work at all, not just skip their alert
    # lookup, so a big sync doesn't bloat our db or make the poller grind
    # through decisions this dashboard was never meant to track.
    new_decisions = [d for d in stream["new"] if d.get("origin") in _LOCAL_ALERT_ORIGINS]
    skipped = len(stream["new"]) - len(new_decisions)
    if skipped:
        log.info("skipped %d non-local decision(s) (CAPI/lists/cscli), not stored", skipped)

    # A burst of new decisions (e.g. a distributed scan hitting from many
    # IPs at once) used to be handled one at a time, each awaiting its own
    # alert lookup — a storm of a few hundred could make one poll cycle take
    # long enough that last_poll_at wouldn't update in time, showing "stale"
    # in the UI right when there's actually an active incident to look at.
    # A bounded semaphore lets lookups run concurrently without hammering
    # CrowdSec's own LAPI harder than sequential would have, just faster.
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ALERT_LOOKUPS)

    async def _handle_with_limit(decision: dict) -> None:
        async with semaphore:
            await _handle_new_decision(client, decision)

    await asyncio.gather(*(_handle_with_limit(d) for d in new_decisions))

    for decision in stream["deleted"]:
        db.revoke_ban(_decision_id(decision))


_BACKFILL_BATCH_SIZE = 50


async def _backfill_missing_enrichment(client: CrowdSecClient) -> None:
    """Retries the alert lookup for bans that came back with no country/AS —
    confirmed (2026-08-01, during a ~5000-decision http:scan botnet burst) to
    be requests that succeed (200 OK) but return an empty alert list, not
    failures: the decision can appear in CrowdSec's stream before its alert
    is queryable. Bounded per cycle so a large backlog doesn't spike load.

    Some rows never succeed — confirmed 2026-08-04 on a live deployment that
    a fixed set of ~19 IPs got retried every single poll cycle indefinitely,
    each a 200 OK/empty-alert response, driving sustained CrowdSec CPU load
    for no benefit. db.bans_missing_enrichment() now caps retries at 3
    attempts per row (see increment_enrichment_attempts below), so a row that
    can never be enriched (e.g. its alert already aged out of CrowdSec's own
    retention before we got to it) stops being retried instead of being
    hammered forever."""
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ALERT_LOOKUPS)

    async def _retry(row: dict) -> None:
        async with semaphore:
            db.increment_enrichment_attempts(row["id"])
            try:
                alert = await client.get_latest_alert_for_ip(row["ip"])
            except Exception:
                return
            if not alert:
                return
            reason_message, matched_rule = _extract_reason(alert)
            source = alert.get("source") or {}
            country = source.get("cn")
            as_name = source.get("as_name")
            if not as_name and source.get("as_number") not in (None, "0", 0):
                as_name = f"AS{source['as_number']}"
            if country or as_name:
                db.update_enrichment(
                    row["id"],
                    reason_message=reason_message,
                    matched_rule=matched_rule,
                    country=country,
                    as_name=as_name,
                    is_cloud_host=_is_cloud_host(as_name),
                )

    rows = db.bans_missing_enrichment(limit=_BACKFILL_BATCH_SIZE)
    await asyncio.gather(*(_retry(r) for r in rows))


async def poll_forever(stop_event: asyncio.Event) -> None:
    global last_poll_at, last_poll_ok, last_poll_error

    client = CrowdSecClient()
    last_purge_at = 0.0
    try:
        while not stop_event.is_set():
            try:
                await poll_once(client)
                last_poll_ok = True
                last_poll_error = None
            except httpx.TimeoutException:
                log.warning("poll cycle timed out talking to CrowdSec LAPI, will retry next cycle")
                last_poll_ok = False
                last_poll_error = "timeout talking to CrowdSec LAPI"
            except Exception as exc:
                log.exception("poll cycle failed")
                last_poll_ok = False
                last_poll_error = str(exc) or exc.__class__.__name__
            last_poll_at = time.time()

            try:
                await _backfill_missing_enrichment(client)
            except Exception:
                log.exception("enrichment backfill failed")

            if last_poll_at - last_purge_at > _PURGE_INTERVAL_SECONDS:
                try:
                    deleted = db.purge_old(settings.retention_days)
                    if deleted:
                        log.info("purged %d ban(s) older than %d days", deleted, settings.retention_days)
                except Exception:
                    log.exception("purge cycle failed")
                last_purge_at = last_poll_at

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=settings.poll_interval_seconds)
            except asyncio.TimeoutError:
                pass
    finally:
        await client.aclose()
