"""AbuseIPDB reputation lookups for repeat offenders, cached in SQLite.

Built around the free tier (1,000 checks/day, shared with AbuseIPDB reports):

- Only repeat offenders are looked up — IPs banned REPEAT_OFFENDER_THRESHOLD+
  times locally (CAPI/lists/cscli never count, see db.abuseipdb_candidates).
  On a normal day that's a handful of lookups, not hundreds.
- Every answer is cached per IP. A cached IP is only looked up again once
  the cache is older than ABUSEIPDB_CACHE_DAYS *and* it has been banned again
  since — an IP that never comes back is never re-checked.
- A local daily budget (ABUSEIPDB_DAILY_LIMIT, below the real 1,000 so there's
  headroom for manual checks on the website) is counted per UTC day, the same
  day boundary AbuseIPDB uses. On top of that, AbuseIPDB's own
  X-RateLimit-Remaining header is honored, and a 429 pauses all lookups
  until the reset time it gives us.
- Lookups run in small batches in the background of the poll loop, never
  inside it, so a slow AbuseIPDB can't make the dashboard look "stale".

Purely informational: nothing here bans, reports or changes anything in
CrowdSec — it only stores a score the UI shows next to the IP.
"""

import asyncio
import ipaddress
import logging
import time
from datetime import datetime, timezone

import httpx

from . import db
from .config import settings

log = logging.getLogger("abuseipdb")

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_BATCH_SIZE = 5
_lock = asyncio.Lock()

# settings-table keys (key/value store shared with runtime_settings)
_K_DAY = "abuseipdb_day"
_K_USED = "abuseipdb_used"
_K_PAUSED_UNTIL = "abuseipdb_paused_until"
_K_REMAINING = "abuseipdb_remaining"
_K_LAST_ERROR = "abuseipdb_last_error"


def has_key() -> bool:
    return bool(settings.abuseipdb_api_key)


def is_enabled() -> bool:
    """Key configured *and* not switched off on the Settings page."""
    from . import runtime_settings  # local import: runtime_settings imports db too
    return has_key() and runtime_settings.get_abuseipdb_enabled()


def _utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _next_utc_midnight() -> int:
    now = int(time.time())
    return now - (now % 86400) + 86400


def get_budget() -> dict:
    """Current usage, for the Settings page and the batch runner."""
    s = db.get_settings([_K_DAY, _K_USED, _K_PAUSED_UNTIL, _K_REMAINING, _K_LAST_ERROR])
    today = _utc_day()
    used = int(s.get(_K_USED) or 0) if s.get(_K_DAY) == today else 0
    paused_until = int(s.get(_K_PAUSED_UNTIL) or 0)
    remaining = s.get(_K_REMAINING)
    return {
        "enabled": is_enabled(),
        "has_key": has_key(),
        "used_today": used,
        "daily_limit": settings.abuseipdb_daily_limit,
        "api_remaining": int(remaining) if remaining not in (None, "") else None,
        "paused_until": paused_until if paused_until > time.time() else None,
        "last_error": s.get(_K_LAST_ERROR) or None,
        "cache_days": settings.abuseipdb_cache_days,
    }


def _count_call() -> None:
    today = _utc_day()
    s = db.get_settings([_K_DAY, _K_USED])
    used = int(s.get(_K_USED) or 0) if s.get(_K_DAY) == today else 0
    db.set_settings({_K_DAY: today, _K_USED: str(used + 1)})


def _pause(until: int, reason: str) -> None:
    db.set_settings({_K_PAUSED_UNTIL: str(until), _K_LAST_ERROR: reason})
    log.warning("AbuseIPDB lookups paused until %s: %s",
                datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M"), reason)


def _budget_left() -> int:
    b = get_budget()
    if b["paused_until"]:
        return 0
    left = b["daily_limit"] - b["used_today"]
    if b["api_remaining"] is not None:
        left = min(left, b["api_remaining"])
    return max(0, left)


def _is_lookupable(ip: str) -> bool:
    """Private/reserved addresses aren't in AbuseIPDB — never spend a call."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def _check(client: httpx.AsyncClient, ip: str) -> None:
    resp = await client.get(
        _API_URL,
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
    )
    _count_call()

    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    if remaining is not None:
        db.set_settings({_K_REMAINING: remaining})

    if resp.status_code == 429:
        until = int(reset) if reset and reset.isdigit() else _next_utc_midnight()
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            until = max(until, int(time.time()) + int(retry_after))
        _pause(until, "daily limit reached (HTTP 429)")
        return
    if resp.status_code in (401, 403):
        _pause(int(time.time()) + 3600, f"API key rejected (HTTP {resp.status_code})")
        return
    if resp.status_code == 422:
        # AbuseIPDB refuses this address — cache that so it's never retried.
        db.upsert_abuseipdb(ip, None, error="rejected by AbuseIPDB (422)")
        return
    resp.raise_for_status()

    data = resp.json().get("data") or {}
    db.upsert_abuseipdb(ip, data)
    db.set_settings({_K_LAST_ERROR: ""})
    if remaining == "0":
        until = int(reset) if reset and reset.isdigit() else _next_utc_midnight()
        _pause(until, "daily quota used up")


async def run_batch() -> int:
    """Look up the next few repeat offenders that need it. Returns how many
    lookups were made. Safe to call every poll cycle: returns immediately if
    disabled, out of budget, or another batch is still running."""
    if not is_enabled() or _lock.locked():
        return 0
    async with _lock:
        n = min(_BATCH_SIZE, _budget_left())
        if n <= 0:
            return 0
        stale_before = int(time.time()) - settings.abuseipdb_cache_days * 86400
        candidates = [
            ip for ip in db.abuseipdb_candidates(
                settings.repeat_offender_threshold, stale_before, limit=n * 3
            )
            if _is_lookupable(ip)
        ][:n]
        done = 0
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            for ip in candidates:
                if _budget_left() <= 0:
                    break
                try:
                    await _check(client, ip)
                    done += 1
                except Exception as exc:
                    db.set_settings({_K_LAST_ERROR: f"{exc.__class__.__name__}: {exc}"[:200]})
                    log.warning("AbuseIPDB lookup for %s failed: %s", ip, exc)
                    break  # network trouble: try again next cycle, don't burn the batch
        if done:
            log.info("AbuseIPDB: looked up %d IP(s), %d used today", done, get_budget()["used_today"])
        return done


def start_batch_in_background() -> None:
    """Fire-and-forget from the poll loop — never awaited there."""
    global _task
    if is_enabled() and not _lock.locked() and (_task is None or _task.done()):
        _task = asyncio.create_task(run_batch())
        _task.add_done_callback(_log_crash)


_task: asyncio.Task | None = None  # strong ref so the task isn't garbage-collected mid-run


def _log_crash(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception():
        log.error("AbuseIPDB batch crashed: %r", task.exception())
