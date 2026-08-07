import time

import httpx

_RDAP_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)

# Abuse-contact info for a given IP barely ever changes, and this is only
# ever triggered by a manual button click — but caching means a re-click (or
# a double-click) on the same IP doesn't hit rdap.org again, which matters
# since it's a shared public service we don't want to hammer. Caches misses
# too (None), so a lookup that fails doesn't get retried every click either.
_CACHE_TTL_SECONDS = 24 * 60 * 60
_cache: dict[str, tuple[float, str | None]] = {}


async def lookup_abuse_email(ip: str) -> str | None:
    cached = _cache.get(ip)
    if cached is not None and (time.time() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    email = await _fetch_abuse_email(ip)
    _cache[ip] = (time.time(), email)
    return email


async def _fetch_abuse_email(ip: str) -> str | None:
    """Looks up the network's abuse contact via RDAP (the modern WHOIS
    replacement) — rdap.org auto-routes to whichever regional registry
    (ARIN/RIPE/APNIC/LACNIC/AFRINIC) actually holds the record for this IP,
    so we don't need to figure out which one ourselves."""
    try:
        async with httpx.AsyncClient(timeout=_RDAP_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/ip/{ip}", headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return None

    for entity in _iter_entities(data):
        if "abuse" in (entity.get("roles") or []):
            email = _email_from_vcard(entity.get("vcardArray"))
            if email:
                return email
    return None


def _iter_entities(node: dict):
    """RDAP nests entities recursively (e.g. the network's entity contains
    the registrar's entity which contains the actual abuse-role entity), so
    walk the whole tree rather than assuming a fixed depth."""
    for entity in node.get("entities") or []:
        yield entity
        yield from _iter_entities(entity)


def _email_from_vcard(vcard_array) -> str | None:
    if not vcard_array or len(vcard_array) < 2:
        return None
    for field in vcard_array[1]:
        if field and field[0] == "email" and len(field) >= 4:
            return field[3]
    return None
