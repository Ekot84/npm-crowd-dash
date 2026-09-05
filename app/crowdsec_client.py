import time
from datetime import datetime, timezone

import httpx

from .config import settings


class CrowdSecClient:
    def __init__(self) -> None:
        # Generous read timeout: this box sees periodic heavy load spikes
        # (many containers sharing disk I/O), which can slow CrowdSec's own
        # LAPI responses well past a typical few-second timeout.
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
        self._client = httpx.AsyncClient(base_url=settings.crowdsec_lapi_url, timeout=timeout)
        self._jwt: str | None = None
        self._jwt_expires_at: float = 0.0
        self._stream_started = False

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _login(self) -> None:
        resp = await self._client.post(
            "/v1/watchers/login",
            json={
                "machine_id": settings.crowdsec_machine_id,
                "password": settings.crowdsec_machine_password,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._jwt = data["token"]
        # CrowdSec JWTs are typically valid ~4h; refresh a bit early.
        self._jwt_expires_at = time.time() + 3 * 60 * 60

    async def _auth_headers(self) -> dict:
        if not self._jwt or time.time() >= self._jwt_expires_at:
            await self._login()
        return {"Authorization": f"Bearer {self._jwt}"}

    async def get_decisions_stream(self) -> dict:
        """Returns {"new": [...], "deleted": [...]} of decision objects."""
        params = {"startup": "true"} if not self._stream_started else {}
        resp = await self._client.get(
            "/v1/decisions/stream",
            headers={"X-Api-Key": settings.crowdsec_bouncer_key},
            params=params,
        )
        resp.raise_for_status()
        self._stream_started = True
        data = resp.json() or {}
        return {"new": data.get("new") or [], "deleted": data.get("deleted") or []}

    async def get_latest_alert_for_ip(self, ip: str) -> dict | None:
        headers = await self._auth_headers()
        resp = await self._client.get(
            "/v1/alerts",
            headers=headers,
            params={"ip": ip, "limit": 1},
        )
        if resp.status_code == 401:
            # token stale despite our cache assumption; force a re-login and retry once
            self._jwt = None
            headers = await self._auth_headers()
            resp = await self._client.get(
                "/v1/alerts",
                headers=headers,
                params={"ip": ip, "limit": 1},
            )
        resp.raise_for_status()
        alerts = resp.json() or []
        return alerts[0] if alerts else None

    async def add_manual_ban(self, ip: str, *, duration: str, reason: str) -> dict:
        """Pushes a manual ban decision straight to CrowdSec's LAPI, using
        the same watcher/machine login already used by get_latest_alert_for_ip
        — this is the same "trusted machine" mechanism CrowdSec's own local
        scenario parsers use to submit alerts, just built by hand here
        instead of from a real log match. Deliberately NOT done via
        `docker exec cscli` (would need Docker socket access — the exact
        privilege escalation this app was built to avoid) and not possible
        via the bouncer key (bouncers only have read access to decisions).

        The decision's origin is set to "cscli" (CrowdSec's own convention
        for manually-added decisions), not "crowdsec" — this dashboard's
        poller only treats origin in {None, "crowdsec"} as a local
        detection (see poller._LOCAL_ALERT_ORIGINS), so when this escalation
        ban streams back on the next poll it's correctly ignored rather than
        counted as a fresh local offense, which would be a feedback loop.

        Returns the alert CrowdSec created, as echoed back in the response."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = [
            {
                "scenario": "npm-crowd-dash/repeat-offender-escalation",
                "scenario_hash": "",
                "scenario_version": "",
                "message": f"npm-crowd-dash: escalating repeat offender {ip} ({reason})",
                "events": [],
                "events_count": 0,
                "capacity": 0,
                "leakspeed": "0s",
                "simulated": False,
                "start_at": now,
                "stop_at": now,
                "source": {"scope": "Ip", "value": ip, "ip": ip},
                "decisions": [
                    {
                        "scope": "Ip",
                        "type": "ban",
                        "value": ip,
                        "duration": duration,
                        "origin": "cscli",
                        "scenario": "npm-crowd-dash/repeat-offender-escalation",
                    }
                ],
            }
        ]
        headers = await self._auth_headers()
        resp = await self._client.post("/v1/alerts", headers=headers, json=payload)
        if resp.status_code == 401:
            self._jwt = None
            headers = await self._auth_headers()
            resp = await self._client.post("/v1/alerts", headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()
