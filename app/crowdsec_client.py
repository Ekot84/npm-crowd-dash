import time

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
