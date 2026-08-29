import asyncio
import ipaddress
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import abuse, db, mailer, poller, reports, runtime_settings, secrets_store
from .config import settings
from .poller import poll_forever

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("main")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_stop_event = asyncio.Event()

_STATS_PAGE_SIZE = 5


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    purged = db.purge_non_local_origin()
    if purged:
        log.info("purged %d pre-existing non-local (CAPI/lists) ban(s)", purged)
    task = asyncio.create_task(poll_forever(_stop_event))
    yield
    _stop_event.set()
    await task


app = FastAPI(title="npm-crowd-dash", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _fmt_ts(ts: int | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _paginate(rows: list, offset: int) -> tuple[list, bool, bool]:
    """rows was fetched with limit=_STATS_PAGE_SIZE+1, so a surplus row means
    there's a next page — avoids a separate COUNT(*) query per box."""
    has_next = len(rows) > _STATS_PAGE_SIZE
    return list(rows[:_STATS_PAGE_SIZE]), offset > 0, has_next


def _row_to_dict(row) -> dict:
    d = dict(row)
    now = int(time.time())
    d["is_active"] = d["revoked_at"] is None and (d["expires_at"] is None or d["expires_at"] > now)
    d["created_at_str"] = _fmt_ts(d["created_at"])
    d["expires_at_str"] = _fmt_ts(d["expires_at"])
    return d


@app.get("/bans")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"active_page": "bans"})


@app.get("/partials/bans-count")
async def bans_count_partial(request: Request):
    return templates.TemplateResponse(
        request, "partials/bans_count.html", {"count": db.count_active_bans()}
    )


@app.get("/partials/status")
async def status_partial(request: Request):
    st = poller.get_status()
    stale = st["last_poll_at"] is None or (time.time() - st["last_poll_at"]) > settings.poll_interval_seconds * 3
    return templates.TemplateResponse(
        request,
        "partials/status.html",
        {
            "last_poll_at_str": time.strftime("%H:%M:%S", time.localtime(st["last_poll_at"])) if st["last_poll_at"] else None,
            "healthy": bool(st["last_poll_ok"]) and not stale,
            "stale": stale,
            "error": st["last_poll_error"],
        },
    )


@app.get("/partials/bans-table")
async def bans_table(
    request: Request,
    ip: str | None = None,
    source_type: str | None = None,
    country: str | None = None,
    scenario: str | None = None,
    status: str = "active",
    limit: int = Query(50, ge=1, le=2000),
):
    rows_raw = db.query_bans(
        ip=ip, source_type=source_type, country=country, scenario=scenario, status=status, limit=limit
    )
    rows = [_row_to_dict(r) for r in rows_raw]
    return templates.TemplateResponse(
        request,
        "partials/bans_table.html",
        {
            "bans": rows,
            "ip": ip or "",
            "source_type": source_type or "",
            "country": country or "",
            "scenario": scenario or "",
            "status": status,
            "limit": limit,
            "has_more": len(rows_raw) == limit,
        },
    )


@app.get("/")
@app.get("/stats")
async def stats_page(request: Request):
    return templates.TemplateResponse(request, "stats.html", {"active_page": "stats"})


@app.get("/partials/stats")
async def stats_partial(request: Request, status: str = "", period: str = ""):
    country_rows, country_has_prev, country_has_next = _paginate(
        db.stats_by_country(status=status, limit=_STATS_PAGE_SIZE), 0
    )
    scenario_rows, scenario_has_prev, scenario_has_next = _paginate(
        db.stats_by_scenario(status=status, limit=_STATS_PAGE_SIZE), 0
    )
    as_rows, as_has_prev, as_has_next = _paginate(
        db.stats_by_as(status=status, limit=_STATS_PAGE_SIZE), 0
    )
    repeat_rows_raw, repeat_has_prev, repeat_has_next = _paginate(
        db.stats_top_ips(period=period, limit=_STATS_PAGE_SIZE), 0
    )
    repeat_rows = [dict(r) for r in repeat_rows_raw]
    for r in repeat_rows:
        r["last_seen_str"] = _fmt_ts(r["last_seen"])

    return templates.TemplateResponse(
        request,
        "partials/stats.html",
        {
            "summary": db.stats_summary(),
            "by_source": db.stats_by_source_type(status=status),
            "status": status,
            "page_size": _STATS_PAGE_SIZE,
            "repeat_offender_threshold": settings.repeat_offender_threshold,
            "country_ban_threshold": settings.country_ban_threshold,
            "country_rows": country_rows,
            "country_offset": 0,
            "country_has_prev": country_has_prev,
            "country_has_next": country_has_next,
            "scenario_rows": scenario_rows,
            "scenario_offset": 0,
            "scenario_has_prev": scenario_has_prev,
            "scenario_has_next": scenario_has_next,
            "as_rows": as_rows,
            "as_offset": 0,
            "as_has_prev": as_has_prev,
            "as_has_next": as_has_next,
            "repeat_rows": repeat_rows,
            "repeat_offset": 0,
            "repeat_has_prev": repeat_has_prev,
            "repeat_has_next": repeat_has_next,
            "period": period,
            "retention_days": settings.retention_days,
        },
    )


@app.get("/partials/stats/panel")
async def stats_panel(
    request: Request, kind: str, status: str = "", offset: int = 0, period: str = ""
):
    common = {
        "status": status,
        "offset": offset,
        "page_size": _STATS_PAGE_SIZE,
        "repeat_offender_threshold": settings.repeat_offender_threshold,
        "country_ban_threshold": settings.country_ban_threshold,
    }
    if kind == "countries":
        rows, has_prev, has_next = _paginate(
            db.stats_by_country(status=status, limit=_STATS_PAGE_SIZE, offset=offset), offset
        )
        return templates.TemplateResponse(
            request, "partials/stats_panel_countries.html",
            {**common, "rows": rows, "has_prev": has_prev, "has_next": has_next},
        )
    if kind == "scenarios":
        rows, has_prev, has_next = _paginate(
            db.stats_by_scenario(status=status, limit=_STATS_PAGE_SIZE, offset=offset), offset
        )
        return templates.TemplateResponse(
            request, "partials/stats_panel_scenarios.html",
            {**common, "rows": rows, "has_prev": has_prev, "has_next": has_next},
        )
    if kind == "as":
        rows, has_prev, has_next = _paginate(
            db.stats_by_as(status=status, limit=_STATS_PAGE_SIZE, offset=offset), offset
        )
        return templates.TemplateResponse(
            request, "partials/stats_panel_as.html",
            {**common, "rows": rows, "has_prev": has_prev, "has_next": has_next},
        )
    if kind == "repeat-offenders":
        # Independent of `status` above (repeat offenders always cover both
        # active and expired bans) — `period` is its own, separate filter
        # local to this one panel, not shared with the other panels' status.
        raw, has_prev, has_next = _paginate(
            db.stats_top_ips(period=period, limit=_STATS_PAGE_SIZE, offset=offset), offset
        )
        rows = [dict(r) for r in raw]
        for r in rows:
            r["last_seen_str"] = _fmt_ts(r["last_seen"])
        return templates.TemplateResponse(
            request, "partials/stats_panel_repeat_offenders.html",
            {
                **common, "rows": rows, "has_prev": has_prev, "has_next": has_next,
                "period": period, "retention_days": settings.retention_days,
            },
        )
    return JSONResponse({"error": f"unknown kind: {kind}"}, status_code=400)


@app.get("/partials/abuse-report")
async def abuse_report_partial(request: Request, ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"error": "invalid ip"}, status_code=400)

    summary = db.ip_summary(ip)
    if summary is None:
        return JSONResponse({"error": "no ban history for this ip"}, status_code=404)

    abuse_email = await abuse.lookup_abuse_email(ip)
    report_text = reports.build_report_text(ip, summary)
    mailto_href = None
    if abuse_email:
        mailto_href = reports.build_mailto_href(ip, abuse_email, report_text)

    return templates.TemplateResponse(
        request,
        "partials/abuse_report.html",
        {"abuse_email": abuse_email, "mailto_href": mailto_href, "report_text": report_text},
    )


@app.get("/api/stats/summary")
async def api_stats_summary():
    s = db.stats_summary()
    return JSONResponse(
        {
            "CurrentlyActive": s["active"],
            "TotalBBans": s["total"],
            "UniqueIpsBanned": s["unique_ips"],
        }
    )


@app.get("/api/bans")
async def api_bans(
    ip: str | None = None,
    source_type: str | None = None,
    country: str | None = None,
    scenario: str | None = None,
    status: str = "active",
    limit: int = Query(200, le=1000),
):
    rows = [
        _row_to_dict(r)
        for r in db.query_bans(
            ip=ip, source_type=source_type, country=country, scenario=scenario, status=status, limit=limit
        )
    ]
    return JSONResponse(rows)


@app.get("/settings")
async def settings_page(request: Request):
    return templates.TemplateResponse(
        request, "settings.html",
        {
            "active_page": "settings",
            "cfg": runtime_settings.get_auto_report_settings(),
            "saved": False,
            "password_rejected": False,
            "key_configured": secrets_store.is_key_configured(),
        },
    )


@app.post("/settings/save")
async def settings_save(
    request: Request,
    auto_abuse_report: bool = Form(False),
    auto_abuse_threshold: int = Form(8),
    smtp_host: str = Form(""),
    smtp_port: int = Form(587),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
):
    password_rejected = runtime_settings.save_auto_report_settings(
        auto_abuse_report=auto_abuse_report,
        auto_abuse_threshold=auto_abuse_threshold,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_password=smtp_password or None,
        smtp_from=smtp_from,
    )
    return templates.TemplateResponse(
        request, "partials/settings_form.html",
        {
            "cfg": runtime_settings.get_auto_report_settings(),
            "saved": True,
            "password_rejected": password_rejected,
            "key_configured": secrets_store.is_key_configured(),
        },
    )


@app.post("/settings/test")
async def settings_test(
    request: Request,
    test_to: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: int = Form(587),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
):
    """Sends a real test email using exactly what's currently typed in the
    Settings form — deliberately independent of save_auto_report_settings(),
    so someone can try credentials before committing to them. An empty
    smtp_password field falls back to whatever's already saved/env-default
    (same "leave blank to keep it" convention as Save), since retyping a
    saved password just to test it would defeat the point of not
    redisplaying it."""
    if not test_to.strip():
        return templates.TemplateResponse(
            request, "partials/settings_test_result.html",
            {"ok": False, "message": "Enter an email address to send the test to."},
        )

    current = runtime_settings.get_auto_report_settings()
    cfg = mailer.SmtpConfig(
        host=smtp_host or None,
        port=smtp_port,
        user=smtp_user or None,
        password=smtp_password or current.smtp_password,
        from_addr=smtp_from or None,
    )
    try:
        await mailer.send_email(
            cfg, test_to.strip(),
            "npm-crowd-dash test email",
            "This is a test email from npm-crowd-dash's Settings page.\n\n"
            "If you got this, your SMTP settings work — you can save them now.",
        )
    except mailer.SmtpNotConfigured as exc:
        return templates.TemplateResponse(
            request, "partials/settings_test_result.html", {"ok": False, "message": str(exc)},
        )
    except Exception as exc:
        log.exception("settings test email failed")
        return templates.TemplateResponse(
            request, "partials/settings_test_result.html",
            {"ok": False, "message": f"Send failed: {exc}"},
        )
    return templates.TemplateResponse(
        request, "partials/settings_test_result.html",
        {"ok": True, "message": f"Test email sent to {test_to.strip()} — check your inbox."},
    )
