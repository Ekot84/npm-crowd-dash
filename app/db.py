import sqlite3
import time
from contextlib import contextmanager

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS bans (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    scope TEXT NOT NULL,
    value TEXT NOT NULL,
    scenario TEXT,
    reason_message TEXT,
    matched_rule TEXT,
    country TEXT,
    as_name TEXT,
    is_cloud_host INTEGER NOT NULL DEFAULT 0,
    origin TEXT,
    source_type TEXT NOT NULL DEFAULT 'crowdsec',
    duration TEXT,
    enrichment_attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
CREATE INDEX IF NOT EXISTS idx_bans_created_at ON bans(created_at);
CREATE INDEX IF NOT EXISTS idx_bans_source_type ON bans(source_type);

CREATE TABLE IF NOT EXISTS abuse_reports (
    ip TEXT PRIMARY KEY,
    sent_at INTEGER NOT NULL,
    times_banned_at_send INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Migration for dbs created before matched_rule existed.
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(bans)").fetchall()}
        if "matched_rule" not in cols:
            conn.execute("ALTER TABLE bans ADD COLUMN matched_rule TEXT")
        if "is_cloud_host" not in cols:
            conn.execute("ALTER TABLE bans ADD COLUMN is_cloud_host INTEGER NOT NULL DEFAULT 0")
        # Note: the abuse_reports table (for auto abuse reporting) needs no
        # migration branch here — it's a brand-new table, so the
        # CREATE TABLE IF NOT EXISTS in SCHEMA above already handles both
        # fresh installs and upgrades from a db that predates it.


def upsert_ban(row: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO bans (id, ip, scope, value, scenario, reason_message,
                               matched_rule, country, as_name, is_cloud_host, origin,
                               source_type, duration, created_at, expires_at, revoked_at)
            VALUES (:id, :ip, :scope, :value, :scenario, :reason_message,
                    :matched_rule, :country, :as_name, :is_cloud_host, :origin,
                    :source_type, :duration, :created_at, :expires_at, :revoked_at)
            ON CONFLICT(id) DO UPDATE SET
                scenario=excluded.scenario,
                reason_message=excluded.reason_message,
                matched_rule=excluded.matched_rule,
                country=excluded.country,
                as_name=excluded.as_name,
                is_cloud_host=excluded.is_cloud_host,
                expires_at=excluded.expires_at
            """,
            row,
        )


def revoke_ban(decision_id: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE bans SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (int(time.time()), decision_id),
        )


def revoke_by_ip_scope(ip: str, scope: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE bans SET revoked_at = ?
            WHERE ip = ? AND scope = ? AND revoked_at IS NULL
            """,
            (int(time.time()), ip, scope),
        )


def purge_old(retention_days: int) -> int:
    """Delete rows that have been revoked/expired for longer than
    retention_days. Rows still active (or never expiring) are always kept.
    Returns the number of rows deleted."""
    cutoff = int(time.time()) - retention_days * 86400
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM bans
            WHERE COALESCE(revoked_at, expires_at) IS NOT NULL
              AND COALESCE(revoked_at, expires_at) < ?
            """,
            (cutoff,),
        )
        return cur.rowcount


def purge_non_local_origin() -> int:
    """One-time-in-effect cleanup: removes bans stored before the poller
    started skipping CAPI/lists/cscli-origin decisions entirely (2026-08-01).
    Safe to run on every startup — once the backlog is gone this always
    matches zero rows, since ingestion no longer stores them."""
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM bans WHERE origin IS NOT NULL AND origin != 'crowdsec'"
        )
        return cur.rowcount


def query_bans(
    ip: str | None = None,
    source_type: str | None = None,
    country: str | None = None,
    scenario: str | None = None,
    status: str = "active",
    limit: int = 200,
) -> list[sqlite3.Row]:
    clauses = []
    params: list = []

    if ip:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip}%")
    if source_type:
        clauses.append("source_type = ?")
        params.append(source_type)
    if country:
        clauses.append("country LIKE ?")
        params.append(f"%{country}%")
    if scenario:
        clauses.append("(scenario LIKE ? OR reason_message LIKE ?)")
        params.append(f"%{scenario}%")
        params.append(f"%{scenario}%")

    now = int(time.time())
    if status == "active":
        clauses.append("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)")
        params.append(now)
    elif status == "expired":
        clauses.append("(revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?))")
        params.append(now)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM bans {where} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        return conn.execute(sql, params).fetchall()


def count_active_bans() -> int:
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count FROM bans
            WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
            """,
            (now,),
        ).fetchone()
        return row["count"]


def stats_summary() -> dict:
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) THEN 1 ELSE 0 END) AS active,
                COUNT(DISTINCT ip) AS unique_ips
            FROM bans
            """,
            (now,),
        ).fetchone()
        return dict(row)


def stats_by_country(status: str = "active", limit: int = 5, offset: int = 0) -> list[sqlite3.Row]:
    """Fetches limit+1 rows so callers can tell whether a next page exists
    without a separate COUNT query."""
    now = int(time.time())
    where = "WHERE country IS NOT NULL"
    params: list = []
    if status == "active":
        where += " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"
        params.append(now)
    elif status == "expired":
        where += " AND (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?))"
        params.append(now)
    params.append(limit + 1)
    params.append(offset)
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT country, COUNT(*) AS count
            FROM bans
            {where}
            GROUP BY country
            ORDER BY count DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()


_REPEAT_OFFENDER_PERIOD_SECONDS = {
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
}


def _repeat_offender_period_cutoff(period: str) -> int | None:
    """None means no cutoff (period is "all", empty, or unrecognized — same
    thing, kept as the backward-compatible default)."""
    seconds = _REPEAT_OFFENDER_PERIOD_SECONDS.get(period)
    if seconds is None:
        return None
    return int(time.time()) - seconds


def stats_top_ips(period: str = "all", limit: int = 5, offset: int = 0) -> list[sqlite3.Row]:
    """Repeat offenders, regardless of current (active/expired) status.
    Excludes CAPI/lists/cscli-origin bans — those were never observed locally
    (proactively pushed down from CrowdSec's shared community blocklist), so
    they're not something you can act on the way a real repeat local offender
    is; including them would bury genuinely-local repeat offenders under
    community-blocklist noise.

    period ("24h" / "7d" / "30d" / "all") scopes the *statistics themselves*,
    not just which IPs are shown: times_banned, first_seen and last_seen are
    all computed only from bans within the window, and the ranking follows
    from that — an IP banned 20 times last year but once in the last 24h
    shows up as "banned once" under the 24h filter, not "banned 20 times".
    "all" (the default, used whenever no period is given) reproduces the
    original unscoped behavior."""
    cutoff = _repeat_offender_period_cutoff(period)
    where = "WHERE (origin IS NULL OR origin = 'crowdsec')"
    params: list = []
    if cutoff is not None:
        where += " AND created_at >= ?"
        params.append(cutoff)
    params.append(limit + 1)
    params.append(offset)
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT ip, COUNT(*) AS times_banned, MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen, MAX(country) AS country,
                   MAX(as_name) AS as_name, MAX(is_cloud_host) AS is_cloud_host
            FROM bans
            {where}
            GROUP BY ip
            HAVING COUNT(*) > 1
            ORDER BY times_banned DESC, last_seen DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()


def bans_missing_enrichment(limit: int = 50) -> list[sqlite3.Row]:
    """Bans whose alert lookup came back empty at ingestion time — a race
    during a burst of local decisions, where the decision shows up in
    CrowdSec's stream slightly before its alert is queryable. Excludes
    non-local origins (CAPI community blocklist, subscribed 'lists', manual
    'cscli' entries) — those were never observed locally, so no alert will
    ever exist for them and retrying is pure waste. Capped at 3 attempts —
    confirmed 2026-08-04 that some rows never succeed (alert already aged
    out of CrowdSec's own retention by the time we retry), so without a cap
    the poller would retry the same handful of IPs forever, every cycle.
    Retried periodically by the poller (see _backfill_missing_enrichment)."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT id, ip FROM bans
            WHERE country IS NULL AND as_name IS NULL
              AND (origin IS NULL OR origin = 'crowdsec')
              AND enrichment_attempts < 3
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def increment_enrichment_attempts(ban_id: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE bans SET enrichment_attempts = enrichment_attempts + 1 WHERE id = ?",
            (ban_id,),
        )


def update_enrichment(
    ban_id: str, *, reason_message: str | None, matched_rule: str | None,
    country: str | None, as_name: str | None, is_cloud_host: bool,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE bans SET reason_message = ?, matched_rule = ?, country = ?,
                            as_name = ?, is_cloud_host = ?
            WHERE id = ?
            """,
            (reason_message, matched_rule, country, as_name, int(is_cloud_host), ban_id),
        )


def ip_summary(ip: str) -> dict | None:
    """Aggregate ban history for a single IP, for building an abuse report."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT ip, COUNT(*) AS times_banned, MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen, MAX(country) AS country,
                   MAX(as_name) AS as_name, MAX(is_cloud_host) AS is_cloud_host
            FROM bans
            WHERE ip = ?
            GROUP BY ip
            """,
            (ip,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        latest = conn.execute(
            """
            SELECT scenario, reason_message
            FROM bans
            WHERE ip = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
        if latest:
            result["scenario"] = latest["scenario"]
            result["reason_message"] = latest["reason_message"]
        return result


def _status_clause(status: str, now: int, params: list) -> str:
    """Shared active/expired/all condition used by every status-scoped stats
    query, so 'Active' means the same thing everywhere on the stats page."""
    if status == "active":
        params.append(now)
        return "revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"
    if status == "expired":
        params.append(now)
        return "(revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?))"
    return ""


def stats_by_source_type(status: str = "active") -> list[sqlite3.Row]:
    now = int(time.time())
    params: list = []
    status_sql = _status_clause(status, now, params)
    where = f"WHERE {status_sql}" if status_sql else ""
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT source_type, COUNT(*) AS count
            FROM bans
            {where}
            GROUP BY source_type
            ORDER BY count DESC
            """,
            params,
        ).fetchall()


def stats_by_as(status: str = "active", limit: int = 5, offset: int = 0) -> list[sqlite3.Row]:
    now = int(time.time())
    # as_name IS NOT NULL already excludes CAPI/lists rows in practice (they
    # never get alert-enriched), but origin is filtered explicitly too so
    # this stays correct even if that ever changes.
    clauses = ["as_name IS NOT NULL", "(origin IS NULL OR origin = 'crowdsec')"]
    params: list = []
    status_sql = _status_clause(status, now, params)
    if status_sql:
        clauses.append(status_sql)
    params.append(limit + 1)
    params.append(offset)
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT as_name, MAX(is_cloud_host) AS is_cloud_host,
                   REPLACE(GROUP_CONCAT(DISTINCT country), ',', ', ') AS countries,
                   COUNT(*) AS count
            FROM bans
            WHERE {' AND '.join(clauses)}
            GROUP BY as_name
            ORDER BY count DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()


def stats_by_scenario(status: str = "active", limit: int = 5, offset: int = 0) -> list[sqlite3.Row]:
    """Groups by the specific matched AppSec rule when we have one (e.g.
    'crowdsecurity/vpatch-env-access'), falling back to the decision's own
    scenario for plain CrowdSec bans. Without this, every AppSec ban would
    collapse into the single generic 'crowdsecurity/appsec-vpatch' collection
    name and the breakdown would be useless.

    Excludes CAPI/lists/cscli-origin bans — the shared community blocklist
    can dump thousands of entries under one scenario name, burying the small
    number of scenarios actually observed against this server."""
    now = int(time.time())
    clauses = ["COALESCE(matched_rule, scenario) IS NOT NULL", "(origin IS NULL OR origin = 'crowdsec')"]
    params: list = []
    status_sql = _status_clause(status, now, params)
    if status_sql:
        clauses.append(status_sql)
    params.append(limit + 1)
    params.append(offset)
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT COALESCE(matched_rule, scenario) AS scenario, COUNT(*) AS count
            FROM bans
            WHERE {' AND '.join(clauses)}
            GROUP BY COALESCE(matched_rule, scenario)
            ORDER BY count DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()


def auto_report_candidates(threshold: int, limit: int = 50) -> list[str]:
    """IPs that have crossed the auto-report ban threshold and don't already
    have a *successfully sent* report on file. A previous failed attempt
    (SMTP down, no abuse email found that day, etc.) doesn't block a retry —
    only status='sent' does, so a transient failure doesn't permanently skip
    an IP that should still get reported.

    Same local-origin exclusion as stats_top_ips: CAPI/lists/cscli decisions
    were never observed locally, so there's no real "repeat offender"
    behavior to report — just noise from the shared community blocklist."""
    with get_conn() as conn:
        return [
            row["ip"]
            for row in conn.execute(
                """
                SELECT ip, COUNT(*) AS times_banned
                FROM bans
                WHERE (origin IS NULL OR origin = 'crowdsec')
                GROUP BY ip
                HAVING COUNT(*) >= ?
                  AND ip NOT IN (SELECT ip FROM abuse_reports WHERE status = 'sent')
                ORDER BY times_banned DESC
                LIMIT ?
                """,
                (threshold, limit),
            ).fetchall()
        ]


def record_abuse_report(ip: str, *, times_banned_at_send: int, recipient: str, status: str) -> None:
    """status is 'sent' or 'failed'. Upserts so a retried failure updates the
    same row rather than piling up duplicates for one IP."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO abuse_reports (ip, sent_at, times_banned_at_send, recipient, status)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                sent_at=excluded.sent_at,
                times_banned_at_send=excluded.times_banned_at_send,
                recipient=excluded.recipient,
                status=excluded.status
            """,
            (ip, int(time.time()), times_banned_at_send, recipient, status),
        )
