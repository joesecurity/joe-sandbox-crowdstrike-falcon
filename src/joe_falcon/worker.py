"""Persist alert progress and resume safe operations after an interruption."""
from datetime import datetime, timezone
import logging
import re
import sqlite3
import time

import requests

from .api import InvalidSample, MissingFile, NoAnalysisResult, Rejected, ServiceError, Throttled

log = logging.getLogger(__name__)
API_ERRORS = (ServiceError, requests.RequestException, KeyError, ValueError)


def timestamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Worker:
    def __init__(self, settings, falcon, sandbox, database):
        self.settings, self.falcon, self.sandbox = settings, falcon, sandbox
        self.db = database
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoint (id INTEGER PRIMARY KEY, until INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, digest TEXT NOT NULL, filename TEXT NOT NULL,
                first_seen INTEGER NOT NULL, phase TEXT NOT NULL DEFAULT 'download',
                submission_id TEXT, message TEXT
            );
            CREATE INDEX IF NOT EXISTS by_digest ON alerts(digest);
            CREATE INDEX IF NOT EXISTS by_phase ON alerts(phase);
        """)

    def discover(self, now):
        cursor = self.db.execute("SELECT until FROM checkpoint WHERE id=1").fetchone()
        # Replay a short overlap to pick up alerts indexed just after the previous scan.
        start = cursor["until"] - 300 if cursor else now - self.settings.initial_lookback_hours * 3600
        for alert in self.falcon.alerts(timestamp(start), timestamp(now)):
            digest = str(alert.get("sha256", "")).lower()
            alert_id = alert.get("composite_id")
            if not alert_id or not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            basename = re.split(r"[/\\]", str(alert.get("filename") or alert.get("filepath") or ""))[-1]
            filename = re.sub(r"[^a-zA-Z0-9_.-]", "_", basename)[-200:].strip(".") or digest
            with self.db:
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO alerts(id,digest,filename,first_seen) VALUES(?,?,?,?)",
                    (alert_id, digest, filename, now)).rowcount
            if inserted:
                log.info("Queued Falcon alert %s SHA-256 %s", alert_id, digest)
        with self.db:
            # Advance only after every page is queued. Replaying a partial scan is safe by alert ID.
            self.db.execute("INSERT OR REPLACE INTO checkpoint VALUES(1,?)", (now,))

    def advance(self, row, phase, **changes):
        # Commit the next phase and its submission ID or message in one transaction.
        columns = {"phase": phase, **changes}
        with self.db:
            self.db.execute("UPDATE alerts SET " + ", ".join(key + "=?" for key in columns) + " WHERE id=?",
                            (*columns.values(), row["id"]))

    def prepare(self, row, now):
        # Reuse a submission for the same bytes across Falcon alerts.
        existing = self.db.execute(
            "SELECT submission_id FROM alerts WHERE digest=? AND submission_id IS NOT NULL LIMIT 1",
            (row["digest"],)).fetchone()
        if existing:
            self.advance(row, "poll", submission_id=existing["submission_id"])
            return
        # Another alert may have sent these bytes and lost the reply. Wait for reconciliation.
        if self.db.execute("SELECT 1 FROM alerts WHERE digest=? AND phase='sending'",
                           (row["digest"],)).fetchone():
            return
        try:
            payload = self.falcon.sample(row["digest"])
        except MissingFile:
            if now - row["first_seen"] >= self.settings.sample_wait_minutes * 60:
                self.skip(row, "Falcon could not supply the file for analysis.")
            return
        except InvalidSample as exc:
            self.skip(row, str(exc))
            return

        # A lost POST response can mean the upload succeeded. Persist intent before sending.
        self.advance(row, "sending")
        try:
            submission = self.sandbox.submit(payload, row["filename"], row["digest"])
        except Rejected:
            self.advance(row, "download")
            raise
        self.advance(row, "poll", submission_id=submission)
        log.info("Falcon alert %s submitted to Joe Sandbox as %s", row["id"], submission)

    def skip(self, row, reason):
        self.advance(row, "skipped", message=reason)
        log.warning("Falcon alert %s SHA-256 %s skipped: %s", row["id"], row["digest"], reason)

    def process(self, row, now):
        if row["phase"] == "download":
            self.prepare(row, now)
        elif row["phase"] == "poll":
            try:
                message = self.sandbox.result(row["submission_id"])
            except NoAnalysisResult as exc:
                self.skip(row, str(exc))
                return
            if message is not None:
                self.advance(row, "comment", message=message)
        elif row["phase"] == "comment":
            if not self.settings.post_alert_comments:
                self.advance(row, "done")
                log.info("Falcon alert %s completed with alert comments disabled", row["id"])
                return
            # Re-evaluate comments queued by an older installation before sending them.
            if not row["message"].startswith("Joe Sandbox Cloud Verdict: "):
                if row["submission_id"]:
                    self.advance(row, "poll", message=None)
                else:
                    self.skip(row, row["message"])
                return
            # Record intent before writing to Falcon so a lost reply cannot duplicate the comment.
            self.advance(row, "posting")
            try:
                self.falcon.comment(row["id"], row["message"])
            except Rejected:
                self.advance(row, "comment")
                raise
            self.advance(row, "done")
            log.info("Comment delivered to Falcon alert %s", row["id"])

    def tick(self):
        now = int(time.time())
        try:
            self.discover(now)
        except Throttled:
            raise
        except API_ERRORS as exc:
            log.warning("Falcon discovery failed (%s); will retry", safe_error(exc))
        # Interrupted writes stay in sending or posting for manual review; reads can resume.
        pending = self.db.execute("SELECT * FROM alerts WHERE phase IN ('download','poll','comment') ORDER BY rowid")
        for row in pending.fetchall():
            try:
                self.process(row, now)
            except Throttled:
                raise
            except API_ERRORS as exc:
                phase = self.db.execute("SELECT phase FROM alerts WHERE id=?", (row["id"],)).fetchone()[0]
                action = "inspect with the review command" if phase in {"sending", "posting"} else "will retry"
                log.warning("Falcon alert %s at %s (%s); %s", row["id"], phase, safe_error(exc), action)

    def review(self):
        return self.db.execute("SELECT id,digest,phase FROM alerts WHERE phase IN ('sending','posting') ORDER BY id")

    def resolve(self, alert_id, decision):
        row = self.db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        # An operator can attach a verified submission ID, or authorize a retry after checking.
        if row and row["phase"] == "sending":
            if re.fullmatch(r"[0-9]+", decision):
                self.advance(row, "poll", submission_id=decision)
                return
            if decision == "retry":
                self.advance(row, "download")
                return
        if row and row["phase"] == "posting" and decision in {"posted", "retry"}:
            self.advance(row, "done" if decision == "posted" else "comment")
            return
        raise ValueError("Decision does not match an alert awaiting review")


def safe_error(exc):
    # Request exception messages may contain query strings or proxy credentials.
    return str(exc) if isinstance(exc, ServiceError) else type(exc).__name__
