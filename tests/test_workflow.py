# Offline workflow tests exercise HTTP serialization, SQLite recovery, and Falcon comment delivery.
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import requests
from requests.adapters import BaseAdapter

from joe_falcon.api import Falcon, Sandbox
from joe_falcon.config import Settings
from joe_falcon.worker import Worker


FILE = b"harmless connector test fixture\n"
DIGEST = hashlib.sha256(FILE).hexdigest()
ROOT = Path(__file__).resolve().parents[1]


class FakeCloud(BaseAdapter):
    """Exercise the real request serialization without contacting either service."""
    def __init__(self):
        self.posts = []
        self.notes = []
        self.alert_requests = []
        self.downloads = []
        self.file_code = 200
        self.content = FILE
        self.submit_timeout = False
        self.note_timeout = False
        self.analysis_status = "finished"
        self.submission_status = "finished"
        self.threat_name = None
        self.reverser_name = None
        self.score = 82
        self.verdict = "malicious"
        self.run_error = ""
        self.reverser_status = None
        self.reverser_rejection = None

    def close(self):
        pass

    def send(self, request, **kwargs):
        path = request.path_url.split("?")[0]
        code = 200
        if path == "/oauth2/token":
            data = {"access_token": "test-token", "expires_in": 1800}
        elif path == "/alerts/combined/alerts/v1":
            query = json.loads(request.body)
            self.alert_requests.append(query)
            # Both pages reference the same sample, alongside an alert without a usable hash.
            page = 2 if "after" in query else 1
            data = {"resources": [{"composite_id": f"alert-{page}", "sha256": DIGEST,
                                   "filename": "test.txt"},
                                  {"composite_id": "no-file-hash"}],
                    "meta": {"pagination": {"after": "next"} if page == 1 else {}}}
        elif path == "/samples/entities/samples/v3":
            self.downloads.append(request.path_url)
            data, code = self.content, self.file_code
        elif path == "/api/v2/submission/new":
            self.posts.append(request.body)
            if self.submit_timeout:
                raise requests.Timeout
            data = {"data": {"submission_id": 701}}
            if self.reverser_rejection and b'name="analyze-on-reverser"\r\n\r\n1' in request.body:
                code = 400
                data = {"errors": [{"code": 1, "message": self.reverser_rejection}]}
        elif path == "/api/v2/submission/info":
            data = {"data": {"status": self.submission_status, "analyses": [{"webid": 98}]}}
            if self.reverser_status and parse_qs(request.body).get("include-reverser-analyses") == ["1"]:
                data["data"]["analyses"].append({"analysis_type": "reverser", "webid": "r-test"})
        elif path == "/api/v2/analysis/info":
            data = {"data": {"webid": 98, "status": self.analysis_status,
                             "threatname": self.threat_name,
                             "runs": [{"detection": self.verdict, "score": self.score, "error": self.run_error}]}}
            if parse_qs(request.body)["webid"] == ["r-test"]:
                data = {"data": {"webid": "r-test", "status": self.reverser_status,
                                 "threatname": self.reverser_name, "runs": [{"detection": "malicious", "score": 99}]}}
        elif path == "/alerts/entities/alerts/v3":
            self.notes.append(json.loads(request.body))
            if self.note_timeout:
                raise requests.Timeout
            data = {"resources": [], "errors": []}
        else:
            raise AssertionError(f"Unexpected API request: {path}")
        if path.startswith(("/alerts/", "/samples/")):
            assert request.headers["Authorization"] == "Bearer test-token"
        response = requests.Response()
        response.status_code, response.request = code, request
        response.raw = io.BytesIO(data if isinstance(data, bytes) else json.dumps(data).encode())
        return response


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)
        config = (ROOT / "config.example.toml").read_text()
        for key in ("client_id", "client_secret", "cloud_api_key"):
            config = config.replace(f'{key} = ""', f'{key} = "example"')
        self.config_file = self.path / "config.toml"
        self.config_file.write_text(config)
        settings = Settings.load(self.config_file)
        self.http = FakeCloud()
        self.falcon = Falcon(settings)
        self.sandbox = Sandbox(settings)
        for client in (self.falcon, self.sandbox):
            client.http.mount("https://", self.http)
        self.database_path = self.path / "state.db"
        self.settings = settings
        self.restart()

    def restart(self):
        if hasattr(self, "db"):
            self.db.close()
        # Reopen the same SQLite file to simulate a connector restart with pending work.
        self.db = sqlite3.connect(self.database_path)
        self.addCleanup(self.db.close)
        self.worker = Worker(self.settings, self.falcon, self.sandbox, self.db)

    def run_polls(self, count=3):
        # Each poll advances an alert by one phase, just as the service loop does.
        for _ in range(count):
            self.worker.tick()

    def test_two_alerts_share_one_submission_across_restart(self):
        self.http.analysis_status = "running"
        self.run_polls()
        self.assertFalse(self.http.notes)
        self.restart()
        self.http.analysis_status = "finished"
        self.run_polls()
        self.assertEqual(len(self.http.posts), 1)
        self.assertIn(FILE, self.http.posts[0])
        self.assertIn(b'filename="test.txt"', self.http.posts[0])
        self.assertEqual(len(self.http.downloads), 1)
        self.assertIn("password_protected=false", self.http.downloads[0])
        self.assertEqual(self.http.alert_requests[1]["after"], "next")
        self.assertEqual([note["composite_ids"] for note in self.http.notes], [["alert-1"], ["alert-2"]])
        for note in self.http.notes:
            self.assertEqual([action["name"] for action in note["action_parameters"]], ["append_comment"])
            message = note["action_parameters"][0]["value"]
            self.assertEqual(message, "Joe Sandbox Cloud Verdict: Malicious\nThreat name: Not reported\n"
                             "Score: 82/100\nReport: https://jbxcloud.joesecurity.org/submission/701")

    def test_missing_sample_recovers_if_it_appears_later(self):
        self.http.file_code = 404
        self.run_polls(1)
        self.assertFalse(self.http.posts)
        self.http.file_code = 200
        self.run_polls()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(len(self.http.notes), 2)

    def test_alert_comments_can_be_disabled_without_disabling_analysis(self):
        template = self.config_file.read_text()
        self.config_file.write_text(template.replace("post_alert_comments = true", ""))
        self.assertTrue(Settings.load(self.config_file).post_alert_comments)
        self.config_file.write_text(template.replace("post_alert_comments = true", "post_alert_comments = false"))
        self.worker.settings = Settings.load(self.config_file)
        self.run_polls()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM alerts WHERE phase='done'").fetchone()[0], 2)
        self.assertFalse(self.http.notes)

    def test_waits_for_reverser_and_uses_its_verdict_and_score(self):
        self.http.verdict = "clean"
        self.http.threat_name = " Emotet "
        self.http.reverser_name = "eMoTeT"
        self.http.reverser_status = "running"
        self.run_polls()
        self.assertIn(b'name="analyze-on-reverser"\r\n\r\n1', self.http.posts[0])
        self.assertFalse(self.http.notes)
        self.http.reverser_status = "finished"
        self.run_polls()
        message = self.http.notes[0]["action_parameters"][0]["value"]
        self.assertIn("Malicious", message)
        self.assertIn("99/100", message)
        self.assertEqual(message.splitlines()[1], "Threat name: Emotet")

    def test_reverser_entitlement_rejection_falls_back_once(self):
        self.http.reverser_rejection = "Joe Reverser is not enabled for your account"
        self.run_polls()
        self.assertEqual(len(self.http.posts), 2)
        self.assertIn(b'name="analyze-on-reverser"\r\n\r\n0', self.http.posts[1])
        self.assertFalse(self.sandbox.request_reverser)
        self.assertEqual(len(self.http.notes), 2)

    def test_unrelated_rejection_does_not_disable_reverser(self):
        from joe_falcon.api import Rejected
        self.http.reverser_rejection = "File rejected for another reason"
        with self.assertRaises(Rejected):
            self.sandbox.submit(FILE, "test.txt", DIGEST)
        self.assertEqual(len(self.http.posts), 1)
        self.assertTrue(self.sandbox.request_reverser)

    def test_disabled_setting_and_config_without_new_option(self):
        config = self.config_file.read_text()
        self.config_file.write_text(config.replace("enable_reverser = true", ""))
        self.assertTrue(Settings.load(self.config_file).enable_reverser)
        self.config_file.write_text(config.replace("enable_reverser = true", "enable_reverser = false"))
        sandbox = Sandbox(Settings.load(self.config_file))
        sandbox.http.mount("https://", self.http)
        sandbox.submit(FILE, "test.txt", DIGEST)
        self.assertIn(b'name="analyze-on-reverser"\r\n\r\n0', self.http.posts[0])

    def test_missing_sample_expires_but_forbidden_is_retried(self):
        self.http.file_code = 403
        with patch("joe_falcon.worker.time.time", return_value=10000):
            self.run_polls(1)
        with patch("joe_falcon.worker.time.time", return_value=14000):
            self.run_polls(2)
            self.assertFalse(self.http.notes)
            self.http.file_code = 404
            self.run_polls(2)
        self.assertFalse(self.http.posts)
        self.assertFalse(self.http.notes)
        self.assertEqual(self.db.execute("SELECT count(*) FROM alerts WHERE phase='skipped'").fetchone()[0], 2)

    def test_hash_mismatch_never_submitted(self):
        self.http.content = b"different file"
        self.run_polls()
        self.assertFalse(self.http.posts)
        self.assertFalse(self.http.notes)
        self.assertEqual(self.db.execute("SELECT count(*) FROM alerts WHERE phase='skipped'").fetchone()[0], 2)

    def test_size_limit_is_logged_without_a_comment(self):
        from dataclasses import replace
        self.falcon.settings = replace(self.settings, max_file_mb=1)
        self.http.content = b"x" * (1024 * 1024 + 1)
        with self.assertLogs("joe_falcon.worker", level="WARNING") as captured:
            self.run_polls()
        self.assertIn("size limit", captured.output[0])
        self.assertFalse(self.http.posts)
        self.assertFalse(self.http.notes)

    def test_canceled_submission_and_failed_reverser_do_not_post(self):
        self.http.submission_status = "canceled"
        self.run_polls()
        self.assertFalse(self.http.notes)
        self.assertEqual(self.db.execute("SELECT phase FROM alerts LIMIT 1").fetchone()[0], "skipped")
        self.db.execute("UPDATE alerts SET phase='poll'")
        self.http.submission_status = "finished"
        self.http.reverser_status = "failed"
        self.run_polls()
        self.assertFalse(self.http.notes)
        self.assertEqual(self.db.execute("SELECT phase FROM alerts LIMIT 1").fetchone()[0], "skipped")

    def test_missing_score_and_placeholder_name(self):
        self.http.score, self.http.threat_name = None, "N/A"
        self.run_polls()
        message = self.http.notes[0]["action_parameters"][0]["value"]
        self.assertIn("Threat name: Not reported\nScore: Not reported\n", message)

    def test_legacy_queued_comments_are_rechecked_after_restart(self):
        self.run_polls(1)
        with self.db:
            self.db.execute("UPDATE alerts SET phase='comment', message='Joe Sandbox Cloud verdict: Malicious'")
            self.db.execute("UPDATE alerts SET submission_id=NULL, message='File unavailable' WHERE id='alert-2'")
        self.restart()
        self.run_polls()
        self.assertEqual(len(self.http.notes), 1)
        self.assertIn("Threat name: Not reported", self.http.notes[0]["action_parameters"][0]["value"])

    def test_lost_submission_response_requires_reconciliation(self):
        self.http.submit_timeout = True
        self.run_polls()
        self.restart()
        self.run_polls()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual([row["id"] for row in self.worker.review()], ["alert-1"])
        self.worker.resolve("alert-1", "701")
        self.run_polls()
        self.assertEqual(len(self.http.notes), 2)

    def test_lost_comment_response_does_not_duplicate(self):
        self.http.note_timeout = True
        self.run_polls(4)
        self.restart()
        for alert_id in ("alert-1", "alert-2"):
            self.worker.resolve(alert_id, "posted")
        self.run_polls()
        self.assertEqual(len(self.http.notes), 2)

    def test_errored_run_does_not_establish_a_clean_verdict(self):
        self.http.verdict, self.http.run_error = "clean", "analysis incomplete"
        self.run_polls()
        self.assertIn("Unknown", self.http.notes[0]["action_parameters"][0]["value"])


if __name__ == "__main__":
    unittest.main()
