"""Exercise the connector through the local Falcon mock over verified HTTPS."""
from dataclasses import replace
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest

from falcon_mock import CLIENT_ID, CLIENT_SECRET, DIGEST, FILE, make_server
from joe_falcon.api import Falcon, MissingFile, Rejected, Sandbox
from joe_falcon.config import Settings
from joe_falcon.worker import Worker
from test_workflow import FakeCloud, ROOT


class FalconHttpsTest(unittest.TestCase):
    def test_authentication_download_and_comment_delivery(self):
        # Give this test its own short-lived certificate and empty alert history.
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            cert, key = folder / "cert.pem", folder / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            template = (ROOT / "config.example.toml").read_text()
            for name, value in (("client_id", CLIENT_ID), ("client_secret", CLIENT_SECRET),
                                ("cloud_api_key", "mock-joe")):
                template = template.replace(f'{name} = ""', f'{name} = "{value}"')
            config = folder / "config.toml"
            config.write_text(template)
            with make_server(cert, key) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    settings = replace(Settings.load(config), base_url=f"https://127.0.0.1:{server.server_port}")
                    falcon = Falcon(replace(settings, client_secret="incorrect"))
                    falcon.http.verify = str(cert)
                    self.addCleanup(falcon.http.close)
                    with self.assertRaisesRegex(Rejected, "HTTP 401"):
                        falcon.sample(DIGEST)
                    falcon.settings = settings
                    with self.assertRaises(MissingFile):
                        falcon.sample("0" * 64)

                    # Only the Joe Sandbox side uses the in-process response adapter.
                    sandbox = Sandbox(settings)
                    sandbox_fixture = FakeCloud()
                    sandbox.http.mount("https://", sandbox_fixture)
                    self.addCleanup(sandbox.http.close)
                    db = sqlite3.connect(":memory:")
                    self.addCleanup(db.close)
                    worker = Worker(settings, falcon, sandbox, db)
                    sandbox_fixture.reverser_status = "running"
                    for _ in range(3):
                        worker.tick()
                    self.assertFalse(server.fixture.notes)
                    sandbox_fixture.reverser_status = "finished"
                    for _ in range(3):
                        worker.tick()
                    self.assertEqual(server.fixture.alert_requests[1]["after"], "next")
                    self.assertEqual(len(server.fixture.downloads), 1)
                    self.assertEqual(len(sandbox_fixture.posts), 1)
                    self.assertIn(FILE, sandbox_fixture.posts[0])
                    with falcon.request("GET", "/mock/comments") as response:
                        response.raise_for_status()
                        notes = response.json()["resources"]
                    expected = ("Joe Sandbox Cloud Verdict: Malicious\nThreat name: Not reported\n"
                                "Score: 99/100\nReport: https://jbxcloud.joesecurity.org/submission/701")
                    self.assertEqual(notes, [
                        {"composite_ids": [alert], "action_parameters": [{"name": "append_comment", "value": expected}]}
                        for alert in ("alert-1", "alert-2")])
                finally:
                    server.shutdown()
                    thread.join()
