"""Loopback HTTPS mock for the Falcon endpoints used by the connector."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import ssl
from urllib.parse import parse_qs, urlsplit


FILE = b"harmless connector test fixture\n"
DIGEST = hashlib.sha256(FILE).hexdigest()
CLIENT_ID = "mock-client"
CLIENT_SECRET = "mock-secret"
TOKEN = "mock-access-token"


def error(status, message):
    return status, {"errors": [{"code": status, "message": message}]}


class FalconFixture:
    """Keep paged alerts, sample downloads, and appended comments in memory."""

    def __init__(self):
        self.created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.alert_requests = []
        self.downloads = []
        self.notes = []
        self.file_code = 200
        self.content = FILE

    def dispatch(self, method, target, headers, body):
        route = urlsplit(target)
        if method == "POST" and route.path == "/oauth2/token":
            credentials = parse_qs(body.decode() if isinstance(body, bytes) else body)
            if credentials != {"client_id": [CLIENT_ID], "client_secret": [CLIENT_SECRET]}:
                return error(401, "Invalid mock credentials")
            return 201, {"access_token": TOKEN, "token_type": "bearer", "expires_in": 1800}

        if headers.get("Authorization") != "Bearer " + TOKEN:
            return error(401, "Mock bearer token required")
        if method == "POST" and route.path == "/alerts/combined/alerts/v1":
            return self.alert_page(json.loads(body))
        if method == "GET" and route.path == "/samples/entities/samples/v3":
            params = parse_qs(route.query)
            if params.get("ids") != [DIGEST]:
                return error(404, "Unknown sample")
            if params.get("password_protected") != ["false"]:
                return error(400, "Only raw fixture bytes are available")
            self.downloads.append(target)
            if self.file_code != 200:
                return error(self.file_code, "Sample unavailable")
            return 200, self.content
        if method == "PATCH" and route.path == "/alerts/entities/alerts/v3":
            return self.append_note(json.loads(body))
        if method == "GET" and route.path == "/mock/comments":
            return 200, {"resources": self.notes, "errors": []}
        return error(404, "Unknown mock endpoint")

    def alert_page(self, query):
        # Implement the endpoint/time window used by this connector, not a general FQL parser.
        match = re.fullmatch(r"product:'epp'\+created_timestamp:>='([^']+)'\+created_timestamp:<='([^']+)'",
                             query.get("filter", "")) if isinstance(query, dict) else None
        if not match or query.get("after") not in {None, "next"}:
            return error(400, "Unsupported alert filter or cursor")
        self.alert_requests.append(query)
        page = 2 if query.get("after") else 1
        resources, pagination = [], {}
        if match[1] <= self.created <= match[2]:
            resources.append({"composite_id": f"alert-{page}", "sha256": DIGEST, "filename": "test.txt",
                              "created_timestamp": self.created, "product": "epp"})
            if page == 1:
                resources.append({"composite_id": "no-file-hash", "created_timestamp": self.created, "product": "epp"})
                pagination["after"] = "next"
        return 200, {"resources": resources, "meta": {"pagination": pagination}, "errors": []}

    def append_note(self, update):
        if not isinstance(update, dict):
            return error(400, "Expected an alert update")
        ids = update.get("composite_ids")
        actions = update.get("action_parameters")
        if not isinstance(ids, list) or len(ids) != 1 or ids[0] not in ("alert-1", "alert-2"):
            return error(404, "Unknown mock alert")
        if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
            return error(400, "Expected one comment")
        if actions[0].get("name") != "append_comment" or not isinstance(actions[0].get("value"), str):
            return error(400, "Only append_comment is supported")
        self.notes.append(update)
        return 200, {"resources": [{"id": ids[0]}], "errors": []}


class Handler(BaseHTTPRequestHandler):
    def handle_api(self):
        try:
            size = int(self.headers.get("Content-Length", 0))
            if not 0 <= size <= 65536:
                status, data = error(413, "Request body too large")
            else:
                status, data = self.server.fixture.dispatch(self.command, self.path, self.headers, self.rfile.read(size))
        except (ValueError, TypeError):
            status, data = error(400, "Invalid request")
        binary = isinstance(data, bytes)
        payload = data if binary else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if binary else "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = handle_api


def make_server(cert, key, port=0):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.fixture = FalconFixture()
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True, help="PEM certificate valid for 127.0.0.1")
    parser.add_argument("--key", required=True, help="PEM private key for the local mock")
    parser.add_argument("--port", type=int, default=8443)
    options = parser.parse_args()
    with make_server(options.cert, options.key, options.port) as server:
        print(f"Falcon mock at https://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
