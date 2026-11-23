"""HTTP clients for the Falcon alert workflow and Joe Sandbox Cloud."""
import hashlib
import logging
import re
import time
from urllib.parse import quote

import requests


class ServiceError(Exception):
    pass


class Rejected(ServiceError):
    """The remote service explicitly rejected the request."""


class ReverserUnavailable(Rejected):
    """The account lacks Joe Reverser and the submission was rejected."""


class Throttled(Rejected):
    def __init__(self, seconds):
        self.seconds = seconds
        super().__init__(f"Rate limited; retry after {seconds}s")


class MissingFile(Exception):
    pass


class InvalidSample(Exception):
    pass


class NoAnalysisResult(Exception):
    """The submission ended without a completed analysis result."""


def check_http(response):
    code = response.status_code
    if code == 429:
        delay = response.headers.get("Retry-After", "")
        raise Throttled(int(delay) if delay.isdigit() else 60)
    # A timeout can leave a remote write in doubt. Only a definite rejection permits a retry.
    if 400 <= code < 500 and code != 408:
        raise Rejected(f"HTTP {code} from {response.request.method} {response.request.path_url.split('?')[0]}")
    if not 200 <= code < 300:
        raise ServiceError(f"Unexpected HTTP {code}")


def json_body(response):
    check_http(response)
    data = response.json()
    if not isinstance(data, dict):
        raise ServiceError("Expected a JSON object")
    if data.get("errors") or data.get("error"):
        raise ServiceError("Service reported an error in the response")
    return data


def connection(settings):
    session = requests.Session()
    # Use the customer's configured proxy for both services, including sample transfers.
    session.trust_env = False
    if settings.proxy_url:
        session.proxies["https"] = settings.proxy_url
    return session


class Falcon:
    def __init__(self, settings):
        self.settings = settings
        self.http = connection(settings)
        self.token = ""
        self.expires = 0

    def request(self, method, path, **kwargs):
        # Renew before expiry; a revoked token is renewed on the next poll.
        if time.monotonic() >= self.expires:
            with self.http.post(self.settings.base_url + "/oauth2/token",
                                data={"client_id": self.settings.client_id,
                                      "client_secret": self.settings.client_secret},
                                timeout=self.settings.timeout_seconds, allow_redirects=False) as response:
                token = json_body(response)
                self.token = token["access_token"]
                self.expires = time.monotonic() + max(1, int(token["expires_in"]) - 60)
        response = self.http.request(method, self.settings.base_url + path,
                                     headers={"Authorization": "Bearer " + self.token},
                                     timeout=self.settings.timeout_seconds, allow_redirects=False, **kwargs)
        if response.status_code == 401:
            self.expires = 0
        return response

    def alerts(self, start, end):
        filters = f"product:'epp'+created_timestamp:>='{start}'+created_timestamp:<='{end}'"
        body = {"filter": filters, "sort": "created_timestamp|asc", "limit": 100}
        # Track page tokens so a repeated cursor cannot trap a discovery run in a loop.
        seen = set()
        while True:
            with self.request("POST", "/alerts/combined/alerts/v1", json=body) as response:
                page = json_body(response)
            yield from page["resources"]
            cursor = page["meta"].get("pagination", {}).get("after")
            if not cursor:
                return
            if cursor in seen:
                raise ServiceError("Falcon returned a repeated pagination cursor")
            seen.add(cursor)
            body["after"] = cursor

    def sample(self, digest):
        limit = self.settings.max_file_mb * 1024 * 1024
        with self.request("GET", "/samples/entities/samples/v3", stream=True,
                          params={"ids": digest, "password_protected": "false"}) as response:
            if response.status_code == 404:
                raise MissingFile
            check_http(response)
            content = bytearray()
            for chunk in response.iter_content(65536):
                if len(content) + len(chunk) > limit:
                    raise InvalidSample("File exceeds the configured size limit.")
                content.extend(chunk)
        # Verify the actual bytes against the alert hash before sending them to Joe Sandbox.
        if not content or hashlib.sha256(content).hexdigest() != digest:
            raise InvalidSample("Downloaded file does not match the Falcon SHA-256.")
        return bytes(content)

    def comment(self, alert_id, message):
        # Falcon addresses an alert by composite ID. Append the result to its existing comments.
        body = {"composite_ids": [alert_id],
                "action_parameters": [{"name": "append_comment", "value": message}]}
        with self.request("PATCH", "/alerts/entities/alerts/v3", json=body) as response:
            check_http(response)
            if response.content:
                json_body(response)


class Sandbox:
    def __init__(self, settings):
        self.settings = settings
        self.http = connection(settings)
        self.request_reverser = settings.enable_reverser

    def call(self, endpoint, fields, files=None):
        with self.http.post(self.settings.cloud_api_url + "/v2/" + endpoint,
                            data={"apikey": self.settings.cloud_api_key, **fields}, files=files,
                            timeout=self.settings.timeout_seconds, allow_redirects=False) as response:
            # Fall back only on the explicit entitlement rejection of a Reverser submission.
            if response.status_code == 400 and fields.get("analyze-on-reverser") == "1":
                payload = response.json()
                errors = payload.get("errors") if isinstance(payload, dict) else None
                if (isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                        and not payload.get("data") and errors[0].get("code") == 1
                        and errors[0].get("message") == "Joe Reverser is not enabled for your account"):
                    raise ReverserUnavailable("Joe Reverser is not enabled for this account")
            return json_body(response)["data"]

    def submit(self, content, filename, digest):
        fields = {"comments": "CrowdStrike Falcon SHA-256 " + digest,
                  "report-cache": "1", "accept-tac": "1",
                  "analyze-on-reverser": "1" if self.request_reverser else "0"}
        files = {"sample": (filename, content, "application/octet-stream")}
        try:
            data = self.call("submission/new", fields, files)
        except ReverserUnavailable:
            logging.getLogger(__name__).warning("Joe Reverser is unavailable; continuing with Joe Sandbox Cloud")
            self.request_reverser = False
            fields["analyze-on-reverser"] = "0"
            data = self.call("submission/new", fields, files)
        submission_id = str(data.get("submission_id", ""))
        if not re.fullmatch(r"[0-9]+", submission_id):
            raise ServiceError("Submission response did not contain a valid ID")
        return submission_id

    def result(self, submission_id):
        # Include previously requested Reverser jobs even if the setting has since changed.
        data = self.call("submission/info", {"submission_id": submission_id, "include-reverser-analyses": "1"})
        link = self.settings.report_base_url + "/submission/" + quote(submission_id, safe="")
        failed = {"failed", "error", "cancelled", "canceled"}
        status = str(data.get("status", "")).lower()
        if status in failed:
            raise NoAnalysisResult(f"Joe Sandbox submission {submission_id} {status}")
        if status != "finished":
            return None
        verdicts = []
        scores = []
        names = {}
        analyses = data.get("analyses") or []
        if not analyses or any(not item.get("webid") for item in analyses):
            raise NoAnalysisResult(f"Joe Sandbox submission {submission_id} is missing analysis IDs")
        # Falcon gets one comment after every analysis in this submission has finished.
        for item in analyses:
            report = self.call("analysis/info", {"webid": item["webid"]})
            if str(report.get("webid")) != str(item["webid"]):
                raise ServiceError("Analysis ID mismatch")
            status = str(report.get("status", "")).lower()
            if status in failed:
                raise NoAnalysisResult(f"Joe Sandbox analysis {item['webid']} {status}")
            if status != "finished":
                return None
            runs = report.get("runs") or []
            name = report.get("threatname")
            if isinstance(name, str):
                name = " ".join(name.split())
                if name and name.casefold() not in {"unknown", "none", "n/a", "-"}:
                    names.setdefault(name.casefold(), name)
            for part in [report, *runs]:
                if "detection" in part or part is not report or not runs:
                    verdicts.append(str(part.get("detection", "unknown")).lower())
                if part.get("error"):
                    verdicts.append("unknown")
                score = part.get("score")
                if type(score) in (float, int) and 0 <= score <= 100:
                    scores.append(score)
        # A single malicious or suspicious detection takes precedence. Clean requires agreement.
        if "malicious" in verdicts:
            verdict = "Malicious"
        elif "suspicious" in verdicts:
            verdict = "Suspicious"
        elif verdicts and all(value == "clean" for value in verdicts):
            verdict = "Clean"
        else:
            verdict = "Unknown"
        threat_name = ", ".join(names.values()) or "Not reported"
        score_text = f"{max(scores):g}/100" if scores else "Not reported"
        return f"Joe Sandbox Cloud Verdict: {verdict}\nThreat name: {threat_name}\nScore: {score_text}\nReport: {link}"
