# Load the customer TOML file before opening the database or contacting either service.
from dataclasses import dataclass
from pathlib import Path
import tomllib
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    base_url: str
    client_id: str
    client_secret: str
    initial_lookback_hours: int
    cloud_api_url: str
    cloud_api_key: str
    report_base_url: str
    timeout_seconds: int
    proxy_url: str
    poll_seconds: int
    sample_wait_minutes: int
    max_file_mb: int
    database_path: str
    enable_reverser: bool = True
    post_alert_comments: bool = True

    @classmethod
    def load(cls, path):
        with Path(path).open("rb") as source:
            config = tomllib.load(source)
        groups = {
            "crowdstrike": ("base_url", "client_id", "client_secret", "initial_lookback_hours"),
            "joe_sandbox": ("cloud_api_url", "cloud_api_key", "report_base_url"),
            "connection": ("timeout_seconds", "proxy_url"),
            "service": ("poll_seconds", "sample_wait_minutes", "max_file_mb", "database_path"),
        }
        values = {}
        for section, keys in groups.items():
            for key in keys:
                value = config.get(section, {}).get(key)
                if cls.__annotations__[key] is int:
                    if type(value) is not int or value < 1:
                        raise ValueError(f"[{section}] {key} must be a positive integer")
                elif not isinstance(value, str) or (not value.strip() and key != "proxy_url"):
                    raise ValueError(f"Set [{section}] {key} in config.toml")
                values[key] = value.strip() if isinstance(value, str) else value
        # These addresses become the base for API requests and customer-facing report links.
        for key in ("base_url", "cloud_api_url", "report_base_url"):
            url = urlsplit(values[key])
            if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError(f"{key} must be an HTTPS URL")
            values[key] = values[key].rstrip("/")
        for section, key in (("joe_sandbox", "enable_reverser"), ("crowdstrike", "post_alert_comments")):
            values[key] = config[section].get(key, True)
            if type(values[key]) is not bool:
                raise ValueError(f"[{section}] {key} must be true or false")
        return cls(**values)
