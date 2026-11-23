# Entry point for the Compose service and its configuration and recovery commands.
import argparse
import fcntl
import logging
from pathlib import Path
import signal
import sqlite3
import threading

from .api import Falcon, Sandbox, Throttled
from .config import Settings
from .worker import Worker


def main():
    parser = argparse.ArgumentParser(description="Joe Sandbox Cloud connector for CrowdStrike Falcon")
    parser.add_argument("--config", default="config.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check-config", "run", "review"):
        commands.add_parser(name)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("alert_id")
    resolve.add_argument("decision", help="Joe submission ID, posted, or retry")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = Settings.load(args.config)
        if args.command == "check-config":
            print("Configuration valid.")
            return 0
        path = Path(settings.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path) + ".lock", "a") as lock:
            # Review can inspect an active worker. Only one process may submit or resolve alerts.
            if args.command != "review":
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError("Connector is already running; stop it before resolving an alert") from None
            db = sqlite3.connect(path)
            try:
                worker = Worker(settings, Falcon(settings), Sandbox(settings), db)
                if args.command == "review":
                    for row in worker.review():
                        print(row["phase"], row["id"], row["digest"])
                elif args.command == "resolve":
                    worker.resolve(args.alert_id, args.decision)
                else:
                    # A stop signal wakes the polling loop or lets the current poll finish.
                    stop = threading.Event()
                    for sig in (signal.SIGTERM, signal.SIGINT):
                        signal.signal(sig, lambda *_: stop.set())
                    logging.info("Monitoring Falcon endpoint alerts")
                    for row in worker.review():
                        logging.warning("Review interrupted %s for Falcon alert %s", row["phase"], row["id"])
                    while not stop.is_set():
                        delay = settings.poll_seconds
                        try:
                            worker.tick()
                        except Throttled as exc:
                            delay = max(delay, exc.seconds)
                            logging.warning("%s", exc)
                        stop.wait(delay)
            finally:
                db.close()
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
