import re
from datetime import datetime

FAILED_REGEX = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPTED_REGEX = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_timestamp(ts: str):
    """
    Supports:
    - 'Feb 12 12:20:11'
    - '2026-02-12T12:20:11'
    """
    ts = ts.strip()

    # ISO format from journalctl
    if "T" in ts and ts[4] == "-":
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")

    # Syslog format (no year included)
    current_year = datetime.now().year
    return datetime.strptime(f"{current_year} {ts}", "%Y %b %d %H:%M:%S")


def parse_auth_log(filepath: str):
    events = []

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()

            failed_match = FAILED_REGEX.search(line)
            if failed_match:
                events.append({
                    "timestamp": parse_timestamp(failed_match.group("timestamp")),
                    "status": "FAILED",
                    "username": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                    "raw": line
                })
                continue

            accepted_match = ACCEPTED_REGEX.search(line)
            if accepted_match:
                events.append({
                    "timestamp": parse_timestamp(accepted_match.group("timestamp")),
                    "status": "SUCCESS",
                    "username": accepted_match.group("user"),
                    "ip": accepted_match.group("ip"),
                    "raw": line
                })
                continue

    return events

