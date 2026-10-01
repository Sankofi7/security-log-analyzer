import re
from datetime import datetime


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?:invalid user) )?"
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip_address>\S+)"
)


def parse_timestamp(line):
    """
    Parse either a traditional syslog timestamp
    or an ISO 8601 timestamp used by newer Ubuntu systems.
    """

    parts = line.split()

    if not parts:
        return None

    first_part = parts[0]

    # Ubuntu 24.04 ISO 8601 format:
    # 2026-10-01T16:41:49.619910+00:00
    try:
        if "T" in first_part:
            return datetime.fromisoformat(first_part)
    except ValueError:
        return None

    # Traditional syslog format:
    # Oct 1 16:41:49
    try:
        timestamp_text = " ".join(parts[0:3])

        return datetime.strptime(
            f"{datetime.now().year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

    except (ValueError, IndexError):
        return None


def parse_failed_login(line):
    """
    Parse a failed SSH login entry.

    Supports both traditional syslog timestamps
    and ISO 8601 timestamps used by newer Ubuntu systems.

    Returns structured information for valid failed-login
    events and None for irrelevant or malformed entries.
    """

    if "Failed password" not in line:
        return None

    timestamp = parse_timestamp(line)

    if timestamp is None:
        return None

    match = FAILED_LOGIN_PATTERN.search(line)

    if match is None:
        return None

    username = match.group("username")
    ip_address = match.group("ip_address")

    return {
        "timestamp": timestamp,
        "username": username,
        "ip_address": ip_address
    }