import re
from datetime import datetime


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?:invalid user) )?"
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip_address>\S+)"
)


def parse_failed_login(line):
    """
    Parse a failed SSH login entry.

    Returns structured information for valid failed-login
    events and None for irrelevant or malformed entries.
    """

    if "Failed password" not in line:
        return None

    try:
        parts = line.split()

        timestamp_text = " ".join(parts[0:3])

        timestamp = datetime.strptime(
            f"{datetime.now().year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

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

    except (ValueError, IndexError):
        return None