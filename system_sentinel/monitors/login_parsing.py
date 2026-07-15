from __future__ import annotations

from datetime import time
from ipaddress import ip_address
import math
import re
from typing import Any

# Matches both:
#   "Failed password for root from 1.2.3.4 port 22 ssh2"
#   "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
#   "Connection closed by invalid user test 1.2.3.4 port 22 [preauth]"
_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)"
)
_CONN_CLOSED_RE = re.compile(
    r"Connection closed by (?:invalid user )?(\S+) ([\d.:a-fA-F]+) port (\d+)"
)
_ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (\S+) for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)"
)


def parse_failed_ssh_line(line: str) -> dict[str, Any] | None:
    """Parse a single auth log line and return extracted fields, or None if not a failure."""
    for pattern in (_FAILED_PASSWORD_RE, _CONN_CLOSED_RE):
        match = pattern.search(line)
        if match:
            username, ip_address_value, port_str = match.groups()
            return {
                "username": username,
                "ip_address": ip_address_value,
                "port": int(port_str),
            }
    return None


def parse_successful_ssh_line(line: str) -> dict[str, Any] | None:
    """Parse a successful SSH login auth line and return extracted fields."""
    match = _ACCEPTED_LOGIN_RE.search(line)
    if match is None:
        return None
    auth_method, username, ip_address_str, port_str = match.groups()
    return {
        "username": username,
        "ip_address": ip_address_str,
        "port": int(port_str),
        "auth_method": auth_method,
    }


def as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_hhmm(value: object, default: time) -> time:
    if not isinstance(value, str):
        return default
    parsed = value.strip()
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", parsed)
    if match is None:
        return default
    hours = int(match.group(1))
    minutes = int(match.group(2))
    if hours < 0 or hours > 23 or minutes < 0 or minutes > 59:
        return default
    return time(hour=hours, minute=minutes)


def is_time_within_window(current: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


def is_private_or_loopback_ip(ip_address_str: str) -> bool:
    try:
        parsed = ip_address(ip_address_str)
    except ValueError:
        return True
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )
