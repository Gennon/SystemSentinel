from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

_T = TypeVar("_T")


def choose_geoip_database_path(*candidates: object) -> str:
    """Return the first non-empty string candidate, stripped."""
    for candidate in candidates:
        if isinstance(candidate, str):
            value = candidate.strip()
            if value:
                return value
    return ""


def geoip_country_code(ip_address: str, db_path: str) -> str | None:
    """Look up ISO country code for *ip_address* using a local GeoIP DB path."""

    def _reader(reader: Any) -> str | None:
        response = reader.country(ip_address)
        country = response.country.iso_code
        return str(country) if isinstance(country, str) and country.strip() else None

    return _with_geoip_reader(db_path, _reader)


def geoip_city_lat_lon(ip_address: str, db_path: str) -> tuple[float, float] | None:
    """Look up (latitude, longitude) for *ip_address* using a local GeoIP DB path."""

    def _reader(reader: Any) -> tuple[float, float] | None:
        response = reader.city(ip_address)
        latitude = response.location.latitude
        longitude = response.location.longitude
        if not isinstance(latitude, (int, float)) or not isinstance(longitude, (int, float)):
            return None
        return float(latitude), float(longitude)

    return _with_geoip_reader(db_path, _reader)


def _with_geoip_reader(db_path: str, callback: Callable[[Any], _T | None]) -> _T | None:
    normalized = db_path.strip()
    if not normalized:
        return None
    if not Path(normalized).is_file():
        return None
    try:
        import geoip2.database  # type: ignore[import-not-found]
        import geoip2.errors  # type: ignore[import-not-found]
    except ImportError:
        return None

    try:
        with geoip2.database.Reader(normalized) as reader:
            return callback(reader)
    except (FileNotFoundError, OSError, ValueError, geoip2.errors.AddressNotFoundError):
        return None
