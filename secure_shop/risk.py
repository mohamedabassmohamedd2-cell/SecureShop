"""Lab 5 — Location and time checks.

The lab keeps the password as the first gate and adds three checks: location
(haversine distance), time (access window), and a passkey. This module provides
the location and time helpers. The passkey concept lives in ``passkey.py``.
"""
import math

EARTH_RADIUS_KM = 6371.0
# Default access window from the lab: 08:00 up to (but not including) 22:00.
WINDOW_START = 8
WINDOW_END = 22
# Default radius from the lab: the login must be within 50 km of home.
RADIUS_KM = 50.0


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two (lat, lon) points in kilometres."""
    phi1, lam1, phi2, lam2 = map(math.radians, (lat1, lon1, lat2, lon2))
    dphi = phi2 - phi1
    dlam = lam2 - lam1
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2)
    return EARTH_RADIUS_KM * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def location_ok(lat1, lon1, lat2, lon2, radius_km=RADIUS_KM):
    """True when the login point is inside the enrolled radius of home."""
    return haversine_km(lat1, lon1, lat2, lon2) <= radius_km


def time_allowed(hour, start=WINDOW_START, end=WINDOW_END):
    """True when the local hour is inside [start, end). 08:00 allowed, 22:00 not."""
    return start <= hour < end
