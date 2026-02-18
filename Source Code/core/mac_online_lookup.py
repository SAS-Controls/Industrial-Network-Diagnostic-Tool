"""
SAS Network Diagnostics Tool — Online MAC Vendor Lookup
Enriches MAC address vendor information by querying the IEEE OUI database
online (via maclookup.app API), falling back to the local offline database
when there is no internet connection.

The online lookup is used as a post-scan enrichment step so that:
  - Scans are never blocked by slow/missing internet
  - Every device gets at least the local-DB vendor name immediately
  - Unknown vendors get a second chance via online lookup
"""

import logging
import re
import threading
import time
import urllib.request
import urllib.error
import json
from typing import Callable, Dict, List, Optional, Tuple

from core.mac_vendors import lookup_vendor

logger = logging.getLogger(__name__)

# In-memory cache: OUI prefix → (vendor_name, category)
_cache: Dict[str, Tuple[str, str]] = {}
_cache_lock = threading.Lock()

# Rate-limit: maclookup.app free tier = 2 req/s
_MIN_INTERVAL = 0.55  # seconds between requests
_last_request_time = 0.0
_rate_lock = threading.Lock()

# API endpoint (no key required for basic lookups)
_API_URL = "https://api.maclookup.app/v2/macs/{oui}"


def _normalize_oui(mac_address: str) -> str:
    """Extract and normalize the OUI prefix (first 6 hex chars, uppercase)."""
    clean = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 6:
        return ""
    return clean[:6]


def _oui_to_colon(oui6: str) -> str:
    """Convert 6-char OUI to colon-separated format for local DB lookup."""
    return f"{oui6[0:2]}:{oui6[2:4]}:{oui6[4:6]}"


def _categorize_vendor(name: str) -> str:
    """
    Best-effort category assignment for an online-resolved vendor name.
    Returns one of: automation, networking, computing, other
    """
    lower = name.lower()

    automation_keywords = [
        "rockwell", "allen-bradley", "siemens", "schneider", "beckhoff",
        "omron", "mitsubishi electric", "abb", "honeywell", "emerson",
        "yokogawa", "endress", "phoenix contact", "wago", "pilz",
        "turck", "balluff", "ifm", "sick", "keyence", "banner",
        "automation", "plc", "drives", "molex", "harting",
        "prosoft", "red lion", "advantech", "weidmuller", "festo",
        "danfoss", "lenze", "sew", "nord", "rexroth", "bosch rexroth",
        "delta electronics", "eaton", "ge fanuc", "ge intelligent",
        "national instruments", "b&r", "bernecker", "elau",
        "hirschmann", "moxa", "westermo",
    ]
    networking_keywords = [
        "cisco", "juniper", "arista", "ubiquiti", "netgear", "tp-link",
        "d-link", "linksys", "mikrotik", "aruba", "ruckus", "fortinet",
        "palo alto", "sophos", "watchguard", "zyxel", "brocade",
        "extreme networks", "allied telesis", "draytek", "huawei",
        "hirschmann", "moxa", "westermo", "hewlett packard enterprise",
        "switch", "router", "firewall", "wireless",
    ]
    computing_keywords = [
        "dell", "hp ", "hewlett-packard", "lenovo", "intel", "amd",
        "supermicro", "apple", "microsoft", "vmware", "nvidia",
        "asustek", "gigabyte", "msi", "acer", "samsung electronics",
        "lg electronics",
    ]

    for kw in automation_keywords:
        if kw in lower:
            return "automation"
    for kw in networking_keywords:
        if kw in lower:
            return "networking"
    for kw in computing_keywords:
        if kw in lower:
            return "computing"

    return "other"


def lookup_vendor_online(mac_address: str) -> Tuple[str, str]:
    """
    Look up a MAC vendor via the online maclookup.app API.

    Returns:
        (vendor_name, category) — or ("", "") if lookup failed
    """
    global _last_request_time

    oui6 = _normalize_oui(mac_address)
    if not oui6:
        return ("", "")

    # Check cache first
    with _cache_lock:
        if oui6 in _cache:
            return _cache[oui6]

    # Rate limiting
    with _rate_lock:
        now = time.time()
        wait = _MIN_INTERVAL - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.time()

    try:
        url = _API_URL.format(oui=oui6)
        req = urllib.request.Request(url, headers={
            "User-Agent": "SAS-NetDiag/2.5",
            "Accept": "application/json",
        })

        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        company = data.get("company", "").strip()
        if not company or company.lower() in ("", "n/a", "private", "unknown"):
            # Cache the miss so we don't retry
            with _cache_lock:
                _cache[oui6] = ("", "")
            return ("", "")

        category = _categorize_vendor(company)

        with _cache_lock:
            _cache[oui6] = (company, category)

        return (company, category)

    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        logger.debug(f"Online MAC lookup failed for {oui6}: {e}")
        return ("", "")
    except Exception as e:
        logger.debug(f"Online MAC lookup error for {oui6}: {e}")
        return ("", "")


def check_internet() -> bool:
    """Quick check whether we can reach the MAC lookup API."""
    try:
        req = urllib.request.Request(
            "https://api.maclookup.app/v2/macs/000000",
            headers={"User-Agent": "SAS-NetDiag/2.5"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def enrich_vendor(mac_address: str, try_online: bool = True) -> Tuple[str, str]:
    """
    Unified vendor lookup: local DB first, online API if local returns Unknown.

    Args:
        mac_address: MAC in any standard format
        try_online: If True and local lookup returns Unknown, try the API

    Returns:
        (vendor_name, category)
    """
    # Local DB first (instant, always available)
    name, cat = lookup_vendor(mac_address)

    if name != "Unknown":
        return (name, cat)

    if not try_online:
        return (name, cat)

    # Try online
    online_name, online_cat = lookup_vendor_online(mac_address)
    if online_name:
        return (online_name, online_cat)

    return (name, cat)


def enrich_devices_online(
    devices: list,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> int:
    """
    Post-scan enrichment: try online MAC lookup for devices with Unknown vendor.

    Modifies devices in place. Returns number of devices enriched.

    Args:
        devices: List of DiscoveredEndpoint objects
        progress_callback: Called with (pct, message)
        cancel_event: Set to abort

    Returns:
        Number of devices that got a new vendor name
    """
    # Find devices that need enrichment
    unknowns = [d for d in devices
                 if d.mac_address
                 and (not d.vendor_name or d.vendor_name == "Unknown")]

    if not unknowns:
        return 0

    # Quick connectivity check — don't waste time probing if offline
    if not check_internet():
        logger.info("Online MAC lookup skipped — no internet connectivity")
        if progress_callback:
            progress_callback(1.0, "MAC lookup skipped (offline)")
        return 0

    enriched = 0
    total = len(unknowns)

    for i, dev in enumerate(unknowns):
        if cancel_event and cancel_event.is_set():
            break

        if progress_callback:
            pct = (i + 1) / total
            progress_callback(pct, f"Looking up {dev.mac_address}... ({i+1}/{total})")

        online_name, online_cat = lookup_vendor_online(dev.mac_address)
        if online_name:
            dev.vendor_name = online_name
            dev.vendor_category = online_cat
            enriched += 1
            logger.info(f"Online MAC lookup: {dev.mac_address} → {online_name}")

    logger.info(f"Online MAC enrichment complete: {enriched}/{total} resolved")
    return enriched


def enrich_devices_online_sync(
    devices: list,
    cancel_event: Optional[threading.Event] = None,
) -> int:
    """
    Synchronous enrichment for DiscoveredDevice objects (scan_view).

    These use .vendor instead of .vendor_name (different dataclass).
    Modifies devices in place. Returns number enriched.
    """
    unknowns = [d for d in devices
                 if d.mac_address
                 and (not getattr(d, "vendor", None)
                      or getattr(d, "vendor", "") == "Unknown")]

    if not unknowns:
        return 0

    if not check_internet():
        logger.info("Online MAC lookup skipped — no internet")
        return 0

    enriched = 0
    for dev in unknowns:
        if cancel_event and cancel_event.is_set():
            break

        online_name, online_cat = lookup_vendor_online(dev.mac_address)
        if online_name:
            dev.vendor = online_name
            enriched += 1
            logger.info(f"Online MAC lookup: {dev.mac_address} → {online_name}")

    logger.info(f"Online MAC enrichment (sync): {enriched}/{len(unknowns)} resolved")
    return enriched
