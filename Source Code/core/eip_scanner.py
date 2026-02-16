"""
SAS Network Diagnostics Tool — EtherNet/IP Scanner
Handles EtherNet/IP device discovery using CIP ListIdentity broadcasts,
and reads diagnostic data from Allen-Bradley Ethernet modules.
"""

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── CIP Vendor IDs (subset of common automation vendors) ─────────────────────
CIP_VENDORS = {
    1: "Rockwell Automation / Allen-Bradley",
    2: "Namco Controls",
    5: "Honeywell",
    9: "Square D (Schneider Electric)",
    13: "Omron",
    34: "Turck",
    43: "WAGO",
    44: "Banner Engineering",
    47: "Belden / Hirschmann",
    48: "Red Lion Controls",
    50: "Phoenix Contact",
    52: "Cognex",
    54: "Parker Hannifin",
    56: "Comau / KUKA",
    71: "Schneider Electric",
    90: "HMS Industrial Networks",
    100: "Pepperl+Fuchs",
    104: "IFM Electronic",
    178: "Festo",
    213: "Balluff",
    283: "Molex",
    287: "ProSoft Technology",
    291: "Bihl+Wiedemann",
    342: "Stratix / Cisco (Rockwell)",
    772: "SEW-EURODRIVE",
}

# ── CIP Device Type IDs ──────────────────────────────────────────────────────
CIP_DEVICE_TYPES = {
    0: "Generic Device",
    2: "AC Drive",
    3: "Motor Overload",
    4: "Limit Switch",
    5: "Inductive Proximity Switch",
    6: "Photoelectric Sensor",
    7: "General Purpose Analog I/O",
    8: "Pneumatic Valve",
    9: "Vacuum Pump",
    10: "Communications Adapter",
    12: "General Purpose Digital I/O",
    13: "Resolver",
    14: "Communications Adapter",
    18: "Programmable Logic Controller",
    21: "Position Controller",
    22: "DC Drive",
    23: "Contactor",
    24: "Motor Starter",
    25: "Soft Start",
    26: "Human-Machine Interface",
    27: "Mass Flow Controller",
    28: "Pneumatic Valve",
    29: "Vacuum Pressure Gauge",
    33: "Safety Input Device",
    34: "Safety Output Device",
    35: "Safety Analog I/O Device",
    43: "Safety Drive",
    44: "Safety Discrete I/O Device",
    50: "Managed Ethernet Switch",
    67: "Embedded Component",
}


@dataclass
class EIPIdentity:
    """Parsed EtherNet/IP ListIdentity response."""
    ip_address: str = ""
    vendor_id: int = 0
    vendor_name: str = ""
    device_type_id: int = 0
    device_type_name: str = ""
    product_code: int = 0
    revision_major: int = 0
    revision_minor: int = 0
    status: int = 0
    serial_number: int = 0
    serial_hex: str = ""
    product_name: str = ""
    state: int = 0
    socket_address: str = ""
    socket_port: int = 0

    @property
    def firmware_version(self) -> str:
        return f"{self.revision_major}.{self.revision_minor:03d}"

    @property
    def status_description(self) -> str:
        """Decode the CIP device status word into plain English."""
        descriptions = []
        if self.status & 0x0001:
            descriptions.append("Owned (active connection)")
        if self.status & 0x0004:
            descriptions.append("Configured")
        if self.status & 0x0008:
            descriptions.append("Extended Device Status 1")
        if self.status & 0x0010:
            descriptions.append("Major Recoverable Fault")
        if self.status & 0x0020:
            descriptions.append("Major Unrecoverable Fault")

        # Extended status bits 4-7
        ext_status = (self.status >> 4) & 0x0F
        ext_map = {
            0: "No extended status",
            1: "Update in progress",
            2: "Needs commissioning",
            3: "At least one I/O connection in Run Mode",
            4: "At least one I/O connection in Idle Mode",
            5: "Run Mode & Idle Mode connections",
            6: "Nonvolatile configuration bad",
        }
        if ext_status in ext_map and ext_status != 0:
            descriptions.append(ext_map[ext_status])

        return "; ".join(descriptions) if descriptions else "Normal"

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "device_type_id": self.device_type_id,
            "device_type_name": self.device_type_name,
            "product_code": self.product_code,
            "firmware_version": self.firmware_version,
            "status": self.status,
            "status_description": self.status_description,
            "serial_number": self.serial_hex,
            "product_name": self.product_name,
        }


def _parse_list_identity_response(data: bytes, addr: Tuple[str, int]) -> Optional[EIPIdentity]:
    """Parse a raw ListIdentity response packet."""
    try:
        # EtherNet/IP encapsulation header is 24 bytes
        if len(data) < 26:
            return None

        # Command should be 0x0063 (ListIdentity reply)
        command = struct.unpack_from("<H", data, 0)[0]
        if command != 0x0063:
            return None

        # Skip encapsulation header (24 bytes), then item count (2 bytes)
        offset = 24
        item_count = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        if item_count < 1:
            return None

        # Parse CIP Identity item
        # Item type ID (2) + item length (2)
        item_type = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        item_length = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        if item_type != 0x000C:  # ListIdentity item
            return None

        # Encapsulation protocol version (2)
        offset += 2

        # Socket address: family(2) + port(2) + ip(4) + zero(8)
        sock_family = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        sock_port = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        sock_ip_bytes = struct.unpack_from("4B", data, offset)
        sock_ip = f"{sock_ip_bytes[0]}.{sock_ip_bytes[1]}.{sock_ip_bytes[2]}.{sock_ip_bytes[3]}"
        offset += 4 + 8  # Skip 8 zero bytes

        # CIP Identity
        vendor_id = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        device_type = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        product_code = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        rev_major = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        rev_minor = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        status = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        serial = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Product name (length-prefixed string)
        name_len = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        product_name = ""
        if name_len > 0 and offset + name_len <= len(data):
            product_name = data[offset:offset + name_len].decode("utf-8", errors="replace").strip("\x00")
            offset += name_len

        # State
        state = 0
        if offset + 1 <= len(data):
            state = struct.unpack_from("<B", data, offset)[0]

        identity = EIPIdentity(
            ip_address=sock_ip if sock_ip != "0.0.0.0" else addr[0],
            vendor_id=vendor_id,
            vendor_name=CIP_VENDORS.get(vendor_id, f"Unknown (VID:{vendor_id})"),
            device_type_id=device_type,
            device_type_name=CIP_DEVICE_TYPES.get(device_type, f"Unknown (DT:{device_type})"),
            product_code=product_code,
            revision_major=rev_major,
            revision_minor=rev_minor,
            status=status,
            serial_number=serial,
            serial_hex=f"{serial:08X}",
            product_name=product_name,
            state=state,
            socket_address=sock_ip,
            socket_port=sock_port,
        )

        return identity

    except Exception as e:
        logger.debug(f"Failed to parse ListIdentity from {addr}: {e}")
        return None


def discover_eip_devices(timeout: float = 3.0,
                         interface_ip: str = "",
                         progress_callback=None) -> List[EIPIdentity]:
    """
    Send EtherNet/IP ListIdentity broadcast and collect responses.
    This discovers all EtherNet/IP devices on the local network.
    """
    devices = []

    # Build ListIdentity request packet
    # EtherNet/IP encapsulation header for ListIdentity command
    command = 0x0063  # ListIdentity
    length = 0
    session_handle = 0
    status_code = 0
    sender_context = b'\x00' * 8
    options = 0

    packet = struct.pack("<HHIHQ8sI",
                         command, length, session_handle,
                         status_code, 0, sender_context, options)
    # Simplified header — just the essential 24 bytes
    packet = struct.pack("<HHI", command, 0, 0) + b'\x00' * 16

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)

        # Bind to specific interface if provided
        if interface_ip:
            try:
                sock.bind((interface_ip, 0))
            except OSError:
                pass  # Fall back to any interface

        # Send broadcast on EtherNet/IP port 44818
        sock.sendto(packet, ("255.255.255.255", 44818))

        if progress_callback:
            progress_callback(0, 1, "Listening for EtherNet/IP responses...")

        start_time = time.time()
        seen_ips = set()

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                identity = _parse_list_identity_response(data, addr)
                if identity and identity.ip_address not in seen_ips:
                    seen_ips.add(identity.ip_address)
                    devices.append(identity)
                    logger.info(f"EIP device found: {identity.product_name} at {identity.ip_address}")
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Error receiving EIP response: {e}")
                continue

        sock.close()

    except Exception as e:
        logger.error(f"EIP discovery failed: {e}")

    if progress_callback:
        progress_callback(1, 1, f"Found {len(devices)} EtherNet/IP devices")

    return devices


def try_pycomm3_discover() -> List[EIPIdentity]:
    """
    Attempt to use pycomm3's discover method as a backup.
    Falls back gracefully if pycomm3 is not available.
    """
    try:
        from pycomm3 import CIPDriver

        raw_devices = CIPDriver.discover()
        devices = []

        for dev in raw_devices:
            identity = EIPIdentity(
                ip_address=str(dev.get("ip_address", "")),
                vendor_id=dev.get("vendor", 0),
                vendor_name=CIP_VENDORS.get(dev.get("vendor", 0), "Unknown"),
                device_type_id=dev.get("device_type", 0),
                device_type_name=CIP_DEVICE_TYPES.get(dev.get("device_type", 0), "Unknown"),
                product_code=dev.get("product_code", 0),
                revision_major=dev.get("revision", {}).get("major", 0) if isinstance(dev.get("revision"), dict) else 0,
                revision_minor=dev.get("revision", {}).get("minor", 0) if isinstance(dev.get("revision"), dict) else 0,
                status=dev.get("status", 0),
                serial_number=dev.get("serial", 0),
                serial_hex=f"{dev.get('serial', 0):08X}",
                product_name=str(dev.get("product_name", "")),
                state=dev.get("state", 0),
            )
            devices.append(identity)

        return devices

    except Exception as e:
        logger.debug(f"pycomm3 discover failed (non-critical): {e}")
        return []


@dataclass
class EthernetDiagnostics:
    """Diagnostic counters from an Ethernet interface — these are the raw numbers
    that Allen-Bradley modules expose. Our analyzer translates these to plain English."""

    # Interface counters
    in_octets: int = 0
    in_ucast_packets: int = 0
    in_nucast_packets: int = 0
    in_discards: int = 0
    in_errors: int = 0
    in_unknown_protos: int = 0
    out_octets: int = 0
    out_ucast_packets: int = 0
    out_nucast_packets: int = 0
    out_discards: int = 0
    out_errors: int = 0

    # Ethernet-specific media counters
    alignment_errors: int = 0
    fcs_errors: int = 0  # CRC errors
    single_collisions: int = 0
    multiple_collisions: int = 0
    sqe_test_errors: int = 0
    deferred_transmissions: int = 0
    late_collisions: int = 0
    excessive_collisions: int = 0
    mac_transmit_errors: int = 0
    carrier_sense_errors: int = 0
    frame_too_long: int = 0
    mac_receive_errors: int = 0

    # CIP connection data
    cip_connections_opened: int = 0
    cip_connections_timed_out: int = 0
    cip_connections_active: int = 0
    cip_connection_limit: int = 0

    # TCP counters
    tcp_connections_established: int = 0
    tcp_connections_failed: int = 0
    tcp_retransmissions: int = 0
    tcp_segments_sent: int = 0
    tcp_segments_received: int = 0

    # General
    link_speed: int = 0  # Mbps
    link_status: str = "Unknown"
    duplex: str = "Unknown"
    uptime_seconds: int = 0

    # ── TCP/IP Interface Object (Class 0xF5) ─────────────────────────────
    tcpip_status: int = -1           # Attribute 1: Status flags (-1 = not read)
    ip_config_method: str = ""       # Derived: "Static", "DHCP", "BOOTP", or ""
    hostname: str = ""               # Attribute 6: Host Name
    ttl_value: int = -1              # Attribute 8: TTL (-1 = not read)
    gateway_address: str = ""        # From Attribute 5: Interface Configuration
    dns_primary: str = ""            # From Attribute 5
    dns_secondary: str = ""          # From Attribute 5
    domain_name: str = ""            # From Attribute 5

    # ARP Conflict Detection (from TCP/IP Interface Object)
    acd_enabled: int = -1            # Attribute 11: -1=unknown, 0=off, 1=on
    acd_conflict_detected: bool = False   # True if last ACD shows conflict
    acd_conflict_mac: str = ""            # MAC address of conflicting device
    acd_conflict_ip: str = ""             # IP that was conflicted

    # Multicast configuration
    mcast_alloc_control: int = -1    # 0=default(device chooses), 1=CIP allocated
    mcast_num_mcast: int = 0         # Number of multicast addresses allocated
    mcast_start_addr: str = ""       # Starting multicast address

    # ── Ethernet Link Object (Class 0xF6) — Extended Attributes ──────────
    autoneg_enabled: int = -1        # From Attr 6: -1=unknown, 0=forced, 1=autoneg
    forced_speed: int = 0            # If autoneg off: forced speed in Mbps
    forced_duplex: str = ""          # If autoneg off: "Full" or "Half"
    interface_type: str = ""         # Attr 7: "Twisted Pair", "Optical", etc.
    interface_label: str = ""        # Attr 9: Port label e.g. "Port 1"
    mac_address: str = ""            # Attr 3: Physical MAC address

    # ── Connection Manager Object (Class 0x06) ──────────────────────────
    cm_open_requests: int = -1       # Total open requests received (-1=not read)
    cm_open_format_rejects: int = 0  # Rejected due to bad format
    cm_open_resource_rejects: int = 0  # Rejected due to lack of resources
    cm_open_other_rejects: int = 0   # Rejected for other reasons
    cm_close_requests: int = 0       # Total close requests
    cm_connection_timeouts: int = 0  # Connections lost to timeout

    timestamp: float = field(default_factory=time.time)

    @property
    def total_errors(self) -> int:
        return (self.in_errors + self.out_errors + self.alignment_errors +
                self.fcs_errors + self.late_collisions + self.excessive_collisions +
                self.mac_transmit_errors + self.mac_receive_errors)

    @property
    def total_packets(self) -> int:
        return self.in_ucast_packets + self.in_nucast_packets + self.out_ucast_packets + self.out_nucast_packets

    @property
    def error_rate(self) -> float:
        """Error rate as percentage of total packets."""
        if self.total_packets == 0:
            return 0.0
        return (self.total_errors / self.total_packets) * 100

    @property
    def collision_rate(self) -> float:
        """Collision rate as percentage of outbound packets."""
        out_total = self.out_ucast_packets + self.out_nucast_packets
        if out_total == 0:
            return 0.0
        total_collisions = self.single_collisions + self.multiple_collisions + self.late_collisions
        return (total_collisions / out_total) * 100


def read_device_diagnostics_via_http(ip: str, timeout: float = 5.0) -> Optional[EthernetDiagnostics]:
    """
    Attempt to read diagnostic data from an Allen-Bradley module's built-in web server.
    Parses the diagnostic page for counter values.
    """
    import urllib.request
    import re

    diag = EthernetDiagnostics()

    try:
        # Try common AB diagnostic pages
        urls_to_try = [
            f"http://{ip}/",
            f"http://{ip}/diagnostics",
        ]

        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SAS-NetDiag/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    html = response.read().decode("utf-8", errors="replace")

                    # Parse counter values from HTML
                    # AB modules often present data in table format
                    _parse_ab_diagnostic_html(html, diag)
                    break

            except Exception:
                continue

    except Exception as e:
        logger.debug(f"HTTP diagnostics failed for {ip}: {e}")

    return diag


def _parse_ab_diagnostic_html(html: str, diag: EthernetDiagnostics):
    """Extract counter values from Allen-Bradley diagnostic HTML pages."""
    import re

    # Common patterns in AB web server pages
    patterns = {
        "in_octets": [r"In\s*Octets[:\s]*(\d+)", r"Octets\s*Received[:\s]*(\d+)"],
        "out_octets": [r"Out\s*Octets[:\s]*(\d+)", r"Octets\s*Sent[:\s]*(\d+)"],
        "in_errors": [r"In\s*Errors[:\s]*(\d+)", r"Input\s*Errors[:\s]*(\d+)"],
        "out_errors": [r"Out\s*Errors[:\s]*(\d+)", r"Output\s*Errors[:\s]*(\d+)"],
        "in_discards": [r"In\s*Discards[:\s]*(\d+)"],
        "out_discards": [r"Out\s*Discards[:\s]*(\d+)"],
        "fcs_errors": [r"FCS\s*Errors[:\s]*(\d+)", r"CRC\s*Errors[:\s]*(\d+)"],
        "alignment_errors": [r"Alignment\s*Errors[:\s]*(\d+)"],
        "single_collisions": [r"Single\s*Collisions?[:\s]*(\d+)"],
        "multiple_collisions": [r"Multiple\s*Collisions?[:\s]*(\d+)"],
        "late_collisions": [r"Late\s*Collisions?[:\s]*(\d+)"],
        "excessive_collisions": [r"Excessive\s*Collisions?[:\s]*(\d+)"],
        "carrier_sense_errors": [r"Carrier\s*Sense\s*Errors?[:\s]*(\d+)"],
        "frame_too_long": [r"Frame\s*Too\s*Long[:\s]*(\d+)"],
    }

    for field_name, regex_list in patterns.items():
        for pattern in regex_list:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                try:
                    setattr(diag, field_name, int(match.group(1)))
                except (ValueError, AttributeError):
                    pass
                break


def read_cip_diagnostics(ip: str, timeout: float = 5.0) -> Optional[EthernetDiagnostics]:
    """
    Read diagnostic attributes from an EtherNet/IP device using CIP.
    Uses pycomm3 for CIP communication when available, falls back to raw sockets.

    Reads from multiple CIP objects:
      - Ethernet Link Object     (Class 0xF6) — speed, duplex, counters, autoneg
      - TCP/IP Interface Object  (Class 0xF5) — IP config, TTL, ACD, multicast
      - Connection Manager       (Class 0x06) — connection health stats
    """
    diag = EthernetDiagnostics()

    try:
        from pycomm3 import CIPDriver

        with CIPDriver(ip) as driver:

            # ─────────────────────────────────────────────────────────────
            # Ethernet Link Object — Class 0xF6, Instance 1
            # ─────────────────────────────────────────────────────────────

            try:
                # Attribute 1: Interface Speed (UDINT, Mbps)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=1,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    speed_data = result.value
                    if isinstance(speed_data, bytes) and len(speed_data) >= 4:
                        diag.link_speed = struct.unpack_from("<I", speed_data)[0]
            except Exception as e:
                logger.debug(f"Failed to read link speed: {e}")

            try:
                # Attribute 2: Interface Flags (UDINT — link status, duplex, etc.)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=2,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    flags_data = result.value
                    if isinstance(flags_data, bytes) and len(flags_data) >= 4:
                        flags = struct.unpack_from("<I", flags_data)[0]
                        diag.link_status = "Active" if (flags & 0x01) else "Inactive"
                        duplex_bit = (flags >> 1) & 0x01
                        diag.duplex = "Full" if duplex_bit else "Half"
                        # Bits 2-4: negotiation status
                        neg_status = (flags >> 2) & 0x07
                        # 0=auto-neg in progress, 1=auto-neg failed, 2=failed (speed forced)
                        # 3=success, 4=not attempted (forced)
                        if neg_status == 4:
                            diag.autoneg_enabled = 0
                        elif neg_status == 3:
                            diag.autoneg_enabled = 1
                        elif neg_status in (0, 1, 2):
                            diag.autoneg_enabled = 1  # was attempted
            except Exception as e:
                logger.debug(f"Failed to read interface flags: {e}")

            try:
                # Attribute 3: Physical Address (MAC — 6 bytes)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=3,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    mac_data = result.value
                    if isinstance(mac_data, bytes) and len(mac_data) >= 6:
                        diag.mac_address = ":".join(f"{b:02X}" for b in mac_data[:6])
            except Exception as e:
                logger.debug(f"Failed to read MAC address: {e}")

            try:
                # Attribute 4: Interface Counters (11x UDINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=4,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    counters = result.value
                    if isinstance(counters, bytes) and len(counters) >= 44:
                        vals = struct.unpack_from("<11I", counters)
                        diag.in_octets = vals[0]
                        diag.in_ucast_packets = vals[1]
                        diag.in_nucast_packets = vals[2]
                        diag.in_discards = vals[3]
                        diag.in_errors = vals[4]
                        diag.in_unknown_protos = vals[5]
                        diag.out_octets = vals[6]
                        diag.out_ucast_packets = vals[7]
                        diag.out_nucast_packets = vals[8]
                        diag.out_discards = vals[9]
                        diag.out_errors = vals[10]
            except Exception as e:
                logger.debug(f"Failed to read interface counters: {e}")

            try:
                # Attribute 5: Media Counters (12x UDINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=5,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    media = result.value
                    if isinstance(media, bytes) and len(media) >= 48:
                        vals = struct.unpack_from("<12I", media)
                        diag.alignment_errors = vals[0]
                        diag.fcs_errors = vals[1]
                        diag.single_collisions = vals[2]
                        diag.multiple_collisions = vals[3]
                        diag.sqe_test_errors = vals[4]
                        diag.deferred_transmissions = vals[5]
                        diag.late_collisions = vals[6]
                        diag.excessive_collisions = vals[7]
                        diag.mac_transmit_errors = vals[8]
                        diag.carrier_sense_errors = vals[9]
                        diag.frame_too_long = vals[10]
                        diag.mac_receive_errors = vals[11]
            except Exception as e:
                logger.debug(f"Failed to read media counters: {e}")

            try:
                # Attribute 6: Interface Control (struct)
                # Bits 0: auto-neg, Bit 1: forced duplex, Bits 16-31: forced speed
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=6,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    ctrl_data = result.value
                    if isinstance(ctrl_data, bytes) and len(ctrl_data) >= 4:
                        ctrl_bits = struct.unpack_from("<H", ctrl_data, 0)[0]
                        diag.autoneg_enabled = 1 if (ctrl_bits & 0x01) else 0
                        if not (ctrl_bits & 0x01):
                            diag.forced_duplex = "Full" if (ctrl_bits & 0x02) else "Half"
                        if len(ctrl_data) >= 8:
                            diag.forced_speed = struct.unpack_from("<H", ctrl_data, 2)[0]
            except Exception as e:
                logger.debug(f"Failed to read interface control: {e}")

            try:
                # Attribute 7: Interface Type (USINT)
                # 0=unknown, 2=twisted pair, 3=optical fiber
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=7,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    type_data = result.value
                    if isinstance(type_data, bytes) and len(type_data) >= 1:
                        type_val = type_data[0]
                        type_map = {0: "Unknown", 1: "Internal", 2: "Twisted Pair",
                                    3: "Optical Fiber"}
                        diag.interface_type = type_map.get(type_val, f"Type {type_val}")
            except Exception as e:
                logger.debug(f"Failed to read interface type: {e}")

            try:
                # Attribute 9: Interface Label (SHORT_STRING)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF6, instance=1, attribute=9,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    label_data = result.value
                    if isinstance(label_data, bytes) and len(label_data) > 1:
                        # SHORT_STRING: first byte is length
                        str_len = label_data[0]
                        if str_len > 0 and len(label_data) > str_len:
                            diag.interface_label = label_data[1:1 + str_len].decode(
                                "utf-8", errors="replace").strip()
            except Exception as e:
                logger.debug(f"Failed to read interface label: {e}")

            # ─────────────────────────────────────────────────────────────
            # TCP/IP Interface Object — Class 0xF5, Instance 1
            # ─────────────────────────────────────────────────────────────

            try:
                # Attribute 1: Status (UDINT)
                # Bit 0: Interface configured
                # Bit 1: Multicast config pending
                # Bit 2: Interface config pending
                # Bit 3: ACD status (conflict detected)
                # Bit 4: ACD fault
                # Bits 5-8: IP config method (0=BOOTP, 1=DHCP, 2=stored/static)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=1,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    status_data = result.value
                    if isinstance(status_data, bytes) and len(status_data) >= 4:
                        status = struct.unpack_from("<I", status_data)[0]
                        diag.tcpip_status = status
                        # ACD conflict detected
                        if status & 0x08:
                            diag.acd_conflict_detected = True
                        # IP config method is bits 4-7 in some implementations
                        # or bits 5-8 in others. Check both common layouts.
                        config_method = (status >> 4) & 0x0F
                        if config_method == 0:
                            diag.ip_config_method = "BOOTP"
                        elif config_method == 1:
                            diag.ip_config_method = "DHCP"
                        elif config_method == 2:
                            diag.ip_config_method = "Static"
                        else:
                            diag.ip_config_method = f"Method {config_method}"
            except Exception as e:
                logger.debug(f"Failed to read TCP/IP status: {e}")

            try:
                # Attribute 3: Configuration Capability (UDINT)
                # Bit 0: BOOTP capable
                # Bit 1: DNS capable
                # Bit 2: DHCP capable
                # Bit 3: DHCP-DNS Update capable
                # Bit 4: Configuration settable
                # Bit 5: Hardware configurable
                # Bit 6: ACD capable
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=3,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    cap_data = result.value
                    if isinstance(cap_data, bytes) and len(cap_data) >= 4:
                        caps = struct.unpack_from("<I", cap_data)[0]
                        # If device doesn't support DHCP/BOOTP, and status
                        # didn't give us a method, assume static
                        if not diag.ip_config_method:
                            if caps & 0x04:
                                diag.ip_config_method = "DHCP Capable"
                            else:
                                diag.ip_config_method = "Static Only"
            except Exception as e:
                logger.debug(f"Failed to read TCP/IP capability: {e}")

            try:
                # Attribute 5: Interface Configuration (struct)
                # IP (4) + Subnet (4) + Gateway (4) + DNS1 (4) + DNS2 (4) + Domain (variable)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=5,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    cfg_data = result.value
                    if isinstance(cfg_data, bytes) and len(cfg_data) >= 20:
                        # IP, Subnet, Gateway, DNS1, DNS2
                        ip_addr = socket.inet_ntoa(cfg_data[0:4])
                        # subnet = socket.inet_ntoa(cfg_data[4:8])
                        gw = socket.inet_ntoa(cfg_data[8:12])
                        dns1 = socket.inet_ntoa(cfg_data[12:16])
                        dns2 = socket.inet_ntoa(cfg_data[16:20])

                        if gw != "0.0.0.0":
                            diag.gateway_address = gw
                        if dns1 != "0.0.0.0":
                            diag.dns_primary = dns1
                        if dns2 != "0.0.0.0":
                            diag.dns_secondary = dns2

                        # Domain name (STRING2 after the 20 bytes)
                        if len(cfg_data) > 22:
                            domain_len = struct.unpack_from("<H", cfg_data, 20)[0]
                            if domain_len > 0 and len(cfg_data) >= 22 + domain_len:
                                diag.domain_name = cfg_data[22:22 + domain_len].decode(
                                    "utf-8", errors="replace").strip()
            except Exception as e:
                logger.debug(f"Failed to read interface configuration: {e}")

            try:
                # Attribute 6: Host Name (STRING2)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=6,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    host_data = result.value
                    if isinstance(host_data, bytes) and len(host_data) >= 2:
                        host_len = struct.unpack_from("<H", host_data, 0)[0]
                        if host_len > 0 and len(host_data) >= 2 + host_len:
                            diag.hostname = host_data[2:2 + host_len].decode(
                                "utf-8", errors="replace").strip()
            except Exception as e:
                logger.debug(f"Failed to read hostname: {e}")

            try:
                # Attribute 8: TTL Value (USINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=8,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    ttl_data = result.value
                    if isinstance(ttl_data, bytes) and len(ttl_data) >= 1:
                        diag.ttl_value = ttl_data[0]
            except Exception as e:
                logger.debug(f"Failed to read TTL: {e}")

            try:
                # Attribute 9: Multicast Config (struct)
                # alloc_control(1) + reserved(1) + num_mcast(2) + mcast_start_addr(4)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=9,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    mc_data = result.value
                    if isinstance(mc_data, bytes) and len(mc_data) >= 8:
                        diag.mcast_alloc_control = mc_data[0]
                        diag.mcast_num_mcast = struct.unpack_from("<H", mc_data, 2)[0]
                        diag.mcast_start_addr = socket.inet_ntoa(mc_data[4:8])
            except Exception as e:
                logger.debug(f"Failed to read multicast config: {e}")

            try:
                # Attribute 11: Select ACD (BOOL — is ACD enabled?)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=11,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    acd_data = result.value
                    if isinstance(acd_data, bytes) and len(acd_data) >= 1:
                        diag.acd_enabled = 1 if acd_data[0] else 0
            except Exception as e:
                logger.debug(f"Failed to read ACD setting: {e}")

            try:
                # Attribute 12: Last Conflict Detected (struct)
                # ACD Activity (1) + Remote MAC (6) + ARP PDU (28)
                result = driver.generic_message(
                    service=0x0E, class_code=0xF5, instance=1, attribute=12,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    acd_data = result.value
                    if isinstance(acd_data, bytes) and len(acd_data) >= 7:
                        activity = acd_data[0]
                        if activity != 0:
                            diag.acd_conflict_detected = True
                            diag.acd_conflict_mac = ":".join(
                                f"{b:02X}" for b in acd_data[1:7])
                            # Try to extract IP from ARP PDU if available
                            if len(acd_data) >= 35:
                                # ARP sender IP is at offset 7+14=21 in ARP PDU
                                try:
                                    diag.acd_conflict_ip = socket.inet_ntoa(
                                        acd_data[21:25])
                                except Exception:
                                    pass
            except Exception as e:
                logger.debug(f"Failed to read ACD conflict data: {e}")

            # ─────────────────────────────────────────────────────────────
            # Connection Manager Object — Class 0x06, Instance 1
            # ─────────────────────────────────────────────────────────────

            try:
                # Attribute 1: Open Requests (UINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=1,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_open_requests = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM open requests: {e}")

            try:
                # Attribute 2: Open Format Rejects (UINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=2,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_open_format_rejects = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM format rejects: {e}")

            try:
                # Attribute 3: Open Resource Rejects (UINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=3,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_open_resource_rejects = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM resource rejects: {e}")

            try:
                # Attribute 4: Open Other Rejects (UINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=4,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_open_other_rejects = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM other rejects: {e}")

            try:
                # Attribute 5: Close Requests (UINT)
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=5,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_close_requests = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM close requests: {e}")

            try:
                # Attribute 13: Connection Timeouts (UINT) — common on AB devices
                result = driver.generic_message(
                    service=0x0E, class_code=0x06, instance=1, attribute=13,
                    data_type=None, connected=False,
                )
                if result and result.value is not None:
                    data = result.value
                    if isinstance(data, bytes) and len(data) >= 2:
                        diag.cm_connection_timeouts = struct.unpack_from("<H", data)[0]
            except Exception as e:
                logger.debug(f"Failed to read CM timeouts: {e}")

        diag.timestamp = time.time()
        logger.info(f"CIP diagnostics collected from {ip} — "
                     f"method={diag.ip_config_method or 'N/A'}, "
                     f"autoneg={diag.autoneg_enabled}, "
                     f"acd={diag.acd_enabled}, "
                     f"ttl={diag.ttl_value}, "
                     f"cm_opens={diag.cm_open_requests}")
        return diag

    except ImportError:
        logger.warning("pycomm3 not available — CIP diagnostics disabled")
        return None
    except Exception as e:
        logger.error(f"CIP diagnostics failed for {ip}: {e}")
        return None
