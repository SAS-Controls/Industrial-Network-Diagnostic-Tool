"""
SAS Network Diagnostics Tool — DeviceNet Diagnostics Engine
Phase 2: DeviceNet network diagnostics via backplane punch-through (CIP routing)
and 1784-U2DN USB adapter (via RSLinx SDK / dtl32.dll).

Connection Methods:
  1. Backplane Punch-Through:
     EtherNet/IP → PLC → Backplane → 1756-DNB/1769-SDN → DeviceNet nodes
     Uses pycomm3 CIPDriver with CIP route paths.

  2. 1784-U2DN USB Adapter (via RSLinx):
     Python (ctypes) → dtl32.dll → RSLinx Engine → PCDC Driver → 1784-U2DN → DeviceNet
     Requires RSLinx Classic with a DeviceNet PCDC driver configured.

DeviceNet Primer:
  - Based on CAN bus, 11-bit identifiers
  - 64 possible MAC IDs (0-63)
  - Baud rates: 125 Kbps, 250 Kbps, 500 Kbps
  - CIP (Common Industrial Protocol) application layer — same family as EtherNet/IP
  - Identity Object (Class 0x01) is mandatory on every CIP device
  - DeviceNet Object (Class 0x03) contains network-specific attributes
"""

import logging
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple, Any

logger = logging.getLogger(__name__)

# ── CIP Constants ────────────────────────────────────────────────────────────

# CIP Service Codes
SVC_GET_ATTR_ALL = 0x01
SVC_GET_ATTR_SINGLE = 0x0E
SVC_SET_ATTR_SINGLE = 0x10

# CIP Class Codes
CLASS_IDENTITY = 0x01
CLASS_MSG_ROUTER = 0x02
CLASS_DEVICENET = 0x03
CLASS_CONNECTION_MGR = 0x06

# DeviceNet Object (Class 0x03) Attribute IDs
DNET_ATTR_MAC_ID = 1
DNET_ATTR_BAUD_RATE = 2
DNET_ATTR_BOI = 3        # Bus-Off Interrupt
DNET_ATTR_BUS_OFF_CNT = 4
DNET_ATTR_ALLOC_CHOICE = 5

# Baud rate mapping
BAUD_RATES = {0: "125 Kbps", 1: "250 Kbps", 2: "500 Kbps"}

# DeviceNet port number for CIP routing (port 2 on 1756-DNB)
DNET_PORT = 2

# ── Vendor ID Lookup (common DeviceNet vendors) ─────────────────────────────
# From CIP / ODVA vendor registry
CIP_VENDORS = {
    1: "Rockwell Automation/Allen-Bradley",
    2: "Namco Controls",
    4: "Parker Hannifin",
    5: "Rockwell Automation/Allen-Bradley (Drives)",
    7: "SMC",
    9: "IDEC",
    11: "Omron",
    12: "GE Fanuc",
    13: "Ford Motor Company",
    17: "Danaher Controls",
    19: "SEW Eurodrive",
    20: "ABB",
    22: "Banner Engineering",
    24: "Yaskawa",
    25: "Danfoss",
    29: "Festo",
    32: "Turck",
    33: "Cutler-Hammer/Eaton",
    34: "Lenze",
    35: "Schneider Electric",
    40: "Beckhoff",
    43: "Cognex",
    44: "Bosch Rexroth",
    47: "Sick",
    48: "WAGO",
    49: "ifm electronic",
    50: "Elau",
    58: "Siemens",
    63: "Pepperl+Fuchs",
    67: "Baldor/ABB",
    70: "Phoenix Contact",
    78: "Belden/Hirschmann",
    90: "Balluff",
    95: "Numatics/ASCO",
    96: "Leuze electronic",
    100: "Molex",
    116: "ESA Automation",
    118: "Pilz",
    149: "Mitsubishi Electric",
    160: "Red Lion Controls",
    163: "HMS Industrial Networks",
    169: "Baumer",
    174: "Keyence",
    180: "Advantech",
    205: "ProSoft Technology",
    283: "Spectrum Controls",
    291: "Weidmuller",
    345: "Bihl+Wiedemann",
}

# CIP Product Type lookup
CIP_PRODUCT_TYPES = {
    0: "Generic Device",
    2: "AC Drive",
    3: "Motor Overload",
    4: "Limit Switch",
    5: "Inductive Proximity Switch",
    6: "Photoelectric Sensor",
    7: "General Purpose Discrete I/O",
    10: "Resolver",
    12: "Communications Adapter",
    14: "Programmable Logic Controller",
    16: "Position Controller",
    18: "Safety Discrete I/O Device",
    19: "Fluid Flow Controller",
    21: "General Purpose Analog I/O",
    23: "DC Drive",
    24: "DC Power Generator",
    26: "Pneumatic Valve",
    27: "Vacuum Pressure Gauge",
    28: "Process Control Valve",
    29: "Residual Gas Analyzer",
    30: "DC Power Generator",
    31: "RF Power Generator",
    32: "Turbomolecular Vacuum Pump",
    33: "Encoder",
    34: "Safety Device",
    35: "Resolver",
    38: "Contactor",
    39: "Motor Starter",
    40: "Soft Start",
    43: "Human Machine Interface (HMI)",
    44: "Mass Flow Controller",
    50: "Safety Analog I/O Device",
    100: "Managed Ethernet Switch",
}


# ── DNB Error Code Reference ────────────────────────────────────────────────
DNB_ERROR_CODES = {
    # Scanner status / display codes
    70: {
        "name": "Device Not in Scanlist",
        "description": "A device responded on the network but is not configured in the scanner's scanlist.",
        "severity": "info",
        "fix": "Add the device to the scanlist in RSNetWorx for DeviceNet, or verify the device should be at that MAC ID.",
    },
    71: {
        "name": "Electronic Keying Mismatch",
        "description": "The device at this node does not match the electronic keying configured in the scanlist.",
        "severity": "warning",
        "fix": "Verify the correct device is at this address. Update electronic keying in RSNetWorx or set keying to 'Disable Keying'.",
    },
    72: {
        "name": "Connection Timeout",
        "description": "An I/O connection to this device timed out — the device did not respond within the expected period.",
        "severity": "error",
        "fix": "Check physical connections, wiring, and termination resistors. Increase the RPI or interscan delay. "
               "Verify baud rate matches. Check for intermittent noise from VFDs or other sources.",
    },
    73: {
        "name": "Connection Refused",
        "description": "The device refused the I/O connection request from the scanner.",
        "severity": "error",
        "fix": "Verify I/O sizes match between scanlist and device configuration. Check that the device supports the "
               "connection type configured (polled, COS, cyclic). Reset the device and retry.",
    },
    74: {
        "name": "Connection Size Mismatch",
        "description": "The I/O data size configured in the scanner doesn't match the device.",
        "severity": "error",
        "fix": "Reconfigure I/O sizes in RSNetWorx. If the device was replaced, ensure the new device is configured "
               "identically to the original.",
    },
    75: {
        "name": "Device Faulted",
        "description": "The device is reporting a fault condition.",
        "severity": "error",
        "fix": "Check the device's local fault indicators (LEDs, display). Clear the fault at the device "
               "and verify operating conditions.",
    },
    76: {
        "name": "Configuration Error",
        "description": "Error downloading configuration to the device during scanner startup.",
        "severity": "error",
        "fix": "Re-download the scanlist. Verify configuration parameters are valid for the device type. "
               "Check EDS file version matches the device firmware.",
    },
    77: {
        "name": "I/O Size Mismatch",
        "description": "The produced or consumed I/O sizes don't match between scanner and device.",
        "severity": "error",
        "fix": "Reconfigure I/O sizes in RSNetWorx to match the device's actual I/O map. This often happens "
               "after replacing a device with a different firmware version.",
    },
    78: {
        "name": "No Message Reply",
        "description": "The scanner sent an explicit message to this device but received no response.",
        "severity": "error",
        "fix": "Check that the device is powered, connected, and set to the correct MAC ID and baud rate. "
               "Verify network cabling and termination. Try increasing interscan delay.",
    },
    79: {
        "name": "Bus-Off",
        "description": "The CAN controller on the scanner has gone bus-off due to excessive bus errors. "
                       "This is a critical network health issue.",
        "severity": "critical",
        "fix": "Check for: damaged cabling, missing termination resistors (need exactly 2, one at each end, 121Ω each), "
               "baud rate mismatches, noise from VFDs/motors, ground faults. Disconnect nodes one by one to isolate "
               "the source. Use dedicated 24VDC supply for DeviceNet power.",
    },
    80: {
        "name": "Scanner Idle",
        "description": "The scanner is in Idle mode — not actively scanning the network.",
        "severity": "info",
        "fix": "The scanner needs to be put into Run mode. In ControlLogix, this is controlled by the PLC program. "
               "Check the run/idle bit in the ladder logic.",
    },
    81: {
        "name": "Duplicate MAC ID Detected",
        "description": "Two or more devices on the network have the same MAC ID.",
        "severity": "critical",
        "fix": "Use the rotary switches on each device to verify unique MAC IDs. Only one device per address (0-63). "
               "Power cycle devices after changing addresses.",
    },
    82: {
        "name": "Baud Rate Auto-Detect Failed",
        "description": "The scanner could not automatically determine the network baud rate.",
        "severity": "warning",
        "fix": "Set the baud rate manually using the DIP switches on the scanner or through RSNetWorx. "
               "Ensure at least one other device is powered and communicating on the network.",
    },
    91: {
        "name": "Bus-Off (SLC/SDN)",
        "description": "CAN bus-off error on 1747-SDN scanner. Similar to error 79 on 1756-DNB.",
        "severity": "critical",
        "fix": "Same as Error 79. Check termination, cabling, noise, and baud rate. "
               "May require module reset via DIP switch procedure.",
    },
}


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class DeviceNetNode:
    """Represents a device discovered on the DeviceNet network."""
    mac_id: int
    is_online: bool = False
    vendor_id: int = 0
    vendor_name: str = ""
    product_type: int = 0
    product_type_name: str = ""
    product_code: int = 0
    revision_major: int = 0
    revision_minor: int = 0
    serial_number: str = ""
    product_name: str = ""
    device_status: int = 0
    status_text: str = ""

    # DeviceNet Object attributes (if readable)
    baud_rate: int = -1
    baud_rate_text: str = ""
    bus_off_count: int = 0

    # Scan metadata
    response_time_ms: float = 0.0
    error_code: int = 0
    error_text: str = ""
    raw_identity: bytes = b""


@dataclass
class ScannerDiagnostics:
    """Diagnostic information from the DeviceNet scanner module."""
    scanner_mac_id: int = 0
    scanner_baud_rate: str = ""
    scanner_product_name: str = ""
    scanner_vendor: str = ""
    scanner_serial: str = ""
    scanner_revision: str = ""
    scanner_status: int = 0
    scanner_status_text: str = ""

    # Error counters
    bus_off_count: int = 0
    tx_error_count: int = 0
    rx_error_count: int = 0

    # Device failure bitmap (64 bits, one per MAC ID)
    device_failure_bitmap: List[bool] = field(default_factory=lambda: [False] * 64)

    # Scanner mode
    is_running: bool = False
    is_idle: bool = False
    error_code: int = 0
    error_text: str = ""


@dataclass
class DeviceNetScanResult:
    """Complete result of a DeviceNet network scan."""
    nodes: List[DeviceNetNode] = field(default_factory=list)
    scanner_diag: Optional[ScannerDiagnostics] = None
    connection_method: str = ""
    plc_ip: str = ""
    scanner_slot: int = 0
    scan_time_seconds: float = 0.0
    nodes_online: int = 0
    nodes_total: int = 64
    errors: List[str] = field(default_factory=list)


# ── Identity Object Decoder ─────────────────────────────────────────────────

def decode_identity_object(data: bytes) -> dict:
    """
    Decode a CIP Identity Object (Class 0x01, Instance 1) Get_Attributes_All response.

    Identity Object format:
      UINT  Vendor ID           (2 bytes)
      UINT  Device Type         (2 bytes)
      UINT  Product Code        (2 bytes)
      USINT Revision Major      (1 byte)
      USINT Revision Minor      (1 byte)
      WORD  Status              (2 bytes)
      UDINT Serial Number       (4 bytes)
      SHORT_STRING Product Name (1 byte length + N bytes)
    """
    if len(data) < 14:
        return {}

    try:
        vendor_id = struct.unpack_from("<H", data, 0)[0]
        device_type = struct.unpack_from("<H", data, 2)[0]
        product_code = struct.unpack_from("<H", data, 4)[0]
        rev_major = data[6]
        rev_minor = data[7]
        status = struct.unpack_from("<H", data, 8)[0]
        serial = struct.unpack_from("<I", data, 10)[0]

        # Product name is a SHORT_STRING: 1 byte length, then ASCII chars
        name_len = data[14] if len(data) > 14 else 0
        product_name = ""
        if name_len > 0 and len(data) >= 15 + name_len:
            product_name = data[15:15 + name_len].decode("ascii", errors="replace").strip("\x00")

        return {
            "vendor_id": vendor_id,
            "device_type": device_type,
            "product_code": product_code,
            "revision_major": rev_major,
            "revision_minor": rev_minor,
            "status": status,
            "serial_number": f"{serial:08X}",
            "product_name": product_name,
        }
    except Exception as e:
        logger.warning(f"Error decoding identity object: {e}")
        return {}


def decode_device_status(status_word: int) -> str:
    """Decode the CIP Identity Object status word into human-readable text."""
    parts = []
    if status_word & 0x0001:
        parts.append("Owned")
    if status_word & 0x0004:
        parts.append("Configured")
    if status_word & 0x0008:
        parts.append("Extended Status Available")

    # Bits 4-7: Extended device status
    ext_status = (status_word >> 4) & 0x0F
    ext_map = {
        0: "Self-testing or unknown",
        1: "Firmware update in progress",
        2: "Waiting for connection",
        3: "At least one I/O connection established",
        4: "No I/O connections, but ready",
        5: "Non-volatile config bad",
        6: "Major fault",
        7: "At least one connection in run mode",
        8: "At least one connection in idle mode",
    }
    if ext_status in ext_map:
        parts.append(ext_map[ext_status])

    if status_word & 0x0100:
        parts.append("Minor Recoverable Fault")
    if status_word & 0x0200:
        parts.append("Minor Unrecoverable Fault")
    if status_word & 0x0400:
        parts.append("Major Recoverable Fault")
    if status_word & 0x0800:
        parts.append("Major Unrecoverable Fault")

    return "; ".join(parts) if parts else "OK"


# ── Backplane Punch-Through Scanner ─────────────────────────────────────────

class DeviceNetBackplaneScanner:
    """
    Scan a DeviceNet network by routing CIP messages through a PLC's backplane
    to the DeviceNet scanner module (1756-DNB, 1769-SDN, etc.).

    This replicates how RSNetWorx browses a DeviceNet network — by sending
    Unconnected Explicit Messages via EtherNet/IP → backplane → scanner → DeviceNet.
    """

    def __init__(self, plc_ip: str, scanner_slot: int):
        self.plc_ip = plc_ip
        self.scanner_slot = scanner_slot
        self._driver = None
        self._cancel_event = threading.Event()
        self._preferred_method: Optional[str] = None  # Learned from first success

    def cancel(self):
        """Cancel an in-progress scan."""
        self._cancel_event.set()

    def connect(self) -> Tuple[bool, str]:
        """
        Establish EtherNet/IP connection to the PLC and verify the scanner module.
        Returns (success, message).
        """
        try:
            from pycomm3 import CIPDriver
        except ImportError:
            return False, ("pycomm3 is not installed. Install it with: "
                           "pip install pycomm3")

        try:
            self._driver = CIPDriver(self.plc_ip)
            self._driver.open()
            logger.info(f"Connected to PLC at {self.plc_ip}")
            return True, "Connected to PLC"
        except Exception as e:
            return False, f"Failed to connect to PLC at {self.plc_ip}: {e}"

    def disconnect(self):
        """Close the EtherNet/IP connection."""
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None

    def get_scanner_info(self) -> Optional[ScannerDiagnostics]:
        """
        Read identity and diagnostic information from the DeviceNet scanner module.
        """
        if not self._driver:
            return None

        from pycomm3 import Services, ClassCode, PADDED_EPATH, PortSegment

        diag = ScannerDiagnostics()

        try:
            # Read scanner identity via backplane
            info = self._driver.get_module_info(self.scanner_slot)
            if info:
                diag.scanner_product_name = info.get("product_name", "Unknown")
                diag.scanner_vendor = CIP_VENDORS.get(
                    info.get("vendor_id", 0),
                    info.get("vendor", "Unknown")
                )
                diag.scanner_serial = info.get("serial", "")
                rev = info.get("revision", {})
                if isinstance(rev, dict):
                    diag.scanner_revision = f"{rev.get('major', 0)}.{rev.get('minor', 0)}"
                else:
                    diag.scanner_revision = str(rev)
                diag.scanner_status = info.get("status", 0) if isinstance(info.get("status"), int) else 0
                diag.scanner_status_text = diag.scanner_product_name
                logger.info(f"Scanner at slot {self.scanner_slot}: {diag.scanner_product_name}")
        except Exception as e:
            logger.warning(f"Could not read scanner identity: {e}")
            diag.error_text = str(e)

        # Read DeviceNet Object (Class 0x03) from the scanner for MAC ID and baud rate
        try:
            # Build route to scanner module
            route = PADDED_EPATH.encode(
                (*self._driver._cfg["cip_path"][:-1], PortSegment("bp", self.scanner_slot)),
                length=True, pad_length=True,
            )

            # Get MAC ID (attribute 1)
            resp = self._driver.generic_message(
                service=SVC_GET_ATTR_SINGLE,
                class_code=CLASS_DEVICENET,
                instance=1,
                attribute=DNET_ATTR_MAC_ID,
                connected=False,
                unconnected_send=True,
                route_path=route,
                name="dnet_mac_id",
            )
            if resp and resp.value is not None:
                if isinstance(resp.value, bytes) and len(resp.value) >= 2:
                    diag.scanner_mac_id = struct.unpack_from("<H", resp.value)[0]
                elif isinstance(resp.value, int):
                    diag.scanner_mac_id = resp.value
                logger.info(f"Scanner MAC ID: {diag.scanner_mac_id}")

            # Get Baud Rate (attribute 2)
            resp = self._driver.generic_message(
                service=SVC_GET_ATTR_SINGLE,
                class_code=CLASS_DEVICENET,
                instance=1,
                attribute=DNET_ATTR_BAUD_RATE,
                connected=False,
                unconnected_send=True,
                route_path=route,
                name="dnet_baud_rate",
            )
            if resp and resp.value is not None:
                baud_val = 0
                if isinstance(resp.value, bytes) and len(resp.value) >= 1:
                    baud_val = resp.value[0]
                elif isinstance(resp.value, int):
                    baud_val = resp.value
                diag.scanner_baud_rate = BAUD_RATES.get(baud_val, f"Unknown ({baud_val})")
                logger.info(f"Scanner baud rate: {diag.scanner_baud_rate}")

            # Get Bus-Off Counter (attribute 4)
            resp = self._driver.generic_message(
                service=SVC_GET_ATTR_SINGLE,
                class_code=CLASS_DEVICENET,
                instance=1,
                attribute=DNET_ATTR_BUS_OFF_CNT,
                connected=False,
                unconnected_send=True,
                route_path=route,
                name="dnet_bus_off_cnt",
            )
            if resp and resp.value is not None:
                if isinstance(resp.value, bytes) and len(resp.value) >= 2:
                    diag.bus_off_count = struct.unpack_from("<H", resp.value)[0]
                elif isinstance(resp.value, int):
                    diag.bus_off_count = resp.value
                logger.info(f"Bus-off count: {diag.bus_off_count}")

        except Exception as e:
            logger.warning(f"Could not read DeviceNet object attributes: {e}")

        return diag

    def scan_node(self, mac_id: int) -> DeviceNetNode:
        """
        Scan a single DeviceNet node by sending a CIP Get_Attributes_All
        to the Identity Object (Class 0x01, Instance 1) through the scanner.

        Tries multiple routing approaches since different ENBT/scanner
        firmware versions may handle multi-hop CIP routing differently.
        """
        node = DeviceNetNode(mac_id=mac_id)

        if not self._driver:
            node.error_text = "Not connected"
            return node

        start_time = time.time()

        # If we already know a working method, try it first
        methods = list(self._scan_methods())
        if self._preferred_method:
            # Reorder so preferred method is first
            preferred = [(n, f) for n, f in methods if n == self._preferred_method]
            others = [(n, f) for n, f in methods if n != self._preferred_method]
            methods = preferred + others

        last_error = ""
        for method_name, method_func in methods:
            try:
                resp = method_func(mac_id)

                elapsed = (time.time() - start_time) * 1000
                node.response_time_ms = round(elapsed, 1)

                if resp and resp.value is not None:
                    raw_data = resp.value if isinstance(resp.value, bytes) else b""
                    node.is_online = True
                    node.raw_identity = raw_data

                    identity = decode_identity_object(raw_data)
                    if identity:
                        node.vendor_id = identity.get("vendor_id", 0)
                        node.vendor_name = CIP_VENDORS.get(
                            node.vendor_id, f"Vendor ID {node.vendor_id}")
                        node.product_type = identity.get("device_type", 0)
                        node.product_type_name = CIP_PRODUCT_TYPES.get(
                            node.product_type, f"Type {node.product_type}")
                        node.product_code = identity.get("product_code", 0)
                        node.revision_major = identity.get("revision_major", 0)
                        node.revision_minor = identity.get("revision_minor", 0)
                        node.serial_number = identity.get("serial_number", "")
                        node.product_name = identity.get("product_name", "")
                        node.device_status = identity.get("status", 0)
                        node.status_text = decode_device_status(node.device_status)

                    # Remember this method for future nodes
                    if not self._preferred_method:
                        self._preferred_method = method_name
                        logger.info(
                            f"Locking scan method to '{method_name}' "
                            f"(first success on MAC {mac_id})")

                    logger.info(
                        f"Node {mac_id}: {node.product_name} "
                        f"({node.vendor_name}) via {method_name}")
                    return node  # Success — stop trying other methods

                else:
                    # Got a response object but no data — CIP error
                    err = ""
                    if resp:
                        err = str(getattr(resp, "error", "")) or ""
                    last_error = err

                    # Check if this is a "no device" error vs a routing error.
                    # "path destination unknown" / "no response" = node isn't there
                    # "path segment error" / "invalid port" = method doesn't work
                    err_lower = err.lower()
                    is_routing_error = any(kw in err_lower for kw in [
                        "path segment", "invalid port", "invalid segment",
                        "port not available", "connection timed out",
                    ])

                    if is_routing_error:
                        # This method's routing doesn't work — try next method
                        logger.debug(
                            f"Node {mac_id}: {method_name} routing error: {err}")
                        continue
                    else:
                        # Node genuinely not present — no point trying other methods
                        logger.debug(
                            f"Node {mac_id}: not present (via {method_name}, err={err})")
                        node.error_text = err
                        return node

            except Exception as e:
                err_str = str(e)
                last_error = err_str
                logger.debug(
                    f"Node {mac_id}: {method_name} exception: {err_str}")
                # Exception likely means routing issue — try next method

        # All methods failed
        node.is_online = False
        node.error_text = last_error
        return node

    def _scan_methods(self):
        """Return an ordered list of (name, callable) scan methods to try."""
        return [
            ("multi-hop UCMM (port 2)", self._scan_via_multihop_ucmm),
            ("multi-hop UCMM (port 3)", self._scan_via_multihop_port3),
            ("nested UCMM", self._scan_via_nested_ucmm),
        ]

    def _scan_via_multihop_ucmm(self, mac_id: int):
        """
        Method 1: Single UCMM with multi-segment route path.
        Route: backplane/slot → DeviceNet port 2/mac_id

        This is the standard CIP multi-hop approach.  The ENBT Connection
        Manager should peel the first segment, forward to the scanner, and
        include the remaining segment for the scanner's CM to process.

        Port 2 is the standard DeviceNet port on 1756-DNB modules.
        """
        from pycomm3 import PortSegment

        route_segments = [
            PortSegment("bp", self.scanner_slot),
            PortSegment(DNET_PORT, mac_id),
        ]

        if mac_id == 0:
            logger.info(
                f"Multi-hop route to MAC {mac_id}: "
                f"bp/{self.scanner_slot} → port{DNET_PORT}/{mac_id}")

        return self._driver.generic_message(
            service=SVC_GET_ATTR_ALL,
            class_code=CLASS_IDENTITY,
            instance=1,
            connected=False,
            unconnected_send=True,
            route_path=route_segments,
            name=f"dnet_node_{mac_id}_identity",
        )

    def _scan_via_multihop_port3(self, mac_id: int):
        """
        Method 2: Same as method 1 but using port 3.
        Some scanner modules (1769-SDN, certain 1756-DNB firmware,
        dual-channel modules) use port 3 for the DeviceNet network.
        """
        from pycomm3 import PortSegment

        route_segments = [
            PortSegment("bp", self.scanner_slot),
            PortSegment(3, mac_id),
        ]

        return self._driver.generic_message(
            service=SVC_GET_ATTR_ALL,
            class_code=CLASS_IDENTITY,
            instance=1,
            connected=False,
            unconnected_send=True,
            route_path=route_segments,
            name=f"dnet_node_{mac_id}_port3",
        )

    def _scan_via_nested_ucmm(self, mac_id: int):
        """
        Method 2: Nested Unconnected Send (double UCMM).

        Some ENBT/scanner firmware doesn't properly forward single-UCMM
        multi-hop routes.  Instead, we manually build an inner UCMM body
        that the scanner's Connection Manager will process, routing the
        embedded Get_Attributes_All through DeviceNet to the target node.

        Outer UCMM (built by pycomm3):
          Routes to scanner via backplane
          Embedded service = 0x52 (Unconnected Send) to scanner's CM

        Inner UCMM body (our request_data):
          Priority/timeout + embedded Get_Attr_All + DeviceNet route
        """
        from pycomm3 import PADDED_EPATH, PortSegment, UINT
        from pycomm3.packets.util import request_path, PRIORITY, TIMEOUT_TICKS

        # ── Build the innermost CIP request (runs on the DeviceNet node)
        inner_service = bytes([SVC_GET_ATTR_ALL])
        inner_path = request_path(
            class_code=CLASS_IDENTITY, instance=b"\x01")
        inner_msg = inner_service + inner_path

        # ── Build the DeviceNet route
        dn_route = PADDED_EPATH.encode(
            (PortSegment(DNET_PORT, mac_id),),
            length=True, pad_length=True,
        )

        # ── Build the inner UCMM body (what the scanner's CM will process)
        # Format: priority + timeout + msg_size + message + [pad] + route
        msg_len = len(inner_msg)
        pad = b"\x00" if msg_len % 2 else b""
        inner_ucmm_body = b"".join([
            PRIORITY,
            TIMEOUT_TICKS,
            UINT.encode(msg_len),
            inner_msg,
            pad,
            dn_route,
        ])

        if mac_id == 0:
            logger.info(
                f"Nested UCMM to MAC {mac_id}: "
                f"outer=bp/{self.scanner_slot}, inner=dnet/{mac_id}, "
                f"body={inner_ucmm_body.hex()}")

        # ── Build the scanner route for the outer UCMM
        scanner_route = [
            PortSegment("bp", self.scanner_slot),
        ]

        # ── Send: outer UCMM routes to scanner, service=0x52 to scanner's CM
        # The scanner's CM receives this as an Unconnected Send request
        # and processes the inner_ucmm_body (which contains the DeviceNet route)
        return self._driver.generic_message(
            service=0x52,                    # Unconnected Send service
            class_code=CLASS_CONNECTION_MGR,  # Connection Manager (0x06)
            instance=1,
            request_data=inner_ucmm_body,
            connected=False,
            unconnected_send=True,
            route_path=scanner_route,
            name=f"dnet_node_{mac_id}_nested",
        )

    def scan_all_nodes(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> DeviceNetScanResult:
        """
        Scan all 64 DeviceNet MAC IDs and return the results.

        First reads scanner diagnostics, then scans all 64 MAC IDs.
        The scan_node method auto-discovers which routing approach works
        and locks onto it once a successful method is found.
        """
        self._cancel_event.clear()
        self._preferred_method = None  # Reset for fresh scan
        result = DeviceNetScanResult(
            connection_method="Backplane Punch-Through",
            plc_ip=self.plc_ip,
            scanner_slot=self.scanner_slot,
        )

        start_time = time.time()

        # ── Step 1: Get scanner diagnostics
        if progress_callback:
            progress_callback(0, 64, "Reading scanner diagnostics...")

        result.scanner_diag = self.get_scanner_info()
        scanner_mac = result.scanner_diag.scanner_mac_id if result.scanner_diag else -1

        logger.info(
            f"Scanner at slot {self.scanner_slot}: MAC ID {scanner_mac}, "
            f"baud={result.scanner_diag.scanner_baud_rate if result.scanner_diag else '?'}")

        # ── Step 2: Scan all 64 MAC IDs
        # Each node is probed with all available routing methods until one works.
        # Once a method succeeds, it becomes the preferred method for remaining nodes.
        for mac_id in range(64):
            if self._cancel_event.is_set():
                result.errors.append("Scan cancelled by user")
                break

            if progress_callback:
                method_hint = f" [{self._preferred_method}]" if self._preferred_method else ""
                progress_callback(
                    mac_id + 1, 64,
                    f"Scanning MAC ID {mac_id}...{method_hint}")

            if mac_id == scanner_mac:
                node = DeviceNetNode(mac_id=mac_id, is_online=True)
                if result.scanner_diag:
                    node.product_name = result.scanner_diag.scanner_product_name
                    node.vendor_name = result.scanner_diag.scanner_vendor
                    node.serial_number = result.scanner_diag.scanner_serial
                    node.status_text = "Scanner (this module)"
                result.nodes.append(node)
                continue

            node = self.scan_node(mac_id)
            result.nodes.append(node)

        if self._preferred_method:
            result.connection_method += f" ({self._preferred_method})"
        else:
            # No method ever found a node — could be all offline or routing issue
            online_count = sum(1 for n in result.nodes if n.is_online)
            if online_count <= 1:  # Only scanner itself
                result.errors.append(
                    "No DeviceNet nodes responded. Possible causes:\n"
                    "• Nodes may be powered off or disconnected\n"
                    "• Scanner module may not support CIP pass-through routing\n"
                    "• Check DeviceNet wiring, termination resistors, and baud rate"
                )

        result.scan_time_seconds = round(time.time() - start_time, 1)
        result.nodes_online = sum(1 for n in result.nodes if n.is_online)

        logger.info(
            f"DeviceNet scan complete: {result.nodes_online}/64 nodes online "
            f"in {result.scan_time_seconds}s"
            f" (method: {self._preferred_method or 'none found'})")
        return result


# ── 1784-U2DN USB Adapter Support ────────────────────────────────────────────

class U2DNAdapter:
    """
    Support for the Allen-Bradley 1784-U2DN USB-to-DeviceNet adapter.

    The 1784-U2DN is a USB device with Rockwell's proprietary PCDC driver.
    Communication is achieved by routing CIP explicit messages through
    RSLinx's dtl32.dll — the same SDK used by RSNetWorx for DeviceNet.

    Architecture:
      Python → dtl32.dll (ctypes) → RSLinx Engine → USB/PCDC Driver → 1784-U2DN → DeviceNet

    Requirements:
      - RSLinx Classic (any edition: Lite, OEM, Professional, or Gateway) running
      - 1784-U2DN connected via USB (RSLinx auto-creates a USB driver)
      - FactoryTalk Linx SDK license activated (for DTL_CIP_MESSAGE_SEND_W)
        OR RSLinx Classic SDK edition
    """

    PRODUCT_STRINGS = [
        "1784-U2DN",
        "USB-to-DeviceNet",
        "DeviceNet USB",
        "USB CIP",
        "Rockwell Automation USB",
        "PCDC",
        "AB_PCDC",
    ]

    @staticmethod
    def detect() -> dict:
        """
        Detect 1784-U2DN adapter AND RSLinx/PCDC driver availability.
        Returns dict with comprehensive detection results.
        """
        result = {
            "detected": False,
            "device_name": "",
            "com_port": "",
            "driver_installed": False,
            "rslinx_installed": False,
            "rslinx_running": False,
            "rslinx_edition": "",
            "rslinx_version": "",
            "devicenet_drivers": [],   # List of RSLinx DeviceNet driver names
            "message": "",
        }

        # ── Step 1: Check RSLinx status ──
        try:
            from core.rslinx_bridge import find_rslinx_install, RSLinxBridge
            rslinx_info = find_rslinx_install()
            result["rslinx_installed"] = rslinx_info.get("installed", False)
            result["rslinx_running"] = rslinx_info.get("running", False)
            result["rslinx_edition"] = rslinx_info.get("edition", "")
            result["rslinx_version"] = rslinx_info.get("version", "")
        except ImportError:
            logger.warning("rslinx_bridge module not available")
        except Exception as e:
            logger.debug(f"RSLinx detection error: {e}")

        # ── Step 2: If RSLinx SDK available, enumerate DeviceNet-capable drivers ──
        if result["rslinx_running"]:
            try:
                bridge = RSLinxBridge()
                ok, msg = bridge.initialize()
                if ok:
                    dnet_drivers = bridge.find_devicenet_drivers()
                    result["devicenet_drivers"] = [d.name for d in dnet_drivers]
                    bridge.shutdown()
            except Exception as e:
                logger.debug(f"RSLinx SDK driver enumeration failed: {e}")

        # ── Step 3: Check Windows Device Manager for 1784-U2DN hardware ──
        try:
            import subprocess
            proc = subprocess.run(
                ["powershell", "-Command",
                 "Get-PnpDevice | Where-Object { $_.FriendlyName -like '*DeviceNet*' -or "
                 "$_.FriendlyName -like '*1784*' -or $_.FriendlyName -like '*U2DN*' -or "
                 "$_.FriendlyName -like '*PCDC*' -or "
                 "$_.FriendlyName -like '*Rockwell*USB*CIP*' } | "
                 "Select-Object -Property FriendlyName, Status, InstanceId | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                devices = json.loads(proc.stdout)
                if isinstance(devices, dict):
                    devices = [devices]
                for dev in devices:
                    if dev.get("Status") == "OK":
                        result["detected"] = True
                        result["device_name"] = dev.get("FriendlyName", "1784-U2DN")
                        result["driver_installed"] = True
                        break
        except Exception as e:
            logger.debug(f"PowerShell device detection failed: {e}")

        # Method 2: Check serial/COM ports
        if not result["detected"]:
            try:
                import serial.tools.list_ports
                for port in serial.tools.list_ports.comports():
                    desc = (port.description or "").lower()
                    if any(s.lower() in desc for s in U2DNAdapter.PRODUCT_STRINGS):
                        result["detected"] = True
                        result["device_name"] = port.description
                        result["com_port"] = port.device
                        result["driver_installed"] = True
                        break
            except ImportError:
                pass
            except Exception as e:
                logger.debug(f"Serial port detection failed: {e}")

        # If RSLinx has DeviceNet drivers, that also counts as "detected"
        if result["devicenet_drivers"] and not result["detected"]:
            result["detected"] = True
            result["device_name"] = "RSLinx DeviceNet Driver"
            result["driver_installed"] = True

        # ── Build status message ──
        lines = []
        if result["detected"]:
            lines.append(f"✅ 1784-U2DN detected: {result['device_name']}")
            lines.append(f"   Driver: {'Installed' if result['driver_installed'] else 'Not found'}")
        else:
            lines.append("❌ 1784-U2DN not detected")

        if result["rslinx_installed"]:
            status = "Running" if result["rslinx_running"] else "Installed (not running)"
            lines.append(f"   RSLinx: {status}")
            if result["rslinx_edition"]:
                lines.append(f"   Edition: {result['rslinx_edition']}")
        else:
            lines.append("   RSLinx: Not installed")

        if result["devicenet_drivers"]:
            lines.append(f"   DeviceNet drivers: {', '.join(result['devicenet_drivers'])}")
        elif result["rslinx_running"]:
            lines.append("   DeviceNet drivers: None found — connect the 1784-U2DN and restart RSLinx")

        # Can we scan?
        can_scan = (result["rslinx_running"] and len(result["devicenet_drivers"]) > 0)
        if can_scan:
            lines.append("\n✅ Ready to scan — select a driver and click Scan Network")
        elif result["rslinx_running"]:
            lines.append("\n⚠ RSLinx is running but no DeviceNet driver found.\n"
                         "   Ensure the 1784-U2DN is connected — RSLinx should auto-detect it.\n"
                         "   The adapter will appear as a USB driver in RSLinx.")
        elif result["rslinx_installed"]:
            lines.append("\n⚠ Start RSLinx Classic and connect the 1784-U2DN")
        else:
            lines.append("\n⚠ Install RSLinx Classic (Lite is free) and connect the 1784-U2DN")

        result["message"] = "\n".join(lines)
        return result

    @staticmethod
    def get_setup_instructions() -> str:
        """Return detailed setup instructions for the 1784-U2DN with RSLinx."""
        return (
            "1784-U2DN USB-to-DeviceNet Adapter Setup\n"
            "=========================================\n\n"
            "Physical Setup:\n"
            "  1. Set the node address using the two rotary switches (0-63)\n"
            "     - Choose an unused address (typically 63 for a diagnostic tool)\n"
            "  2. Set the baud rate using the 3-position slide switch:\n"
            "     - Position 1: 125 Kbps\n"
            "     - Position 2: 250 Kbps\n"
            "     - Position 3: 500 Kbps\n"
            "     - Auto: Detects from network traffic (requires active network)\n"
            "  3. Wire the 10-pin DeviceNet connector:\n"
            "     - V+  (pin 1) → 24VDC positive\n"
            "     - V-  (pin 2) → 24VDC negative / common\n"
            "     - CAN_H (pin 4) → DeviceNet White wire\n"
            "     - CAN_L (pin 5) → DeviceNet Blue wire\n"
            "     - Shield/Drain (pin 3) → Shield/drain wire\n"
            "  4. Connect the USB end to your PC\n\n"
            "Software Setup:\n"
            "  1. Install RSLinx Classic (Lite edition is free with RSLogix)\n"
            "  2. Connect the 1784-U2DN via USB\n"
            "  3. RSLinx will auto-detect the adapter and create a USB driver\n"
            "  4. Open RSWho to verify the adapter and DeviceNet nodes appear\n\n"
            "In This Tool:\n"
            "  1. Click 'Detect RSLinx' to verify the connection\n"
            "  2. Select the driver name from the dropdown (typically 'USB')\n"
            "  3. Click 'Scan Network' to browse all 64 MAC IDs\n\n"
            "LED Indicators:\n"
            "  - Module Status: Solid Green = OK, Flashing Green = Self-test,\n"
            "    Flashing Red = Recoverable fault, Solid Red = Unrecoverable fault\n"
            "  - Network Status: Flashing Green = Network traffic present,\n"
            "    Solid Green = Communicating, Off = No power/not connected\n"
            "  - USB: Blue = USB connection active"
        )


# ── RSLinx-Based DeviceNet Scanner ───────────────────────────────────────────

class DeviceNetRSLinxScanner:
    """
    Scan a DeviceNet network by sending CIP explicit messages through RSLinx's
    dtl32.dll to the 1784-U2DN adapter (or any RSLinx DeviceNet driver).

    Supports two driver types:
      - PCDC/KFD drivers (network_type=7): Direct DeviceNet port access
        Path: DRIVER\2,NODE
      - USB CIP drivers (network_type=9): Multi-hop through USB adapter
        Path: DRIVER\1,ADAPTER_STATION\2,NODE

    Architecture:
      Python (ctypes) → dtl32.dll → RSLinx Engine → Driver → DeviceNet
    """

    def __init__(self, driver_name: str):
        """
        Args:
            driver_name: RSLinx driver name (e.g. "AB_PCDC-1" or "USB")
        """
        self.driver_name = driver_name
        self._bridge = None
        self._connected = False
        self._cancel_event = threading.Event()
        self._adapter_mac_id = -1  # MAC ID of our U2DN adapter on DeviceNet
        self._usb_station = -1     # USB adapter station (-1 = not USB / auto-detect)
        self._is_usb_driver = False  # True if this is a USB-type driver

    def connect(self) -> Tuple[bool, str]:
        """
        Initialize the RSLinx SDK bridge and verify the driver exists.
        For USB drivers, discovers the adapter station automatically.
        """
        try:
            from core.rslinx_bridge import RSLinxBridge
        except ImportError:
            return False, "rslinx_bridge module not available"

        self._bridge = RSLinxBridge()

        # Initialize DTL
        ok, msg = self._bridge.initialize()
        if not ok:
            return False, f"RSLinx SDK init failed: {msg}"

        # Verify our driver exists and is DeviceNet-capable
        drivers = self._bridge.find_devicenet_drivers()
        driver_names = [d.name for d in drivers]

        if self.driver_name not in driver_names:
            available = ", ".join(driver_names) if driver_names else "none found"
            self._bridge.shutdown()
            self._bridge = None
            return False, (
                f"Driver '{self.driver_name}' not found in RSLinx.\n"
                f"Available DeviceNet-capable drivers: {available}\n\n"
                "Make sure RSLinx is running and the 1784-U2DN is connected."
            )

        # Check if this is a USB driver
        drv_info = next((d for d in drivers if d.name == self.driver_name), None)
        if drv_info and drv_info.is_usb:
            self._is_usb_driver = True
            logger.info(f"Driver '{self.driver_name}' is USB type — "
                       f"discovering adapter station...")

            # Discover the U2DN adapter station on the USB bus
            station, adapter_name = self._bridge.discover_usb_adapter(
                self.driver_name)

            if station < 0:
                # Discovery failed — try the station from driver info
                if drv_info.station > 0:
                    self._usb_station = drv_info.station
                    logger.info(
                        f"USB adapter discovery failed, using driver station: "
                        f"{drv_info.station}")
                else:
                    self._bridge.shutdown()
                    self._bridge = None
                    return False, (
                        f"USB driver '{self.driver_name}' found but could not "
                        f"locate the 1784-U2DN adapter on the USB bus.\n\n"
                        "Verify the adapter is connected and powered."
                    )
            else:
                self._usb_station = station
                logger.info(
                    f"USB adapter found at station {station}: {adapter_name}")

        self._connected = True
        conn_info = f"Connected via RSLinx driver '{self.driver_name}'"
        if self._is_usb_driver:
            conn_info += f" (USB station {self._usb_station})"
        logger.info(conn_info)
        return True, conn_info

    def disconnect(self):
        """Shutdown the RSLinx bridge."""
        if self._bridge:
            self._bridge.shutdown()
            self._bridge = None
        self._connected = False

    def scan_node(self, mac_id: int) -> DeviceNetNode:
        """
        Scan a single DeviceNet node by sending CIP Get_Attributes_All
        to Identity Object (Class 0x01) through RSLinx.
        """
        node = DeviceNetNode(mac_id=mac_id)

        if not self._bridge or not self._connected:
            node.error_text = "Not connected"
            return node

        start_time = time.time()

        try:
            # Send CIP explicit message through RSLinx
            resp = self._bridge.read_identity(
                driver_name=self.driver_name,
                node_address=mac_id,
                timeout_ms=3000,  # Shorter timeout per node for responsiveness
                usb_adapter_station=self._usb_station,
            )

            elapsed = (time.time() - start_time) * 1000
            node.response_time_ms = round(elapsed, 1)

            if resp.success and resp.data:
                node.is_online = True
                node.raw_identity = resp.data

                identity = decode_identity_object(resp.data)
                if identity:
                    node.vendor_id = identity.get("vendor_id", 0)
                    node.vendor_name = CIP_VENDORS.get(node.vendor_id,
                                                        f"Vendor ID {node.vendor_id}")
                    node.product_type = identity.get("device_type", 0)
                    node.product_type_name = CIP_PRODUCT_TYPES.get(node.product_type,
                                                                     f"Type {node.product_type}")
                    node.product_code = identity.get("product_code", 0)
                    node.revision_major = identity.get("revision_major", 0)
                    node.revision_minor = identity.get("revision_minor", 0)
                    node.serial_number = identity.get("serial_number", "")
                    node.product_name = identity.get("product_name", "")
                    node.device_status = identity.get("status", 0)
                    node.status_text = decode_device_status(node.device_status)

                logger.info(f"Node {mac_id}: {node.product_name} ({node.vendor_name})")

            elif resp.success and not resp.data:
                # Empty response — likely the U2DN adapter itself
                node.is_online = False
            else:
                node.is_online = False
                node.error_text = resp.error_text or "No response"

        except Exception as e:
            node.is_online = False
            node.error_text = str(e)
            logger.debug(f"Node {mac_id}: no response ({e})")

        return node

    def read_node_devicenet_object(self, mac_id: int) -> dict:
        """
        Read DeviceNet Object (Class 0x03) attributes for a specific node.
        Returns dict with baud_rate, bus_off_count, mac_id from the device.
        """
        info = {}
        if not self._bridge or not self._connected:
            return info

        # Attribute 1: MAC ID
        resp = self._bridge.read_devicenet_object(
            self.driver_name, mac_id, attribute=DNET_ATTR_MAC_ID,
            usb_adapter_station=self._usb_station)
        if resp.success and len(resp.data) >= 1:
            info["mac_id"] = resp.data[0]

        # Attribute 2: Baud Rate
        resp = self._bridge.read_devicenet_object(
            self.driver_name, mac_id, attribute=DNET_ATTR_BAUD_RATE,
            usb_adapter_station=self._usb_station)
        if resp.success and len(resp.data) >= 1:
            baud_idx = resp.data[0]
            info["baud_rate"] = baud_idx
            info["baud_rate_text"] = BAUD_RATES.get(baud_idx, f"Unknown ({baud_idx})")

        # Attribute 4: Bus-Off Counter
        resp = self._bridge.read_devicenet_object(
            self.driver_name, mac_id, attribute=DNET_ATTR_BUS_OFF_CNT,
            usb_adapter_station=self._usb_station)
        if resp.success and len(resp.data) >= 1:
            info["bus_off_count"] = resp.data[0]

        return info

    def scan_all_nodes(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> DeviceNetScanResult:
        """
        Scan all 64 DeviceNet MAC IDs through RSLinx and return results.

        Args:
            progress_callback: Called with (current_node, total_nodes, status_text)
        """
        self._cancel_event.clear()
        result = DeviceNetScanResult(
            connection_method="1784-U2DN via RSLinx",
            plc_ip="",  # Not applicable for direct U2DN
            scanner_slot=0,
        )

        start_time = time.time()

        if progress_callback:
            progress_callback(0, 64, f"Scanning via RSLinx driver '{self.driver_name}'...")

        # Scan all 64 MAC IDs
        for mac_id in range(64):
            if self._cancel_event.is_set():
                result.errors.append("Scan cancelled by user")
                break

            if progress_callback:
                progress_callback(mac_id + 1, 64, f"Scanning MAC ID {mac_id}...")

            node = self.scan_node(mac_id)
            result.nodes.append(node)

            # If this node responded and looks like a U2DN adapter, note it
            if node.is_online and node.product_name:
                pname = node.product_name.lower()
                if "u2dn" in pname or "usb" in pname or "pcdc" in pname:
                    self._adapter_mac_id = mac_id
                    node.status_text = "U2DN Adapter (this device)"

        # Try to read DeviceNet Object attributes for online nodes
        # (baud rate, bus-off count) — this is a second pass for extra diag info
        online_nodes = [n for n in result.nodes if n.is_online]
        if online_nodes and not self._cancel_event.is_set():
            if progress_callback:
                progress_callback(64, 64, "Reading DeviceNet attributes...")

            for node in online_nodes:
                if self._cancel_event.is_set():
                    break
                try:
                    dnet_info = self.read_node_devicenet_object(node.mac_id)
                    if "baud_rate" in dnet_info:
                        node.baud_rate = dnet_info["baud_rate"]
                        node.baud_rate_text = dnet_info.get("baud_rate_text", "")
                    if "bus_off_count" in dnet_info:
                        node.bus_off_count = dnet_info["bus_off_count"]
                except Exception as e:
                    logger.debug(f"DeviceNet object read failed for node {node.mac_id}: {e}")

        # Build scanner diagnostics (the U2DN adapter info, if found)
        if self._adapter_mac_id >= 0:
            adapter_node = next((n for n in result.nodes
                                  if n.mac_id == self._adapter_mac_id), None)
            if adapter_node:
                result.scanner_diag = ScannerDiagnostics(
                    scanner_mac_id=self._adapter_mac_id,
                    scanner_product_name=adapter_node.product_name or "1784-U2DN",
                    scanner_vendor=adapter_node.vendor_name or "Rockwell Automation",
                    scanner_serial=adapter_node.serial_number,
                    scanner_revision=(f"{adapter_node.revision_major}."
                                      f"{adapter_node.revision_minor}"),
                    is_running=True,
                )
                if adapter_node.baud_rate_text:
                    result.scanner_diag.scanner_baud_rate = adapter_node.baud_rate_text

        result.scan_time_seconds = round(time.time() - start_time, 1)
        result.nodes_online = sum(1 for n in result.nodes if n.is_online)

        logger.info(f"RSLinx DeviceNet scan complete: {result.nodes_online}/64 nodes online "
                     f"in {result.scan_time_seconds}s")
        return result


# ── Convenience Functions ────────────────────────────────────────────────────

def get_error_info(error_code: int) -> dict:
    """Look up a DNB/SDN error code and return its details."""
    return DNB_ERROR_CODES.get(error_code, {
        "name": f"Unknown Error ({error_code})",
        "description": f"Error code {error_code} is not in the known error database.",
        "severity": "unknown",
        "fix": "Consult the scanner module's user manual for this error code.",
    })


def get_vendor_name(vendor_id: int) -> str:
    """Look up a CIP vendor name by ID."""
    return CIP_VENDORS.get(vendor_id, f"Vendor ID {vendor_id}")


def get_product_type_name(product_type: int) -> str:
    """Look up a CIP product type name."""
    return CIP_PRODUCT_TYPES.get(product_type, f"Type {product_type}")


def run_devicenet_scan(
    plc_ip: str,
    scanner_slot: int,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> DeviceNetScanResult:
    """
    Convenience function to run a full DeviceNet scan via backplane punch-through.

    Args:
        plc_ip: IP address of the PLC with the DeviceNet scanner
        scanner_slot: Chassis slot number of the DNB/SDN module
        progress_callback: Called with (current, total, status_text)
        cancel_event: Set this event to cancel the scan

    Returns:
        DeviceNetScanResult with all discovered nodes and diagnostics
    """
    scanner = DeviceNetBackplaneScanner(plc_ip, scanner_slot)

    if cancel_event:
        scanner._cancel_event = cancel_event

    # Connect
    if progress_callback:
        progress_callback(0, 64, f"Connecting to PLC at {plc_ip}...")

    success, msg = scanner.connect()
    if not success:
        result = DeviceNetScanResult(
            connection_method="Backplane Punch-Through",
            plc_ip=plc_ip,
            scanner_slot=scanner_slot,
        )
        result.errors.append(msg)
        return result

    try:
        return scanner.scan_all_nodes(progress_callback)
    finally:
        scanner.disconnect()


def run_u2dn_scan(
    driver_name: str,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> DeviceNetScanResult:
    """
    Convenience function to run a full DeviceNet scan via 1784-U2DN / RSLinx.

    Args:
        driver_name: RSLinx DeviceNet driver name (e.g. "AB_PCDC-1")
        progress_callback: Called with (current, total, status_text)
        cancel_event: Set this event to cancel the scan

    Returns:
        DeviceNetScanResult with all discovered nodes and diagnostics
    """
    scanner = DeviceNetRSLinxScanner(driver_name)

    if cancel_event:
        scanner._cancel_event = cancel_event

    # Connect (initializes RSLinx SDK, verifies driver)
    if progress_callback:
        progress_callback(0, 64, f"Initializing RSLinx SDK (driver: {driver_name})...")

    success, msg = scanner.connect()
    if not success:
        result = DeviceNetScanResult(
            connection_method="1784-U2DN via RSLinx",
        )
        result.errors.append(msg)
        return result

    try:
        return scanner.scan_all_nodes(progress_callback)
    finally:
        scanner.disconnect()
