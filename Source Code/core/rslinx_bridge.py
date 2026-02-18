"""
SAS Network Diagnostics Tool — RSLinx SDK Bridge
Wraps Rockwell's dtl32.dll (FactoryTalk Linx SDK / RSLinx C API) via ctypes
to send CIP explicit messages through RSLinx drivers.

Primary use case: DeviceNet diagnostics through the 1784-U2DN adapter.
RSLinx must be running — the U2DN auto-creates a USB driver when connected.

Supported driver types:
  - USB CIP (network_type=9): 1784-U2DN auto-detected by RSLinx
    Path: USB\1,ADAPTER_STATION\2,NODE_ADDRESS
  - DeviceNet PCDC (network_type=7): Legacy PCI/ISA DeviceNet cards
    Path: DRIVER_NAME\2,NODE_ADDRESS

Architecture:
  Python (ctypes) → dtl32.dll → RSLinx Engine → Driver → DeviceNet

SDK Functions Used:
  DTL_INIT                     — Initialize the DTL library
  DTL_UNINIT                   — Shutdown the DTL library
  DTL_DRIVER_LIST_EX           — Enumerate configured RSLinx drivers
  DTL_CreatetDriverList        — Allocate driver list
  DTL_DestroyDriverList        — Free driver list
  DTL_Get*FromDriverListEntry  — Read driver list fields
  DTL_CreateDtsaFromPathString — Build a path handle (DTSA) from a string
  DTL_DestroyDtsa              — Free a DTSA handle
  DTL_OpenDtsa                 — Open a routing path for messaging
  DTL_CloseDtsa                — Close a routing path
  DTL_CIP_MESSAGE_SEND_W       — Send CIP explicit message (synchronous)
  DTL_ERROR_S                  — Convert error code to human-readable string

References:
  - FactoryTalk Linx SDK Reference Manual (LNXSDK-RM001B-EN-E)
  - RSLinx Classic Getting Results Guide (LINX-GR001Z-EN-E)
"""

import ctypes
import ctypes.wintypes as wt
import logging
import os
import struct
import sys
import time
from ctypes import (
    POINTER, Structure, byref, c_byte, c_char, c_char_p,
    c_int, c_long, c_short, c_ubyte, c_uint, c_ulong, c_ushort, c_void_p,
    create_string_buffer, sizeof,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── DTL Return Codes ────────────────────────────────────────────────────────
DTL_SUCCESS = 0
DTL_E_FAIL = -1

# Common error codes from dtl.h
DTL_ERRORS = {
    0: "DTL_I_SUCCESS",
    -1: "DTL_E_FAIL",
    -2: "DTL_E_NOT_INITIALIZED",
    -3: "DTL_E_ALREADY_INITIALIZED",
    -4: "DTL_E_OUT_OF_MEMORY",
    -5: "DTL_E_BADPARAM",
    -6: "DTL_E_BADID",
    -7: "DTL_E_TIMEOUT",
    -8: "DTL_E_NOT_CONNECTED",
    -9: "DTL_E_DRIVER_NOT_FOUND",
    -10: "DTL_E_DRIVER_NOT_OPEN",
    -14: "DTL_E_PATH_NOT_FOUND",
    -15: "DTL_E_NODE_NOT_FOUND",
    -16: "DTL_E_MSG_REJECTED",
    -100: "DTL_E_NO_RSLINX",
}

# Network type constants for driver identification
NET_TYPE_DEVICENET = 7    # DeviceNet driver (PCDC, 1770-KFD, etc.)
NET_TYPE_ETHERNET = 6     # EtherNet/IP driver
NET_TYPE_DH_PLUS = 2      # DH+ driver
NET_TYPE_CONTROLNET = 5   # ControlNet driver
NET_TYPE_USB = 9           # USB CIP driver (1784-U2DN, USB-to-DeviceNet)

NETWORK_TYPE_NAMES = {
    1: "DH485",
    2: "DH+",
    3: "Serial/DF1",
    5: "ControlNet",
    6: "EtherNet/IP",
    7: "DeviceNet",
    8: "Virtual Backplane",
    9: "USB",
}

# CIP Service Codes
CIP_GET_ATTR_ALL = 0x01
CIP_GET_ATTR_SINGLE = 0x0E

# CIP Class Codes
CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_DEVICENET = 0x03

# Timeout for CIP messages (ms)
DEFAULT_TIMEOUT_MS = 5000


# ── DTL Structures ──────────────────────────────────────────────────────────

# The DTSA (Data Table Source Address) is an opaque handle in the SDK.
# We treat it as a void pointer.
DTSA_HANDLE = c_void_p

# Driver list entry is also opaque
DRIVER_LIST_ENTRY = c_void_p


@dataclass
class RSLinxDriver:
    """Information about a configured RSLinx driver."""
    name: str = ""
    handle: int = 0
    driver_id: int = 0
    network_type: int = 0
    network_type_name: str = ""
    station: int = 0
    is_devicenet: bool = False       # Traditional PCDC/KFD DeviceNet driver
    is_usb: bool = False             # USB CIP driver (1784-U2DN)
    is_devicenet_capable: bool = False  # Either PCDC or USB DeviceNet


@dataclass
class CIPResponse:
    """Result of a CIP explicit message."""
    success: bool = False
    service: int = 0
    general_status: int = 0
    extended_status: int = 0
    data: bytes = b""
    error_text: str = ""
    elapsed_ms: float = 0.0


# ── RSLinx Bridge Class ─────────────────────────────────────────────────────

class RSLinxBridge:
    """
    Low-level wrapper for RSLinx's dtl32.dll via ctypes.

    Requires:
      - RSLinx Classic (any edition) or FactoryTalk Linx installed and running
      - For SDK functions: RSLinx Classic SDK or FactoryTalk Linx SDK activated
      - dtl32.dll in the system PATH (installed automatically with RSLinx)

    The bridge provides:
      - RSLinx detection and connection
      - Driver enumeration (find DeviceNet-capable drivers: USB and PCDC)
      - USB adapter station discovery for 1784-U2DN
      - CIP explicit messaging through any RSLinx driver
    """

    # Possible DLL locations (searched in order)
    DLL_SEARCH_PATHS = [
        # RSLinx Classic default install
        r"C:\Program Files (x86)\Rockwell Software\RSLinx\dtl32.dll",
        r"C:\Program Files\Rockwell Software\RSLinx\dtl32.dll",
        # FactoryTalk Linx
        r"C:\Program Files (x86)\Common Files\Rockwell\FactoryTalk Linx\dtl32.dll",
        r"C:\Program Files\Common Files\Rockwell\FactoryTalk Linx\dtl32.dll",
        # System32 (RSLinx copies it here)
        r"C:\Windows\System32\dtl32.dll",
        r"C:\Windows\SysWOW64\dtl32.dll",
    ]

    def __init__(self):
        self._dll = None
        self._initialized = False
        self._dll_path = ""

    # ── Lifecycle ────────────────────────────────────────────────────────

    def find_dll(self) -> Tuple[bool, str]:
        """
        Locate dtl32.dll on the system.
        Returns (found, path_or_message).
        """
        # First try loading from system PATH
        try:
            test = ctypes.WinDLL("dtl32")
            # If that worked, it's in the PATH
            ctypes.windll.kernel32.FreeLibrary(test._handle)
            return True, "dtl32.dll (system PATH)"
        except OSError:
            pass

        # Search known install locations
        for path in self.DLL_SEARCH_PATHS:
            if os.path.exists(path):
                return True, path

        return False, (
            "dtl32.dll not found. RSLinx Classic or FactoryTalk Linx "
            "must be installed.\n\n"
            "Install RSLinx Classic Lite (free) from:\n"
            "  rockwellautomation.com → Downloads → RSLinx Classic"
        )

    def initialize(self, max_definitions: int = 128) -> Tuple[bool, str]:
        """
        Load dtl32.dll and call DTL_INIT.

        Args:
            max_definitions: Maximum number of simultaneous DTL definitions.
                            64 nodes + overhead = 128 is safe.

        Returns:
            (success, message)
        """
        if self._initialized:
            return True, "Already initialized"

        # Find and load the DLL
        found, path_info = self.find_dll()
        if not found:
            return False, path_info

        try:
            if os.path.exists(path_info):
                self._dll = ctypes.WinDLL(path_info)
                self._dll_path = path_info
            else:
                # In system PATH
                self._dll = ctypes.WinDLL("dtl32")
                self._dll_path = "dtl32.dll (PATH)"
            logger.info(f"Loaded {self._dll_path}")
        except OSError as e:
            return False, f"Failed to load dtl32.dll: {e}"

        # Set up function prototypes
        self._setup_prototypes()

        # Initialize the library
        try:
            status = self._dll.DTL_INIT(max_definitions)
            if status != DTL_SUCCESS:
                err = self._get_error_string(status)
                return False, f"DTL_INIT failed: {err} (code {status})"

            self._initialized = True
            logger.info("DTL_INIT successful")
            return True, f"RSLinx SDK initialized ({self._dll_path})"

        except Exception as e:
            return False, f"DTL_INIT exception: {e}"

    def shutdown(self):
        """Call DTL_UNINIT and release the DLL."""
        if self._initialized and self._dll:
            try:
                self._dll.DTL_UNINIT()
                logger.info("DTL_UNINIT called")
            except Exception as e:
                logger.warning(f"DTL_UNINIT error: {e}")
            self._initialized = False
        self._dll = None

    def is_initialized(self) -> bool:
        return self._initialized

    # ── Function Prototypes ──────────────────────────────────────────────

    def _setup_prototypes(self):
        """Define ctypes function signatures for the DTL functions we use."""
        dll = self._dll

        # DTL_INIT(int max_defs) → long
        dll.DTL_INIT.argtypes = [c_int]
        dll.DTL_INIT.restype = c_long

        # DTL_UNINIT() → long
        dll.DTL_UNINIT.argtypes = []
        dll.DTL_UNINIT.restype = c_long

        # DTL_ERROR_S(long status, char* buf, int bufsize) → long
        dll.DTL_ERROR_S.argtypes = [c_long, c_char_p, c_int]
        dll.DTL_ERROR_S.restype = c_long

        # DTL_CreatetDriverList() → void*
        dll.DTL_CreatetDriverList.argtypes = []
        dll.DTL_CreatetDriverList.restype = c_void_p

        # DTL_DestroyDriverList(void* list) → void
        dll.DTL_DestroyDriverList.argtypes = [c_void_p]
        dll.DTL_DestroyDriverList.restype = None

        # DTL_DRIVER_LIST_EX(void* list) → long
        dll.DTL_DRIVER_LIST_EX.argtypes = [c_void_p]
        dll.DTL_DRIVER_LIST_EX.restype = c_long

        # DTL_GetDriverListEntryFromDriverListIndex(void* list, int idx) → void*
        dll.DTL_GetDriverListEntryFromDriverListIndex.argtypes = [c_void_p, c_int]
        dll.DTL_GetDriverListEntryFromDriverListIndex.restype = c_void_p

        # DTL_GetDriverNameFromDriverListEntry(void* entry, char* buf, int size) → long
        dll.DTL_GetDriverNameFromDriverListEntry.argtypes = [c_void_p, c_char_p, c_int]
        dll.DTL_GetDriverNameFromDriverListEntry.restype = c_long

        # DTL_GetNetworkTypeFromDriverListEntry(void* entry) → int
        dll.DTL_GetNetworkTypeFromDriverListEntry.argtypes = [c_void_p]
        dll.DTL_GetNetworkTypeFromDriverListEntry.restype = c_int

        # DTL_GetHandleFromDriverListEntry(void* entry) → int
        dll.DTL_GetHandleFromDriverListEntry.argtypes = [c_void_p]
        dll.DTL_GetHandleFromDriverListEntry.restype = c_int

        # DTL_GetDriverIDFromDriverListEntry(void* entry) → int
        dll.DTL_GetDriverIDFromDriverListEntry.argtypes = [c_void_p]
        dll.DTL_GetDriverIDFromDriverListEntry.restype = c_int

        # DTL_GetStationFromDriverListEntry(void* entry) → int
        dll.DTL_GetStationFromDriverListEntry.argtypes = [c_void_p]
        dll.DTL_GetStationFromDriverListEntry.restype = c_int

        # DTL_MaxDrivers() → int
        dll.DTL_MaxDrivers.argtypes = []
        dll.DTL_MaxDrivers.restype = c_int

        # DTL_CreateDtsaFromPathString(char* path) → void*
        dll.DTL_CreateDtsaFromPathString.argtypes = [c_char_p]
        dll.DTL_CreateDtsaFromPathString.restype = c_void_p

        # DTL_DestroyDtsa(void* dtsa) → void
        dll.DTL_DestroyDtsa.argtypes = [c_void_p]
        dll.DTL_DestroyDtsa.restype = None

        # DTL_OpenDtsa(void* dtsa) → long
        dll.DTL_OpenDtsa.argtypes = [c_void_p]
        dll.DTL_OpenDtsa.restype = c_long

        # DTL_CloseDtsa(void* dtsa) → long
        dll.DTL_CloseDtsa.argtypes = [c_void_p]
        dll.DTL_CloseDtsa.restype = c_long

        # DTL_CIP_MESSAGE_SEND_W(
        #   void* dtsa,           — routing path
        #   BYTE  service,        — CIP service code
        #   BYTE* req_path,       — encoded CIP path (class/instance)
        #   WORD  req_path_size,  — size of req_path in WORDs
        #   BYTE* req_data,       — request data (NULL for reads)
        #   WORD  req_data_size,  — size of request data in bytes
        #   BYTE* rsp_data,       — response buffer
        #   WORD* rsp_data_size,  — [in] buffer size, [out] actual response size
        #   DWORD timeout_ms      — timeout in milliseconds
        # ) → long
        dll.DTL_CIP_MESSAGE_SEND_W.argtypes = [
            c_void_p,    # dtsa
            c_ubyte,     # service
            c_char_p,    # req_path
            c_ushort,    # req_path_size (in WORDs)
            c_char_p,    # req_data
            c_ushort,    # req_data_size
            c_char_p,    # rsp_data
            POINTER(c_ushort),  # rsp_data_size
            c_ulong,     # timeout
        ]
        dll.DTL_CIP_MESSAGE_SEND_W.restype = c_long

    # ── Error Handling ───────────────────────────────────────────────────

    def _get_error_string(self, status: int) -> str:
        """Convert a DTL status code to a human-readable string."""
        if self._dll:
            try:
                buf = create_string_buffer(256)
                self._dll.DTL_ERROR_S(status, buf, 256)
                return buf.value.decode("ascii", errors="replace")
            except Exception:
                pass
        return DTL_ERRORS.get(status, f"Unknown error ({status})")

    # ── Driver Enumeration ───────────────────────────────────────────────

    def list_drivers(self) -> List[RSLinxDriver]:
        """
        Enumerate all configured RSLinx drivers.
        Returns a list of RSLinxDriver objects.
        """
        if not self._initialized:
            logger.warning("DTL not initialized")
            return []

        drivers = []
        driver_list = None

        try:
            # Allocate and populate driver list
            driver_list = self._dll.DTL_CreatetDriverList()
            if not driver_list:
                logger.warning("DTL_CreatetDriverList returned NULL")
                return []

            status = self._dll.DTL_DRIVER_LIST_EX(driver_list)
            if status != DTL_SUCCESS:
                logger.warning(f"DTL_DRIVER_LIST_EX failed: {self._get_error_string(status)}")
                return []

            # Iterate entries — try indices 0..max_drivers
            max_drivers = self._dll.DTL_MaxDrivers()
            for i in range(max_drivers):
                entry = self._dll.DTL_GetDriverListEntryFromDriverListIndex(driver_list, i)
                if not entry:
                    continue

                drv = RSLinxDriver()

                # Get driver name
                name_buf = create_string_buffer(256)
                self._dll.DTL_GetDriverNameFromDriverListEntry(entry, name_buf, 256)
                drv.name = name_buf.value.decode("ascii", errors="replace")

                if not drv.name:
                    continue

                # Get network type
                drv.network_type = self._dll.DTL_GetNetworkTypeFromDriverListEntry(entry)
                drv.network_type_name = NETWORK_TYPE_NAMES.get(
                    drv.network_type, f"Type {drv.network_type}")
                drv.is_devicenet = (drv.network_type == NET_TYPE_DEVICENET)
                drv.is_usb = (drv.network_type == NET_TYPE_USB)
                # USB drivers can bridge to DeviceNet (1784-U2DN)
                drv.is_devicenet_capable = drv.is_devicenet or drv.is_usb

                # Get handle and IDs
                drv.handle = self._dll.DTL_GetHandleFromDriverListEntry(entry)
                drv.driver_id = self._dll.DTL_GetDriverIDFromDriverListEntry(entry)
                drv.station = self._dll.DTL_GetStationFromDriverListEntry(entry)

                drivers.append(drv)
                flags = []
                if drv.is_devicenet:
                    flags.append("DeviceNet")
                if drv.is_usb:
                    flags.append("USB/U2DN")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                logger.info(f"Driver: {drv.name} ({drv.network_type_name})"
                           f" handle={drv.handle} station={drv.station}"
                           f"{flag_str}")

        except Exception as e:
            logger.error(f"Error enumerating drivers: {e}")
        finally:
            if driver_list:
                self._dll.DTL_DestroyDriverList(driver_list)

        return drivers

    def find_devicenet_drivers(self) -> List[RSLinxDriver]:
        """Find all drivers capable of DeviceNet access (PCDC, USB/U2DN, etc.)."""
        drivers = [d for d in self.list_drivers() if d.is_devicenet_capable]

        # USB drivers created by auto-detect (1784-U2DN) often don't appear in
        # DTL_DRIVER_LIST_EX. Probe common USB driver names directly.
        usb_names_found = {d.name for d in drivers if d.is_usb}
        for usb_name in ["USB", "USB1", "USB2"]:
            if usb_name in usb_names_found:
                continue  # Already found via enumeration
            station, desc = self.probe_usb_driver(usb_name)
            if station >= 0:
                drv = RSLinxDriver(
                    name=usb_name,
                    network_type=NET_TYPE_USB,
                    network_type_name="USB",
                    is_usb=True,
                    is_devicenet_capable=True,
                    station=station,
                )
                drivers.append(drv)
                logger.info(f"USB driver '{usb_name}' found via direct probe "
                           f"(station {station}: {desc})")

        return drivers

    def probe_usb_driver(
        self,
        driver_name: str,
        timeout_ms: int = 2000,
    ) -> Tuple[int, str]:
        """
        Probe whether a USB driver exists and find the adapter station
        by attempting DTSA paths. Returns (station, description) or (-1, msg).

        Tries multiple path formats since RSLinx USB driver paths vary:
          Format 1: DRIVER\\1,STATION  (port 1, station N)
          Format 2: DRIVER\\STATION    (bare address, no port)
        """
        if not self._initialized:
            return -1, "DTL not initialized"

        # Try common adapter station numbers
        # 1784-U2DN typically appears at station 16 (from RSLinx RSWho)
        # but can also be at 2, 0, etc.
        probe_stations = [16, 2, 0, 1, 3, 4, 5, 6, 7, 8] + list(range(9, 33))

        # Path format patterns to try for each station
        path_templates = [
            lambda drv, stn: f"{drv}\\1,{stn}",   # Port 1, station N
            lambda drv, stn: f"{drv}\\{stn}",      # Bare address
        ]

        errors_seen = set()

        for station in probe_stations:
            for fmt_idx, fmt in enumerate(path_templates):
                try:
                    path = fmt(driver_name, station)
                    path_bytes = path.encode("ascii")

                    dtsa = self._dll.DTL_CreateDtsaFromPathString(path_bytes)
                    if not dtsa:
                        errors_seen.add(f"CreateDtsa NULL: '{path}'")
                        continue

                    status = self._dll.DTL_OpenDtsa(dtsa)
                    if status != DTL_SUCCESS:
                        err = self._get_error_string(status)
                        errors_seen.add(f"OpenDtsa '{path}': {err} ({status})")
                        self._dll.DTL_DestroyDtsa(dtsa)

                        # If driver not found, skip remaining stations for this format
                        if status in (-9, -14):  # DRIVER_NOT_FOUND, PATH_NOT_FOUND
                            logger.debug(f"USB probe '{path}': {err} — "
                                       f"skipping format {fmt_idx}")
                            break
                        continue

                    # Build CIP Get_Attributes_All for Identity Object
                    cip_path = self.build_cip_path(CIP_CLASS_IDENTITY, 1)
                    path_size_words = len(cip_path) // 2
                    req_path_buf = create_string_buffer(cip_path)
                    rsp_buf = create_string_buffer(256)
                    rsp_size = c_ushort(256)

                    msg_status = self._dll.DTL_CIP_MESSAGE_SEND_W(
                        dtsa,
                        c_ubyte(CIP_GET_ATTR_ALL),
                        req_path_buf,
                        c_ushort(path_size_words),
                        None,
                        c_ushort(0),
                        rsp_buf,
                        byref(rsp_size),
                        c_ulong(timeout_ms),
                    )

                    try:
                        self._dll.DTL_CloseDtsa(dtsa)
                    except Exception:
                        pass
                    self._dll.DTL_DestroyDtsa(dtsa)

                    if msg_status == DTL_SUCCESS and rsp_size.value > 0:
                        desc = f"Adapter at station {station}"
                        # Try to extract product name from identity response
                        if rsp_size.value > 4:
                            raw = bytes(rsp_buf.raw[:rsp_size.value])
                            ext_size = raw[3] if len(raw) > 3 else 0
                            data_offset = 4 + (ext_size * 2)
                            if data_offset < len(raw):
                                try:
                                    from core.devicenet_diag import decode_identity_object
                                    identity = decode_identity_object(raw[data_offset:])
                                    pname = identity.get("product_name", "")
                                    if pname:
                                        desc = pname
                                except Exception:
                                    pass
                        logger.info(f"USB probe SUCCESS: '{path}' → {desc}")
                        return station, desc
                    else:
                        if msg_status != DTL_SUCCESS:
                            err = self._get_error_string(msg_status)
                            errors_seen.add(f"CIP msg '{path}': {err}")

                except Exception as e:
                    errors_seen.add(f"Exception '{path}': {e}")

        # Log diagnostic summary if we failed
        if errors_seen:
            sample = list(errors_seen)[:5]
            logger.info(f"USB probe failed for driver '{driver_name}'. "
                       f"Errors ({len(errors_seen)} total): {sample}")

        return -1, f"No adapter found on driver '{driver_name}'"

    # ── CIP Messaging ────────────────────────────────────────────────────

    def build_cip_path(self, class_id: int, instance: int) -> bytes:
        """
        Build an encoded CIP path for class/instance addressing.

        CIP path encoding (padded EPATH):
          Segment type 0x20 = 8-bit Class ID
          Segment type 0x21 = 16-bit Class ID
          Segment type 0x24 = 8-bit Instance ID
          Segment type 0x25 = 16-bit Instance ID
        """
        path = bytearray()

        # Class segment
        if class_id <= 0xFF:
            path += bytes([0x20, class_id & 0xFF])
        else:
            path += bytes([0x21, 0x00])  # 0x00 pad
            path += struct.pack("<H", class_id)

        # Instance segment
        if instance <= 0xFF:
            path += bytes([0x24, instance & 0xFF])
        else:
            path += bytes([0x25, 0x00])  # 0x00 pad
            path += struct.pack("<H", instance)

        return bytes(path)

    def send_cip_message(
        self,
        driver_name: str,
        node_address: int,
        service: int,
        class_id: int,
        instance: int,
        attribute: int = 0,
        request_data: bytes = b"",
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        usb_adapter_station: int = -1,
    ) -> CIPResponse:
        """
        Send a CIP explicit message through an RSLinx driver to a DeviceNet node.

        Args:
            driver_name: RSLinx driver name (e.g. "AB_PCDC-1" or "USB")
            node_address: DeviceNet MAC ID (0-63)
            service: CIP service code (e.g. 0x01 for Get_Attributes_All)
            class_id: CIP class (e.g. 0x01 for Identity)
            instance: CIP instance (typically 1)
            attribute: CIP attribute (0 = all, or specific attribute ID)
            request_data: Additional request data bytes
            timeout_ms: Timeout in milliseconds
            usb_adapter_station: For USB drivers, the adapter's station number
                                 on the USB bus (e.g. 16 for U2DN). When >= 0,
                                 builds a multi-hop path: USB → adapter → DeviceNet.

        Returns:
            CIPResponse with the result
        """
        result = CIPResponse()

        if not self._initialized:
            result.error_text = "DTL not initialized"
            return result

        # Build the DTSA path string based on driver type
        if usb_adapter_station >= 0:
            # USB driver: multi-hop path through the adapter
            # Format: "DRIVER\1,ADAPTER_STATION\2,NODE_ADDRESS"
            # Port 1 = USB CIP port to adapter, Port 2 = DeviceNet port
            path_str = (f"{driver_name}\\1,{usb_adapter_station}"
                       f"\\2,{node_address}").encode("ascii")
        else:
            # Traditional DeviceNet driver (PCDC, KFD):
            # Format: "DRIVER_NAME\2,NODE_ADDRESS"
            # Where 2 = DeviceNet port, NODE_ADDRESS = MAC ID
            path_str = f"{driver_name}\\2,{node_address}".encode("ascii")

        dtsa = None
        start_time = time.time()

        try:
            # Create DTSA from path string
            dtsa = self._dll.DTL_CreateDtsaFromPathString(path_str)
            if not dtsa:
                result.error_text = f"Failed to create DTSA for path: {path_str.decode()}"
                return result

            # Open the routing path
            status = self._dll.DTL_OpenDtsa(dtsa)
            if status != DTL_SUCCESS:
                result.error_text = f"DTL_OpenDtsa failed: {self._get_error_string(status)}"
                return result

            # Build CIP request path (class/instance[/attribute])
            if service == CIP_GET_ATTR_SINGLE and attribute > 0:
                # For Get_Attribute_Single, include the attribute in the path
                cip_path = self.build_cip_path(class_id, instance)
                # Add attribute segment
                if attribute <= 0xFF:
                    cip_path += bytes([0x30, attribute & 0xFF])
                else:
                    cip_path += bytes([0x31, 0x00])
                    cip_path += struct.pack("<H", attribute)
            else:
                cip_path = self.build_cip_path(class_id, instance)

            # Path size is in WORDs (16-bit words)
            path_size_words = len(cip_path) // 2

            # Prepare request/response buffers
            req_path_buf = create_string_buffer(cip_path)
            req_data_buf = create_string_buffer(request_data) if request_data else None
            req_data_size = len(request_data)

            rsp_buf = create_string_buffer(1024)
            rsp_size = c_ushort(1024)

            # Send the CIP message (synchronous)
            status = self._dll.DTL_CIP_MESSAGE_SEND_W(
                dtsa,
                c_ubyte(service),
                req_path_buf,
                c_ushort(path_size_words),
                req_data_buf,
                c_ushort(req_data_size),
                rsp_buf,
                byref(rsp_size),
                c_ulong(timeout_ms),
            )

            result.elapsed_ms = (time.time() - start_time) * 1000

            if status == DTL_SUCCESS:
                result.success = True
                actual_size = rsp_size.value
                result.data = bytes(rsp_buf.raw[:actual_size])

                # Parse CIP response header if present
                # CIP response: service | reserved | general_status | ext_status_size | [ext_status] | data
                if actual_size >= 4:
                    result.service = result.data[0]
                    result.general_status = result.data[2]
                    ext_size = result.data[3]
                    data_offset = 4 + (ext_size * 2)
                    if data_offset < actual_size:
                        result.data = result.data[data_offset:]
                    else:
                        result.data = b""

                    if result.general_status != 0:
                        result.success = False
                        result.error_text = f"CIP error: general_status=0x{result.general_status:02X}"
                elif actual_size > 0:
                    # Raw data without CIP header (some drivers strip it)
                    result.data = bytes(rsp_buf.raw[:actual_size])
            else:
                result.error_text = self._get_error_string(status)

            # Close the DTSA path
            try:
                self._dll.DTL_CloseDtsa(dtsa)
            except Exception:
                pass

        except Exception as e:
            result.error_text = f"Exception: {e}"
            result.elapsed_ms = (time.time() - start_time) * 1000
        finally:
            if dtsa:
                try:
                    self._dll.DTL_DestroyDtsa(dtsa)
                except Exception:
                    pass

        return result

    # ── Convenience Methods ──────────────────────────────────────────────

    def read_identity(
        self,
        driver_name: str,
        node_address: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        usb_adapter_station: int = -1,
    ) -> CIPResponse:
        """
        Read the CIP Identity Object from a DeviceNet node.
        Sends Get_Attributes_All (service 0x01) to Class 0x01, Instance 1.
        """
        return self.send_cip_message(
            driver_name=driver_name,
            node_address=node_address,
            service=CIP_GET_ATTR_ALL,
            class_id=CIP_CLASS_IDENTITY,
            instance=1,
            timeout_ms=timeout_ms,
            usb_adapter_station=usb_adapter_station,
        )

    def read_devicenet_object(
        self,
        driver_name: str,
        node_address: int,
        attribute: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        usb_adapter_station: int = -1,
    ) -> CIPResponse:
        """
        Read an attribute from the DeviceNet Object (Class 0x03).
        """
        return self.send_cip_message(
            driver_name=driver_name,
            node_address=node_address,
            service=CIP_GET_ATTR_SINGLE,
            class_id=CIP_CLASS_DEVICENET,
            instance=1,
            attribute=attribute,
            timeout_ms=timeout_ms,
            usb_adapter_station=usb_adapter_station,
        )

    def discover_usb_adapter(
        self,
        driver_name: str,
        timeout_ms: int = 3000,
    ) -> Tuple[int, str]:
        """
        Discover the 1784-U2DN adapter station on a USB driver.
        Delegates to probe_usb_driver with a longer timeout.

        Returns:
            (station_number, description) — station_number is -1 if not found
        """
        return self.probe_usb_driver(driver_name, timeout_ms=timeout_ms)


# ── RSLinx Status Check (no SDK required) ────────────────────────────────

def is_rslinx_running() -> bool:
    """Check if RSLinx Classic is currently running."""
    try:
        import subprocess
        proc = subprocess.run(
            ["powershell", "-Command",
             "Get-Process -Name 'RSLinx','rslinx','RSLINX' -ErrorAction SilentlyContinue | "
             "Select-Object -First 1 -ExpandProperty Id"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(proc.stdout.strip())
    except Exception:
        pass

    # Fallback: check window title
    try:
        import subprocess
        proc = subprocess.run(
            ["powershell", "-Command",
             "Get-Process | Where-Object {$_.MainWindowTitle -like '*RSLinx*'} | "
             "Select-Object -First 1 -ExpandProperty Id"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(proc.stdout.strip())
    except Exception:
        return False


def find_rslinx_install() -> dict:
    """
    Detect RSLinx installation and capabilities.
    Returns dict with detection results — does NOT require RSLinx SDK.
    """
    result = {
        "installed": False,
        "running": False,
        "dll_found": False,
        "dll_path": "",
        "version": "",
        "edition": "",
        "message": "",
    }

    # Check if running
    result["running"] = is_rslinx_running()

    # Check DLL
    bridge = RSLinxBridge()
    found, path = bridge.find_dll()
    result["dll_found"] = found
    result["dll_path"] = path if found else ""

    # Check registry for install info
    try:
        import subprocess
        proc = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Rockwell Software\\RSLinx\\CurrentVersion' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object -Property ProductVersion,ProductName | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            info = json.loads(proc.stdout)
            result["version"] = info.get("ProductVersion", "")
            result["edition"] = info.get("ProductName", "")
            result["installed"] = True
    except Exception:
        pass

    # Also try WOW64 registry path (32-bit app on 64-bit Windows)
    if not result["installed"]:
        try:
            import subprocess
            proc = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKLM:\\SOFTWARE\\WOW6432Node\\Rockwell Software\\RSLinx\\CurrentVersion' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object -Property ProductVersion,ProductName | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                info = json.loads(proc.stdout)
                result["version"] = info.get("ProductVersion", "")
                result["edition"] = info.get("ProductName", "")
                result["installed"] = True
        except Exception:
            pass

    if not result["installed"]:
        result["installed"] = result["dll_found"]

    # Build message
    parts = []
    if result["installed"]:
        parts.append(f"RSLinx {'detected' if result['running'] else 'installed but not running'}")
        if result["edition"]:
            parts.append(f"Edition: {result['edition']}")
        if result["version"]:
            parts.append(f"Version: {result['version']}")
    else:
        parts.append("RSLinx not found on this system")

    result["message"] = "\n".join(parts)
    return result
