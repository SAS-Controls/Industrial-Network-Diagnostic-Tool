"""
SAS Network Diagnostics Tool — Packet Capture Engine

Two capture backends:
  1. Built-in (default): Uses Windows raw sockets — zero external dependencies.
     Works on any Windows 10/11 PC.  Requires "Run as Administrator" for full
     promiscuous-mode capture.  Provides IP-layer analysis (no Ethernet/ARP/STP).
  2. tshark (optional): If Wireshark+Npcap are installed, uses tshark for
     full Layer-2 capture including MAC addresses, ARP, and STP detection.

The user never sees raw packets — the capture is processed by capture_analyzer.py
and presented as plain-English findings, charts, and timeline events.
"""

import csv
import io
import logging
import os
import platform
import re
import shutil
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable, Dict, Tuple, Set

logger = logging.getLogger(__name__)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class CaptureInterface:
    """A network interface available for packet capture."""
    name: str               # Interface identifier
    friendly_name: str      # Human-readable name (e.g. "Ethernet 2")
    description: str = ""   # Additional description
    address: str = ""       # IP address if known

    def __str__(self):
        if self.address:
            return f"{self.friendly_name} ({self.address})"
        return self.friendly_name


@dataclass
class CapturedPacket:
    """Parsed fields from a single captured packet."""
    frame_number: int = 0
    timestamp: float = 0.0          # Epoch seconds (relative to capture start)
    frame_len: int = 0              # Total frame length (bytes)
    eth_src: str = ""               # Source MAC
    eth_dst: str = ""               # Destination MAC
    eth_type: str = ""              # Ethertype (e.g. "0x0800" for IPv4)
    ip_src: str = ""                # Source IP
    ip_dst: str = ""                # Destination IP
    ip_proto: int = 0               # IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    tcp_src_port: int = 0           # TCP source port
    tcp_dst_port: int = 0           # TCP destination port
    tcp_flags: int = 0              # TCP flags bitmask
    tcp_retransmission: bool = False
    udp_src_port: int = 0           # UDP source port
    udp_dst_port: int = 0           # UDP destination port
    arp_opcode: int = 0             # ARP: 1=request, 2=reply
    arp_src_hw: str = ""            # ARP sender hardware address
    arp_src_ip: str = ""            # ARP sender protocol address
    arp_dst_hw: str = ""            # ARP target hardware address
    arp_dst_ip: str = ""            # ARP target protocol address
    protocol_name: str = ""         # Highest-layer protocol (e.g. "CIP", "ARP", "TCP")
    info: str = ""                  # Info column

    @property
    def is_broadcast(self) -> bool:
        return (self.eth_dst.lower() == "ff:ff:ff:ff:ff:ff"
                or self.ip_dst in ("255.255.255.255", "")
                or self.ip_dst.endswith(".255"))

    @property
    def is_multicast(self) -> bool:
        if self.eth_dst.lower().startswith("01:00:5e"):
            return True
        if self.ip_dst:
            try:
                first_octet = int(self.ip_dst.split(".")[0])
                return 224 <= first_octet <= 239
            except (ValueError, IndexError):
                pass
        return False

    @property
    def is_arp(self) -> bool:
        return self.arp_opcode > 0 or self.protocol_name.upper() == "ARP"

    @property
    def is_stp(self) -> bool:
        return self.protocol_name.upper() in ("STP", "RSTP", "MSTP")

    @property
    def src_port(self) -> int:
        return self.tcp_src_port or self.udp_src_port

    @property
    def dst_port(self) -> int:
        return self.tcp_dst_port or self.udp_dst_port


@dataclass
class CaptureConfig:
    """Configuration for a packet capture session."""
    interface: str = ""             # Interface IP to capture on
    duration_seconds: int = 30      # Capture duration
    promiscuous: bool = True        # Promiscuous mode
    max_packets: int = 0            # 0 = no limit
    capture_filter: str = ""        # BPF filter (tshark only)
    snap_length: int = 256          # Bytes per packet (tshark only)


@dataclass
class CaptureResult:
    """Complete results from a capture session."""
    packets: List[CapturedPacket] = field(default_factory=list)
    interface: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_bytes: int = 0
    was_cancelled: bool = False
    error: str = ""
    backend: str = ""               # "builtin" or "tshark"

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def packets_per_second(self) -> float:
        if self.duration_seconds > 0:
            return self.packet_count / self.duration_seconds
        return 0.0


# ── Well-known port → protocol name ─────────────────────────────────────────

_PORT_PROTOCOLS: Dict[int, str] = {
    44818: "EtherNet/IP", 2222: "EtherNet/IP",
    102: "S7comm", 502: "Modbus/TCP", 20000: "DNP3",
    4840: "OPC-UA", 48898: "ADS/AMS",
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB",
    514: "Syslog", 1900: "SSDP", 3389: "RDP",
    5353: "mDNS", 5355: "LLMNR",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

_IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
    112: "VRRP", 132: "SCTP",
}


def _identify_protocol(ip_proto: int, src_port: int, dst_port: int) -> str:
    """Identify the application-layer protocol from ports."""
    if dst_port in _PORT_PROTOCOLS:
        return _PORT_PROTOCOLS[dst_port]
    if src_port in _PORT_PROTOCOLS:
        return _PORT_PROTOCOLS[src_port]
    return _IP_PROTO_NAMES.get(ip_proto, f"IP-{ip_proto}")


def _tcp_flags_str(flags: int) -> str:
    """Convert TCP flags byte to a human-readable string."""
    parts = []
    if flags & 0x01: parts.append("FIN")
    if flags & 0x02: parts.append("SYN")
    if flags & 0x04: parts.append("RST")
    if flags & 0x08: parts.append("PSH")
    if flags & 0x10: parts.append("ACK")
    if flags & 0x20: parts.append("URG")
    return ", ".join(parts) if parts else str(flags)


# ── Built-in Capture (Windows raw sockets) ───────────────────────────────────

class BuiltinCaptureEngine:
    """
    Pure-Python packet capture using Windows raw sockets.

    Zero external dependencies.  Requires "Run as Administrator" for
    promiscuous mode (seeing all traffic on the segment).

    Captures: IP-layer traffic — src/dst IP, TCP/UDP headers, protocol
    identification, TCP retransmission detection.

    Does NOT capture: Ethernet headers (MAC addresses), ARP, STP.
    For full Layer-2 capture, install Wireshark + Npcap and the tool
    will automatically use the enhanced tshark backend.
    """

    def capture(self, config: CaptureConfig,
                on_progress: Optional[Callable] = None,
                cancel_event: Optional[threading.Event] = None,
                ) -> CaptureResult:
        """Blocking capture — run in a background thread."""
        result = CaptureResult(
            interface=config.interface,
            start_time=datetime.now(),
            backend="builtin",
        )

        raw_sock = None
        try:
            bind_ip = config.interface or self._get_default_ip()
            logger.info(f"Starting builtin capture on {bind_ip} "
                        f"for {config.duration_seconds}s")

            raw_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw_sock.bind((bind_ip, 0))
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode — requires admin
            promisc = False
            try:
                raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                promisc = True
            except OSError as e:
                logger.warning(f"Promiscuous mode failed (need Admin): {e}")

            raw_sock.settimeout(0.5)

            # TCP retransmission tracking
            tcp_seen_seqs: Set[tuple] = set()

            frame_num = 0
            start_ts = time.monotonic()
            last_progress = 0

            while True:
                elapsed = time.monotonic() - start_ts
                if elapsed >= config.duration_seconds:
                    break
                if cancel_event and cancel_event.is_set():
                    result.was_cancelled = True
                    break
                if 0 < config.max_packets <= frame_num:
                    break

                elapsed_int = int(elapsed)
                if elapsed_int > last_progress and on_progress:
                    on_progress(elapsed_int, config.duration_seconds)
                    last_progress = elapsed_int

                try:
                    raw_data, addr = raw_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue

                if len(raw_data) < 20:
                    continue

                frame_num += 1
                pkt = self._parse_ip_packet(
                    raw_data, frame_num, elapsed, tcp_seen_seqs)
                if pkt:
                    result.packets.append(pkt)
                    result.total_bytes += pkt.frame_len

            if promisc:
                try:
                    raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass

            if not promisc and len(result.packets) == 0:
                result.error = (
                    "No packets captured. Run this application as Administrator "
                    "to enable promiscuous mode (see all network traffic)."
                )

        except PermissionError:
            result.error = (
                "Packet capture requires Administrator privileges.\n"
                "Right-click the application and select 'Run as administrator'."
            )
            logger.error("Raw socket PermissionError — need admin rights")
        except OSError as e:
            if "10013" in str(e) or "permitted" in str(e).lower():
                result.error = (
                    "Packet capture requires Administrator privileges.\n"
                    "Right-click the application and select "
                    "'Run as administrator'."
                )
            else:
                result.error = f"Capture error: {e}"
            logger.error(f"Capture OSError: {e}")
        except Exception as e:
            result.error = f"Capture failed: {e}"
            logger.error(f"Capture exception: {e}", exc_info=True)
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass
            result.end_time = datetime.now()
            result.duration_seconds = (
                result.end_time - result.start_time).total_seconds()

        logger.info(f"Builtin capture: {result.packet_count} packets "
                     f"in {result.duration_seconds:.1f}s")
        return result

    def _parse_ip_packet(self, data: bytes, frame_num: int,
                          timestamp: float,
                          tcp_seen_seqs: Set[tuple],
                          ) -> Optional[CapturedPacket]:
        """Parse an IP packet from raw bytes."""
        try:
            version_ihl = data[0]
            ihl = (version_ihl & 0x0F) * 4
            if ihl < 20 or len(data) < ihl:
                return None

            total_length = struct.unpack("!H", data[2:4])[0]
            ip_proto = data[9]
            src_ip = socket.inet_ntoa(data[12:16])
            dst_ip = socket.inet_ntoa(data[16:20])

            pkt = CapturedPacket(
                frame_number=frame_num,
                timestamp=timestamp,
                frame_len=total_length,
                ip_src=src_ip,
                ip_dst=dst_ip,
                ip_proto=ip_proto,
            )

            payload = data[ihl:]

            if ip_proto == 6 and len(payload) >= 20:
                # TCP
                src_port = struct.unpack("!H", payload[0:2])[0]
                dst_port = struct.unpack("!H", payload[2:4])[0]
                seq_num = struct.unpack("!I", payload[4:8])[0]
                ack_num = struct.unpack("!I", payload[8:12])[0]
                flags = payload[13]

                pkt.tcp_src_port = src_port
                pkt.tcp_dst_port = dst_port
                pkt.tcp_flags = flags

                # Retransmission: same src/dst/port/seq seen before
                is_syn_only = (flags & 0x02) and not (flags & 0x10)
                is_rst = bool(flags & 0x04)
                if not is_syn_only and not is_rst and seq_num > 0:
                    key = (src_ip, dst_ip, src_port, dst_port, seq_num)
                    if key in tcp_seen_seqs:
                        pkt.tcp_retransmission = True
                    else:
                        tcp_seen_seqs.add(key)

                # Memory bound
                if len(tcp_seen_seqs) > 500_000:
                    trimmed = set(list(tcp_seen_seqs)[250_000:])
                    tcp_seen_seqs.clear()
                    tcp_seen_seqs.update(trimmed)

                pkt.protocol_name = _identify_protocol(6, src_port, dst_port)
                pkt.info = (
                    f"{src_port} > {dst_port} "
                    f"[{_tcp_flags_str(flags)}] "
                    f"Seq={seq_num} Ack={ack_num}"
                )

            elif ip_proto == 17 and len(payload) >= 8:
                # UDP
                src_port = struct.unpack("!H", payload[0:2])[0]
                dst_port = struct.unpack("!H", payload[2:4])[0]
                pkt.udp_src_port = src_port
                pkt.udp_dst_port = dst_port
                pkt.protocol_name = _identify_protocol(17, src_port, dst_port)
                pkt.info = f"{src_port} > {dst_port} Len={total_length}"

            elif ip_proto == 1 and len(payload) >= 4:
                # ICMP
                icmp_type = payload[0]
                icmp_code = payload[1]
                pkt.protocol_name = "ICMP"
                type_names = {
                    0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded",
                }
                pkt.info = type_names.get(
                    icmp_type, f"Type={icmp_type} Code={icmp_code}")

            elif ip_proto == 2:
                pkt.protocol_name = "IGMP"
            else:
                pkt.protocol_name = _IP_PROTO_NAMES.get(
                    ip_proto, f"IP-{ip_proto}")

            return pkt

        except Exception as e:
            logger.debug(f"Failed to parse packet #{frame_num}: {e}")
            return None

    def _get_default_ip(self) -> str:
        """Get the default local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"


# ── tshark field extraction ──────────────────────────────────────────────────

TSHARK_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "eth.src", "eth.dst", "eth.type",
    "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "tcp.flags",
    "tcp.analysis.retransmission",
    "udp.srcport", "udp.dstport",
    "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4",
    "arp.dst.hw_mac", "arp.dst.proto_ipv4",
    "_ws.col.Protocol", "_ws.col.Info",
]

_WINDOWS_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
]


# ── Path helpers ─────────────────────────────────────────────────────────────

def get_app_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_tools_dir() -> str:
    return os.path.join(get_app_dir(), "tools")

def _get_bundled_tshark_path() -> Optional[str]:
    tools = get_tools_dir()
    for sub in ("tshark", "Wireshark"):
        p = os.path.join(tools, sub, "tshark.exe")
        if os.path.isfile(p):
            return p
    p = os.path.join(tools, "tshark.exe")
    if os.path.isfile(p):
        return p
    return None


# ── Main Capture Engine ──────────────────────────────────────────────────────

class CaptureEngine:
    """
    Packet capture engine — always available, zero dependencies.

    Uses Windows raw sockets by default.  If tshark + Npcap are found on
    the system, automatically upgrades to full Layer-2 capture.
    """

    def __init__(self):
        self._tshark_path: Optional[str] = self._find_tshark()
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._capturing = False
        self._pcap_file: Optional[str] = None
        self._builtin = BuiltinCaptureEngine()

    @property
    def is_available(self) -> bool:
        """Always True — built-in engine has no dependencies."""
        return True

    @property
    def has_tshark(self) -> bool:
        return self._tshark_path is not None

    @property
    def has_npcap(self) -> bool:
        ok, _ = check_npcap_installed()
        return ok

    @property
    def is_capturing(self) -> bool:
        return self._capturing

    @property
    def tshark_path(self) -> Optional[str]:
        return self._tshark_path

    @property
    def backend_name(self) -> str:
        if self._tshark_path and self.has_npcap:
            return "tshark"
        return "builtin"

    @property
    def backend_description(self) -> str:
        if self.backend_name == "tshark":
            ver = self.get_tshark_version()
            short = ver.split("(")[0].strip() if ver else "tshark"
            return f"{short} + Npcap (full Layer-2 capture)"
        return "Built-in capture (run as Administrator for best results)"

    def get_tshark_version(self) -> str:
        if not self._tshark_path:
            return ""
        try:
            result = subprocess.run(
                [self._tshark_path, "--version"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            return result.stdout.strip().split("\n")[0]
        except Exception as e:
            logger.debug(f"Failed to get tshark version: {e}")
            return ""

    def list_interfaces(self) -> List[CaptureInterface]:
        """List available network interfaces for capture."""
        import psutil
        from core.network_utils import get_network_interfaces
        from core.settings_manager import get_settings

        interfaces = get_network_interfaces()
        interfaces = get_settings().filter_interfaces(interfaces)

        # Build tshark device name map if tshark backend is active
        tshark_map: Dict[str, str] = {}  # friendly_name → tshark_device
        if self._tshark_path and self.has_npcap:
            tshark_map = self._build_tshark_interface_map()

        # Build psutil IP map: psutil_name → ip_address
        psutil_ip_map: Dict[str, str] = {}
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                        psutil_ip_map[addr.address] = name
                        break
        except Exception:
            pass

        result = []
        for iface in interfaces:
            # For tshark: try to match this interface's psutil name
            # to a tshark device name via the friendly name
            tshark_device = ""
            psutil_name = psutil_ip_map.get(iface.ip_address, "")
            if psutil_name and tshark_map:
                # Try exact match first
                tshark_device = tshark_map.get(psutil_name, "")
                if not tshark_device:
                    # Try case-insensitive partial match
                    pn_lower = psutil_name.lower()
                    for tname, tdev in tshark_map.items():
                        if tname.lower() == pn_lower or pn_lower in tname.lower():
                            tshark_device = tdev
                            break

            # name = tshark device if available, otherwise IP for raw socket
            iface_name = tshark_device if tshark_device else iface.ip_address

            result.append(CaptureInterface(
                name=iface_name,
                friendly_name=iface.display_name,
                description=iface.name,
                address=iface.ip_address,
            ))
        return result

    def _build_tshark_interface_map(self) -> Dict[str, str]:
        """Parse tshark -D to build friendly_name → device_name map."""
        result: Dict[str, str] = {}
        if not self._tshark_path:
            return result
        try:
            r = subprocess.run(
                [self._tshark_path, "-D"],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            for line in r.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Format: "1. \Device\NPF_{GUID} (Ethernet)"
                match = re.match(r'^\d+\.\s+(.+?)\s+\((.+)\)\s*$', line)
                if match:
                    device_name = match.group(1).strip()
                    friendly_name = match.group(2).strip()
                    result[friendly_name] = device_name
                    logger.debug(f"tshark iface: {friendly_name} → {device_name}")
        except Exception as e:
            logger.debug(f"Failed to build tshark interface map: {e}")
        return result

    def start_capture(self, config: CaptureConfig,
                      on_progress: Optional[Callable[[int, int], None]] = None,
                      on_complete: Optional[Callable[[CaptureResult], None]] = None):
        if self._capturing:
            logger.warning("Capture already in progress")
            return

        self._cancel_event.clear()
        self._capturing = True

        self._thread = threading.Thread(
            target=self._capture_thread,
            args=(config, on_progress, on_complete),
            daemon=True,
        )
        self._thread.start()

    def stop_capture(self):
        if self._capturing:
            logger.info("Stopping capture...")
            self._cancel_event.set()
            if self._process and self._process.poll() is None:
                try:
                    self._process.terminate()
                except Exception:
                    pass

    # ── Internal ─────────────────────────────────────────────────────────────

    def _find_tshark(self) -> Optional[str]:
        bundled = _get_bundled_tshark_path()
        if bundled and os.path.isfile(bundled):
            logger.info(f"Found bundled tshark: {bundled}")
            return bundled

        tshark = shutil.which("tshark")
        if tshark:
            logger.info(f"Found tshark on PATH: {tshark}")
            return tshark

        if platform.system() == "Windows":
            for path in _WINDOWS_TSHARK_PATHS:
                expanded = os.path.expandvars(path)
                if os.path.isfile(expanded):
                    logger.info(f"Found tshark at: {expanded}")
                    return expanded

        logger.info("tshark not found — using built-in capture")
        return None

    def _capture_thread(self, config, on_progress, on_complete):
        try:
            use_tshark = (self._tshark_path is not None and self.has_npcap)
            if use_tshark:
                result = self._tshark_capture(config, on_progress)
            else:
                result = self._builtin.capture(
                    config, on_progress, self._cancel_event)
        except Exception as e:
            logger.error(f"Capture thread failed: {e}", exc_info=True)
            result = CaptureResult(
                interface=config.interface,
                start_time=datetime.now(), end_time=datetime.now(),
                error=str(e),
            )
        finally:
            self._capturing = False

        if on_complete:
            on_complete(result)

    # ── tshark backend ───────────────────────────────────────────────────────

    def _tshark_capture(self, config, on_progress):
        result = CaptureResult(
            interface=config.interface,
            start_time=datetime.now(), backend="tshark",
        )
        try:
            # If interface is already a tshark device name, use directly
            iface = config.interface
            if not iface.startswith("\\"):
                # It's an IP — try to resolve to tshark device name
                resolved = self._resolve_tshark_interface(iface)
                if resolved:
                    iface = resolved
                else:
                    # Can't resolve — fall back to built-in capture
                    logger.warning(
                        f"Cannot resolve '{iface}' to tshark interface "
                        f"— falling back to built-in capture")
                    return self._builtin.capture(
                        config, on_progress, self._cancel_event)

            pcap_path = self._run_tshark_capture(iface, config, on_progress)

            if self._cancel_event.is_set():
                result.was_cancelled = True
                if not (pcap_path and os.path.exists(pcap_path)
                        and os.path.getsize(pcap_path) > 0):
                    result.end_time = datetime.now()
                    result.duration_seconds = (
                        result.end_time - result.start_time).total_seconds()
                    return result

            if not pcap_path or not os.path.exists(pcap_path):
                result.error = "Capture produced no output file"
                result.end_time = datetime.now()
                result.duration_seconds = (
                    result.end_time - result.start_time).total_seconds()
                return result

            if os.path.getsize(pcap_path) == 0:
                result.error = (
                    "Capture produced an empty file — tshark could not "
                    "capture on the selected interface. Try running as "
                    "Administrator."
                )
                result.end_time = datetime.now()
                result.duration_seconds = (
                    result.end_time - result.start_time).total_seconds()
                return result

            if on_progress:
                on_progress(-1, config.duration_seconds)

            packets = self._parse_pcap(pcap_path)
            result.packets = packets
            result.total_bytes = sum(p.frame_len for p in packets)

        except Exception as e:
            logger.error(f"tshark capture failed: {e}", exc_info=True)
            result.error = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration_seconds = (
                result.end_time - result.start_time).total_seconds()
            if self._pcap_file and os.path.exists(self._pcap_file):
                try:
                    os.unlink(self._pcap_file)
                except Exception:
                    pass
                self._pcap_file = None

        return result

    def _resolve_tshark_interface(self, ip_address):
        if not self._tshark_path:
            return None
        try:
            r = subprocess.run(
                [self._tshark_path, "-D"],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            for line in r.stdout.strip().split("\n"):
                line = line.strip()
                if ip_address in line:
                    match = re.match(
                        r'^\d+\.\s+(.+?)(?:\s+\(.+\))?\s*$', line)
                    if match:
                        return match.group(1).strip()
        except Exception:
            pass
        return None

    def _run_tshark_capture(self, interface, config, on_progress):
        fd, pcap_path = tempfile.mkstemp(
            suffix=".pcapng", prefix="sas_capture_")
        os.close(fd)
        self._pcap_file = pcap_path

        cmd = [self._tshark_path, "-i", interface,
               "-a", f"duration:{config.duration_seconds}",
               "-w", pcap_path, "-s", str(config.snap_length)]
        if not config.promiscuous:
            cmd += ["-p"]
        if config.max_packets > 0:
            cmd += ["-c", str(config.max_packets)]
        if config.capture_filter:
            cmd += ["-f", config.capture_filter]

        logger.info(f"Starting tshark: {' '.join(cmd)}")

        creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=creation_flags,
        )

        elapsed = 0
        while elapsed < config.duration_seconds:
            if self._cancel_event.is_set():
                break
            if self._process.poll() is not None:
                break
            time.sleep(1)
            elapsed += 1
            if on_progress:
                on_progress(elapsed, config.duration_seconds)

        if self._process.poll() is None:
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                self._process.wait(timeout=5)

        # Log stderr for debugging
        try:
            stderr = self._process.stderr.read().decode("utf-8", errors="replace").strip()
            if stderr:
                logger.info(f"tshark stderr: {stderr[:500]}")
        except Exception:
            pass

        return pcap_path

    def _parse_pcap(self, pcap_path):
        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            return []

        field_args = []
        for f in TSHARK_FIELDS:
            field_args += ["-e", f]

        cmd = [self._tshark_path, "-r", pcap_path,
               "-T", "fields", "-E", "separator=\t",
               "-E", "quote=n", "-E", "occurrence=f"] + field_args

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
        except subprocess.TimeoutExpired:
            logger.error("tshark parsing timed out")
            return []

        packets = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            pkt = self._parse_field_line(line)
            if pkt:
                packets.append(pkt)

        logger.info(f"Parsed {len(packets)} packets from pcap")
        return packets

    def _parse_field_line(self, line):
        fields = line.split("\t")
        if len(fields) < len(TSHARK_FIELDS):
            fields += [""] * (len(TSHARK_FIELDS) - len(fields))
        try:
            pkt = CapturedPacket()
            pkt.frame_number = _safe_int(fields[0])
            pkt.timestamp = _safe_float(fields[1])
            pkt.frame_len = _safe_int(fields[2])
            pkt.eth_src = fields[3]
            pkt.eth_dst = fields[4]
            pkt.eth_type = fields[5]
            pkt.ip_src = fields[6]
            pkt.ip_dst = fields[7]
            pkt.ip_proto = _safe_int(fields[8])
            pkt.tcp_src_port = _safe_int(fields[9])
            pkt.tcp_dst_port = _safe_int(fields[10])
            pkt.tcp_flags = _safe_int(fields[11], base=16)
            pkt.tcp_retransmission = fields[12].strip() != ""
            pkt.udp_src_port = _safe_int(fields[13])
            pkt.udp_dst_port = _safe_int(fields[14])
            pkt.arp_opcode = _safe_int(fields[15])
            pkt.arp_src_hw = fields[16]
            pkt.arp_src_ip = fields[17]
            pkt.arp_dst_hw = fields[18]
            pkt.arp_dst_ip = fields[19]
            pkt.protocol_name = fields[20]
            pkt.info = fields[21] if len(fields) > 21 else ""
            return pkt
        except Exception as e:
            logger.debug(f"Failed to parse packet line: {e}")
            return None


# ── Npcap Detection ──────────────────────────────────────────────────────────

def check_npcap_installed() -> Tuple[bool, str]:
    if platform.system() != "Windows":
        return True, "Non-Windows — native capture"
    npcap_path = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "Npcap")
    if os.path.isdir(npcap_path):
        return True, "Npcap found"
    winpcap_dll = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "wpcap.dll")
    if os.path.isfile(winpcap_dll):
        return True, "WinPcap found"
    return False, "Npcap not installed"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_int(s: str, base: int = 10) -> int:
    s = s.strip()
    if not s:
        return 0
    try:
        if base == 16 and s.startswith("0x"):
            return int(s, 16)
        return int(s, base)
    except (ValueError, TypeError):
        return 0

def _safe_float(s: str) -> float:
    s = s.strip()
    if not s:
        return 0.0
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0
