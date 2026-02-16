"""
SAS Network Diagnostics Tool — Network Utilities
Low-level network operations: interface detection, ping sweep, ARP lookups.
Uses only standard library + psutil to avoid WinPcap/Npcap dependency.
"""

import ipaddress
import logging
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)


@dataclass
class NetworkInterface:
    """Represents a local network interface."""
    name: str
    display_name: str
    ip_address: str
    subnet_mask: str
    mac_address: str
    is_up: bool = True
    speed_mbps: int = 0

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.ip_address}/{self.subnet_mask}", strict=False)

    @property
    def host_count(self) -> int:
        return self.network.num_addresses - 2  # Exclude network and broadcast

    def __str__(self):
        return f"{self.display_name} ({self.ip_address}/{self.subnet_mask})"


@dataclass
class DiscoveredDevice:
    """A device found on the network."""
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""
    is_reachable: bool = True
    response_time_ms: float = 0.0
    open_ports: List[int] = field(default_factory=list)
    device_type: str = "Unknown"
    product_name: str = ""
    serial_number: str = ""
    firmware_rev: str = ""
    eip_identity: Optional[dict] = None
    last_seen: float = field(default_factory=time.time)

    @property
    def display_name(self) -> str:
        if self.product_name:
            return self.product_name
        if self.hostname and self.hostname != self.ip_address:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} Device"
        if self.device_type and self.device_type != "Unknown":
            return f"{self.device_type}"
        return self.ip_address


def get_network_interfaces() -> List[NetworkInterface]:
    """Detect all active network interfaces with IPv4 addresses."""
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        stat = stats.get(name)
        if not stat or not stat.isup:
            continue

        for addr in addr_list:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                # Get MAC address from the same interface
                mac = ""
                for a in addr_list:
                    if a.family == psutil.AF_LINK:
                        mac = a.address
                        break

                iface = NetworkInterface(
                    name=name,
                    display_name=name,
                    ip_address=addr.address,
                    subnet_mask=addr.netmask or "255.255.255.0",
                    mac_address=mac,
                    is_up=stat.isup,
                    speed_mbps=stat.speed if stat.speed else 0,
                )
                interfaces.append(iface)
                logger.info(f"Found interface: {iface}")

    return interfaces


def ping_host(ip: str, timeout: float = 1.0,
              source_ip: str = "") -> Tuple[bool, float]:
    """
    Ping a single host and return (reachable, response_time_ms).
    Uses system ping command for compatibility without raw sockets.

    Args:
        ip: Target IP to ping
        timeout: Timeout in seconds
        source_ip: Source IP to bind to (forces ping through specific adapter).
                   If empty, OS chooses the route automatically.
    """
    try:
        is_win = platform.system().lower() == "windows"
        cmd = ["ping"]

        if is_win:
            cmd += ["-n", "1", "-w", str(int(timeout * 1000))]
            # -S forces ping through the adapter that owns this IP
            if source_ip:
                cmd += ["-S", source_ip]
        else:
            cmd += ["-c", "1", "-W", str(int(timeout))]
            # -I forces ping through specific interface/IP
            if source_ip:
                cmd += ["-I", source_ip]

        cmd.append(ip)

        start = time.perf_counter()
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if is_win else 0,
        )
        elapsed = (time.perf_counter() - start) * 1000

        if result.returncode == 0:
            match = re.search(r"time[=<](\d+\.?\d*)", result.stdout)
            if match:
                elapsed = float(match.group(1))
            return True, round(elapsed, 2)
        return False, 0.0

    except (subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"Ping failed for {ip}: {e}")
        return False, 0.0


def get_arp_table(interface_ip: str = "") -> Dict[str, str]:
    """
    Read the system ARP table and return a dict of {ip: mac}.

    Args:
        interface_ip: If provided, only return ARP entries from the
                      interface that owns this IP address.  On Windows
                      this uses 'arp -a -N <ip>' which is critical for
                      avoiding cross-interface leakage (e.g. WiFi entries
                      appearing when scanning Ethernet).
    """
    ip_mac_map = {}
    is_win = platform.system().lower() == "windows"
    flags = subprocess.CREATE_NO_WINDOW if is_win else 0

    try:
        cmd = ["arp", "-a"]
        if is_win and interface_ip:
            cmd += ["-N", interface_ip]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            creationflags=flags,
        )
        for line in result.stdout.splitlines():
            if is_win:
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:]"
                    r"[\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})",
                    line,
                )
            else:
                match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\) at ([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:"
                    r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})",
                    line,
                )
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                if mac.startswith("01:00:5E"):
                    continue
                try:
                    if ipaddress.IPv4Address(ip).is_multicast:
                        continue
                except Exception:
                    pass
                ip_mac_map[ip] = mac

    except Exception as e:
        logger.warning(f"Failed to read ARP table: {e}")

    return ip_mac_map


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a specific TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# Common industrial Ethernet ports to check
INDUSTRIAL_PORTS = {
    80: "HTTP (Web Server)",
    443: "HTTPS",
    44818: "EtherNet/IP (CIP)",
    2222: "EtherNet/IP (Implicit I/O)",
    502: "Modbus TCP",
    102: "Siemens S7 / ISO-TSAP",
    4840: "OPC UA",
    20000: "DNP3",
    47808: "BACnet",
}


def scan_industrial_ports(ip: str, timeout: float = 0.5) -> List[int]:
    """Scan common industrial ports on a device."""
    open_ports = []
    for port in INDUSTRIAL_PORTS:
        if check_port(ip, port, timeout):
            open_ports.append(port)
    return open_ports


def identify_device_type(open_ports: List[int], mac: str = "", eip_data: dict = None) -> str:
    """
    Identify the device type/manufacturer based on all available information.

    Priority order:
    1. EtherNet/IP CIP identity data (most reliable for EIP devices)
    2. MAC address OUI vendor lookup (works for ALL devices)
    3. Open port heuristics (fallback)
    """
    from core.mac_vendors import lookup_vendor

    # 1) CIP identity — highest confidence
    if eip_data:
        vendor_id = eip_data.get("vendor_id", 0)
        if vendor_id == 1:
            return "Allen-Bradley (Rockwell)"
        elif vendor_id == 34:
            return "Turck"
        elif vendor_id == 43:
            return "WAGO"
        elif vendor_id == 44:
            return "Banner Engineering"
        elif vendor_id == 283:
            return "Molex"
        elif vendor_id == 90:
            return "HMS Industrial (Anybus)"
        elif vendor_id == 40:
            return "Siemens"
        elif vendor_id == 48:
            return "Phoenix Contact"
        elif vendor_id == 345:
            return "Beckhoff Automation"
        elif vendor_id == 50:
            return "Schneider Electric"

    # 2) MAC address vendor lookup — works for all devices with a MAC
    if mac:
        vendor_name, category = lookup_vendor(mac)
        if vendor_name != "Unknown":
            return vendor_name

    # 3) Open port heuristics — fallback when no MAC or unknown MAC
    if 44818 in open_ports:
        return "EtherNet/IP Device"
    if 502 in open_ports:
        return "Modbus TCP Device"
    if 102 in open_ports:
        return "Siemens S7 Device"
    if 4840 in open_ports:
        return "OPC UA Device"
    if 47808 in open_ports:
        return "BACnet Device"
    if 20000 in open_ports:
        return "DNP3 Device"
    if 80 in open_ports or 443 in open_ports:
        return "Network Device (Web)"

    return "Unknown"


def ping_sweep(network: ipaddress.IPv4Network,
               progress_callback: Optional[Callable[[int, int, str], None]] = None,
               cancel_event: Optional[threading.Event] = None,
               max_threads: int = 50,
               source_ip: str = "") -> List[DiscoveredDevice]:
    """
    Perform a ping sweep across a network range.

    After pinging, also checks the ARP table for devices that are physically
    on the wire but don't respond to ICMP (common with Siemens PLCs and
    managed switches).  Any device with a valid ARP entry in the target
    subnet is included, even if ping returned "unreachable".

    Subnets larger than /22 (1022 hosts) are automatically capped to prevent
    extremely long scans.  Virtual/link-local subnets are skipped entirely.

    Args:
        network: IPv4 network to scan
        progress_callback: fn(current, total, ip) for progress updates
        cancel_event: set to cancel
        max_threads: max concurrent pings
        source_ip: bind pings to this IP (forces correct adapter)
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    hosts = list(network.hosts())
    total = len(hosts)

    # ── Guard: Skip link-local or enormous subnets ────────────────────
    if total > 1022:  # Larger than /22
        logger.warning(f"Subnet {network} has {total:,} hosts — capping to "
                       f"first 254 hosts to prevent excessive scan time")
        hosts = hosts[:254]
        total = len(hosts)

    if total == 0:
        return []

    devices = []
    devices_lock = threading.Lock()
    completed = [0]
    completed_lock = threading.Lock()
    found_ips = set()

    def scan_host(ip_str):
        if cancel_event and cancel_event.is_set():
            return None

        reachable, rtt = ping_host(ip_str, timeout=1.0, source_ip=source_ip)

        with completed_lock:
            completed[0] += 1
            if progress_callback:
                progress_callback(completed[0], total, ip_str)

        if reachable:
            return DiscoveredDevice(
                ip_address=ip_str,
                is_reachable=True,
                response_time_ms=rtt,
            )
        return None

    # Use ThreadPoolExecutor for cleaner thread management
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {}
        for host in hosts:
            if cancel_event and cancel_event.is_set():
                break
            ip_str = str(host)
            futures[executor.submit(scan_host, ip_str)] = ip_str

        # Collect results with cancel checking
        for future in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break
            try:
                result = future.result(timeout=3)
                if result:
                    with devices_lock:
                        devices.append(result)
                        found_ips.add(result.ip_address)
            except Exception:
                pass

    # ── ARP-based discovery ────────────────────────────────────────────
    # Even if a device doesn't respond to ICMP, the OS still performs
    # an ARP exchange to send the ping packet.  So the ARP table will
    # contain entries for devices that are physically on the wire.
    # This catches Siemens PLCs and other devices with ICMP disabled.
    arp_table = get_arp_table(interface_ip=source_ip)

    # Add ARP-only devices (on wire but didn't respond to ping)
    for ip, mac in arp_table.items():
        if ip in found_ips:
            continue  # already found via ping
        try:
            if ipaddress.IPv4Address(ip) not in network:
                continue  # not in our target subnet
        except Exception:
            continue
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue

        device = DiscoveredDevice(
            ip_address=ip,
            mac_address=mac,
            is_reachable=False,  # didn't respond to ping
            response_time_ms=0.0,
        )
        devices.append(device)
        found_ips.add(ip)

    # Enrich ALL devices with ARP/MAC data
    for device in devices:
        if not device.mac_address and device.ip_address in arp_table:
            device.mac_address = arp_table[device.ip_address]

    # Enrich with MAC vendor data
    from core.mac_vendors import lookup_vendor
    for device in devices:
        if device.mac_address:
            vendor_name, category = lookup_vendor(device.mac_address)
            if vendor_name != "Unknown":
                device.vendor = vendor_name
                if not device.device_type or device.device_type == "Unknown":
                    device.device_type = vendor_name

    # Resolve hostnames
    for device in devices:
        hostname = resolve_hostname(device.ip_address, timeout=0.5)
        if hostname:
            device.hostname = hostname

    # Sort by IP address
    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip_address))

    return devices
