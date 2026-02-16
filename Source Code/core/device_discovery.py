"""
SAS Network Diagnostics Tool — Device Discovery Engine
Find devices on the local wire regardless of IP subnet configuration.

ARCHITECTURE:
All discovery is scoped to the SELECTED adapter.  When the adapter is on
DHCP (link-local 169.254.x.x) and we need to reach a device on e.g.
192.168.1.0/24, we:

  1.  Get the adapter's Windows interface index
  2.  Add a temp secondary IP (e.g. 192.168.1.253) on that adapter
  3.  Force-add a route:  route add 192.168.1.0/24  via Ethernet  metric 1
      This overrides WiFi's route to the same subnet.
  4.  Ping sweep all 254 hosts with  -S 192.168.1.253
  5.  TCP port probe all 254 hosts on industrial ports (102, 502, 80, etc.)
      This triggers ARP even for devices that block ICMP ping (e.g. Siemens S7).
  6.  Harvest ARP with  arp -a -N <ADAPTER_PRIMARY_IP>  (not the temp IP!)
      Windows files ARP entries under the adapter's primary IP, not secondary/temp IPs.
      When primary is link-local (169.254.x.x), we read the full ARP table and
      filter by subnet instead — route forcing prevents WiFi contamination.
  7.  Clean up: delete route, delete temp IP

Without step 3, Windows sends traffic through WiFi (lower metric).
Without step 5, devices with ICMP firewalls (Siemens) are missed.
Step 6 is critical — using the temp IP for -N returns ZERO entries.
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from core.mac_vendors import lookup_vendor, get_category_label

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system().lower() == "windows"
_NOWND = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0


# ─── Common Factory Default Subnets ──────────────────────────────────────────
FACTORY_DEFAULT_RANGES: List[Tuple[str, str]] = [
    ("192.168.1.0/24",  "Common default — AB, WAGO, Phoenix Contact, Moxa"),
    ("192.168.0.0/24",  "Common default — Siemens, consumer routers"),
    ("192.168.2.0/24",  "AB secondary / Siemens alternate"),
    ("192.168.3.0/24",  "Some AB / Turck defaults"),
    ("10.10.0.0/24",    "Schneider Electric common default"),
    ("10.0.0.0/24",     "Schneider / generic default"),
    ("10.1.0.0/24",     "Schneider / generic default"),
    ("192.168.10.0/24", "Beckhoff / generic default"),
    ("172.17.0.0/24",   "Beckhoff TwinCAT default"),
    ("192.168.100.0/24","Moxa / generic default"),
    ("192.168.254.0/24","Some drives / VFDs"),
]

INDUSTRIAL_PORTS = {
    102:   "S7 COMM (Siemens S7)",
    80:    "HTTP Web Server",
    443:   "HTTPS Web Server",
    44818: "EtherNet/IP (CIP)",
    502:   "Modbus TCP",
    20000: "DNP3",
    4840:  "OPC UA",
    2222:  "EtherNet/IP (implicit)",
}


@dataclass
class DiscoveredEndpoint:
    """A device found during discovery."""
    ip_address: str
    mac_address: str = ""
    vendor_name: str = ""
    vendor_category: str = "other"
    discovery_method: str = ""
    is_eip: bool = False
    is_profinet: bool = False
    profinet_name: str = ""
    eip_product_name: str = ""
    eip_vendor_name: str = ""
    eip_serial: str = ""
    eip_firmware: str = ""
    eip_device_type: str = ""
    response_time_ms: float = 0.0
    suggested_subnet: str = ""
    suggested_ip: str = ""
    open_ports: List[int] = field(default_factory=list)
    port_info: str = ""


def _suggest_subnet(device_ip: str) -> Tuple[str, str]:
    try:
        addr = ipaddress.IPv4Address(device_ip)
        net = ipaddress.IPv4Network(f"{device_ip}/24", strict=False)
        host_part = int(addr) & 0xFF
        laptop_host = 249 if host_part == 250 else 250
        laptop_ip = str(ipaddress.IPv4Address(int(net.network_address) + laptop_host))
        return (str(net), laptop_ip)
    except Exception:
        return ("", "")


# ═════════════════════════════════════════════════════════════════════════════
# WINDOWS INTERFACE INDEX
#
# We need the interface index to force-route traffic through a specific
# adapter.  Without this, "route add" picks whichever adapter Windows
# thinks is best (usually WiFi).
# ═════════════════════════════════════════════════════════════════════════════

def _get_interface_index(adapter_name: str) -> Optional[int]:
    """
    Get the Windows interface index for a named adapter.
    This is needed for 'route add ... if <index>'.
    """
    if not IS_WINDOWS:
        return None
    try:
        # Method 1: netsh interface ipv4 show interfaces
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
            creationflags=_NOWND,
        )
        for line in result.stdout.splitlines():
            if adapter_name.lower() in line.lower():
                # Format: "  8    75 ...   connected    Ethernet"
                parts = line.split()
                if parts and parts[0].isdigit():
                    idx = int(parts[0])
                    logger.info(f"Interface index for '{adapter_name}': {idx}")
                    return idx
    except Exception as e:
        logger.warning(f"Failed to get interface index: {e}")

    try:
        # Method 2: route print — parse interface list
        result = subprocess.run(
            ["route", "print"],
            capture_output=True, text=True, timeout=10,
            creationflags=_NOWND,
        )
        for line in result.stdout.splitlines():
            if adapter_name.lower() in line.lower():
                match = re.search(r"^\s*(\d+)", line)
                if match:
                    idx = int(match.group(1))
                    logger.info(f"Interface index for '{adapter_name}' "
                                f"(from route print): {idx}")
                    return idx
    except Exception as e:
        logger.warning(f"route print failed: {e}")

    return None


# ═════════════════════════════════════════════════════════════════════════════
# TEMPORARY IP + ROUTE MANAGEMENT
#
# For cross-subnet discovery we need BOTH:
#   - A temp IP on the Ethernet adapter (so the OS has a source address)
#   - A forced route through that adapter (so traffic doesn't go via WiFi)
# ═════════════════════════════════════════════════════════════════════════════

def _add_temp_ip(adapter_name: str, ip: str,
                 mask: str = "255.255.255.0") -> bool:
    """Add a temporary secondary IP address to a network adapter."""
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["netsh", "interface", "ip", "add", "address",
                 f"name={adapter_name}", f"addr={ip}", f"mask={mask}"],
                capture_output=True, text=True, timeout=15,
                creationflags=_NOWND,
            )
            ok = result.returncode == 0
            if not ok:
                stderr = result.stderr.strip()
                logger.warning(f"netsh add IP failed (rc={result.returncode}): "
                               f"{stderr}")
                # Check common failures
                if "requires elevation" in stderr.lower() or \
                   "access is denied" in stderr.lower():
                    logger.error("ADMIN REQUIRED: netsh needs administrator")
                elif "already been configured" in stderr.lower() or \
                     "object already exists" in stderr.lower():
                    logger.info(f"IP {ip} already exists on adapter — OK")
                    return True
            return ok
        else:
            prefix = sum(bin(int(x)).count("1") for x in mask.split("."))
            result = subprocess.run(
                ["ip", "addr", "add", f"{ip}/{prefix}", "dev", adapter_name],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
    except Exception as e:
        logger.warning(f"Failed to add temp IP {ip} to {adapter_name}: {e}")
        return False


def _remove_temp_ip(adapter_name: str, ip: str) -> bool:
    """Remove a temporary secondary IP address from an adapter."""
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["netsh", "interface", "ip", "delete", "address",
                 f"name={adapter_name}", f"addr={ip}"],
                capture_output=True, text=True, timeout=15,
                creationflags=_NOWND,
            )
            return result.returncode == 0
        else:
            result = subprocess.run(
                ["ip", "addr", "del", f"{ip}/24", "dev", adapter_name],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
    except Exception as e:
        logger.warning(f"Failed to remove temp IP {ip} from {adapter_name}: {e}")
        return False


def _add_route(network_str: str, temp_ip: str, if_index: int) -> bool:
    """
    Force-add a route for a subnet through a specific interface.
    This overrides WiFi's route to the same subnet.
    """
    if not IS_WINDOWS:
        return True  # Linux routing handles this via source IP
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        mask = str(net.netmask)
        net_addr = str(net.network_address)

        result = subprocess.run(
            ["route", "add", net_addr, "mask", mask,
             temp_ip, "metric", "1", "if", str(if_index)],
            capture_output=True, text=True, timeout=10,
            creationflags=_NOWND,
        )
        ok = result.returncode == 0
        if ok:
            logger.info(f"Route added: {net_addr} mask {mask} via "
                        f"{temp_ip} if {if_index}")
        else:
            logger.warning(f"route add failed: {result.stderr.strip()} "
                           f"{result.stdout.strip()}")
        return ok
    except Exception as e:
        logger.warning(f"Failed to add route for {network_str}: {e}")
        return False


def _suppress_competing_routes(
    network_str: str,
    competing_ifaces: List[Tuple[str, str, int]],
) -> List[Tuple[str, str, int]]:
    """
    Temporarily delete routes from competing interfaces on the same subnet.

    When WiFi is on the same subnet we want to probe via Ethernet (e.g.
    WiFi 192.168.1.56 and target 192.168.1.0/24), Windows routes ALL
    traffic through WiFi's connected route regardless of metric.
    Deleting the WiFi route forces traffic through our Ethernet route.

    Returns list of (name, ip, if_index) of suppressed interfaces so they
    can be restored later.
    """
    if not IS_WINDOWS or not competing_ifaces:
        return []

    suppressed = []
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        mask = str(net.netmask)
        net_addr = str(net.network_address)
    except Exception:
        return []

    for iface_name, iface_ip, iface_if_index in competing_ifaces:
        try:
            if ipaddress.IPv4Address(iface_ip) not in net:
                continue  # not on this subnet — no conflict
        except Exception:
            continue

        logger.info(f"WiFi conflict: {iface_name} ({iface_ip}) is on "
                    f"{network_str} — suppressing route")
        try:
            # Delete ALL routes for this subnet via the competing interface.
            # Windows creates multiple entries (on-link, broadcast, etc.)
            # so we delete by interface to remove them all.
            result = subprocess.run(
                ["route", "delete", net_addr, "mask", mask,
                 iface_ip],
                capture_output=True, text=True, timeout=10,
                creationflags=_NOWND,
            )
            if result.returncode == 0:
                logger.info(f"Suppressed route: {net_addr}/{mask} via "
                            f"{iface_ip} ({iface_name})")
                suppressed.append((iface_name, iface_ip, iface_if_index))
            else:
                logger.warning(f"Route suppress failed for {iface_name}: "
                               f"{result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"Route suppress error for {iface_name}: {e}")

    return suppressed


def _restore_competing_routes(
    network_str: str,
    suppressed: List[Tuple[str, str, int]],
) -> None:
    """
    Restore previously suppressed routes from competing interfaces.

    Re-adds the connected route for each suppressed interface so WiFi
    connectivity is restored after our probe completes.
    """
    if not IS_WINDOWS or not suppressed:
        return

    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        mask = str(net.netmask)
        net_addr = str(net.network_address)
    except Exception:
        return

    for iface_name, iface_ip, iface_if_index in suppressed:
        try:
            result = subprocess.run(
                ["route", "add", net_addr, "mask", mask,
                 iface_ip, "if", str(iface_if_index)],
                capture_output=True, text=True, timeout=10,
                creationflags=_NOWND,
            )
            if result.returncode == 0:
                logger.info(f"Restored route: {net_addr}/{mask} via "
                            f"{iface_ip} ({iface_name})")
            else:
                logger.warning(f"Route restore failed for {iface_name}: "
                               f"{result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"Route restore error for {iface_name}: {e}")


def _remove_route(network_str: str, temp_ip: str, if_index: int) -> bool:
    """Remove a forced route."""
    if not IS_WINDOWS:
        return True
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        mask = str(net.netmask)
        net_addr = str(net.network_address)

        result = subprocess.run(
            ["route", "delete", net_addr, "mask", mask,
             temp_ip, "if", str(if_index)],
            capture_output=True, text=True, timeout=10,
            creationflags=_NOWND,
        )
        return result.returncode == 0
    except Exception as e:
        logger.warning(f"Failed to remove route for {network_str}: {e}")
        return False


def _pick_temp_ip(network_str: str, avoid_ips: set,
                  adapter_name: str = "") -> Optional[str]:
    """
    Choose a temp IP for a subnet that won't conflict with existing devices.

    Safety measures:
      1. Avoids IPs already in our ARP table
      2. Sends an ARP probe (ping) to each candidate to detect devices
         not yet in the ARP table
      3. Tries multiple candidates (.253, .252, .251, .248, .247)

    This is critical on active networks where assigning a duplicate IP
    could disrupt other devices.
    """
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        base = int(net.network_address)
        for host_part in [253, 252, 251, 248, 247]:
            if host_part >= net.num_addresses - 1:
                continue
            candidate = str(ipaddress.IPv4Address(base + host_part))
            if candidate in avoid_ips:
                logger.debug(f"Temp IP {candidate} in avoid set — skip")
                continue

            # ARP probe: send a single ping to see if anything responds.
            # If something does, this IP is in use — skip it.
            try:
                if IS_WINDOWS:
                    result = subprocess.run(
                        ["ping", "-n", "1", "-w", "300", "-l", "1", candidate],
                        capture_output=True, text=True, timeout=2,
                        creationflags=_NOWND,
                    )
                    if result.returncode == 0 and "TTL=" in result.stdout:
                        logger.info(f"Temp IP {candidate} is ALREADY IN USE — skip")
                        continue
                else:
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", "-s", "1", candidate],
                        capture_output=True, text=True, timeout=2,
                    )
                    if result.returncode == 0:
                        logger.info(f"Temp IP {candidate} is ALREADY IN USE — skip")
                        continue
            except Exception:
                pass  # timeout = no response = IP is free

            logger.info(f"Temp IP {candidate} is available (no ARP response)")
            return candidate
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════════
# INTERFACE-FILTERED ARP TABLE
# ═════════════════════════════════════════════════════════════════════════════

def _get_arp_by_if_index(if_index: int) -> Dict[str, str]:
    """
    Read ARP/neighbor table filtered by INTERFACE INDEX using PowerShell.

    This is the CORRECT way to isolate ARP entries on Windows when:
      - The adapter's primary IP is link-local (169.254.x.x)
      - We've added a temp secondary IP
      - WiFi is on the same subnet as the target

    'arp -a -N <ip>' fails with secondary/temp IPs and link-local primaries.
    'Get-NetNeighbor -InterfaceIndex <idx>' always works because it filters
    by the physical interface, not by any particular IP.
    """
    ip_mac = {}
    if not IS_WINDOWS or if_index is None:
        return ip_mac

    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"Get-NetNeighbor -InterfaceIndex {if_index} "
            f"-State Reachable,Stale,Delay,Probe "
            f"| Select-Object IPAddress,LinkLayerAddress "
            f"| Format-Table -HideTableHeaders"
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            creationflags=_NOWND,
        )

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac_raw = parts[1].replace("-", ":").upper()
                # Validate IP
                try:
                    addr = ipaddress.IPv4Address(ip)
                except Exception:
                    continue  # skip IPv6 or garbage
                # Skip broadcast, null, multicast
                if mac_raw in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                if mac_raw.startswith("01:00:5E"):
                    continue
                if addr.is_multicast:
                    continue
                ip_mac[ip] = mac_raw

        logger.info(f"Get-NetNeighbor (if {if_index}): {len(ip_mac)} entries")
    except Exception as e:
        logger.warning(f"Get-NetNeighbor failed: {e}")

    return ip_mac


def _get_arp_for_interface(interface_ip: str) -> Dict[str, str]:
    """
    Read ARP table filtered to a SINGLE interface (legacy method).

    On Windows: 'arp -a -N <interface_ip>' returns entries only for the
    interface that owns that IP.

    NOTE: This fails when interface_ip is a temp/secondary IP or when
    the primary is link-local.  Prefer _get_arp_by_if_index() when
    the interface index is known.
    """
    ip_mac = {}
    is_win = IS_WINDOWS
    flags = _NOWND if is_win else 0

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
                    r"(\d+\.\d+\.\d+\.\d+)\s+"
                    r"([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:]"
                    r"[\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})",
                    line,
                )
            else:
                match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\) at "
                    r"([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:"
                    r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})",
                    line,
                )
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                # Skip multicast MACs (01:00:5E:xx:xx:xx) and IPs (224.0.0.0/4)
                if mac.startswith("01:00:5E"):
                    continue
                try:
                    if ipaddress.IPv4Address(ip).is_multicast:
                        continue
                except Exception:
                    pass
                ip_mac[ip] = mac
    except Exception as e:
        logger.warning(f"ARP read failed: {e}")

    return ip_mac


# ═════════════════════════════════════════════════════════════════════════════
# PING SWEEP — bound to a specific source IP
# ═════════════════════════════════════════════════════════════════════════════

def _ping_sweep_subnet(
    network_str: str,
    source_ip: str = "",
    adapter_primary_ip: str = "",
    if_index: Optional[int] = None,
    cancel: Optional[threading.Event] = None,
    tcp_probe_ports: bool = True,
) -> Dict[str, str]:
    """
    Ping + TCP-probe every host in a /24, then harvest ARP for that interface.

    Args:
        network_str:        The /24 to sweep (e.g. "192.168.1.0/24")
        source_ip:          IP for ping -S (could be temp IP)
        adapter_primary_ip: Adapter's original/primary IP
        if_index:           Windows interface index — used for
                            Get-NetNeighbor filtering (most reliable)
        cancel:             Threading event to cancel early
        tcp_probe_ports:    If True, do full TCP port probes (slower,
                            ~10s extra per subnet).  False for fast
                            discovery scans where pings alone trigger ARP.
    """
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
    except Exception:
        return {}

    hosts = [str(ip) for ip in net.hosts()]
    if len(hosts) > 3000:
        hosts = hosts[:3000]

    # ── Pre-sweep ARP snapshot ───────────────────────────────────────────
    # Capture existing ARP entries in this subnet BEFORE we ping.
    # If we later fall back to unfiltered 'arp -a', we use this snapshot
    # to DIFF out pre-existing WiFi entries and keep only NEW responses.
    arp_before_sweep: Dict[str, str] = {}
    if IS_WINDOWS and if_index is not None:
        try:
            raw = _get_arp_for_interface("")
            for ip_addr, mac_addr in raw.items():
                try:
                    if ipaddress.IPv4Address(ip_addr) in net:
                        arp_before_sweep[ip_addr] = mac_addr
                except Exception:
                    continue
            if arp_before_sweep:
                logger.debug(f"Pre-sweep ARP snapshot for {network_str}: "
                             f"{len(arp_before_sweep)} existing entries")
        except Exception:
            pass  # snapshot failure is non-fatal — fallback is normal behavior

    sem = threading.Semaphore(50)

    def ping_one(ip):
        if cancel and cancel.is_set():
            return
        with sem:
            try:
                if IS_WINDOWS:
                    cmd = ["ping", "-n", "1", "-w", "800", "-l", "1"]
                    if source_ip:
                        cmd += ["-S", source_ip]
                    cmd.append(ip)
                    subprocess.run(cmd, capture_output=True, timeout=3,
                                   creationflags=_NOWND)
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", "-s", "1"]
                    if source_ip:
                        cmd += ["-I", source_ip]
                    cmd.append(ip)
                    subprocess.run(cmd, capture_output=True, timeout=3)
            except Exception:
                pass

    threads = []
    for ip in hosts:
        if cancel and cancel.is_set():
            break
        t = threading.Thread(target=ping_one, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=8)

    time.sleep(0.5)

    # ── TCP port probe ──────────────────────────────────────────────────
    # Many industrial devices (especially Siemens S7) block ICMP ping but
    # still have open TCP ports.  A TCP SYN to any port triggers an ARP
    # request on the local segment, so even if the port is closed/filtered,
    # the device's MAC appears in the ARP table.  We probe key ports:
    #   102   = S7comm (Siemens S7-300/400/1200/1500)
    #   502   = Modbus TCP
    #   80    = Web server (managed switches, HMIs)
    #   443   = HTTPS
    #   44818 = EtherNet/IP (AB, etc.)
    #   34962 = PROFINET IO RT
    #   161   = SNMP
    if tcp_probe_ports:
        INDUSTRIAL_PORTS = [102, 502, 80, 443, 44818, 34962, 161]
        tcp_sem = threading.Semaphore(80)

        def tcp_probe(ip):
            """Try TCP connect — triggers ARP even if port is closed."""
            if cancel and cancel.is_set():
                return
            with tcp_sem:
                for port in INDUSTRIAL_PORTS:
                    if cancel and cancel.is_set():
                        return
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.3)
                        if source_ip:
                            try:
                                sock.bind((source_ip, 0))
                            except OSError:
                                pass
                        sock.connect_ex((ip, port))
                        sock.close()
                    except Exception:
                        try:
                            sock.close()
                        except Exception:
                            pass

        logger.info(f"TCP port probe {network_str}: {len(hosts)} hosts × "
                    f"{len(INDUSTRIAL_PORTS)} ports...")
        tcp_threads = []
        for ip in hosts:
            if cancel and cancel.is_set():
                break
            t = threading.Thread(target=tcp_probe, args=(ip,), daemon=True)
            tcp_threads.append(t)
            t.start()
        for t in tcp_threads:
            t.join(timeout=15)

        time.sleep(0.5)

    # ── ARP / Neighbor Harvest ──────────────────────────────────────────
    # PRIORITY ORDER:
    #   1. Get-NetNeighbor -InterfaceIndex N  (most reliable, no IP issues)
    #   2. arp -a -N <primary_ip>             (works if primary isn't link-local)
    #   3. arp -a (full table)                (last resort — WiFi leaks!)
    #
    # The old approach (arp -a -N <temp_ip>) NEVER works because Windows
    # files entries under the adapter's primary IP, not secondary/temp IPs.
    # When primary is link-local (169.254.x.x), -N also fails.
    # Get-NetNeighbor filters by physical interface index — always correct.

    arp = {}
    harvest_method = "none"

    # Method 1: Get-NetNeighbor by interface index (BEST)
    if if_index is not None:
        arp = _get_arp_by_if_index(if_index)
        harvest_method = f"Get-NetNeighbor(if={if_index})"
        logger.info(f"ARP harvest via {harvest_method}: {len(arp)} entries")

    # Method 2: arp -a -N <primary_ip> (only if primary is NOT link-local)
    if len(arp) == 0 and adapter_primary_ip and not adapter_primary_ip.startswith("169.254."):
        arp = _get_arp_for_interface(adapter_primary_ip)
        harvest_method = f"arp -N {adapter_primary_ip}"
        logger.info(f"ARP harvest via {harvest_method}: {len(arp)} entries")

    # Method 3: full ARP table (WARNING: includes WiFi entries!)
    if len(arp) == 0:
        arp = _get_arp_for_interface("")
        harvest_method = "arp -a (UNFILTERED)"

        # DIFF FILTER: if we have a pre-sweep snapshot, remove all
        # pre-existing entries — they're from WiFi, not our Ethernet sweep.
        if arp_before_sweep:
            new_only = {ip: mac for ip, mac in arp.items()
                        if ip not in arp_before_sweep}
            logger.info(f"ARP diff: {len(arp)} total, "
                        f"{len(arp_before_sweep)} pre-existing, "
                        f"{len(new_only)} new from this sweep")
            arp = new_only
            harvest_method = "arp -a (DIFF — WiFi filtered)"
        else:
            logger.warning(f"ARP harvest via {harvest_method}: {len(arp)} entries "
                           f"— WiFi entries may leak in!")

    # Filter to target subnet only
    result = {}
    for ip, mac in arp.items():
        try:
            if ipaddress.IPv4Address(ip) in net:
                result[ip] = mac
        except Exception:
            continue

    # If first pass found nothing, wait for slow devices and retry
    if len(result) == 0 and if_index is not None:
        logger.info(f"No devices in {network_str} — waiting 1s for slow ARP...")
        time.sleep(1.0)
        arp2 = _get_arp_by_if_index(if_index)
        for ip, mac in arp2.items():
            try:
                if ipaddress.IPv4Address(ip) in net:
                    result[ip] = mac
            except Exception:
                continue
        if len(result) > 0:
            logger.info(f"Retry found {len(result)} devices in {network_str}")

    # Remove our own temp/source IP
    if source_ip and source_ip in result:
        del result[source_ip]
    if adapter_primary_ip and adapter_primary_ip in result:
        del result[adapter_primary_ip]

    logger.info(f"Ping sweep {network_str} via {source_ip}: "
                f"{harvest_method} total={len(arp)}, in-subnet={len(result)}")
    return result


# ═════════════════════════════════════════════════════════════════════════════
# PROTOCOL DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def _eip_broadcast_discover(
    cancel: Optional[threading.Event] = None,
    interface_ip: str = "",
) -> List[dict]:
    """EtherNet/IP ListIdentity broadcast, bound to specific interface."""
    try:
        from core.eip_scanner import discover_eip_devices
        devices = discover_eip_devices(timeout=3.0, interface_ip=interface_ip)
        return [
            {"ip": d.ip_address, "vendor_name": d.vendor_name,
             "product_name": d.product_name, "serial": d.serial_hex,
             "firmware": d.firmware_version, "device_type": d.device_type_name}
            for d in devices
        ]
    except Exception as e:
        logger.warning(f"EIP discovery failed: {e}")
        return []


def _profinet_dcp_discover(
    cancel: Optional[threading.Event] = None,
    adapter_name: str = "",
) -> List[dict]:
    """PROFINET DCP Identify All (Layer 2), scoped to selected adapter."""
    results = []
    try:
        from profi_dcp import DCP
        import psutil
        for iface_name, stat in psutil.net_if_stats().items():
            if cancel and cancel.is_set():
                break
            if not stat.isup:
                continue
            if adapter_name and iface_name != adapter_name:
                continue
            name_lower = iface_name.lower()
            if any(x in name_lower for x in [
                "loopback", "vmware", "virtualbox", "vpn",
                "docker", "wsl", "hyper-v", "vethernet",
            ]):
                continue
            try:
                dcp = DCP(iface_name)
                devices = dcp.identify_all(timeout=3)
                for dev in devices:
                    ip = getattr(dev, 'ip', '') or ''
                    mac = getattr(dev, 'mac', '') or ''
                    name = getattr(dev, 'name_of_station', '') or ''
                    results.append({"ip": ip, "mac": mac.upper() if mac else "",
                                    "station_name": name, "vendor": "PROFINET Device"})
                dcp.close()
            except Exception as e:
                logger.debug(f"PROFINET DCP on {iface_name}: {e}")
    except ImportError:
        logger.info("profi-dcp not installed — PROFINET DCP skipped")
    except Exception as e:
        logger.warning(f"PROFINET DCP failed: {e}")
    return results


def _tcp_probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _enrich_device_ports(dev: DiscoveredEndpoint,
                         cancel: Optional[threading.Event] = None):
    """Probe industrial TCP ports to identify device type."""
    if cancel and cancel.is_set():
        return
    open_ports = []
    descs = []
    for port in [102, 44818, 80, 443, 502]:
        if cancel and cancel.is_set():
            return
        if _tcp_probe_port(dev.ip_address, port, 0.8):
            open_ports.append(port)
            descs.append(INDUSTRIAL_PORTS.get(port, f"Port {port}"))
    dev.open_ports = open_ports
    if descs:
        dev.port_info = ", ".join(descs)
    if 102 in open_ports and not dev.is_eip:
        if not dev.eip_product_name:
            dev.eip_product_name = "S7 Device (port 102 open)"
        if not dev.vendor_name or dev.vendor_name == "Unknown":
            dev.vendor_name = "Siemens AG (S7)"
            dev.vendor_category = "automation"
    if 44818 in open_ports and not dev.is_eip:
        dev.is_eip = True
        if not dev.eip_product_name:
            dev.eip_product_name = "EtherNet/IP Device (port 44818 open)"
    if 502 in open_ports:
        if not dev.eip_product_name:
            dev.eip_product_name = "Modbus TCP Device (port 502 open)"
        if dev.vendor_category == "other":
            dev.vendor_category = "automation"


# ═════════════════════════════════════════════════════════════════════════════
# CROSS-SUBNET DISCOVERY — one subnet at a time
#
# This is the core function.  For each /24 to probe it:
#   1. Adds temp IP on the selected adapter
#   2. Adds explicit route through that adapter (overrides WiFi)
#   3. Pings all 254 hosts with -S (bound to adapter)
#   4. Harvests ARP with -N (filtered to adapter)
#   5. Cleans up route and temp IP
# ═════════════════════════════════════════════════════════════════════════════

def _discover_subnet(
    network_str: str,
    adapter_name: str,
    adapter_ip: str,
    if_index: Optional[int],
    cancel: Optional[threading.Event] = None,
    progress: Optional[Callable[[str], None]] = None,
    competing_ifaces: Optional[List[Tuple[str, str, int]]] = None,
    tcp_probe_ports: bool = True,
) -> Dict[str, str]:
    """
    Discover devices on a subnet, handling temp IP + route if needed.

    If the adapter is already on this subnet, just sweep.
    Otherwise: add temp IP, force route, sweep, clean up.

    Args:
        competing_ifaces:  List of (name, ip, if_index) for OTHER interfaces
                           (e.g. WiFi) that may conflict with this subnet.
                           Their routes are suppressed during the probe.

    Returns {ip: mac} of discovered devices.
    """
    def _msg(m):
        if progress:
            progress(m)

    # Check if we're already on this subnet
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
        if adapter_ip and not adapter_ip.startswith("169.254."):
            try:
                if ipaddress.IPv4Address(adapter_ip) in net:
                    _msg(f"Sweep {network_str} (already connected)...")
                    return _ping_sweep_subnet(
                        network_str, source_ip=adapter_ip,
                        if_index=if_index, cancel=cancel,
                        tcp_probe_ports=tcp_probe_ports)
            except Exception:
                pass
    except Exception:
        return {}

    # Need temp IP — probe candidates to avoid IP conflicts
    existing = set(_get_arp_for_interface("").keys())
    temp_ip = _pick_temp_ip(network_str, existing, adapter_name=adapter_name)
    if not temp_ip:
        _msg(f"Skip {network_str} — no temp IP available")
        return {}

    _msg(f"Adding {temp_ip} to {adapter_name}...")
    if not _add_temp_ip(adapter_name, temp_ip):
        _msg(f"FAILED — need administrator. Skipping {network_str}")
        return {}

    route_added = False
    suppressed = []
    try:
        time.sleep(0.8)

        # Suppress competing routes (e.g. WiFi on same subnet)
        # MUST happen BEFORE adding our route — otherwise Windows
        # continues to prefer WiFi's connected route.
        if competing_ifaces:
            suppressed = _suppress_competing_routes(
                network_str, competing_ifaces)

        # Force route through our adapter
        if if_index is not None:
            route_added = _add_route(network_str, temp_ip, if_index)
            if route_added:
                _msg(f"Route forced via {adapter_name} (if {if_index})")
                time.sleep(0.3)
            else:
                _msg(f"Route add failed — traffic may go via WiFi")

        _msg(f"Sweep {network_str} via {temp_ip}...")
        results = _ping_sweep_subnet(
            network_str, source_ip=temp_ip,
            adapter_primary_ip=adapter_ip, if_index=if_index,
            cancel=cancel, tcp_probe_ports=tcp_probe_ports)

        _msg(f"Found {len(results)} on {network_str}")
        return results

    finally:
        # ALWAYS clean up — route first, then IP, then restore WiFi
        if route_added and if_index is not None:
            _remove_route(network_str, temp_ip, if_index)
        _remove_temp_ip(adapter_name, temp_ip)
        if suppressed:
            _restore_competing_routes(network_str, suppressed)
        time.sleep(0.3)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN DISCOVERY ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

def run_device_discovery(
    progress_callback: Optional[Callable[[float, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    probe_all_subnets: bool = True,
    custom_ranges: Optional[List[str]] = None,
    adapter_name: str = "",
    adapter_ip: str = "",
) -> List[DiscoveredEndpoint]:
    """
    Run device discovery scoped to the selected adapter only.
    """
    def _progress(pct: float, msg: str):
        logger.info(f"[{pct:.0%}] {msg}")
        if progress_callback:
            progress_callback(pct, msg)

    all_devices: Dict[str, DiscoveredEndpoint] = {}
    ip_to_mac: Dict[str, str] = {}

    def _add_device(ip: str, mac: str, method: str):
        ip_to_mac[ip] = mac
        if mac not in all_devices:
            vname, vcat = lookup_vendor(mac)
            all_devices[mac] = DiscoveredEndpoint(
                ip_address=ip, mac_address=mac,
                vendor_name=vname, vendor_category=vcat,
                discovery_method=method,
            )

    # ── Get interface index (needed for route forcing) ───────────────────
    if_index = None
    if IS_WINDOWS and adapter_name:
        if_index = _get_interface_index(adapter_name)

    _progress(0.01, f"Adapter: {adapter_name} | IP: {adapter_ip} | "
                     f"IF index: {if_index}")

    # ── Determine selected adapter's subnet ──────────────────────────────
    selected_subnet = ""
    if adapter_ip and not adapter_ip.startswith("169.254."):
        try:
            selected_subnet = str(ipaddress.IPv4Network(
                f"{adapter_ip}/24", strict=False))
        except Exception:
            pass

    is_link_local = adapter_ip.startswith("169.254.") if adapter_ip else False

    # ── Gather competing interfaces (WiFi etc.) ─────────────────────────
    # These are OTHER active interfaces whose routes may conflict with
    # subnets we want to probe via the selected Ethernet adapter.
    # When WiFi is on the same subnet (e.g. 192.168.1.0/24), Windows
    # routes ALL traffic through WiFi, ignoring our metric-1 route.
    # We pass these to _discover_subnet() so it can suppress their routes.
    competing_ifaces: List[Tuple[str, str, int]] = []
    if IS_WINDOWS and adapter_name:
        try:
            from core.network_utils import get_network_interfaces
            for iface in get_network_interfaces():
                if iface.name == adapter_name:
                    continue  # skip our selected adapter
                if iface.ip_address.startswith("169.254."):
                    continue  # link-local has no meaningful routes
                comp_if_index = _get_interface_index(iface.name)
                if comp_if_index is not None:
                    competing_ifaces.append(
                        (iface.name, iface.ip_address, comp_if_index))
                    logger.info(f"Competing interface: {iface.name} "
                                f"({iface.ip_address}) if={comp_if_index}")
        except Exception as e:
            logger.warning(f"Failed to gather competing interfaces: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: Ping sweep selected adapter's current subnet
    # Skip if link-local (DHCP) — the PLC isn't on 169.254.x.x
    # ══════════════════════════════════════════════════════════════════════
    if (not (cancel_event and cancel_event.is_set())
            and selected_subnet
            and not is_link_local):
        _progress(0.02, f"Phase 1/7: Sweep {selected_subnet} "
                        f"(selected adapter)...")
        results = _ping_sweep_subnet(
            selected_subnet, source_ip=adapter_ip,
            if_index=if_index, cancel=cancel_event)
        for ip, mac in results.items():
            _add_device(ip, mac, f"Ping sweep ({selected_subnet})")
        _progress(0.18, f"Phase 1: {len(all_devices)} devices on "
                        f"{selected_subnet}")
    else:
        reason = "link-local (DHCP)" if is_link_local else "no subnet"
        _progress(0.18, f"Phase 1: Skipped — adapter is {reason}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: EtherNet/IP broadcast
    # ══════════════════════════════════════════════════════════════════════
    if not (cancel_event and cancel_event.is_set()):
        _progress(0.19, "Phase 2/7: EtherNet/IP broadcast...")
        eip_results = _eip_broadcast_discover(
            cancel=cancel_event, interface_ip=adapter_ip)
        for eip in eip_results:
            ip = eip["ip"]
            mac = ip_to_mac.get(ip, "")
            if mac and mac in all_devices:
                dev = all_devices[mac]
            elif mac:
                vname, vcat = lookup_vendor(mac)
                dev = DiscoveredEndpoint(ip_address=ip, mac_address=mac,
                                         vendor_name=vname, vendor_category=vcat)
                all_devices[mac] = dev
            else:
                key = f"eip_{ip}"
                dev = all_devices.get(key, DiscoveredEndpoint(ip_address=ip))
                all_devices[key] = dev
            dev.is_eip = True
            dev.discovery_method = "EtherNet/IP broadcast"
            dev.eip_product_name = eip.get("product_name", "")
            dev.eip_vendor_name = eip.get("vendor_name", "")
            dev.eip_serial = eip.get("serial", "")
            dev.eip_firmware = eip.get("firmware", "")
            dev.eip_device_type = eip.get("device_type", "")
            if dev.eip_vendor_name and not dev.vendor_name:
                dev.vendor_name = dev.eip_vendor_name
                dev.vendor_category = "automation"
        _progress(0.24, f"Phase 2: {len(eip_results)} EtherNet/IP devices")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: PROFINET DCP (Layer 2)
    # ══════════════════════════════════════════════════════════════════════
    if not (cancel_event and cancel_event.is_set()):
        _progress(0.25, "Phase 3/7: PROFINET DCP broadcast...")
        pn_results = _profinet_dcp_discover(
            cancel=cancel_event, adapter_name=adapter_name)
        for pn in pn_results:
            ip = pn.get("ip", "")
            mac = pn.get("mac", "") or ip_to_mac.get(ip, "")
            if mac and mac in all_devices:
                dev = all_devices[mac]
            elif mac:
                vname, vcat = lookup_vendor(mac)
                dev = DiscoveredEndpoint(ip_address=ip, mac_address=mac,
                                         vendor_name=vname, vendor_category=vcat)
                all_devices[mac] = dev
            elif ip:
                key = f"pn_{ip}"
                dev = all_devices.get(key, DiscoveredEndpoint(ip_address=ip))
                all_devices[key] = dev
            else:
                continue
            dev.is_profinet = True
            dev.profinet_name = pn.get("station_name", "")
            dev.discovery_method = "PROFINET DCP"
            if not dev.vendor_name or dev.vendor_name == "Unknown":
                dev.vendor_name = pn.get("vendor", "PROFINET Device")
            dev.vendor_category = "automation"
            if dev.profinet_name and not dev.eip_product_name:
                dev.eip_product_name = f"PROFINET: {dev.profinet_name}"
        _progress(0.30, f"Phase 3: {len(pn_results)} PROFINET devices")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: Probe factory-default subnets (temp IP + forced route)
    # ══════════════════════════════════════════════════════════════════════
    if probe_all_subnets and not (cancel_event and cancel_event.is_set()):
        _progress(0.31, "Phase 4/7: Probing factory-default subnets...")

        subnets_to_probe = [
            (ns, desc) for ns, desc in FACTORY_DEFAULT_RANGES
            if ns != selected_subnet
        ]
        total = max(len(subnets_to_probe), 1)

        for i, (net_str, desc) in enumerate(subnets_to_probe):
            if cancel_event and cancel_event.is_set():
                break

            pct = 0.31 + (i / total) * 0.40

            try:
                net = ipaddress.IPv4Network(net_str, strict=False)
                if net.prefixlen < 24:
                    continue
            except Exception:
                continue

            _progress(pct, f"Phase 4/7: {net_str} — {desc}")

            def sub_progress(msg, _p=pct):
                _progress(_p, f"Phase 4/7: {msg}")

            results = _discover_subnet(
                net_str, adapter_name, adapter_ip, if_index,
                cancel=cancel_event, progress=sub_progress,
                competing_ifaces=competing_ifaces,
                tcp_probe_ports=False,  # Fast mode — pings only (~6s vs ~18s)
            )
            for ip, mac in results.items():
                _add_device(ip, mac, f"Discovery ({net_str})")

        _progress(0.72, f"Phase 4: {len(all_devices)} total devices")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: Custom subnet ranges
    # ══════════════════════════════════════════════════════════════════════
    if custom_ranges and not (cancel_event and cancel_event.is_set()):
        _progress(0.73, "Phase 5/7: Custom subnets...")
        total = max(len(custom_ranges), 1)

        for i, net_str in enumerate(custom_ranges):
            if cancel_event and cancel_event.is_set():
                break
            net_str = net_str.strip()
            if not net_str:
                continue
            pct = 0.73 + (i / total) * 0.07
            _progress(pct, f"Phase 5/7: {net_str}...")

            def sub_progress(msg, _p=pct):
                _progress(_p, f"Phase 5/7: {msg}")

            results = _discover_subnet(
                net_str, adapter_name, adapter_ip, if_index,
                cancel=cancel_event, progress=sub_progress,
                competing_ifaces=competing_ifaces,
            )
            for ip, mac in results.items():
                _add_device(ip, mac, f"Custom ({net_str})")

        _progress(0.80, f"Phase 5: {len(all_devices)} total")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: Final ARP — only from selected adapter
    # ══════════════════════════════════════════════════════════════════════
    if not (cancel_event and cancel_event.is_set()):
        _progress(0.81, "Phase 6/7: Final ARP check...")
        # Use interface-index-based ARP (handles link-local primary)
        if if_index is not None:
            arp = _get_arp_by_if_index(if_index)
        else:
            arp = _get_arp_for_interface(adapter_ip)
        for ip, mac in arp.items():
            if mac in all_devices:
                continue
            _add_device(ip, mac, "ARP table")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: TCP port enrichment (with temp IP if needed)
    # ══════════════════════════════════════════════════════════════════════
    if not (cancel_event and cancel_event.is_set()):
        _progress(0.83, "Phase 7/7: Identifying devices (port scan)...")

        dev_list = list(all_devices.values())
        enrich_targets = [
            d for d in dev_list
            if d.vendor_category in ("automation", "other")
            and not d.is_eip and d.ip_address
        ]

        # Group by /24 for temp IP batching
        subnet_groups: Dict[str, List[DiscoveredEndpoint]] = {}
        for dev in enrich_targets:
            try:
                skey = str(ipaddress.IPv4Network(
                    f"{dev.ip_address}/24", strict=False))
            except Exception:
                skey = "unknown"
            subnet_groups.setdefault(skey, []).append(dev)

        done = [0]
        total_t = max(len(enrich_targets), 1)

        for sn, devs in subnet_groups.items():
            if cancel_event and cancel_event.is_set():
                break

            # Does this subnet need a temp IP?
            need_temp = (sn != selected_subnet and is_link_local) or \
                        (sn != selected_subnet and selected_subnet != "")
            temp_ip = None
            route_added = False

            if need_temp and adapter_name:
                existing = set(_get_arp_for_interface("").keys())
                temp_ip = _pick_temp_ip(sn, existing, adapter_name=adapter_name)
                if temp_ip and _add_temp_ip(adapter_name, temp_ip):
                    time.sleep(1.0)
                    if if_index is not None:
                        route_added = _add_route(sn, temp_ip, if_index)
                        time.sleep(0.3)
                else:
                    temp_ip = None

            try:
                sem = threading.Semaphore(8)
                threads = []

                def _do_enrich(d):
                    if cancel_event and cancel_event.is_set():
                        return
                    with sem:
                        _enrich_device_ports(d, cancel=cancel_event)
                    done[0] += 1
                    p = 0.83 + (done[0] / total_t) * 0.12
                    _progress(p, f"Phase 7/7: Port probe "
                              f"({done[0]}/{len(enrich_targets)})...")

                for d in devs:
                    if cancel_event and cancel_event.is_set():
                        break
                    t = threading.Thread(target=_do_enrich, args=(d,),
                                         daemon=True)
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join(timeout=8)
            finally:
                if route_added and if_index is not None:
                    _remove_route(sn, temp_ip, if_index)
                if temp_ip:
                    _remove_temp_ip(adapter_name, temp_ip)
                    time.sleep(0.2)

        _progress(0.96, f"Phase 7: enriched {done[0]} devices")

    # ── Final ────────────────────────────────────────────────────────────
    _progress(0.97, "Calculating suggested network settings...")
    result_list = list(all_devices.values())
    for dev in result_list:
        subnet, lip = _suggest_subnet(dev.ip_address)
        dev.suggested_subnet = subnet
        dev.suggested_ip = lip

    def sort_key(d):
        cat_order = {"automation": 0, "networking": 1, "computing": 2, "other": 3}
        try:
            ip_val = int(ipaddress.IPv4Address(d.ip_address))
        except Exception:
            ip_val = 0
        return (cat_order.get(d.vendor_category, 3), ip_val)

    result_list.sort(key=sort_key)
    _progress(1.0, f"Done — found {len(result_list)} devices")
    return result_list


# ─── Legacy compat ───────────────────────────────────────────────────────────
def send_arp_probe(target_ip: str) -> Optional[str]:
    """Cross-platform ARP probe (same-subnet only)."""
    import ctypes
    if IS_WINDOWS:
        try:
            iplib = ctypes.windll.iphlpapi
            ws2 = ctypes.windll.ws2_32
            dest_ip = ws2.inet_addr(target_ip.encode("ascii"))
            if dest_ip == 0xFFFFFFFF:
                return None
            mac_addr = (ctypes.c_ulong * 2)()
            addr_len = ctypes.c_ulong(6)
            ret = iplib.SendARP(dest_ip, 0, ctypes.byref(mac_addr),
                                ctypes.byref(addr_len))
            if ret != 0:
                return None
            mac_bytes = bytes(mac_addr)[:6]
            mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
            if mac_str in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                return None
            return mac_str
        except Exception:
            return None
    else:
        try:
            subprocess.run(["ping", "-c", "1", "-W", "1", target_ip],
                           capture_output=True, timeout=3)
            result = subprocess.run(["arp", "-n", target_ip],
                                    capture_output=True, text=True, timeout=3)
            match = re.search(
                r"([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:"
                r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})",
                result.stdout)
            if match:
                return match.group(1).upper()
        except Exception:
            pass
        return None
