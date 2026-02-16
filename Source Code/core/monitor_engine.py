"""
SAS Network Diagnostics Tool — Device Monitor Engine
Continuous background monitoring of a network device to capture intermittent issues.

Collects:
  - ICMP ping (network layer reachability + round-trip time)
  - CIP Identity read (application layer health + response time)
  - Timestamped history of every poll cycle

Designed to run for minutes, hours, or even days to catch transient faults.
"""

import csv
import logging
import os
import struct
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable, Tuple, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class PollSample:
    """Single data point from one poll cycle."""
    timestamp: datetime
    elapsed_seconds: float          # Seconds since monitoring started

    # ICMP ping results
    ping_success: bool = False
    ping_time_ms: float = 0.0
    ping_error: str = ""

    # CIP Identity read results
    cip_success: bool = False
    cip_time_ms: float = 0.0
    cip_error: str = ""
    cip_status_code: int = 0

    # Device identity (from CIP, if successful)
    product_name: str = ""
    vendor_name: str = ""
    device_status: int = 0
    device_status_text: str = ""

    @property
    def is_reachable(self) -> bool:
        """Device responded to at least one probe."""
        return self.ping_success or self.cip_success

    @property
    def best_response_ms(self) -> float:
        """Best response time from either method."""
        times = []
        if self.ping_success:
            times.append(self.ping_time_ms)
        if self.cip_success:
            times.append(self.cip_time_ms)
        return min(times) if times else 0.0


@dataclass
class MonitorStats:
    """Running statistics calculated from collected samples."""
    total_samples: int = 0
    duration_seconds: float = 0.0

    # Ping statistics
    ping_sent: int = 0
    ping_success: int = 0
    ping_loss_pct: float = 0.0
    ping_min_ms: float = 0.0
    ping_max_ms: float = 0.0
    ping_avg_ms: float = 0.0
    ping_p95_ms: float = 0.0
    ping_jitter_ms: float = 0.0       # Std deviation of response times

    # CIP statistics
    cip_sent: int = 0
    cip_success: int = 0
    cip_loss_pct: float = 0.0
    cip_min_ms: float = 0.0
    cip_max_ms: float = 0.0
    cip_avg_ms: float = 0.0
    cip_p95_ms: float = 0.0

    # Availability
    uptime_pct: float = 0.0           # % of samples where device was reachable
    longest_outage_sec: float = 0.0   # Longest continuous period of failed polls
    outage_count: int = 0             # Number of distinct outage events
    current_streak: int = 0           # Current consecutive success/fail streak
    current_streak_type: str = ""     # "success" or "failure"


@dataclass
class OutageEvent:
    """A period where the device was unreachable."""
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    sample_count: int = 0             # Number of failed polls in this outage
    recovery_time_ms: float = 0.0     # Response time of first successful poll after

    @property
    def is_ongoing(self) -> bool:
        return self.end_time is None


# ── Monitor Engine ───────────────────────────────────────────────────────────

class DeviceMonitor:
    """
    Background device monitor that continuously polls a target and collects data.

    Usage:
        monitor = DeviceMonitor("192.168.1.10")
        monitor.start(interval_sec=2.0)
        # ... let it run ...
        stats = monitor.get_stats()
        monitor.stop()
        monitor.export_csv("device_log.csv")
    """

    def __init__(
        self,
        target_ip: str,
        poll_interval: float = 2.0,
        enable_ping: bool = True,
        enable_cip: bool = True,
        ping_timeout: float = 2.0,
        cip_timeout: float = 3.0,
    ):
        self.target_ip = target_ip
        self.poll_interval = max(0.5, poll_interval)  # Minimum 500ms
        self.enable_ping = enable_ping
        self.enable_cip = enable_cip
        self.ping_timeout = ping_timeout
        self.cip_timeout = cip_timeout

        # Data storage
        self.samples: List[PollSample] = []
        self.outages: List[OutageEvent] = []
        self._lock = threading.Lock()

        # Control
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._start_time: Optional[datetime] = None

        # Callbacks
        self._on_sample: Optional[Callable[[PollSample], None]] = None
        self._on_status_change: Optional[Callable[[bool, PollSample], None]] = None

        # CIP connection (reused across polls)
        self._cip_driver = None

        # Track state for outage detection
        self._last_reachable = None  # None = unknown, True/False
        self._current_outage: Optional[OutageEvent] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def sample_count(self) -> int:
        with self._lock:
            return len(self.samples)

    @property
    def elapsed_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return (datetime.now() - self._start_time).total_seconds()

    def set_on_sample(self, callback: Callable[[PollSample], None]):
        """Set callback for each new sample (called from monitor thread)."""
        self._on_sample = callback

    def set_on_status_change(self, callback: Callable[[bool, PollSample], None]):
        """Set callback for reachability changes (True=came online, False=went offline)."""
        self._on_status_change = callback

    # ── Start / Stop ─────────────────────────────────────────────────────

    def start(self):
        """Start monitoring in a background thread."""
        if self._running:
            return

        self._stop_event.clear()
        self._start_time = datetime.now()
        self._running = True
        self._last_reachable = None
        self._current_outage = None

        self._thread = threading.Thread(target=self._poll_loop, daemon=True,
                                         name=f"monitor-{self.target_ip}")
        self._thread.start()
        logger.info(f"Monitor started for {self.target_ip} "
                     f"(interval={self.poll_interval}s)")

    def stop(self):
        """Stop monitoring and close connections."""
        if not self._running:
            return

        self._stop_event.set()
        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.poll_interval + 5)

        # Close any open outage
        if self._current_outage and self._current_outage.is_ongoing:
            self._current_outage.end_time = datetime.now()
            self._current_outage.duration_seconds = (
                self._current_outage.end_time - self._current_outage.start_time
            ).total_seconds()

        # Close CIP connection
        self._close_cip()

        logger.info(f"Monitor stopped for {self.target_ip} "
                     f"({len(self.samples)} samples collected)")

    def clear(self):
        """Clear all collected data."""
        with self._lock:
            self.samples.clear()
            self.outages.clear()
        self._last_reachable = None
        self._current_outage = None
        self._start_time = None

    # ── Poll Loop ────────────────────────────────────────────────────────

    def _poll_loop(self):
        """Main polling loop running in background thread."""
        while not self._stop_event.is_set():
            cycle_start = time.monotonic()

            sample = self._do_poll()

            with self._lock:
                self.samples.append(sample)

            # Detect outage transitions
            self._check_outage(sample)

            # Fire callbacks
            if self._on_sample:
                try:
                    self._on_sample(sample)
                except Exception as e:
                    logger.debug(f"Sample callback error: {e}")

            # Sleep for remainder of interval
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0, self.poll_interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)

    def _do_poll(self) -> PollSample:
        """Execute one poll cycle (ping + CIP read)."""
        now = datetime.now()
        elapsed = (now - self._start_time).total_seconds() if self._start_time else 0

        sample = PollSample(timestamp=now, elapsed_seconds=elapsed)

        # ICMP Ping
        if self.enable_ping:
            try:
                success, rtt = self._ping(self.target_ip, self.ping_timeout)
                sample.ping_success = success
                sample.ping_time_ms = rtt
                if not success:
                    sample.ping_error = "Timeout"
            except Exception as e:
                sample.ping_success = False
                sample.ping_error = str(e)

        # CIP Identity Read
        if self.enable_cip:
            try:
                success, rtt, identity = self._cip_read_identity()
                sample.cip_success = success
                sample.cip_time_ms = rtt
                if success and identity:
                    sample.product_name = identity.get("product_name", "")
                    sample.vendor_name = identity.get("vendor_name", "")
                    sample.device_status = identity.get("status", 0)
                    sample.device_status_text = identity.get("status_text", "")
                elif not success:
                    sample.cip_error = identity.get("error", "No response") if identity else "No response"
            except Exception as e:
                sample.cip_success = False
                sample.cip_error = str(e)

        return sample

    def _check_outage(self, sample: PollSample):
        """Track outage events based on reachability changes."""
        reachable = sample.is_reachable

        if self._last_reachable is None:
            # First sample
            self._last_reachable = reachable
            if not reachable:
                self._current_outage = OutageEvent(
                    start_time=sample.timestamp, sample_count=1)
            return

        if self._last_reachable and not reachable:
            # Went offline
            self._current_outage = OutageEvent(
                start_time=sample.timestamp, sample_count=1)
            if self._on_status_change:
                try:
                    self._on_status_change(False, sample)
                except Exception:
                    pass

        elif not self._last_reachable and reachable:
            # Came back online
            if self._current_outage:
                self._current_outage.end_time = sample.timestamp
                self._current_outage.duration_seconds = (
                    sample.timestamp - self._current_outage.start_time
                ).total_seconds()
                self._current_outage.recovery_time_ms = sample.best_response_ms
                with self._lock:
                    self.outages.append(self._current_outage)
                self._current_outage = None

            if self._on_status_change:
                try:
                    self._on_status_change(True, sample)
                except Exception:
                    pass

        elif not reachable and self._current_outage:
            # Still offline
            self._current_outage.sample_count += 1

        self._last_reachable = reachable

    # ── ICMP Ping ────────────────────────────────────────────────────────

    @staticmethod
    def _ping(host: str, timeout: float) -> Tuple[bool, float]:
        """
        ICMP ping using system ping command.
        Returns (success, round_trip_ms).
        """
        try:
            # Use system ping — works without admin/raw sockets
            timeout_ms = int(timeout * 1000)
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]

            # CREATE_NO_WINDOW on Windows prevents console flash
            kwargs = {}
            import sys
            if sys.platform == "win32":
                kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

            start = time.monotonic()
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout + 2, **kwargs
            )
            elapsed = (time.monotonic() - start) * 1000

            if proc.returncode == 0 and "TTL=" in proc.stdout.upper():
                # Parse actual RTT from ping output
                # Look for "time=XXms" or "time<1ms"
                import re
                match = re.search(r'time[=<](\d+)', proc.stdout, re.IGNORECASE)
                if match:
                    rtt = float(match.group(1))
                else:
                    rtt = elapsed
                return True, round(rtt, 2)
            else:
                return False, 0.0

        except subprocess.TimeoutExpired:
            return False, 0.0
        except FileNotFoundError:
            # ping command not available — shouldn't happen on Windows
            return False, 0.0
        except Exception:
            return False, 0.0

    # ── CIP Identity Read ────────────────────────────────────────────────

    def _cip_read_identity(self) -> Tuple[bool, float, Optional[dict]]:
        """
        Read CIP Identity Object from an EtherNet/IP device.
        Uses a lightweight ListIdentity (UDP broadcast) first,
        then falls back to connected CIP read.
        Returns (success, response_time_ms, identity_dict_or_error).
        """
        start = time.monotonic()

        try:
            identity = self._list_identity_udp()
            elapsed = (time.monotonic() - start) * 1000

            if identity:
                return True, round(elapsed, 2), identity
            else:
                return False, round(elapsed, 2), {"error": "No ListIdentity response"}

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return False, round(elapsed, 2), {"error": str(e)}

    def _list_identity_udp(self) -> Optional[dict]:
        """
        Send an EtherNet/IP ListIdentity request via UDP.
        This is lightweight (no TCP connection) and every EtherNet/IP device
        must respond to it. Perfect for monitoring without connection overhead.
        """
        # EtherNet/IP encapsulation header for ListIdentity
        # Command: 0x0063 (ListIdentity)
        # Length: 0
        # Session Handle: 0
        # Status: 0
        # Sender Context: 8 bytes
        # Options: 0
        list_identity_packet = struct.pack(
            "<HHIIII",
            0x0063,     # Command: ListIdentity
            0,          # Length
            0,          # Session Handle
            0,          # Status
            0,          # Sender Context (low)
            0,          # Options
        )
        # Pad to 24 bytes (standard encap header)
        list_identity_packet = list_identity_packet.ljust(24, b'\x00')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.cip_timeout)

        try:
            sock.sendto(list_identity_packet, (self.target_ip, 44818))
            data, addr = sock.recvfrom(1024)

            if len(data) < 26:
                return None

            return self._parse_list_identity(data)

        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"ListIdentity UDP error: {e}")
            return None
        finally:
            sock.close()

    def _parse_list_identity(self, data: bytes) -> Optional[dict]:
        """Parse a ListIdentity response from an EtherNet/IP device."""
        try:
            # Skip encapsulation header (24 bytes)
            if len(data) < 26:
                return None

            # Item count at offset 24
            item_count = struct.unpack_from("<H", data, 24)[0]
            if item_count < 1:
                return None

            # First item starts at offset 26
            # Type ID (2) + Length (2) = 4 byte item header
            if len(data) < 30:
                return None

            item_type = struct.unpack_from("<H", data, 26)[0]
            item_length = struct.unpack_from("<H", data, 28)[0]

            if item_type != 0x000C:  # CIP Identity Item
                return None

            # Identity data starts at offset 30
            pos = 30
            if len(data) < pos + 33:
                return None

            # Protocol version (2)
            pos += 2

            # Socket address (16 bytes: sin_family(2), sin_port(2), sin_addr(4), sin_zero(8))
            pos += 16

            # Vendor ID
            vendor_id = struct.unpack_from("<H", data, pos)[0]
            pos += 2

            # Device Type
            device_type = struct.unpack_from("<H", data, pos)[0]
            pos += 2

            # Product Code
            product_code = struct.unpack_from("<H", data, pos)[0]
            pos += 2

            # Revision (major, minor)
            rev_major = data[pos]
            rev_minor = data[pos + 1]
            pos += 2

            # Status
            status = struct.unpack_from("<H", data, pos)[0]
            pos += 2

            # Serial Number
            serial = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            # Product Name (SHORT_STRING: 1 byte len + chars)
            if pos < len(data):
                name_len = data[pos]
                pos += 1
                product_name = ""
                if name_len > 0 and pos + name_len <= len(data):
                    product_name = data[pos:pos + name_len].decode("ascii", errors="replace").strip("\x00")
            else:
                product_name = ""

            # Build vendor name
            from core.devicenet_diag import CIP_VENDORS, CIP_PRODUCT_TYPES, decode_device_status
            vendor_name = CIP_VENDORS.get(vendor_id, f"Vendor {vendor_id}")
            type_name = CIP_PRODUCT_TYPES.get(device_type, f"Type {device_type}")
            status_text = decode_device_status(status)

            return {
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "device_type": device_type,
                "device_type_name": type_name,
                "product_code": product_code,
                "revision_major": rev_major,
                "revision_minor": rev_minor,
                "status": status,
                "status_text": status_text,
                "serial_number": f"{serial:08X}",
                "product_name": product_name,
            }

        except Exception as e:
            logger.debug(f"ListIdentity parse error: {e}")
            return None

    def _close_cip(self):
        """Close CIP driver if open."""
        if self._cip_driver:
            try:
                self._cip_driver.close()
            except Exception:
                pass
            self._cip_driver = None

    # ── Statistics ────────────────────────────────────────────────────────

    def get_stats(self) -> MonitorStats:
        """Calculate statistics from collected samples."""
        with self._lock:
            samples = list(self.samples)
            outages = list(self.outages)

        stats = MonitorStats()
        if not samples:
            return stats

        stats.total_samples = len(samples)
        stats.duration_seconds = (
            samples[-1].timestamp - samples[0].timestamp
        ).total_seconds() if len(samples) > 1 else 0

        # Ping stats
        ping_samples = [s for s in samples if self.enable_ping]
        ping_times = [s.ping_time_ms for s in ping_samples if s.ping_success]
        stats.ping_sent = len(ping_samples)
        stats.ping_success = len(ping_times)
        stats.ping_loss_pct = (
            (1 - len(ping_times) / len(ping_samples)) * 100
            if ping_samples else 0
        )

        if ping_times:
            stats.ping_min_ms = round(min(ping_times), 2)
            stats.ping_max_ms = round(max(ping_times), 2)
            stats.ping_avg_ms = round(sum(ping_times) / len(ping_times), 2)
            sorted_times = sorted(ping_times)
            p95_idx = int(len(sorted_times) * 0.95)
            stats.ping_p95_ms = round(sorted_times[min(p95_idx, len(sorted_times) - 1)], 2)

            # Jitter (standard deviation)
            if len(ping_times) > 1:
                mean = stats.ping_avg_ms
                variance = sum((t - mean) ** 2 for t in ping_times) / len(ping_times)
                stats.ping_jitter_ms = round(variance ** 0.5, 2)

        # CIP stats
        cip_samples = [s for s in samples if self.enable_cip]
        cip_times = [s.cip_time_ms for s in cip_samples if s.cip_success]
        stats.cip_sent = len(cip_samples)
        stats.cip_success = len(cip_times)
        stats.cip_loss_pct = (
            (1 - len(cip_times) / len(cip_samples)) * 100
            if cip_samples else 0
        )

        if cip_times:
            stats.cip_min_ms = round(min(cip_times), 2)
            stats.cip_max_ms = round(max(cip_times), 2)
            stats.cip_avg_ms = round(sum(cip_times) / len(cip_times), 2)
            sorted_cip = sorted(cip_times)
            p95_idx = int(len(sorted_cip) * 0.95)
            stats.cip_p95_ms = round(sorted_cip[min(p95_idx, len(sorted_cip) - 1)], 2)

        # Uptime / outages
        reachable_count = sum(1 for s in samples if s.is_reachable)
        stats.uptime_pct = round(reachable_count / len(samples) * 100, 2)

        stats.outage_count = len(outages)
        if self._current_outage and self._current_outage.is_ongoing:
            stats.outage_count += 1

        if outages:
            stats.longest_outage_sec = max(o.duration_seconds for o in outages)

        # Current streak
        if samples:
            streak_type = samples[-1].is_reachable
            streak_count = 0
            for s in reversed(samples):
                if s.is_reachable == streak_type:
                    streak_count += 1
                else:
                    break
            stats.current_streak = streak_count
            stats.current_streak_type = "success" if streak_type else "failure"

        return stats

    # ── Data Export ───────────────────────────────────────────────────────

    def export_csv(self, filepath: str) -> Tuple[bool, str]:
        """Export collected samples to a CSV file."""
        with self._lock:
            samples = list(self.samples)

        if not samples:
            return False, "No data to export"

        try:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                # Header
                writer.writerow([
                    "Timestamp", "Elapsed_Sec",
                    "Ping_Success", "Ping_Time_ms", "Ping_Error",
                    "CIP_Success", "CIP_Time_ms", "CIP_Error",
                    "Product_Name", "Device_Status", "Status_Text",
                ])

                for s in samples:
                    writer.writerow([
                        s.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        f"{s.elapsed_seconds:.1f}",
                        int(s.ping_success), f"{s.ping_time_ms:.2f}", s.ping_error,
                        int(s.cip_success), f"{s.cip_time_ms:.2f}", s.cip_error,
                        s.product_name, s.device_status, s.device_status_text,
                    ])

            return True, f"Exported {len(samples)} samples to {filepath}"

        except Exception as e:
            return False, f"Export failed: {e}"

    def get_samples_snapshot(self) -> List[PollSample]:
        """Get a copy of all samples (thread-safe)."""
        with self._lock:
            return list(self.samples)

    def get_outages_snapshot(self) -> List[OutageEvent]:
        """Get a copy of all outage events (thread-safe)."""
        with self._lock:
            outages = list(self.outages)
        # Include current ongoing outage if any
        if self._current_outage and self._current_outage.is_ongoing:
            ongoing = OutageEvent(
                start_time=self._current_outage.start_time,
                sample_count=self._current_outage.sample_count,
            )
            ongoing.duration_seconds = (
                datetime.now() - ongoing.start_time
            ).total_seconds()
            outages.append(ongoing)
        return outages

    def get_recent_samples(self, count: int = 100) -> List[PollSample]:
        """Get the most recent N samples."""
        with self._lock:
            return list(self.samples[-count:])
