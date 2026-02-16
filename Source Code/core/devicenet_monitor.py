"""
SAS Network Diagnostics Tool — DeviceNet Network Monitor Engine
Continuous monitoring of an entire DeviceNet network to catch intermittent issues.

Architecture:
  1. Initial discovery scan: find all online nodes (full 64 MAC ID sweep)
  2. Monitoring loop: poll only discovered nodes + scanner diagnostics each cycle
  3. Track per-node availability, response times, and bus-off counters over time
  4. Detect when nodes go offline/online and correlate with bus-off events

Why network-wide monitoring matters on DeviceNet:
  - One bad device can cause a bus-off that takes the whole network down
  - The device that CAUSES the bus-off might not be the one that FAULTS first
  - EMI, grounding issues, and trunk cable problems affect multiple nodes
  - You need to see which node dropped FIRST to find the root cause

Connection Methods:
  - Backplane: EtherNet/IP → PLC → 1756-DNB/1769-SDN → DeviceNet
  - U2DN: RSLinx → PCDC → 1784-U2DN → DeviceNet (not yet integrated)
"""

import csv
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Callable, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class NodePollResult:
    """Result of polling a single node in one cycle."""
    mac_id: int
    online: bool = False
    response_time_ms: float = 0.0
    device_status: int = 0
    status_text: str = ""
    error: str = ""


@dataclass
class NetworkPollCycle:
    """One complete polling cycle of the entire monitored network."""
    timestamp: datetime = field(default_factory=datetime.now)
    elapsed_seconds: float = 0.0
    cycle_number: int = 0
    cycle_duration_ms: float = 0.0

    # Scanner diagnostics (read each cycle)
    bus_off_count: int = 0
    bus_off_delta: int = 0          # Change since last cycle
    scanner_online: bool = True

    # Per-node results
    node_results: Dict[int, NodePollResult] = field(default_factory=dict)

    # Summary stats for this cycle
    nodes_monitored: int = 0
    nodes_online: int = 0
    nodes_offline: int = 0

    @property
    def any_offline(self) -> bool:
        return self.nodes_offline > 0

    @property
    def had_bus_off(self) -> bool:
        return self.bus_off_delta > 0


@dataclass
class NodeHistory:
    """Accumulated history for a single node across all poll cycles."""
    mac_id: int
    product_name: str = ""
    vendor_name: str = ""

    # Counters
    polls_total: int = 0
    polls_online: int = 0
    polls_offline: int = 0

    # Availability
    uptime_pct: float = 100.0

    # Response times (from successful polls)
    rt_min_ms: float = 0.0
    rt_max_ms: float = 0.0
    rt_avg_ms: float = 0.0
    _rt_sum: float = 0.0

    # State transitions
    went_offline_count: int = 0     # Number of times it went from online to offline
    went_online_count: int = 0      # Number of times it came back online
    last_seen_online: Optional[datetime] = None
    last_seen_offline: Optional[datetime] = None

    # Bus-off correlation
    offline_during_bus_off: int = 0  # Times it was offline when bus-off occurred
    first_offline_before_bus_off: int = 0  # Times it was the FIRST to go offline before bus-off

    def update_from_poll(self, result: NodePollResult, timestamp: datetime):
        """Update history from a new poll result."""
        self.polls_total += 1
        if result.online:
            self.polls_online += 1
            self.last_seen_online = timestamp

            # Response time tracking
            rt = result.response_time_ms
            if rt > 0:
                self._rt_sum += rt
                if self.rt_min_ms == 0 or rt < self.rt_min_ms:
                    self.rt_min_ms = rt
                if rt > self.rt_max_ms:
                    self.rt_max_ms = rt
                self.rt_avg_ms = self._rt_sum / self.polls_online
        else:
            self.polls_offline += 1
            self.last_seen_offline = timestamp

        # Update uptime
        if self.polls_total > 0:
            self.uptime_pct = round(self.polls_online / self.polls_total * 100, 2)


@dataclass
class NetworkEvent:
    """A significant event detected during monitoring."""
    timestamp: datetime
    event_type: str        # "node_offline", "node_online", "bus_off",
                           # "multi_dropout", "network_recovered"
    severity: str          # "info", "warning", "critical"
    description: str
    mac_ids: List[int] = field(default_factory=list)
    bus_off_count: int = 0


@dataclass
class DeviceNetMonitorStats:
    """Aggregate statistics from a monitoring session."""
    total_cycles: int = 0
    duration_seconds: float = 0.0
    monitored_nodes: int = 0

    # Network health
    network_uptime_pct: float = 100.0   # % of cycles where ALL monitored nodes were online
    cycles_all_online: int = 0
    cycles_with_dropouts: int = 0

    # Bus-off tracking
    bus_off_total: int = 0              # Total bus-off events detected
    bus_off_initial: int = 0            # Starting bus-off count
    bus_off_final: int = 0              # Ending bus-off count

    # Per-node summary
    node_histories: Dict[int, NodeHistory] = field(default_factory=dict)

    # Problem ranking
    most_problematic_nodes: List[Tuple[int, float]] = field(default_factory=list)

    # Events
    total_events: int = 0
    critical_events: int = 0


# ── DeviceNet Network Monitor ────────────────────────────────────────────────

class DeviceNetNetworkMonitor:
    """
    Continuously monitors an entire DeviceNet network through a scanner module.

    Usage:
        monitor = DeviceNetNetworkMonitor(
            plc_ip="192.168.1.10",
            scanner_slot=3,
        )
        monitor.start(interval_sec=5.0)
        # ... let it run ...
        stats = monitor.get_stats()
        monitor.stop()
    """

    def __init__(
        self,
        plc_ip: str,
        scanner_slot: int,
        poll_interval: float = 5.0,
        monitored_mac_ids: Optional[Set[int]] = None,
    ):
        self.plc_ip = plc_ip
        self.scanner_slot = scanner_slot
        self.poll_interval = max(2.0, poll_interval)
        self._user_mac_ids = monitored_mac_ids  # None = auto-discover

        # Data storage
        self.cycles: List[NetworkPollCycle] = []
        self.events: List[NetworkEvent] = []
        self.node_histories: Dict[int, NodeHistory] = {}
        self._lock = threading.Lock()

        # Discovered nodes from initial scan
        self._discovered_nodes: Dict[int, dict] = {}  # mac_id -> {name, vendor, ...}
        self._monitored_mac_ids: Set[int] = set()

        # State tracking
        self._last_node_states: Dict[int, bool] = {}  # mac_id -> was_online
        self._last_bus_off: int = 0
        self._initial_bus_off: int = 0
        self._cycle_count: int = 0

        # Control
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._start_time: Optional[datetime] = None
        self._scanner = None

        # Callbacks
        self._on_cycle: Optional[Callable[[NetworkPollCycle], None]] = None
        self._on_event: Optional[Callable[[NetworkEvent], None]] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def elapsed_seconds(self) -> float:
        if self._start_time:
            return (datetime.now() - self._start_time).total_seconds()
        return 0.0

    @property
    def discovered_node_count(self) -> int:
        return len(self._discovered_nodes)

    def set_on_cycle(self, callback: Callable[[NetworkPollCycle], None]):
        self._on_cycle = callback

    def set_on_event(self, callback: Callable[[NetworkEvent], None]):
        self._on_event = callback

    # ── Discovery ────────────────────────────────────────────────────────

    def discover_nodes(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Tuple[bool, str, Dict[int, dict]]:
        """
        Run initial discovery scan to find all online nodes.
        Returns (success, message, discovered_nodes_dict).
        """
        from core.devicenet_diag import DeviceNetBackplaneScanner

        scanner = DeviceNetBackplaneScanner(self.plc_ip, self.scanner_slot)
        ok, msg = scanner.connect()
        if not ok:
            return False, msg, {}

        try:
            result = scanner.scan_all_nodes(progress_callback)

            discovered = {}
            for node in result.nodes:
                if node.is_online:
                    discovered[node.mac_id] = {
                        "product_name": node.product_name,
                        "vendor_name": node.vendor_name,
                        "product_type_name": node.product_type_name,
                        "serial_number": node.serial_number,
                        "revision": f"{node.revision_major}.{node.revision_minor}",
                    }

            self._discovered_nodes = discovered

            # Set up monitoring targets
            if self._user_mac_ids:
                self._monitored_mac_ids = self._user_mac_ids
            else:
                self._monitored_mac_ids = set(discovered.keys())

            # Initialize node histories
            for mac_id in self._monitored_mac_ids:
                info = discovered.get(mac_id, {})
                self.node_histories[mac_id] = NodeHistory(
                    mac_id=mac_id,
                    product_name=info.get("product_name", f"Node {mac_id}"),
                    vendor_name=info.get("vendor_name", ""),
                )

            # Capture initial bus-off count
            if result.scanner_diag:
                self._last_bus_off = result.scanner_diag.bus_off_count
                self._initial_bus_off = result.scanner_diag.bus_off_count

            count = len(discovered)
            scanner_info = ""
            if result.scanner_diag:
                scanner_info = (
                    f" | Scanner: {result.scanner_diag.scanner_product_name} "
                    f"@ MAC {result.scanner_diag.scanner_mac_id}, "
                    f"Bus-off count: {result.scanner_diag.bus_off_count}"
                )

            msg = f"Found {count} online node(s){scanner_info}"
            return True, msg, discovered

        finally:
            scanner.disconnect()

    # ── Start / Stop ─────────────────────────────────────────────────────

    def start(self):
        """Start network monitoring in a background thread."""
        if self._running:
            return
        if not self._monitored_mac_ids:
            logger.warning("No nodes to monitor — run discover_nodes() first")
            return

        self._stop_event.clear()
        self._start_time = datetime.now()
        self._running = True
        self._cycle_count = 0

        # Initialize last-known states
        for mac_id in self._monitored_mac_ids:
            self._last_node_states[mac_id] = True  # Assume online from discovery

        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True,
            name=f"dnet-monitor-{self.plc_ip}")
        self._thread.start()
        logger.info(f"DeviceNet monitor started: {len(self._monitored_mac_ids)} nodes, "
                     f"interval={self.poll_interval}s")

    def stop(self):
        """Stop monitoring."""
        if not self._running:
            return
        self._stop_event.set()
        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)

        if self._scanner:
            try:
                self._scanner.disconnect()
            except Exception:
                pass
            self._scanner = None

        logger.info(f"DeviceNet monitor stopped: {self._cycle_count} cycles")

    def clear(self):
        """Clear all collected data."""
        with self._lock:
            self.cycles.clear()
            self.events.clear()
            self.node_histories.clear()
        self._cycle_count = 0
        self._start_time = None

    # ── Monitor Loop ─────────────────────────────────────────────────────

    def _monitor_loop(self):
        """Main monitoring loop."""
        from core.devicenet_diag import DeviceNetBackplaneScanner

        self._scanner = DeviceNetBackplaneScanner(self.plc_ip, self.scanner_slot)
        ok, msg = self._scanner.connect()
        if not ok:
            self._fire_event(NetworkEvent(
                timestamp=datetime.now(),
                event_type="connection_lost",
                severity="critical",
                description=f"Cannot connect to PLC: {msg}",
            ))
            self._running = False
            return

        while not self._stop_event.is_set():
            cycle_start = time.monotonic()
            cycle = self._do_poll_cycle()

            with self._lock:
                self.cycles.append(cycle)

            # Detect events from this cycle
            self._detect_events(cycle)

            # Fire cycle callback
            if self._on_cycle:
                try:
                    self._on_cycle(cycle)
                except Exception as e:
                    logger.debug(f"Cycle callback error: {e}")

            # Sleep for remainder of interval
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0, self.poll_interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)

        # Cleanup
        if self._scanner:
            self._scanner.disconnect()
            self._scanner = None

    def _do_poll_cycle(self) -> NetworkPollCycle:
        """Execute one poll cycle: read scanner diagnostics, then poll each node."""
        self._cycle_count += 1
        now = datetime.now()
        elapsed = (now - self._start_time).total_seconds() if self._start_time else 0
        cycle_start = time.monotonic()

        cycle = NetworkPollCycle(
            timestamp=now,
            elapsed_seconds=elapsed,
            cycle_number=self._cycle_count,
        )

        # Read scanner diagnostics (bus-off counter)
        try:
            diag = self._scanner.get_scanner_info()
            if diag:
                cycle.bus_off_count = diag.bus_off_count
                cycle.bus_off_delta = diag.bus_off_count - self._last_bus_off
                self._last_bus_off = diag.bus_off_count
                cycle.scanner_online = True
            else:
                cycle.scanner_online = False
        except Exception as e:
            logger.debug(f"Scanner diagnostics read failed: {e}")
            cycle.scanner_online = False

        # Poll each monitored node
        for mac_id in sorted(self._monitored_mac_ids):
            if self._stop_event.is_set():
                break

            node_result = NodePollResult(mac_id=mac_id)

            try:
                node = self._scanner.scan_node(mac_id)
                node_result.online = node.is_online
                node_result.response_time_ms = node.response_time_ms
                node_result.device_status = node.device_status
                node_result.status_text = node.status_text
                node_result.error = node.error_text
            except Exception as e:
                node_result.online = False
                node_result.error = str(e)

            cycle.node_results[mac_id] = node_result

            # Update node history
            if mac_id in self.node_histories:
                self.node_histories[mac_id].update_from_poll(node_result, now)

        # Cycle summary
        cycle.nodes_monitored = len(cycle.node_results)
        cycle.nodes_online = sum(1 for r in cycle.node_results.values() if r.online)
        cycle.nodes_offline = cycle.nodes_monitored - cycle.nodes_online
        cycle.cycle_duration_ms = (time.monotonic() - cycle_start) * 1000

        return cycle

    def _detect_events(self, cycle: NetworkPollCycle):
        """Detect significant events from a poll cycle."""
        now = cycle.timestamp

        # ── Bus-off event ──
        if cycle.had_bus_off:
            self._fire_event(NetworkEvent(
                timestamp=now,
                event_type="bus_off",
                severity="critical",
                description=(
                    f"Bus-off event detected! Counter increased by {cycle.bus_off_delta} "
                    f"(now {cycle.bus_off_count}). The CAN bus was reset."
                ),
                bus_off_count=cycle.bus_off_count,
            ))

        # ── Per-node state changes ──
        newly_offline = []
        newly_online = []

        for mac_id, result in cycle.node_results.items():
            was_online = self._last_node_states.get(mac_id, True)

            if was_online and not result.online:
                # Node went offline
                newly_offline.append(mac_id)
                if mac_id in self.node_histories:
                    self.node_histories[mac_id].went_offline_count += 1

                    # Correlate with bus-off
                    if cycle.had_bus_off:
                        self.node_histories[mac_id].offline_during_bus_off += 1

            elif not was_online and result.online:
                # Node came back online
                newly_online.append(mac_id)
                if mac_id in self.node_histories:
                    self.node_histories[mac_id].went_online_count += 1

            self._last_node_states[mac_id] = result.online

        # ── Multi-node dropout (simultaneous) ──
        if len(newly_offline) >= 3:
            node_names = [self._node_label(m) for m in newly_offline]
            self._fire_event(NetworkEvent(
                timestamp=now,
                event_type="multi_dropout",
                severity="critical",
                description=(
                    f"{len(newly_offline)} nodes went offline simultaneously: "
                    f"{', '.join(node_names)}. "
                    f"This indicates a network-wide event (not a single device failure)."
                ),
                mac_ids=newly_offline,
            ))
        elif len(newly_offline) == 2:
            node_names = [self._node_label(m) for m in newly_offline]
            self._fire_event(NetworkEvent(
                timestamp=now,
                event_type="multi_dropout",
                severity="warning",
                description=(
                    f"2 nodes went offline together: {', '.join(node_names)}. "
                    f"Possible trunk cable issue or shared power supply."
                ),
                mac_ids=newly_offline,
            ))
        elif len(newly_offline) == 1:
            mac_id = newly_offline[0]
            self._fire_event(NetworkEvent(
                timestamp=now,
                event_type="node_offline",
                severity="warning",
                description=(
                    f"{self._node_label(mac_id)} went offline"
                    + (f" — {cycle.node_results[mac_id].error}" if cycle.node_results[mac_id].error else "")
                ),
                mac_ids=[mac_id],
            ))

        # ── Node recovery ──
        if len(newly_online) > 0:
            names = [self._node_label(m) for m in newly_online]
            self._fire_event(NetworkEvent(
                timestamp=now,
                event_type="node_online",
                severity="info",
                description=(
                    f"{len(newly_online)} node(s) came back online: {', '.join(names)}"
                ),
                mac_ids=newly_online,
            ))

        # ── Full network recovery ──
        was_any_offline = any(not v for v in self._last_node_states.values())
        all_online_now = cycle.nodes_offline == 0
        if newly_online and all_online_now and len(self.cycles) > 1:
            prev = self.cycles[-2] if len(self.cycles) >= 2 else None
            if prev and prev.nodes_offline > 0:
                self._fire_event(NetworkEvent(
                    timestamp=now,
                    event_type="network_recovered",
                    severity="info",
                    description="All monitored nodes are back online.",
                ))

    def _fire_event(self, event: NetworkEvent):
        """Store event and fire callback."""
        with self._lock:
            self.events.append(event)
        if self._on_event:
            try:
                self._on_event(event)
            except Exception:
                pass

    def _node_label(self, mac_id: int) -> str:
        """Get a human-readable label for a node."""
        info = self._discovered_nodes.get(mac_id, {})
        name = info.get("product_name", "")
        if name:
            return f"MAC {mac_id} ({name})"
        return f"MAC {mac_id}"

    # ── Statistics ────────────────────────────────────────────────────────

    def get_stats(self) -> DeviceNetMonitorStats:
        """Calculate aggregate statistics."""
        with self._lock:
            cycles = list(self.cycles)
            events = list(self.events)

        stats = DeviceNetMonitorStats()
        if not cycles:
            return stats

        stats.total_cycles = len(cycles)
        stats.duration_seconds = (
            cycles[-1].timestamp - cycles[0].timestamp
        ).total_seconds() if len(cycles) > 1 else 0
        stats.monitored_nodes = len(self._monitored_mac_ids)

        # Network-level uptime
        stats.cycles_all_online = sum(1 for c in cycles if c.nodes_offline == 0)
        stats.cycles_with_dropouts = len(cycles) - stats.cycles_all_online
        stats.network_uptime_pct = round(
            stats.cycles_all_online / len(cycles) * 100, 2
        ) if cycles else 100.0

        # Bus-off tracking
        stats.bus_off_initial = self._initial_bus_off
        stats.bus_off_final = self._last_bus_off
        stats.bus_off_total = sum(c.bus_off_delta for c in cycles if c.bus_off_delta > 0)

        # Node histories
        stats.node_histories = dict(self.node_histories)

        # Problem ranking: sort nodes by offline count (most problematic first)
        node_problems = []
        for mac_id, hist in self.node_histories.items():
            if hist.polls_offline > 0:
                node_problems.append((mac_id, hist.uptime_pct))
        node_problems.sort(key=lambda x: x[1])  # Lowest uptime first
        stats.most_problematic_nodes = node_problems

        # Event counts
        stats.total_events = len(events)
        stats.critical_events = sum(1 for e in events if e.severity == "critical")

        return stats

    # ── Data Export ───────────────────────────────────────────────────────

    def export_csv(self, filepath: str) -> Tuple[bool, str]:
        """Export monitoring data to CSV (one row per node per cycle)."""
        with self._lock:
            cycles = list(self.cycles)

        if not cycles:
            return False, "No data to export"

        try:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                # Header
                writer.writerow([
                    "Timestamp", "Cycle", "Elapsed_Sec", "Cycle_Duration_ms",
                    "Bus_Off_Count", "Bus_Off_Delta", "Scanner_Online",
                    "MAC_ID", "Node_Name", "Online", "Response_Time_ms",
                    "Device_Status", "Status_Text", "Error",
                    "Nodes_Online_Total", "Nodes_Offline_Total",
                ])

                for cycle in cycles:
                    ts = cycle.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    for mac_id in sorted(cycle.node_results.keys()):
                        r = cycle.node_results[mac_id]
                        name = self._discovered_nodes.get(mac_id, {}).get(
                            "product_name", f"Node {mac_id}")
                        writer.writerow([
                            ts, cycle.cycle_number,
                            f"{cycle.elapsed_seconds:.1f}",
                            f"{cycle.cycle_duration_ms:.0f}",
                            cycle.bus_off_count, cycle.bus_off_delta,
                            int(cycle.scanner_online),
                            mac_id, name, int(r.online),
                            f"{r.response_time_ms:.1f}",
                            r.device_status, r.status_text, r.error,
                            cycle.nodes_online, cycle.nodes_offline,
                        ])

            row_count = sum(len(c.node_results) for c in cycles)
            return True, f"Exported {row_count} rows ({len(cycles)} cycles) to {filepath}"

        except Exception as e:
            return False, f"Export failed: {e}"

    def get_recent_cycles(self, count: int = 50) -> List[NetworkPollCycle]:
        """Get the most recent N cycles."""
        with self._lock:
            return list(self.cycles[-count:])

    def get_events_snapshot(self) -> List[NetworkEvent]:
        """Get all events."""
        with self._lock:
            return list(self.events)
