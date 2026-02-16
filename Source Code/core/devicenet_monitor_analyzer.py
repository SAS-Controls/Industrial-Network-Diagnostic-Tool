"""
SAS Network Diagnostics Tool — DeviceNet Monitor Analyzer
Analyzes network-wide DeviceNet monitoring data to identify root causes
of intermittent issues, bus-off events, and comm failures.

Key analysis types:
  - Bus-off root cause: which node dropped BEFORE the bus-off?
  - Multi-node dropout correlation: shared cause analysis
  - Per-node reliability ranking: who's the weakest link?
  - Timing patterns: periodic failures, time-of-day correlation
  - Network-wide vs single-node issue classification
  - Recovery pattern analysis
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class DeviceNetFinding:
    """A diagnostic finding with recommendation."""
    severity: str          # "info", "warning", "critical"
    title: str
    description: str
    likely_cause: str
    suggestion: str
    category: str = ""     # "bus_off", "node", "network", "pattern", "stability"
    metric_value: str = ""
    related_nodes: List[int] = field(default_factory=list)

    @property
    def icon(self) -> str:
        return {"info": "ℹ️", "warning": "⚠️", "critical": "🔴"}.get(
            self.severity, "ℹ️")


@dataclass
class DeviceNetAnalysisReport:
    """Complete analysis of a DeviceNet monitoring session."""
    target_info: str = ""           # "PLC 192.168.1.10, Slot 3"
    scanner_info: str = ""
    monitoring_duration: str = ""
    cycle_count: int = 0
    generated_at: str = ""

    # Summary
    health_score: int = 100
    health_label: str = "Healthy"
    summary: str = ""

    # Key metrics
    network_uptime_pct: float = 100.0
    bus_off_events: int = 0
    total_node_dropouts: int = 0
    most_problematic_node: str = ""
    monitored_nodes: int = 0

    # Per-node reliability table
    node_table: List[Dict] = field(default_factory=list)

    # Findings
    findings: List[DeviceNetFinding] = field(default_factory=list)


# ── Analyzer ─────────────────────────────────────────────────────────────────

class DeviceNetMonitorAnalyzer:
    """Analyzes DeviceNet monitoring data and produces actionable reports."""

    def analyze(self, cycles, events, stats, discovered_nodes,
                plc_ip: str, scanner_slot: int) -> DeviceNetAnalysisReport:
        """
        Run full analysis on DeviceNet monitoring data.

        Args:
            cycles: List of NetworkPollCycle
            events: List of NetworkEvent
            stats: DeviceNetMonitorStats
            discovered_nodes: Dict of mac_id -> node info
            plc_ip: PLC IP address
            scanner_slot: Scanner module slot
        """
        report = DeviceNetAnalysisReport(
            target_info=f"PLC {plc_ip}, Slot {scanner_slot}",
            cycle_count=stats.total_cycles,
            monitored_nodes=stats.monitored_nodes,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        if not cycles:
            report.summary = "No data collected. Run monitoring to gather diagnostic data."
            report.health_label = "No Data"
            report.health_score = 0
            return report

        report.monitoring_duration = self._format_duration(stats.duration_seconds)
        report.network_uptime_pct = stats.network_uptime_pct
        report.bus_off_events = stats.bus_off_total
        report.total_node_dropouts = sum(
            h.went_offline_count for h in stats.node_histories.values())

        # Most problematic node
        if stats.most_problematic_nodes:
            worst = stats.most_problematic_nodes[0]
            info = discovered_nodes.get(worst[0], {})
            name = info.get("product_name", f"MAC {worst[0]}")
            report.most_problematic_node = f"MAC {worst[0]} ({name}): {worst[1]:.1f}% uptime"

        # Build node reliability table
        report.node_table = self._build_node_table(stats, discovered_nodes)

        # ── Run all analysis checks ──
        findings = []

        findings.extend(self._check_bus_off_events(cycles, events, stats, discovered_nodes))
        findings.extend(self._check_bus_off_root_cause(cycles, stats, discovered_nodes))
        findings.extend(self._check_network_uptime(cycles, stats))
        findings.extend(self._check_problematic_nodes(stats, discovered_nodes))
        findings.extend(self._check_multi_dropout_patterns(events, discovered_nodes))
        findings.extend(self._check_dropout_correlation(cycles, stats, discovered_nodes))
        findings.extend(self._check_periodic_failures(cycles, stats, discovered_nodes))
        findings.extend(self._check_response_time_issues(stats, discovered_nodes))
        findings.extend(self._check_single_node_issues(stats, discovered_nodes))

        if not findings:
            findings.append(DeviceNetFinding(
                severity="info",
                title="Network Healthy",
                description=(
                    f"Over {report.monitoring_duration}, all {stats.monitored_nodes} "
                    f"monitored nodes maintained 100% uptime with no bus-off events."
                ),
                likely_cause="The DeviceNet network is stable and well-configured.",
                suggestion=(
                    "No action needed. Save this as a baseline for future comparison. "
                    "Consider running a longer monitoring session (4+ hours) to catch "
                    "issues that may correlate with shift changes or machine cycles."
                ),
                category="network",
            ))

        severity_order = {"critical": 0, "warning": 1, "info": 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 3))
        report.findings = findings

        report.health_score = self._calculate_health_score(stats, findings)
        report.health_label = self._health_label(report.health_score)
        report.summary = self._build_summary(report, stats, findings, discovered_nodes)

        return report

    # ── Node Table ───────────────────────────────────────────────────────

    def _build_node_table(self, stats, discovered_nodes) -> List[Dict]:
        """Build per-node reliability table for the report."""
        table = []
        for mac_id in sorted(stats.node_histories.keys()):
            hist = stats.node_histories[mac_id]
            info = discovered_nodes.get(mac_id, {})
            table.append({
                "mac_id": mac_id,
                "product_name": info.get("product_name", f"Node {mac_id}"),
                "vendor": info.get("vendor_name", ""),
                "uptime_pct": hist.uptime_pct,
                "dropouts": hist.went_offline_count,
                "avg_rt_ms": round(hist.rt_avg_ms, 1),
                "max_rt_ms": round(hist.rt_max_ms, 1),
                "bus_off_corr": hist.offline_during_bus_off,
            })
        # Sort by uptime (worst first)
        table.sort(key=lambda r: r["uptime_pct"])
        return table

    # ── Bus-Off Analysis ─────────────────────────────────────────────────

    def _check_bus_off_events(self, cycles, events, stats, discovered_nodes) -> List[DeviceNetFinding]:
        findings = []

        if stats.bus_off_total == 0:
            return []

        findings.append(DeviceNetFinding(
            severity="critical",
            title=f"{stats.bus_off_total} Bus-Off Event(s) Detected",
            description=(
                f"The scanner's bus-off counter increased {stats.bus_off_total} time(s) "
                f"during monitoring (from {stats.bus_off_initial} to {stats.bus_off_final}). "
                f"Each bus-off means the CAN controller detected excessive errors and "
                f"temporarily shut down, then restarted the network."
            ),
            likely_cause=(
                "Bus-off is CAN's built-in protection against a malfunctioning device "
                "flooding the bus with errors. Common causes:\n"
                "• A device with a failing CAN transceiver\n"
                "• Incorrect baud rate on one device\n"
                "• Severe EMI from a nearby VFD or motor\n"
                "• Trunk cable damage (short, open, shield break)\n"
                "• Missing or wrong-value termination resistors"
            ),
            suggestion=(
                "1. Check the 'Root Cause' finding below — it identifies which node "
                "most likely triggered the bus-off\n"
                "2. Verify termination: measure 60Ω between CAN_H and CAN_L (power off)\n"
                "3. Check baud rate on every device — they must ALL match\n"
                "4. Inspect trunk cable for damage, especially near motors/VFDs\n"
                "5. Check grounding: the DeviceNet shield should be grounded at ONE point only"
            ),
            category="bus_off",
            metric_value=f"{stats.bus_off_total} bus-off events",
        ))

        return findings

    def _check_bus_off_root_cause(self, cycles, stats, discovered_nodes) -> List[DeviceNetFinding]:
        """Identify which node is most likely causing bus-off events."""
        findings = []

        if stats.bus_off_total == 0:
            return []

        # Find cycles where bus-off occurred
        bus_off_cycles = [c for c in cycles if c.bus_off_delta > 0]
        if not bus_off_cycles:
            return []

        # For each bus-off, look at which nodes were offline in that cycle
        # and the cycle immediately before
        suspect_counts = Counter()

        for i, cycle in enumerate(cycles):
            if cycle.bus_off_delta <= 0:
                continue

            # Which nodes are offline in this cycle?
            offline_now = set(
                mac_id for mac_id, r in cycle.node_results.items() if not r.online)

            # Which nodes were offline in the previous cycle? (they went down BEFORE bus-off)
            if i > 0:
                prev = cycles[i - 1]
                offline_prev = set(
                    mac_id for mac_id, r in prev.node_results.items() if not r.online)

                # Nodes that went offline before or at the bus-off are prime suspects
                newly_offline = offline_now - offline_prev
                for mac_id in newly_offline:
                    suspect_counts[mac_id] += 2  # Strong correlation

            # All offline nodes during bus-off get a weaker count
            for mac_id in offline_now:
                suspect_counts[mac_id] += 1

        if not suspect_counts:
            return []

        # Also consider nodes with high offline_during_bus_off correlation
        for mac_id, hist in stats.node_histories.items():
            if hist.offline_during_bus_off > 0:
                suspect_counts[mac_id] += hist.offline_during_bus_off

        # Rank suspects
        ranked = suspect_counts.most_common()
        if not ranked:
            return []

        top_suspect = ranked[0]
        mac_id = top_suspect[0]
        info = discovered_nodes.get(mac_id, {})
        name = info.get("product_name", f"Node {mac_id}")
        vendor = info.get("vendor_name", "")

        suspect_list = []
        for mac_id_s, score in ranked[:5]:
            info_s = discovered_nodes.get(mac_id_s, {})
            name_s = info_s.get("product_name", f"Node {mac_id_s}")
            suspect_list.append(f"  MAC {mac_id_s} — {name_s} (correlation score: {score})")

        findings.append(DeviceNetFinding(
            severity="critical",
            title=f"Likely Bus-Off Cause: MAC {mac_id} ({name})",
            description=(
                f"Analysis of {stats.bus_off_total} bus-off event(s) shows that "
                f"MAC {mac_id} ({name}{' — ' + vendor if vendor else ''}) "
                f"is the most likely cause. This node was offline or went offline "
                f"immediately before/during bus-off events more than any other.\n\n"
                f"Suspect ranking:\n" + "\n".join(suspect_list)
            ),
            likely_cause=(
                f"MAC {mac_id} may have:\n"
                f"• A failing CAN transceiver that's transmitting garbage\n"
                f"• An incorrect baud rate (mismatch with the rest of the network)\n"
                f"• A bad tap cable or loose connection causing noise on the bus\n"
                f"• A firmware issue causing erratic CAN behavior"
            ),
            suggestion=(
                f"1. Inspect MAC {mac_id}'s tap cable and DeviceNet connector — look for damage\n"
                f"2. Verify its baud rate matches the network (check DIP switches or config)\n"
                f"3. If possible, temporarily remove MAC {mac_id} from the network and "
                f"see if bus-off events stop\n"
                f"4. Replace the tap cable to MAC {mac_id}\n"
                f"5. If the problem persists without MAC {mac_id}, move to the next suspect in the ranking"
            ),
            category="bus_off",
            metric_value=f"MAC {mac_id}",
            related_nodes=[mac_id],
        ))

        return findings

    # ── Network Uptime ───────────────────────────────────────────────────

    def _check_network_uptime(self, cycles, stats) -> List[DeviceNetFinding]:
        findings = []

        if stats.network_uptime_pct >= 99.5:
            return []

        if stats.network_uptime_pct < 80:
            findings.append(DeviceNetFinding(
                severity="critical",
                title="Severe Network Instability",
                description=(
                    f"Only {stats.network_uptime_pct:.1f}% of poll cycles had all nodes online. "
                    f"{stats.cycles_with_dropouts} out of {stats.total_cycles} cycles "
                    f"had at least one node offline."
                ),
                likely_cause=(
                    "A network this unstable typically has a fundamental infrastructure "
                    "problem: trunk cable damage, incorrect termination, power supply "
                    "issues, or a major EMI source nearby."
                ),
                suggestion=(
                    "1. Check termination: 121Ω resistor at EACH END of the trunk cable only\n"
                    "2. Measure trunk cable: CAN_H to CAN_L should be ~60Ω (power off)\n"
                    "3. Check 24VDC power supply for the DeviceNet network — is it adequate?\n"
                    "4. Look at the node reliability table — are ALL nodes affected or just some?\n"
                    "5. If all nodes are affected, the problem is trunk cable, power, or termination"
                ),
                category="network",
                metric_value=f"{stats.network_uptime_pct:.1f}% network uptime",
            ))

        elif stats.network_uptime_pct < 95:
            findings.append(DeviceNetFinding(
                severity="warning",
                title="Intermittent Network Issues",
                description=(
                    f"Network uptime was {stats.network_uptime_pct:.1f}%. "
                    f"{stats.cycles_with_dropouts} poll cycles had node dropout(s)."
                ),
                likely_cause=(
                    "Intermittent issues at this level often point to: marginal cable "
                    "connections, EMI from nearby equipment, or one problematic device "
                    "affecting the whole bus."
                ),
                suggestion=(
                    "1. Review the node reliability table — which node(s) have the most dropouts?\n"
                    "2. If one node is much worse than others, focus on that node's tap cable\n"
                    "3. If multiple nodes drop together, look at trunk cable and power\n"
                    "4. Check the timing analysis — do drops correlate with machine operations?"
                ),
                category="network",
                metric_value=f"{stats.network_uptime_pct:.1f}% uptime",
            ))

        return findings

    # ── Problematic Nodes ────────────────────────────────────────────────

    def _check_problematic_nodes(self, stats, discovered_nodes) -> List[DeviceNetFinding]:
        findings = []

        if not stats.most_problematic_nodes:
            return []

        # Find nodes with significantly worse uptime than the network average
        avg_uptime = sum(h.uptime_pct for h in stats.node_histories.values()) / max(
            len(stats.node_histories), 1)

        for mac_id, uptime in stats.most_problematic_nodes[:3]:
            if uptime >= 99:
                continue

            info = discovered_nodes.get(mac_id, {})
            name = info.get("product_name", f"Node {mac_id}")
            hist = stats.node_histories.get(mac_id)
            if not hist:
                continue

            is_outlier = (avg_uptime - uptime) > 10  # Much worse than average

            if uptime < 80:
                severity = "critical"
            elif uptime < 95:
                severity = "warning"
            else:
                severity = "info" if not is_outlier else "warning"

            desc = (
                f"MAC {mac_id} ({name}) has {uptime:.1f}% uptime — "
                f"it went offline {hist.went_offline_count} time(s) during monitoring."
            )

            if is_outlier:
                desc += (
                    f"\nThis is significantly worse than the network average ({avg_uptime:.1f}%), "
                    f"suggesting the problem is with THIS device specifically, "
                    f"not a network-wide issue."
                )

            cause = (
                f"When a single node is much less reliable than others, the problem "
                f"is usually local to that node:\n"
                f"• Bad tap cable connection (most common)\n"
                f"• Device power supply issue\n"
                f"• Failing DeviceNet port on the device\n"
                f"• Loose or corroded connector"
            )

            suggestion = (
                f"1. Inspect MAC {mac_id}'s tap cable connector — clean and reseat it\n"
                f"2. Check the device's power supply (measure at the DeviceNet connector)\n"
                f"3. Measure the tap cable: CAN_H to CAN_L continuity\n"
                f"4. Try a new tap cable to rule out cable issues\n"
                f"5. Check the device's Module Status LED during a dropout"
            )

            findings.append(DeviceNetFinding(
                severity=severity,
                title=f"Unreliable Node: MAC {mac_id} ({name})",
                description=desc,
                likely_cause=cause,
                suggestion=suggestion,
                category="node",
                metric_value=f"{uptime:.1f}% uptime",
                related_nodes=[mac_id],
            ))

        return findings

    # ── Multi-Dropout Patterns ───────────────────────────────────────────

    def _check_multi_dropout_patterns(self, events, discovered_nodes) -> List[DeviceNetFinding]:
        findings = []

        multi_events = [e for e in events if e.event_type == "multi_dropout"]
        if not multi_events:
            return []

        # Check if the same set of nodes always drops together
        dropout_sets = []
        for e in multi_events:
            dropout_sets.append(frozenset(e.mac_ids))

        set_counts = Counter(dropout_sets)
        most_common = set_counts.most_common(1)[0]

        if most_common[1] >= 2:
            nodes = sorted(most_common[0])
            names = [
                f"MAC {m} ({discovered_nodes.get(m, {}).get('product_name', '?')})"
                for m in nodes
            ]

            findings.append(DeviceNetFinding(
                severity="warning",
                title="Same Nodes Always Drop Together",
                description=(
                    f"The following nodes dropped together {most_common[1]} time(s):\n"
                    + "\n".join(f"  {n}" for n in names) +
                    f"\n\nThis consistent grouping suggests a shared physical cause."
                ),
                likely_cause=(
                    "Nodes that always drop together typically share:\n"
                    "• The same section of trunk cable\n"
                    "• The same power supply tap\n"
                    "• The same cable tray or conduit (common EMI exposure)\n"
                    "• The same network segment (if there's a repeater/gateway)"
                ),
                suggestion=(
                    "1. Trace the cable path — are these nodes on the same trunk segment?\n"
                    "2. Check if they share a power distribution tap\n"
                    "3. Look for a common EMI source along their cable path\n"
                    "4. If they're after a junction or repeater, check that connection point"
                ),
                category="pattern",
                metric_value=f"{most_common[1]} simultaneous dropouts",
                related_nodes=list(most_common[0]),
            ))

        return findings

    # ── Dropout Correlation ──────────────────────────────────────────────

    def _check_dropout_correlation(self, cycles, stats, discovered_nodes) -> List[DeviceNetFinding]:
        """Check which nodes tend to go offline together (even if not simultaneously)."""
        findings = []

        if stats.total_cycles < 10:
            return []

        # Build offline-per-cycle matrix
        mac_ids = sorted(stats.node_histories.keys())
        if len(mac_ids) < 2:
            return []

        # Count how often pairs of nodes are offline in the same cycle
        pair_counts = Counter()
        for cycle in cycles:
            offline_in_cycle = [
                m for m, r in cycle.node_results.items() if not r.online]
            if len(offline_in_cycle) >= 2:
                for i in range(len(offline_in_cycle)):
                    for j in range(i + 1, len(offline_in_cycle)):
                        pair = (min(offline_in_cycle[i], offline_in_cycle[j]),
                                max(offline_in_cycle[i], offline_in_cycle[j]))
                        pair_counts[pair] += 1

        if not pair_counts:
            return []

        # Find highly correlated pairs
        top_pairs = pair_counts.most_common(3)
        for pair, count in top_pairs:
            if count < 3:
                continue

            m1, m2 = pair
            n1 = discovered_nodes.get(m1, {}).get("product_name", f"Node {m1}")
            n2 = discovered_nodes.get(m2, {}).get("product_name", f"Node {m2}")

            # What fraction of their failures are shared?
            h1 = stats.node_histories.get(m1)
            h2 = stats.node_histories.get(m2)
            if not h1 or not h2:
                continue

            shared_pct = count / max(min(h1.polls_offline, h2.polls_offline), 1) * 100

            if shared_pct > 50:
                findings.append(DeviceNetFinding(
                    severity="warning",
                    title=f"MAC {m1} and MAC {m2} Fail Together Often",
                    description=(
                        f"MAC {m1} ({n1}) and MAC {m2} ({n2}) were both offline "
                        f"in the same cycle {count} times ({shared_pct:.0f}% of their failures). "
                        f"Their failures are highly correlated."
                    ),
                    likely_cause=(
                        "Correlated failures between specific nodes usually means they "
                        "share a physical infrastructure element — cable segment, power tap, "
                        "or they're near the same noise source."
                    ),
                    suggestion=(
                        f"1. Check if MAC {m1} and MAC {m2} are on the same trunk cable segment\n"
                        f"2. Check if they share a DeviceNet power supply tap\n"
                        f"3. Look for a common noise source between them\n"
                        f"4. Inspect the connectors and cable between these two nodes"
                    ),
                    category="pattern",
                    related_nodes=[m1, m2],
                ))
                break  # One finding is enough

        return findings

    # ── Periodic Failure Detection ───────────────────────────────────────

    def _check_periodic_failures(self, cycles, stats, discovered_nodes) -> List[DeviceNetFinding]:
        """Check for failures happening at regular intervals."""
        findings = []

        if stats.total_cycles < 10:
            return []

        # Find cycles where any node dropped
        dropout_times = [
            c.elapsed_seconds for c in cycles if c.nodes_offline > 0]

        if len(dropout_times) < 3:
            return []

        # Calculate intervals between dropout events
        intervals = []
        for i in range(1, len(dropout_times)):
            gap = dropout_times[i] - dropout_times[i - 1]
            if gap > stats.duration_seconds / stats.total_cycles * 2:
                intervals.append(gap)

        if len(intervals) < 2:
            return []

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval <= 0:
            return []

        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / avg_interval

        if cv < 0.35 and len(intervals) >= 3:
            period = self._format_duration(avg_interval)
            findings.append(DeviceNetFinding(
                severity="warning",
                title=f"Network Issues Occurring Every ~{period}",
                description=(
                    f"Node dropouts are happening at roughly regular intervals of ~{period}. "
                    f"This periodic pattern was seen across {len(intervals) + 1} events."
                ),
                likely_cause=(
                    f"Periodic failures every ~{period} suggest a recurring external cause:\n"
                    "• A machine or motor cycling on/off at that interval (EMI burst)\n"
                    "• A compressor, heater, or solenoid operating on a timer\n"
                    "• A PLC program executing a periodic task that loads the scanner\n"
                    "• Scheduled network activity (polling cycle, backup)"
                ),
                suggestion=(
                    f"1. Ask operators: 'What runs on a ~{period} cycle near this network?'\n"
                    "2. Check for VFDs, compressors, or heaters near the DeviceNet cable\n"
                    "3. Look at the PLC program for periodic tasks matching this interval\n"
                    "4. If EMI: check cable routing and shielding — separate from power cables"
                ),
                category="pattern",
                metric_value=f"~{period} cycle",
            ))

        return findings

    # ── Response Time Issues ─────────────────────────────────────────────

    def _check_response_time_issues(self, stats, discovered_nodes) -> List[DeviceNetFinding]:
        findings = []

        slow_nodes = []
        for mac_id, hist in stats.node_histories.items():
            if hist.rt_avg_ms > 2000 and hist.polls_online > 0:  # >2 sec is very slow for DN
                slow_nodes.append((mac_id, hist.rt_avg_ms))

        if slow_nodes:
            slow_nodes.sort(key=lambda x: x[1], reverse=True)
            node_list = []
            for mac_id, avg_rt in slow_nodes[:5]:
                name = discovered_nodes.get(mac_id, {}).get("product_name", f"Node {mac_id}")
                node_list.append(f"  MAC {mac_id} ({name}): {avg_rt:.0f}ms avg")

            findings.append(DeviceNetFinding(
                severity="warning",
                title="Slow-Responding Nodes Detected",
                description=(
                    f"{len(slow_nodes)} node(s) are responding slowly:\n"
                    + "\n".join(node_list)
                ),
                likely_cause=(
                    "Slow CIP responses on DeviceNet often indicate the device is "
                    "heavily loaded, its explicit message server is busy, or there's "
                    "CAN bus congestion reducing throughput."
                ),
                suggestion=(
                    "1. This may be normal for some devices under heavy I/O load\n"
                    "2. Check if the baud rate is appropriate for the number of nodes\n"
                    "3. Verify the scanner's scanlist isn't overloaded\n"
                    "4. Slow response alone isn't necessarily a problem — focus on dropouts"
                ),
                category="stability",
            ))

        return findings

    # ── Single Node Issues ───────────────────────────────────────────────

    def _check_single_node_issues(self, stats, discovered_nodes) -> List[DeviceNetFinding]:
        """Check if only one node has issues while the rest are fine."""
        findings = []

        problem_nodes = [
            (m, h) for m, h in stats.node_histories.items()
            if h.uptime_pct < 99
        ]
        healthy_nodes = [
            (m, h) for m, h in stats.node_histories.items()
            if h.uptime_pct >= 99
        ]

        if len(problem_nodes) == 1 and len(healthy_nodes) >= 2:
            mac_id = problem_nodes[0][0]
            hist = problem_nodes[0][1]
            info = discovered_nodes.get(mac_id, {})
            name = info.get("product_name", f"Node {mac_id}")

            findings.append(DeviceNetFinding(
                severity="warning",
                title=f"Only MAC {mac_id} Has Issues — All Other Nodes Are Fine",
                description=(
                    f"MAC {mac_id} ({name}) is the ONLY node experiencing problems "
                    f"({hist.uptime_pct:.1f}% uptime, {hist.went_offline_count} dropouts). "
                    f"All other {len(healthy_nodes)} monitored nodes are at 99%+ uptime."
                ),
                likely_cause=(
                    "When only one node is problematic while the rest of the network is "
                    "healthy, the issue is almost certainly local to that device:\n"
                    "• Bad tap cable or connector (most likely)\n"
                    "• The device itself is failing\n"
                    "• A localized EMI source near that device\n"
                    "• Power issue at that device's location"
                ),
                suggestion=(
                    f"1. This is your smoking gun — focus ALL troubleshooting on MAC {mac_id}\n"
                    f"2. Replace the tap cable to MAC {mac_id}\n"
                    f"3. Clean and reseat the DeviceNet connector on the device\n"
                    f"4. Check for loose wiring at the device's DeviceNet terminal\n"
                    f"5. If the tap cable is good, the device port itself may be failing"
                ),
                category="node",
                metric_value=f"MAC {mac_id} only",
                related_nodes=[mac_id],
            ))

        return findings

    # ── Scoring & Summary ────────────────────────────────────────────────

    def _calculate_health_score(self, stats, findings) -> int:
        score = 100

        # Deduct for network uptime
        if stats.network_uptime_pct < 100:
            score -= min(30, int((100 - stats.network_uptime_pct) * 1.5))

        # Deduct for bus-off events
        score -= min(30, stats.bus_off_total * 15)

        # Deduct for findings
        critical = sum(1 for f in findings if f.severity == "critical")
        warning = sum(1 for f in findings if f.severity == "warning")
        score -= critical * 10
        score -= warning * 3

        return max(0, min(100, score))

    def _health_label(self, score: int) -> str:
        if score >= 90:
            return "Healthy"
        elif score >= 70:
            return "Degraded"
        elif score >= 40:
            return "Unstable"
        else:
            return "Critical"

    def _build_summary(self, report, stats, findings, discovered_nodes) -> str:
        critical = [f for f in findings if f.severity == "critical"]
        warnings = [f for f in findings if f.severity == "warning"]

        parts = [
            f"Monitored {stats.monitored_nodes} DeviceNet nodes for "
            f"{report.monitoring_duration}."
        ]

        if stats.bus_off_total > 0:
            parts.append(f"{stats.bus_off_total} bus-off event(s) detected.")

        if stats.network_uptime_pct < 100:
            parts.append(
                f"Network-wide uptime was {stats.network_uptime_pct:.1f}%.")

        if critical:
            parts.append(
                f"Found {len(critical)} critical issue(s): "
                + "; ".join(f.title for f in critical[:2]) + ".")
        elif warnings:
            parts.append(
                f"Found {len(warnings)} issue(s): "
                + "; ".join(f.title for f in warnings[:2]) + ".")
        elif not critical and not warnings:
            parts.append("No issues detected — network is healthy.")

        return " ".join(parts)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds <= 0:
            return "0s"
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s" if secs else f"{mins}m"
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m" if mins else f"{hours}h"
