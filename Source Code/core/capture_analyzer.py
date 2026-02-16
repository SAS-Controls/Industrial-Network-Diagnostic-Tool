"""
SAS Network Diagnostics Tool — Capture Traffic Analyzer
Analyzes packets captured by capture_engine.py and produces plain-English findings,
protocol breakdowns, top talker lists, and timeline events.

This is the "intelligence" layer — it turns raw packet data into actionable
diagnostics that maintenance techs and automation engineers can understand
without being Wireshark experts.
"""

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set

from core.capture_engine import CapturedPacket, CaptureResult

logger = logging.getLogger(__name__)


# ── Analysis Results ─────────────────────────────────────────────────────────

class Severity:
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class CaptureFinding:
    """A single diagnostic finding from traffic analysis."""
    title: str
    severity: str                    # Severity constant
    summary: str
    explanation: str
    recommendation: str
    raw_value: str = ""
    category: str = ""


@dataclass
class TimelineEvent:
    """A notable event during the capture period."""
    timestamp: float                 # Seconds from capture start
    event_type: str                  # "broadcast_burst", "arp_conflict", "retransmission", etc.
    severity: str
    description: str
    details: str = ""


@dataclass
class TrafficFlow:
    """A conversation between two endpoints."""
    src_ip: str
    dst_ip: str
    packet_count: int = 0
    total_bytes: int = 0
    protocols: Set[str] = field(default_factory=set)


@dataclass
class CaptureAnalysis:
    """Complete analysis results from a packet capture."""
    # Summary
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    unique_hosts: int = 0

    # Findings (same card format as device diagnostics)
    findings: List[CaptureFinding] = field(default_factory=list)

    # Protocol breakdown: {protocol_name: packet_count}
    protocol_breakdown: Dict[str, int] = field(default_factory=dict)

    # Top talkers: [(ip, total_bytes)]
    top_talkers_by_bytes: List[Tuple[str, int]] = field(default_factory=list)
    top_talkers_by_packets: List[Tuple[str, int]] = field(default_factory=list)

    # Traffic type breakdown
    unicast_count: int = 0
    broadcast_count: int = 0
    multicast_count: int = 0
    broadcast_pct: float = 0.0
    multicast_pct: float = 0.0

    # ARP stats
    arp_requests: int = 0
    arp_replies: int = 0
    gratuitous_arps: int = 0
    arp_conflicts: List[Dict] = field(default_factory=list)

    # TCP stats
    tcp_packets: int = 0
    tcp_retransmissions: int = 0
    tcp_retransmission_pct: float = 0.0

    # Timeline events
    timeline: List[TimelineEvent] = field(default_factory=list)

    # Health score (0-100)
    health_score: int = 100


# ── Analysis Engine ──────────────────────────────────────────────────────────

def analyze_capture(capture: CaptureResult) -> CaptureAnalysis:
    """
    Analyze captured packets and produce a comprehensive traffic analysis.

    Args:
        capture: CaptureResult from CaptureEngine

    Returns:
        CaptureAnalysis with findings, charts data, and timeline events
    """
    analysis = CaptureAnalysis(
        total_packets=capture.packet_count,
        total_bytes=capture.total_bytes,
        duration_seconds=capture.duration_seconds,
    )

    if capture.packet_count == 0:
        analysis.findings.append(CaptureFinding(
            title="No Packets Captured",
            severity=Severity.WARNING,
            summary="The capture completed but no packets were recorded.",
            explanation="This could mean the selected interface has no traffic, "
                        "or the capture filter excluded all packets. It may also "
                        "indicate a permissions issue with Npcap.",
            recommendation="1. Verify you selected the correct network interface.\n"
                           "2. Try running the capture without any filter.\n"
                           "3. Make sure Npcap is installed with 'WinPcap API-compatible' mode.\n"
                           "4. Try running the application as Administrator.",
            category="Capture",
        ))
        return analysis

    analysis.packets_per_second = capture.packets_per_second
    packets = capture.packets

    # Calculate time base (normalize timestamps to seconds from start)
    if packets:
        t0 = packets[0].timestamp
        for p in packets:
            p.timestamp = p.timestamp - t0

    score = 100

    # ── Collect statistics ────────────────────────────────────────────────
    protocol_counter = Counter()
    host_bytes_sent = Counter()       # ip -> bytes sent
    host_bytes_recv = Counter()       # ip -> bytes received
    host_packets_sent = Counter()     # ip -> packets sent
    host_packets_recv = Counter()     # ip -> packets received
    mac_to_ips = defaultdict(set)     # mac -> set of IPs (for conflict detection)
    ip_to_macs = defaultdict(set)     # ip -> set of MACs (for duplicate IP)
    all_ips = set()
    all_macs = set()

    broadcast_count = 0
    multicast_count = 0
    unicast_count = 0
    arp_requests = 0
    arp_replies = 0
    gratuitous_arps = 0
    tcp_total = 0
    tcp_retransmissions = 0
    stp_count = 0
    stp_topology_changes = 0

    # Time-window tracking for burst detection
    BURST_WINDOW = 1.0  # 1-second windows
    broadcast_per_second = Counter()  # int(timestamp) -> count
    arp_per_second = Counter()

    for pkt in packets:
        # Protocol
        proto = pkt.protocol_name or "Unknown"
        protocol_counter[proto] += 1

        # Traffic type classification
        if pkt.is_broadcast:
            broadcast_count += 1
            broadcast_per_second[int(pkt.timestamp)] += 1
        elif pkt.is_multicast:
            multicast_count += 1
        else:
            unicast_count += 1

        # Host tracking
        if pkt.ip_src:
            host_bytes_sent[pkt.ip_src] += pkt.frame_len
            host_packets_sent[pkt.ip_src] += 1
            all_ips.add(pkt.ip_src)
        if pkt.ip_dst:
            host_bytes_recv[pkt.ip_dst] += pkt.frame_len
            host_packets_recv[pkt.ip_dst] += 1
            all_ips.add(pkt.ip_dst)

        if pkt.eth_src:
            all_macs.add(pkt.eth_src.lower())
        if pkt.eth_dst:
            all_macs.add(pkt.eth_dst.lower())

        # MAC-to-IP mapping (from regular IP traffic)
        if pkt.ip_src and pkt.eth_src:
            mac_lower = pkt.eth_src.lower()
            if mac_lower != "ff:ff:ff:ff:ff:ff":
                mac_to_ips[mac_lower].add(pkt.ip_src)
                ip_to_macs[pkt.ip_src].add(mac_lower)

        # ARP analysis
        if pkt.is_arp:
            arp_per_second[int(pkt.timestamp)] += 1
            if pkt.arp_opcode == 1:
                arp_requests += 1
                # Gratuitous ARP: sender asks for its own IP
                if pkt.arp_src_ip == pkt.arp_dst_ip:
                    gratuitous_arps += 1
            elif pkt.arp_opcode == 2:
                arp_replies += 1

            # Track ARP sender MAC-to-IP for conflict detection
            if pkt.arp_src_hw and pkt.arp_src_ip:
                mac_lower = pkt.arp_src_hw.lower()
                mac_to_ips[mac_lower].add(pkt.arp_src_ip)
                ip_to_macs[pkt.arp_src_ip].add(mac_lower)

        # TCP analysis
        if pkt.ip_proto == 6:  # TCP
            tcp_total += 1
            if pkt.tcp_retransmission:
                tcp_retransmissions += 1

        # STP detection
        if pkt.is_stp:
            stp_count += 1
            # Check for topology change notifications in info
            info_lower = (pkt.info or "").lower()
            if "topology" in info_lower or "tcn" in info_lower:
                stp_topology_changes += 1
                analysis.timeline.append(TimelineEvent(
                    timestamp=pkt.timestamp,
                    event_type="stp_topology_change",
                    severity=Severity.WARNING,
                    description="Spanning Tree topology change detected",
                    details=pkt.info,
                ))

    # ── Store aggregated stats ────────────────────────────────────────────
    analysis.protocol_breakdown = dict(protocol_counter.most_common(20))
    analysis.unique_hosts = len(all_ips)
    analysis.unicast_count = unicast_count
    analysis.broadcast_count = broadcast_count
    analysis.multicast_count = multicast_count
    analysis.broadcast_pct = (broadcast_count / len(packets) * 100) if packets else 0
    analysis.multicast_pct = (multicast_count / len(packets) * 100) if packets else 0
    analysis.arp_requests = arp_requests
    analysis.arp_replies = arp_replies
    analysis.gratuitous_arps = gratuitous_arps
    analysis.tcp_packets = tcp_total
    analysis.tcp_retransmissions = tcp_retransmissions
    analysis.tcp_retransmission_pct = (
        (tcp_retransmissions / tcp_total * 100) if tcp_total > 0 else 0
    )

    # Top talkers — combine sent+received
    host_total_bytes = Counter()
    host_total_packets = Counter()
    for ip in all_ips:
        host_total_bytes[ip] = host_bytes_sent[ip] + host_bytes_recv[ip]
        host_total_packets[ip] = host_packets_sent[ip] + host_packets_recv[ip]

    analysis.top_talkers_by_bytes = host_total_bytes.most_common(15)
    analysis.top_talkers_by_packets = host_total_packets.most_common(15)

    # ── Generate Findings ─────────────────────────────────────────────────

    # 1. Capture Summary (always first)
    analysis.findings.append(CaptureFinding(
        title="Capture Summary",
        severity=Severity.INFO,
        summary=f"Captured {analysis.total_packets:,} packets "
                f"({_format_bytes(analysis.total_bytes)}) over "
                f"{analysis.duration_seconds:.0f} seconds. "
                f"{analysis.unique_hosts} unique IP addresses seen.",
        explanation=f"Average traffic rate: {analysis.packets_per_second:.0f} packets/sec. "
                    f"Traffic breakdown: {unicast_count:,} unicast, "
                    f"{broadcast_count:,} broadcast, {multicast_count:,} multicast.",
        recommendation="Review the findings below for any detected issues.",
        raw_value=f"Packets: {analysis.total_packets}, Bytes: {analysis.total_bytes}, "
                  f"Duration: {analysis.duration_seconds:.1f}s",
        category="Summary",
    ))

    # 2. Broadcast Storm Detection
    score = _analyze_broadcasts(analysis, packets, broadcast_count,
                                broadcast_per_second, score)

    # 3. Duplicate IP / ARP Conflict Detection
    score = _analyze_arp_conflicts(analysis, ip_to_macs, mac_to_ips, score)

    # 4. Excessive ARP Traffic
    score = _analyze_arp_volume(analysis, arp_requests, arp_replies,
                                gratuitous_arps, arp_per_second, len(packets), score)

    # 5. TCP Retransmission Analysis
    score = _analyze_tcp_retransmissions(analysis, tcp_total, tcp_retransmissions,
                                         packets, score)

    # 6. Multicast Traffic Analysis
    score = _analyze_multicast(analysis, multicast_count, len(packets), score)

    # 7. STP / Spanning Tree Detection
    score = _analyze_stp(analysis, stp_count, stp_topology_changes, score)

    # 8. Top Talker / Bandwidth Hog Detection
    _analyze_top_talkers(analysis, host_total_bytes, analysis.total_bytes)

    # 9. Protocol Distribution Summary
    _analyze_protocols(analysis, protocol_counter, len(packets))

    # 10. Network Health Summary
    analysis.health_score = max(0, min(100, score))
    _add_health_summary(analysis)

    return analysis


# ── Finding Generators ───────────────────────────────────────────────────────

def _analyze_broadcasts(analysis: CaptureAnalysis, packets: List[CapturedPacket],
                        broadcast_count: int,
                        broadcast_per_second: Counter,
                        score: int) -> int:
    """Detect broadcast storms and excessive broadcast traffic."""
    if not packets:
        return score

    total = len(packets)
    bcast_pct = (broadcast_count / total * 100) if total > 0 else 0

    # Check for broadcast bursts (>100 broadcasts in a single second)
    peak_bcast = max(broadcast_per_second.values()) if broadcast_per_second else 0
    burst_seconds = [t for t, c in broadcast_per_second.items() if c > 50]

    if peak_bcast > 200:
        score -= 30
        analysis.findings.append(CaptureFinding(
            title="🔴 Broadcast Storm Detected",
            severity=Severity.CRITICAL,
            summary=f"Peak broadcast rate: {peak_bcast} packets/sec — "
                    f"this is a broadcast storm that will severely impact all devices.",
            explanation="A broadcast storm occurs when broadcast traffic floods the network "
                        "to the point where it consumes most of the available bandwidth. "
                        "Every device on the network must process every broadcast packet, "
                        "which steals CPU time from normal operations.\n\n"
                        "Common causes:\n"
                        "• Network loop — a cable accidentally connects two switch ports "
                        "creating a circular path\n"
                        "• A malfunctioning device flooding the network\n"
                        "• A switch with Spanning Tree Protocol (STP) disabled\n"
                        "• Excessive ARP requests from a misconfigured device",
            recommendation="1. CHECK FOR NETWORK LOOPS FIRST — unplug cables one at a time "
                           "to see if the storm stops.\n"
                           "2. Enable Spanning Tree Protocol (STP) on all managed switches.\n"
                           "3. Enable broadcast storm control on the switch (rate-limits broadcasts).\n"
                           "4. Use the Top Talkers data to identify which device is flooding.\n"
                           "5. Separate the industrial network from the office network if not already done.",
            raw_value=f"Peak: {peak_bcast}/sec, Total: {broadcast_count} ({bcast_pct:.1f}%)",
            category="Traffic Health",
        ))
        # Add timeline events for burst windows
        for t in sorted(burst_seconds)[:10]:
            count = broadcast_per_second[t]
            if count > 100:
                analysis.timeline.append(TimelineEvent(
                    timestamp=float(t),
                    event_type="broadcast_burst",
                    severity=Severity.CRITICAL,
                    description=f"Broadcast burst: {count} packets in 1 second",
                ))

    elif peak_bcast > 50 or bcast_pct > 15:
        score -= 15
        analysis.findings.append(CaptureFinding(
            title="⚠ High Broadcast Traffic",
            severity=Severity.WARNING,
            summary=f"Broadcast traffic is {bcast_pct:.1f}% of all traffic "
                    f"(peak: {peak_bcast}/sec). This is higher than normal "
                    f"and may be slowing down devices.",
            explanation="On a healthy industrial Ethernet network, broadcast traffic "
                        "should typically be under 5% of total traffic. Higher percentages "
                        "mean every device is spending more time processing packets that "
                        "aren't meant for it.\n\n"
                        "Common causes of excessive broadcasts:\n"
                        "• Too many devices on the same subnet without VLANs\n"
                        "• Devices constantly searching for other devices (ARP floods)\n"
                        "• A chatty protocol generating unnecessary broadcasts\n"
                        "• Pre-storm condition — a loop may be forming",
            recommendation="1. Check for network loops.\n"
                           "2. Consider segmenting the network with VLANs.\n"
                           "3. Enable IGMP Snooping on managed switches.\n"
                           "4. Review which devices are generating the most broadcasts.",
            raw_value=f"Broadcasts: {broadcast_count} ({bcast_pct:.1f}%), "
                      f"Peak: {peak_bcast}/sec",
            category="Traffic Health",
        ))
    elif broadcast_count > 0:
        analysis.findings.append(CaptureFinding(
            title="Broadcast Traffic",
            severity=Severity.OK,
            summary=f"Broadcast traffic is {bcast_pct:.1f}% of total — normal level.",
            explanation="Some broadcast traffic is expected on any Ethernet network. "
                        "ARP requests, DHCP, and device discovery all use broadcasts. "
                        "The level seen here is within normal operating range.",
            recommendation="No action needed.",
            raw_value=f"Broadcasts: {broadcast_count} ({bcast_pct:.1f}%)",
            category="Traffic Health",
        ))

    return score


def _analyze_arp_conflicts(analysis: CaptureAnalysis,
                           ip_to_macs: Dict[str, Set[str]],
                           mac_to_ips: Dict[str, Set[str]],
                           score: int) -> int:
    """Detect duplicate IP addresses and ARP conflicts."""
    conflicts = []

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1 and ip not in ("0.0.0.0", "255.255.255.255"):
            # Filter out broadcast/multicast MACs
            real_macs = {m for m in macs
                         if m != "ff:ff:ff:ff:ff:ff"
                         and not m.startswith("01:00:5e")}
            if len(real_macs) > 1:
                conflicts.append({
                    "ip": ip,
                    "macs": sorted(real_macs),
                })

    analysis.arp_conflicts = conflicts

    if conflicts:
        score -= 25 * min(len(conflicts), 3)  # Cap deduction
        conflict_details = []
        for c in conflicts[:5]:  # Show max 5
            mac_list = ", ".join(c["macs"])
            conflict_details.append(f"IP {c['ip']} → MACs: {mac_list}")

        analysis.findings.append(CaptureFinding(
            title="🔴 Duplicate IP Address Detected",
            severity=Severity.CRITICAL,
            summary=f"{len(conflicts)} IP address conflict(s) found — "
                    f"multiple devices are using the same IP address!",
            explanation="The capture detected that multiple MAC addresses (physical devices) "
                        "are responding to the same IP address. This is one of the most "
                        "difficult-to-diagnose network problems because it causes:\n\n"
                        "• Random communication failures (packets go to the wrong device)\n"
                        "• Intermittent PLC connection faults that seem to 'fix themselves'\n"
                        "• Devices alternately appearing online and offline\n\n"
                        "Conflicts detected:\n" + "\n".join(conflict_details),
            recommendation="1. Use the MAC addresses above to identify both conflicting devices.\n"
                           "2. Change one device to a unique IP address.\n"
                           "3. After fixing, clear ARP caches: power-cycle affected devices "
                           "and run 'arp -d *' on any PCs.\n"
                           "4. Document all IP assignments to prevent future conflicts.\n"
                           "5. Consider using the Network Scanner to verify no other conflicts exist.",
            raw_value=f"Conflicts: {len(conflicts)}",
            category="IP Configuration",
        ))

        # Timeline events for conflicts
        for c in conflicts:
            analysis.timeline.append(TimelineEvent(
                timestamp=0,  # Detected across whole capture
                event_type="ip_conflict",
                severity=Severity.CRITICAL,
                description=f"IP conflict: {c['ip']} used by {len(c['macs'])} devices",
                details=", ".join(c["macs"]),
            ))
    else:
        analysis.findings.append(CaptureFinding(
            title="IP Address Conflicts",
            severity=Severity.OK,
            summary="No duplicate IP addresses detected during the capture.",
            explanation="Every IP address observed in the capture maps to exactly one "
                        "MAC address, meaning no two devices are fighting over the same IP.",
            recommendation="No action needed.",
            raw_value="Conflicts: 0",
            category="IP Configuration",
        ))

    return score


def _analyze_arp_volume(analysis: CaptureAnalysis,
                        arp_requests: int, arp_replies: int,
                        gratuitous_arps: int,
                        arp_per_second: Counter,
                        total_packets: int,
                        score: int) -> int:
    """Check for excessive ARP traffic."""
    total_arp = arp_requests + arp_replies
    if total_arp == 0:
        return score

    arp_pct = (total_arp / total_packets * 100) if total_packets > 0 else 0
    peak_arp = max(arp_per_second.values()) if arp_per_second else 0

    # Unanswered ARPs: lots of requests but few replies = devices not found
    unanswered_ratio = 0.0
    if arp_requests > 10:
        unanswered_ratio = 1.0 - (arp_replies / arp_requests) if arp_requests > 0 else 0

    if arp_pct > 20 or peak_arp > 100:
        score -= 15
        analysis.findings.append(CaptureFinding(
            title="⚠ Excessive ARP Traffic",
            severity=Severity.WARNING,
            summary=f"ARP traffic is {arp_pct:.1f}% of total "
                    f"({total_arp:,} packets, peak {peak_arp}/sec).",
            explanation="ARP (Address Resolution Protocol) is how devices find each other's "
                        "MAC addresses on the network. Excessive ARP usually means:\n\n"
                        "• A device is searching for addresses that don't exist\n"
                        "• A network scanner is probing the entire subnet\n"
                        "• A device has a misconfigured gateway or subnet mask\n"
                        "• Pre-condition of a network loop",
            recommendation="1. Identify which device is generating the most ARP requests "
                           "(check the Top Talkers).\n"
                           "2. Verify subnet masks are correct on all devices.\n"
                           "3. Check that the default gateway is correct.\n"
                           "4. Make sure no devices are trying to reach IPs outside the subnet.",
            raw_value=f"ARP: {total_arp} ({arp_pct:.1f}%), "
                      f"Requests: {arp_requests}, Replies: {arp_replies}",
            category="Traffic Health",
        ))

    if unanswered_ratio > 0.5 and arp_requests > 20:
        analysis.findings.append(CaptureFinding(
            title="Unanswered ARP Requests",
            severity=Severity.INFO,
            summary=f"{int(unanswered_ratio * 100)}% of ARP requests got no reply "
                    f"({arp_requests} requests, {arp_replies} replies).",
            explanation="A high ratio of unanswered ARP requests means devices are looking "
                        "for IP addresses that don't exist on this network. This wastes "
                        "bandwidth and can indicate misconfigured devices trying to reach "
                        "the wrong subnet, or a device that was recently removed.",
            recommendation="1. Check which IPs are being requested but not responding.\n"
                           "2. Verify all device IP configurations (subnet, gateway).\n"
                           "3. Remove stale entries from PLC I/O trees if devices were removed.",
            raw_value=f"Unanswered: {unanswered_ratio*100:.0f}%",
            category="Traffic Health",
        ))

    if gratuitous_arps > 5:
        analysis.findings.append(CaptureFinding(
            title="Gratuitous ARP Activity",
            severity=Severity.INFO,
            summary=f"{gratuitous_arps} gratuitous ARP packets detected.",
            explanation="Gratuitous ARPs are when a device broadcasts its own IP-to-MAC mapping "
                        "without being asked. Some gratuitous ARPs are normal — devices send "
                        "them at startup to announce themselves and to detect IP conflicts. "
                        "A large number may indicate a device that is repeatedly restarting "
                        "or having an ACD (Address Conflict Detection) issue.",
            recommendation="If the count keeps growing, check which device is sending "
                           "them — it may be power-cycling or detecting conflicts.",
            raw_value=f"Gratuitous ARPs: {gratuitous_arps}",
            category="Traffic Health",
        ))

    return score


def _analyze_tcp_retransmissions(analysis: CaptureAnalysis,
                                  tcp_total: int, tcp_retransmissions: int,
                                  packets: List[CapturedPacket],
                                  score: int) -> int:
    """Analyze TCP retransmission rate."""
    if tcp_total == 0:
        return score

    retx_pct = (tcp_retransmissions / tcp_total * 100)

    if retx_pct > 5:
        score -= 20
        analysis.findings.append(CaptureFinding(
            title="🔴 High TCP Retransmissions",
            severity=Severity.CRITICAL,
            summary=f"{tcp_retransmissions:,} TCP retransmissions "
                    f"({retx_pct:.1f}% of TCP traffic) — significant packet loss.",
            explanation="TCP retransmissions happen when sent data isn't acknowledged in time, "
                        "forcing the sender to repeat it. A rate above 5% indicates serious "
                        "and consistent packet loss on this network.\n\n"
                        "Impact on industrial systems:\n"
                        "• HMI screens update slowly or freeze\n"
                        "• Program uploads/downloads fail or take forever\n"
                        "• Explicit messaging (MSG instructions) time out\n"
                        "• Web server pages on devices won't load\n\n"
                        "While TCP retransmissions don't directly cause I/O faults (those "
                        "use UDP), they indicate a network-level problem that is very likely "
                        "also affecting the I/O traffic.",
            recommendation="1. Check cables and connections — most retransmissions are caused "
                           "by physical layer issues (bad cable, loose connector).\n"
                           "2. Look at the CRC/collision data from device diagnostics.\n"
                           "3. Check for bandwidth overload on the network segment.\n"
                           "4. Verify switch port settings (speed/duplex) match on both ends.",
            raw_value=f"Retransmissions: {tcp_retransmissions}/{tcp_total} ({retx_pct:.1f}%)",
            category="TCP/IP Health",
        ))
    elif retx_pct > 1:
        score -= 10
        analysis.findings.append(CaptureFinding(
            title="⚠ TCP Retransmissions Detected",
            severity=Severity.WARNING,
            summary=f"{tcp_retransmissions:,} TCP retransmissions "
                    f"({retx_pct:.1f}% of TCP traffic) — moderate packet loss.",
            explanation="Some TCP retransmissions are occurring. While a rate of 1-5% "
                        "won't cripple the network, it does indicate packets are being "
                        "lost and retransmitted, which slows down all TCP-based communication "
                        "(HMI updates, web access, program transfers, explicit messaging).",
            recommendation="1. Check physical connections — cables, connectors, patch panels.\n"
                           "2. Verify no duplex mismatches exist.\n"
                           "3. Run device diagnostics to check for CRC errors on specific ports.",
            raw_value=f"Retransmissions: {tcp_retransmissions}/{tcp_total} ({retx_pct:.1f}%)",
            category="TCP/IP Health",
        ))
    elif tcp_retransmissions > 0:
        analysis.findings.append(CaptureFinding(
            title="TCP Retransmissions",
            severity=Severity.OK,
            summary=f"Very low retransmission rate ({retx_pct:.2f}%) — within normal range.",
            explanation="A small number of TCP retransmissions is normal on any network. "
                        "The rate observed here is not a concern.",
            recommendation="No action needed.",
            raw_value=f"Retransmissions: {tcp_retransmissions}/{tcp_total} ({retx_pct:.2f}%)",
            category="TCP/IP Health",
        ))
    else:
        analysis.findings.append(CaptureFinding(
            title="TCP Retransmissions",
            severity=Severity.OK,
            summary="Zero TCP retransmissions — clean TCP traffic.",
            explanation="No TCP packets needed to be retransmitted during the capture, "
                        "which means the network is delivering TCP traffic reliably.",
            recommendation="No action needed.",
            raw_value="Retransmissions: 0",
            category="TCP/IP Health",
        ))

    return score


def _analyze_multicast(analysis: CaptureAnalysis,
                       multicast_count: int, total_packets: int,
                       score: int) -> int:
    """Analyze multicast traffic levels."""
    if total_packets == 0 or multicast_count == 0:
        return score

    mcast_pct = (multicast_count / total_packets * 100)

    if mcast_pct > 30:
        score -= 10
        analysis.findings.append(CaptureFinding(
            title="⚠ High Multicast Traffic",
            severity=Severity.WARNING,
            summary=f"Multicast traffic is {mcast_pct:.1f}% of total — "
                    f"this suggests IGMP Snooping may not be configured.",
            explanation="EtherNet/IP uses multicast for I/O data, which is efficient — "
                        "but ONLY if the switches have IGMP Snooping enabled. Without "
                        "IGMP Snooping, every multicast packet is flooded to every port "
                        "on the switch, wasting bandwidth and forcing devices to process "
                        "traffic they don't need.\n\n"
                        "A high multicast percentage usually means the switches are flooding "
                        "multicast to all ports instead of only to the ports that need it.",
            recommendation="1. Enable IGMP Snooping on all managed switches.\n"
                           "2. Configure IGMP Querier on exactly one switch per VLAN.\n"
                           "3. For Stratix switches, use Smartport profiles which enable "
                           "IGMP Snooping automatically.\n"
                           "4. Consider using unicast I/O connections where multicast "
                           "is not required.",
            raw_value=f"Multicast: {multicast_count} ({mcast_pct:.1f}%)",
            category="Traffic Health",
        ))
    elif multicast_count > 0:
        analysis.findings.append(CaptureFinding(
            title="Multicast Traffic",
            severity=Severity.INFO,
            summary=f"Multicast traffic: {multicast_count:,} packets ({mcast_pct:.1f}%).",
            explanation="Some multicast traffic is expected on EtherNet/IP networks. "
                        "The level observed is within normal range.",
            recommendation="Verify IGMP Snooping is enabled on your switches.",
            raw_value=f"Multicast: {multicast_count} ({mcast_pct:.1f}%)",
            category="Traffic Health",
        ))

    return score


def _analyze_stp(analysis: CaptureAnalysis,
                 stp_count: int, topology_changes: int,
                 score: int) -> int:
    """Analyze Spanning Tree Protocol traffic."""
    if stp_count == 0:
        return score

    if topology_changes > 0:
        score -= 15
        analysis.findings.append(CaptureFinding(
            title="⚠ STP Topology Changes",
            severity=Severity.WARNING,
            summary=f"{topology_changes} Spanning Tree topology change(s) detected "
                    f"during the capture — the network is reconfiguring.",
            explanation="A Spanning Tree topology change means the network's loop-prevention "
                        "system detected a change (a link went down, a switch was added/removed, "
                        "or a cable was plugged/unplugged). During a topology change:\n\n"
                        "• Traffic may be briefly interrupted (up to 30 seconds with classic STP)\n"
                        "• MAC address tables are flushed, causing a burst of flooding\n"
                        "• Devices may lose communication temporarily\n\n"
                        "Frequent topology changes usually mean an unstable link is flapping "
                        "(repeatedly going up and down).",
            recommendation="1. Check for loose or damaged cables that could be causing "
                           "link flapping.\n"
                           "2. Upgrade from classic STP to Rapid STP (RSTP) for faster recovery.\n"
                           "3. Enable 'portfast' on switch ports connected to end devices "
                           "(not other switches) to avoid unnecessary STP events.\n"
                           "4. Check the switch logs for which port is flapping.",
            raw_value=f"STP packets: {stp_count}, Topology changes: {topology_changes}",
            category="Network Infrastructure",
        ))
    else:
        analysis.findings.append(CaptureFinding(
            title="Spanning Tree Protocol",
            severity=Severity.INFO,
            summary=f"{stp_count} STP packets detected — switches are running "
                    f"Spanning Tree (loop protection).",
            explanation="STP is active on this network, which means managed switches "
                        "are protecting against network loops. This is normal and expected "
                        "on a properly configured network.",
            recommendation="No action needed. STP is working as expected.",
            raw_value=f"STP packets: {stp_count}",
            category="Network Infrastructure",
        ))

    return score


def _analyze_top_talkers(analysis: CaptureAnalysis,
                         host_total_bytes: Counter,
                         total_bytes: int):
    """Flag any single device using an outsized share of bandwidth."""
    if total_bytes == 0 or not host_total_bytes:
        return

    top_ip, top_bytes = host_total_bytes.most_common(1)[0]
    top_pct = (top_bytes / total_bytes * 100) if total_bytes > 0 else 0

    if top_pct > 60 and len(host_total_bytes) > 3:
        analysis.findings.append(CaptureFinding(
            title="⚠ Bandwidth Hog Detected",
            severity=Severity.WARNING,
            summary=f"Device {top_ip} is using {top_pct:.0f}% of all network bandwidth "
                    f"({_format_bytes(top_bytes)}) — dominating the network.",
            explanation="One device is consuming the majority of the network bandwidth. "
                        "On a shared industrial network, this can starve other devices "
                        "of bandwidth and cause slow responses or timeouts.\n\n"
                        "Common causes:\n"
                        "• A camera or vision system streaming video on the control network\n"
                        "• An HMI downloading large files or screen updates\n"
                        "• A PC running backups or updates over the industrial network\n"
                        "• A historian collecting too much data too frequently",
            recommendation="1. Identify what the device is doing with all that bandwidth.\n"
                           "2. Consider moving high-bandwidth devices to a separate VLAN.\n"
                           "3. Reduce polling rates or data collection frequency if possible.\n"
                           "4. Use QoS (Quality of Service) to prioritize I/O traffic.",
            raw_value=f"Top: {top_ip} = {_format_bytes(top_bytes)} ({top_pct:.0f}%)",
            category="Bandwidth",
        ))


def _analyze_protocols(analysis: CaptureAnalysis,
                       protocol_counter: Counter,
                       total_packets: int):
    """Summarize protocol distribution."""
    if not protocol_counter or total_packets == 0:
        return

    lines = []
    for proto, count in protocol_counter.most_common(8):
        pct = (count / total_packets * 100)
        lines.append(f"{proto}: {count:,} ({pct:.1f}%)")

    # Check for unexpected protocols
    unexpected = []
    for proto in protocol_counter:
        upper = proto.upper()
        # Flag protocols that shouldn't be on an isolated industrial network
        if upper in ("SSDP", "LLMNR", "MDNS", "NBNS", "BROWSER",
                     "DROPBOX-LSNR", "SPOTIFY", "BITTORRENT"):
            unexpected.append(proto)

    if unexpected:
        analysis.findings.append(CaptureFinding(
            title="Non-Industrial Traffic Detected",
            severity=Severity.INFO,
            summary=f"Found traffic from non-industrial protocols: "
                    f"{', '.join(unexpected)}.",
            explanation="These protocols are typically associated with office or consumer "
                        "networks, not industrial control networks. Their presence suggests "
                        "the industrial network may not be fully isolated from the office "
                        "network or that a PC on the network is running unnecessary services.",
            recommendation="1. Verify the industrial network is properly segmented "
                           "from the office/IT network.\n"
                           "2. Disable unnecessary services on any PCs connected to "
                           "the industrial network.\n"
                           "3. Consider using a firewall or managed switch ACLs to "
                           "block non-essential traffic.",
            raw_value=f"Unexpected: {', '.join(unexpected)}",
            category="Network Hygiene",
        ))

    analysis.findings.append(CaptureFinding(
        title="Protocol Distribution",
        severity=Severity.INFO,
        summary="Top protocols: " + " | ".join(lines[:5]),
        explanation="This shows which network protocols are consuming the most "
                    "bandwidth. On a typical EtherNet/IP industrial network, you'd "
                    "expect to see CIP/ENIP, ARP, TCP, and UDP as the dominant protocols.",
        recommendation="For reference — review the protocol chart for a visual breakdown.",
        raw_value="\n".join(lines),
        category="Protocol Analysis",
    ))


def _add_health_summary(analysis: CaptureAnalysis):
    """Add an overall health assessment based on the score."""
    score = analysis.health_score

    if score >= 90:
        analysis.findings.insert(0, CaptureFinding(
            title="Network Traffic Health: Excellent",
            severity=Severity.OK,
            summary=f"Health score: {score}/100 — the captured traffic looks healthy "
                    f"with no significant issues detected.",
            explanation="Based on the traffic patterns captured, this network segment "
                        "is operating normally with no broadcast storms, no IP conflicts, "
                        "low retransmission rates, and normal traffic distribution.",
            recommendation="No immediate action needed. Consider running periodic captures "
                           "to establish a baseline.",
            raw_value=f"Score: {score}",
            category="Overall",
        ))
    elif score >= 70:
        analysis.findings.insert(0, CaptureFinding(
            title="Network Traffic Health: Minor Issues",
            severity=Severity.WARNING,
            summary=f"Health score: {score}/100 — some issues detected that "
                    f"should be investigated.",
            explanation="The capture revealed some traffic patterns that aren't ideal. "
                        "While these may not be causing visible problems yet, they could "
                        "lead to intermittent issues under load.",
            recommendation="Review the findings below and address warnings.",
            raw_value=f"Score: {score}",
            category="Overall",
        ))
    elif score >= 50:
        analysis.findings.insert(0, CaptureFinding(
            title="Network Traffic Health: Needs Attention",
            severity=Severity.WARNING,
            summary=f"Health score: {score}/100 — significant traffic issues detected.",
            explanation="The captured traffic reveals problems that are likely "
                        "contributing to communication issues. Addressing these "
                        "could significantly improve network reliability.",
            recommendation="Review and address the critical and warning findings below.",
            raw_value=f"Score: {score}",
            category="Overall",
        ))
    else:
        analysis.findings.insert(0, CaptureFinding(
            title="Network Traffic Health: Critical Problems",
            severity=Severity.CRITICAL,
            summary=f"Health score: {score}/100 — serious network problems detected "
                    f"in the captured traffic.",
            explanation="The traffic capture reveals critical issues that are very likely "
                        "causing communication faults, timeouts, and unreliable operation. "
                        "Immediate investigation is recommended.",
            recommendation="Address the critical findings below as soon as possible.",
            raw_value=f"Score: {score}",
            category="Overall",
        ))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _format_bytes(b: int) -> str:
    """Format byte count as human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"
