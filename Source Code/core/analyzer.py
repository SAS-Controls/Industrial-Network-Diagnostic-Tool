"""
SAS Network Diagnostics Tool — Diagnostic Analyzer
The 'brain' that translates raw network counters into plain-English explanations.
This is what makes the tool useful for non-network-engineers.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from core.eip_scanner import EthernetDiagnostics

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Severity levels for diagnostic findings."""
    INFO = "info"
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class DiagnosticFinding:
    """A single diagnostic finding with plain-English explanation."""
    title: str
    severity: Severity
    summary: str  # One-line plain English summary
    explanation: str  # Detailed explanation for someone who is NOT a network engineer
    recommendation: str  # What to do about it
    raw_value: str = ""  # The actual counter value(s) for reference
    category: str = ""  # Grouping category

    @property
    def severity_label(self) -> str:
        return {
            Severity.INFO: "ℹ️ Info",
            Severity.OK: "✅ OK",
            Severity.WARNING: "⚠️ Warning",
            Severity.CRITICAL: "🔴 Problem Found",
        }[self.severity]


@dataclass
class DiagnosticReport:
    """Complete diagnostic report for a device."""
    device_ip: str
    device_name: str = ""
    timestamp: float = field(default_factory=time.time)
    health_score: int = 100  # 0-100
    findings: List[DiagnosticFinding] = field(default_factory=list)
    overall_status: str = ""
    overall_summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def ok_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.OK)


def analyze_diagnostics(diag: EthernetDiagnostics,
                        prev_diag: Optional[EthernetDiagnostics] = None,
                        device_ip: str = "",
                        device_name: str = "",
                        ping_ms: float = 0.0,
                        packet_loss_pct: float = 0.0) -> DiagnosticReport:
    """
    Analyze diagnostic data and produce a plain-English report.
    If prev_diag is provided, calculates rate of change (new errors since last check).
    """
    report = DiagnosticReport(device_ip=device_ip, device_name=device_name)
    score = 100  # Start perfect, deduct for issues

    # ── 1. Link Status Check ─────────────────────────────────────────────────
    if diag.link_status:
        if diag.link_status.lower() in ("active", "up"):
            report.findings.append(DiagnosticFinding(
                title="Network Link",
                severity=Severity.OK,
                summary="The network cable is connected and the link is active.",
                explanation="The physical Ethernet connection between this device and the "
                            "network switch is working properly.",
                recommendation="No action needed.",
                raw_value=f"Link Status: {diag.link_status}",
                category="Connection",
            ))
        elif diag.link_status.lower() == "unknown":
            # Can't determine link status — but if we're running diagnostics,
            # we ARE communicating with the device, so don't flag as down.
            report.findings.append(DiagnosticFinding(
                title="Network Link",
                severity=Severity.OK,
                summary="Device is reachable — link status details not available.",
                explanation="The device responded to network communication, confirming "
                            "the link is functional. Detailed link status attributes "
                            "were not available from this device (not all devices "
                            "expose CIP Ethernet link diagnostics).",
                recommendation="No action needed — the connection is working.",
                raw_value=f"Link Status: {diag.link_status}",
                category="Connection",
            ))
        else:
            score -= 50
            report.findings.append(DiagnosticFinding(
                title="Network Link Down",
                severity=Severity.CRITICAL,
                summary="The network cable appears to be disconnected or the link is down.",
                explanation="This device does not have an active network connection. This means "
                            "the Ethernet cable may be unplugged, damaged, or the network switch "
                            "port it's connected to may be turned off or faulty.",
                recommendation="1. Check that the Ethernet cable is firmly plugged in at both ends.\n"
                               "2. Look at the LED lights on the Ethernet port — they should be lit.\n"
                               "3. Try a different cable.\n"
                               "4. Try a different port on the network switch.\n"
                               "5. Check if the switch port is enabled.",
                raw_value=f"Link Status: {diag.link_status}",
                category="Connection",
            ))

    # ── 2. Link Speed & Duplex ───────────────────────────────────────────────
    if diag.link_speed > 0:
        speed_issue = False
        if diag.link_speed < 100:
            score -= 10
            speed_issue = True

        duplex_issue = diag.duplex.lower() == "half"
        if duplex_issue:
            score -= 15

        if speed_issue or duplex_issue:
            issues = []
            if speed_issue:
                issues.append(f"running at only {diag.link_speed} Mbps")
            if duplex_issue:
                issues.append("running in Half Duplex mode")

            report.findings.append(DiagnosticFinding(
                title="Link Speed / Duplex Issue",
                severity=Severity.WARNING,
                summary=f"The network connection is {' and '.join(issues)}.",
                explanation="Most modern industrial Ethernet devices should run at 100 Mbps in Full Duplex mode. "
                            "Half Duplex means the device can only send OR receive data at one time (not both), "
                            "which can cause communication slowdowns and collisions. A speed below 100 Mbps may "
                            "indicate a bad cable, a bad port, or a mismatched configuration.",
                recommendation="1. Check the Ethernet cable — damaged cables often negotiate slower speeds.\n"
                               "2. Ensure the cable is Cat5e or better (Cat5e supports Gigabit).\n"
                               "3. Verify the switch port speed/duplex settings match the device.\n"
                               "4. Most AB modules auto-negotiate — the switch port should too.\n"
                               "5. Avoid forcing speed/duplex unless both ends match exactly.",
                raw_value=f"Speed: {diag.link_speed} Mbps, Duplex: {diag.duplex}",
                category="Connection",
            ))
        else:
            report.findings.append(DiagnosticFinding(
                title="Link Speed & Duplex",
                severity=Severity.OK,
                summary=f"Running at {diag.link_speed} Mbps, {diag.duplex} Duplex — normal.",
                explanation="The connection speed and duplex settings look appropriate for industrial Ethernet.",
                recommendation="No action needed.",
                raw_value=f"Speed: {diag.link_speed} Mbps, Duplex: {diag.duplex}",
                category="Connection",
            ))

    # ── 3. CRC / FCS Errors ──────────────────────────────────────────────────
    _analyze_counter(report, "CRC / Frame Check Errors", diag.fcs_errors,
                     prev_diag.fcs_errors if prev_diag else None,
                     threshold_warn=10, threshold_crit=100,
                     category="Cable / Physical",
                     ok_summary="No frame check (CRC) errors detected.",
                     ok_explanation="CRC errors indicate damaged data packets. Zero errors means "
                                   "the physical cable and connections are delivering data cleanly.",
                     warn_summary="Some CRC errors detected — possible cable or connection problem.",
                     crit_summary="High number of CRC errors — there is likely a cable or connector problem.",
                     explanation="CRC (Cyclic Redundancy Check) errors happen when data arrives corrupted. "
                                 "This almost always points to a physical problem: a damaged cable, a loose "
                                 "connector, electrical interference from nearby motors or VFDs, or a cable "
                                 "that's too long. Each CRC error means a packet of data had to be thrown "
                                 "away and re-sent, which slows down communication and can cause timeouts.",
                     recommendation="1. Inspect the Ethernet cable for damage — look for kinks, cuts, or crushed spots.\n"
                                    "2. Re-seat both ends of the cable (unplug and firmly re-plug).\n"
                                    "3. Try replacing the cable with a known-good one.\n"
                                    "4. Check cable routing — keep Ethernet cables away from VFD power cables, "
                                    "motors, and high-voltage wiring.\n"
                                    "5. Verify the cable length is within spec (100m / 328ft max for copper Ethernet).\n"
                                    "6. Use shielded cable (STP) in areas with heavy electrical noise.",
                     score_tracker=score)
    score = _get_adjusted_score(score, diag.fcs_errors, 10, 100, 10, 25)

    # ── 4. Alignment Errors ──────────────────────────────────────────────────
    _analyze_counter(report, "Alignment Errors", diag.alignment_errors,
                     prev_diag.alignment_errors if prev_diag else None,
                     threshold_warn=5, threshold_crit=50,
                     category="Cable / Physical",
                     ok_summary="No alignment errors detected.",
                     ok_explanation="Alignment errors happen when received frames are not properly byte-aligned. "
                                   "Zero means the physical connection is clean.",
                     warn_summary="Some alignment errors detected — similar to CRC errors, likely a cable issue.",
                     crit_summary="High alignment errors — physical connection problem likely.",
                     explanation="Alignment errors mean the device is receiving data frames that don't end on "
                                 "proper byte boundaries. This is very similar to CRC errors and usually has "
                                 "the same root causes: bad cables, loose connections, or electrical interference.",
                     recommendation="Same as CRC errors:\n"
                                    "1. Replace or re-seat the Ethernet cable.\n"
                                    "2. Route cables away from electrical noise sources.\n"
                                    "3. Use shielded cable in industrial environments.",
                     score_tracker=score)
    score = _get_adjusted_score(score, diag.alignment_errors, 5, 50, 5, 15)

    # ── 5. Collision Errors ──────────────────────────────────────────────────
    total_collisions = diag.single_collisions + diag.multiple_collisions
    _analyze_counter(report, "Network Collisions", total_collisions,
                     (prev_diag.single_collisions + prev_diag.multiple_collisions) if prev_diag else None,
                     threshold_warn=50, threshold_crit=500,
                     category="Network Traffic",
                     ok_summary="No collisions detected — good network traffic flow.",
                     ok_explanation="Collisions happen when two devices try to talk at the same time. "
                                   "Zero collisions means the network is properly configured. Most modern "
                                   "switched Ethernet networks should have zero collisions.",
                     warn_summary="Some collisions detected — this is unusual on a switched network.",
                     crit_summary="High collision count — network configuration problem.",
                     explanation="Collisions happen when multiple devices try to send data at the same "
                                 "exact moment. On a modern network using switches (not hubs), collisions "
                                 "should be rare or zero. If you're seeing collisions, it could mean:\n"
                                 "• A network hub is being used instead of a switch\n"
                                 "• The port or device is stuck in Half Duplex mode\n"
                                 "• There's a speed/duplex mismatch between the device and switch",
                     recommendation="1. Make sure you're using a network switch, not a hub.\n"
                                    "2. Check that both the device and switch port are set to Full Duplex.\n"
                                    "3. Set both ends to auto-negotiate (recommended) or manually match settings.\n"
                                    "4. Check for any network loops (a cable accidentally connecting two switch ports).",
                     score_tracker=score)
    score = _get_adjusted_score(score, total_collisions, 50, 500, 5, 15)

    # ── 6. Late Collisions ───────────────────────────────────────────────────
    if diag.late_collisions > 0:
        severity = Severity.CRITICAL if diag.late_collisions > 20 else Severity.WARNING
        score -= 20 if severity == Severity.CRITICAL else 10
        report.findings.append(DiagnosticFinding(
            title="Late Collisions",
            severity=severity,
            summary=f"{diag.late_collisions} late collisions detected — this indicates a serious problem.",
            explanation="Late collisions are especially bad. They happen when a collision occurs AFTER the "
                        "device has already started transmitting a full frame. This typically means:\n\n"
                        "• The Ethernet cable is too long (over 100 meters / 328 feet)\n"
                        "• There is a duplex mismatch — one end is Full Duplex, the other is Half Duplex\n"
                        "• A faulty network device (bad port on switch)\n\n"
                        "Late collisions waste a lot of bandwidth and cause significant communication delays.",
            recommendation="1. CHECK FOR DUPLEX MISMATCH first — this is the most common cause.\n"
                           "2. Measure the cable length — must be under 100m (328ft).\n"
                           "3. Try a different switch port.\n"
                           "4. Replace the cable.",
            raw_value=f"Late Collisions: {diag.late_collisions}",
            category="Network Traffic",
        ))

    # ── 7. Excessive Collisions ──────────────────────────────────────────────
    if diag.excessive_collisions > 0:
        score -= 20
        report.findings.append(DiagnosticFinding(
            title="Excessive Collisions",
            severity=Severity.CRITICAL,
            summary=f"{diag.excessive_collisions} excessive collisions — the device is failing to send data.",
            explanation="Excessive collisions mean the device tried to send a packet and experienced "
                        "so many collisions (16 or more attempts) that it gave up and dropped the packet. "
                        "This means data is being LOST, not just delayed. This will absolutely cause "
                        "communication faults in a PLC system.",
            recommendation="1. This is almost always a duplex mismatch or a faulty hub/switch.\n"
                           "2. Check and match duplex settings on both ends.\n"
                           "3. Replace any hubs with proper switches.\n"
                           "4. Try a different switch port.",
            raw_value=f"Excessive Collisions: {diag.excessive_collisions}",
            category="Network Traffic",
        ))

    # ── 8. Carrier Sense Errors ──────────────────────────────────────────────
    _analyze_counter(report, "Carrier Sense Errors", diag.carrier_sense_errors,
                     prev_diag.carrier_sense_errors if prev_diag else None,
                     threshold_warn=5, threshold_crit=50,
                     category="Cable / Physical",
                     ok_summary="No carrier sense errors.",
                     ok_explanation="The device can properly detect the network signal.",
                     warn_summary="Some carrier sense errors — may indicate a physical problem.",
                     crit_summary="Many carrier sense errors — the device is having trouble detecting the network.",
                     explanation="Carrier sense errors mean the device is having trouble detecting or maintaining "
                                 "the electrical signal on the Ethernet cable. This usually indicates a bad cable, "
                                 "a failing port on the device or switch, or severe electrical interference.",
                     recommendation="1. Replace the Ethernet cable.\n"
                                    "2. Try a different switch port.\n"
                                    "3. Check for sources of electrical interference nearby.",
                     score_tracker=score)
    score = _get_adjusted_score(score, diag.carrier_sense_errors, 5, 50, 5, 15)

    # ── 9. Input / Output Errors (general) ───────────────────────────────────
    total_io_errors = diag.in_errors + diag.out_errors
    if total_io_errors > 0 and diag.fcs_errors == 0 and diag.alignment_errors == 0:
        # Only report if not already covered by CRC/alignment
        severity = Severity.CRITICAL if total_io_errors > 100 else Severity.WARNING
        deduction = 15 if severity == Severity.CRITICAL else 5
        score -= deduction
        report.findings.append(DiagnosticFinding(
            title="Input / Output Errors",
            severity=severity,
            summary=f"{total_io_errors} I/O errors detected on the network interface.",
            explanation="The device's network interface is reporting general input/output errors. "
                        "These could be caused by various issues including buffer overflows (too much "
                        "traffic for the device to handle), driver issues, or hardware problems.",
            recommendation="1. Check if the device is overloaded with too many connections.\n"
                           "2. Reduce the polling rate if possible.\n"
                           "3. Check for network congestion — too many devices on the same network segment.",
            raw_value=f"In Errors: {diag.in_errors}, Out Errors: {diag.out_errors}",
            category="Device Performance",
        ))

    # ── 10. Discarded Packets ────────────────────────────────────────────────
    total_discards = diag.in_discards + diag.out_discards
    _analyze_counter(report, "Discarded Packets", total_discards,
                     (prev_diag.in_discards + prev_diag.out_discards) if prev_diag else None,
                     threshold_warn=50, threshold_crit=500,
                     category="Device Performance",
                     ok_summary="No packets being discarded.",
                     ok_explanation="The device is able to process all incoming and outgoing data "
                                   "without dropping any packets.",
                     warn_summary="Some packets are being discarded — the device may be overloaded.",
                     crit_summary="High number of discarded packets — the device is dropping data.",
                     explanation="When a device discards packets, it means it received data but couldn't "
                                 "process it in time (input discards) or couldn't send data out fast enough "
                                 "(output discards). This is often a sign that the device is being asked to "
                                 "handle too much traffic, or that there's a bottleneck somewhere.",
                     recommendation="1. Reduce the number of connections to this device if possible.\n"
                                    "2. Increase the RPI (Requested Packet Interval) to reduce traffic.\n"
                                    "3. Check if the device's connection limit is being reached.\n"
                                    "4. Consider using a faster Ethernet module or splitting the network load.",
                     score_tracker=score)
    score = _get_adjusted_score(score, total_discards, 50, 500, 5, 15)

    # ── 11. Oversized Frames ─────────────────────────────────────────────────
    if diag.frame_too_long > 0:
        score -= 5
        report.findings.append(DiagnosticFinding(
            title="Oversized Frames",
            severity=Severity.WARNING,
            summary=f"{diag.frame_too_long} oversized frames received.",
            explanation="The device received some Ethernet frames that were larger than the maximum "
                        "allowed size (1518 bytes for standard Ethernet). This can happen if a device "
                        "on the network is misconfigured or if jumbo frames are enabled on some devices "
                        "but not others.",
            recommendation="1. Check if any devices or switches have jumbo frames enabled.\n"
                           "2. Ensure all devices on the network agree on the maximum frame size.\n"
                           "3. This is usually a configuration issue, not a hardware problem.",
            raw_value=f"Frame Too Long: {diag.frame_too_long}",
            category="Network Configuration",
        ))

    # ── 12. Ping Response Time ───────────────────────────────────────────────
    if ping_ms > 0:
        if ping_ms < 5:
            report.findings.append(DiagnosticFinding(
                title="Response Time",
                severity=Severity.OK,
                summary=f"Device responds in {ping_ms:.1f}ms — excellent.",
                explanation="The device responds very quickly to network requests. "
                            "For industrial Ethernet, under 5ms is excellent.",
                recommendation="No action needed.",
                raw_value=f"Ping: {ping_ms:.1f}ms",
                category="Responsiveness",
            ))
        elif ping_ms < 20:
            report.findings.append(DiagnosticFinding(
                title="Response Time",
                severity=Severity.OK,
                summary=f"Device responds in {ping_ms:.1f}ms — normal.",
                explanation="The device response time is within normal range for industrial Ethernet.",
                recommendation="No action needed.",
                raw_value=f"Ping: {ping_ms:.1f}ms",
                category="Responsiveness",
            ))
        elif ping_ms < 100:
            score -= 10
            report.findings.append(DiagnosticFinding(
                title="Slow Response Time",
                severity=Severity.WARNING,
                summary=f"Device responds in {ping_ms:.1f}ms — slower than expected.",
                explanation="The device is taking longer than usual to respond. For industrial "
                            "Ethernet/IP networks, response times under 10ms are typical. Slow responses "
                            "can indicate network congestion, a busy device, or a marginal connection.",
                recommendation="1. Check network traffic levels — is the network congested?\n"
                               "2. Is this device handling a lot of connections?\n"
                               "3. Check the cable quality and connection.\n"
                               "4. Try pinging during different times to see if it's consistent.",
                raw_value=f"Ping: {ping_ms:.1f}ms",
                category="Responsiveness",
            ))
        else:
            score -= 25
            report.findings.append(DiagnosticFinding(
                title="Very Slow Response Time",
                severity=Severity.CRITICAL,
                summary=f"Device responds in {ping_ms:.1f}ms — this is very slow and will cause problems.",
                explanation="The device is responding extremely slowly. Response times over 100ms on a "
                            "local industrial network will almost certainly cause communication timeouts "
                            "and faults. This device is likely struggling to keep up with network demands.",
                recommendation="1. Check for network congestion or broadcast storms.\n"
                               "2. The device may be overloaded — reduce connections.\n"
                               "3. Check for IP address conflicts (two devices with the same IP).\n"
                               "4. The switch or cable may be faulty.\n"
                               "5. Try isolating this device on a separate switch port for testing.",
                raw_value=f"Ping: {ping_ms:.1f}ms",
                category="Responsiveness",
            ))

    # ── 13. Packet Loss ──────────────────────────────────────────────────────
    if packet_loss_pct > 0:
        if packet_loss_pct < 1:
            score -= 10
            severity = Severity.WARNING
        else:
            score -= 30
            severity = Severity.CRITICAL

        report.findings.append(DiagnosticFinding(
            title="Packet Loss Detected",
            severity=severity,
            summary=f"{packet_loss_pct:.1f}% of messages are being lost.",
            explanation="Packet loss means some messages sent to this device never arrive, or the "
                        "device's responses never make it back. Even small amounts of packet loss (over "
                        "0.1%) can cause communication faults in PLC systems because the controller "
                        "expects responses within strict time windows. Packet loss is one of the most "
                        "common causes of intermittent 'communication loss' faults.",
            recommendation="1. Check ALL cables and connections in the path to this device.\n"
                           "2. Look for duplex mismatches on the device and switch.\n"
                           "3. Check for IP address conflicts on the network.\n"
                           "4. Inspect the switch for errors on the port this device is connected to.\n"
                           "5. Try replacing the cable and using a different switch port.\n"
                           "6. Check if the network is overloaded with too much broadcast traffic.",
            raw_value=f"Packet Loss: {packet_loss_pct:.1f}%",
            category="Reliability",
        ))

    # ── 14. Traffic Volume Summary ───────────────────────────────────────────
    if diag.total_packets > 0:
        report.findings.append(DiagnosticFinding(
            title="Traffic Summary",
            severity=Severity.INFO,
            summary=f"Total packets processed: {diag.total_packets:,} "
                    f"({diag.in_ucast_packets + diag.in_nucast_packets:,} received, "
                    f"{diag.out_ucast_packets + diag.out_nucast_packets:,} sent).",
            explanation="This shows the total volume of network traffic this device has handled. "
                        "High numbers just mean the device has been running a while — they are not "
                        "a problem by themselves.",
            recommendation="For reference only — no action needed.",
            raw_value=f"In: {diag.in_octets:,} bytes, Out: {diag.out_octets:,} bytes",
            category="Traffic",
        ))

    # ── 15. IP Configuration Method ──────────────────────────────────────────
    if diag.ip_config_method:
        method = diag.ip_config_method
        if method.upper() in ("DHCP", "DHCP CAPABLE"):
            score -= 10
            report.findings.append(DiagnosticFinding(
                title="IP Address Source: DHCP",
                severity=Severity.WARNING,
                summary="This device is getting its IP address from a DHCP server.",
                explanation="DHCP means the device's IP address is assigned automatically by a DHCP "
                            "server (usually a router or IT server). In industrial networks, this is "
                            "usually a bad idea because:\n\n"
                            "• If the DHCP server goes down, the device may lose its IP address after "
                            "its lease expires.\n"
                            "• If the DHCP server assigns a different IP, the PLC will lose "
                            "communication with this device.\n"
                            "• DHCP adds a dependency on IT infrastructure that the plant floor "
                            "shouldn't depend on.\n\n"
                            "Most industrial Ethernet devices should use static (manually set) IP addresses.",
                recommendation="1. Switch this device to a static IP address.\n"
                               "2. In Studio 5000 or the device's web page, change the IP config "
                               "from DHCP to Static and assign a fixed IP.\n"
                               "3. Make sure the static IP doesn't conflict with the DHCP range.\n"
                               "4. Update the PLC program if the IP address changes.",
                raw_value=f"IP Config Method: {method}",
                category="Network Configuration",
            ))
        elif method.upper() == "BOOTP":
            report.findings.append(DiagnosticFinding(
                title="IP Address Source: BOOTP",
                severity=Severity.INFO,
                summary="This device uses BOOTP for IP address configuration.",
                explanation="BOOTP is the traditional Rockwell Automation method for assigning IP "
                            "addresses. It requires a BOOTP server (like Rockwell's BOOTP/DHCP Tool) "
                            "to be running when the device powers up. Once the address is set, the "
                            "device keeps it until reset. This is a standard and acceptable approach "
                            "for Allen-Bradley devices.",
                recommendation="No action needed. Just make sure the BOOTP utility is available if "
                               "this device is ever factory-reset or replaced.",
                raw_value=f"IP Config Method: {method}",
                category="Network Configuration",
            ))
        elif method.upper() == "STATIC":
            report.findings.append(DiagnosticFinding(
                title="IP Address Source: Static",
                severity=Severity.OK,
                summary="This device has a statically configured IP address — this is the recommended "
                        "configuration for industrial devices.",
                explanation="A static IP address means the IP was manually set and won't change "
                            "unexpectedly. This is the most reliable configuration for production "
                            "automation networks.",
                recommendation="No action needed.",
                raw_value=f"IP Config Method: {method}",
                category="Network Configuration",
            ))
        else:
            report.findings.append(DiagnosticFinding(
                title=f"IP Address Source: {method}",
                severity=Severity.INFO,
                summary=f"This device's IP address configuration method is: {method}.",
                explanation="The tool detected how this device gets its IP address.",
                recommendation="For reference only.",
                raw_value=f"IP Config Method: {method}",
                category="Network Configuration",
            ))

    # ── 16. Auto-Negotiation Check ───────────────────────────────────────────
    if diag.autoneg_enabled >= 0:
        if diag.autoneg_enabled == 1:
            report.findings.append(DiagnosticFinding(
                title="Speed/Duplex: Auto-Negotiate",
                severity=Severity.OK,
                summary="The port is using auto-negotiation — this is the recommended setting.",
                explanation="Auto-negotiation lets the device and the switch agree on the best speed "
                            "and duplex setting automatically. This prevents the duplex mismatches "
                            "that are one of the most common causes of communication faults on "
                            "industrial Ethernet networks. Rockwell Automation recommends "
                            "auto-negotiation for all EtherNet/IP connections.",
                recommendation="No action needed. Make sure the switch port is also set to auto-negotiate.",
                raw_value=f"Auto-Negotiate: Enabled",
                category="Network Configuration",
            ))
        else:
            forced_info = ""
            if diag.forced_speed > 0:
                forced_info = f" (Forced: {diag.forced_speed} Mbps {diag.forced_duplex})"
            score -= 5
            report.findings.append(DiagnosticFinding(
                title="Speed/Duplex: Forced (Auto-Neg OFF)",
                severity=Severity.WARNING,
                summary=f"Auto-negotiation is disabled — speed and duplex are forced{forced_info}.",
                explanation="When auto-negotiation is turned off, the device's speed and duplex are "
                            "manually forced to specific values. This is risky because:\n\n"
                            "• The switch port MUST be set to the exact same speed and duplex.\n"
                            "• If there's a mismatch, you'll get a duplex mismatch which causes "
                            "late collisions, CRC errors, and intermittent communication faults.\n"
                            "• A common mistake is forcing one side but leaving the other on auto — "
                            "this always causes a half-duplex mismatch.\n\n"
                            "Unless there's a specific reason to force settings, auto-negotiate is "
                            "the safer choice.",
                recommendation="1. Switch this device back to auto-negotiate unless you have a "
                               "specific reason not to.\n"
                               "2. If forced settings are required, verify the switch port is set to "
                               "the exact same speed and duplex.\n"
                               "3. NEVER force one side and auto-negotiate the other — this always "
                               "causes a duplex mismatch.",
                raw_value=f"Auto-Negotiate: Disabled{forced_info}",
                category="Network Configuration",
            ))

    # ── 17. ACD — IP Address Conflict Detection ─────────────────────────────
    if diag.acd_conflict_detected:
        score -= 30
        conflict_detail = ""
        if diag.acd_conflict_mac:
            conflict_detail += f"\nConflicting device MAC: {diag.acd_conflict_mac}"
        if diag.acd_conflict_ip:
            conflict_detail += f"\nConflicted IP: {diag.acd_conflict_ip}"
        report.findings.append(DiagnosticFinding(
            title="⚠ IP Address Conflict Detected!",
            severity=Severity.CRITICAL,
            summary="This device has detected another device using the same IP address!",
            explanation="An IP address conflict means two devices on the same network are trying to "
                        "use the same IP address. This is a serious problem that will cause "
                        "intermittent communication failures because network packets get delivered "
                        "to the wrong device randomly.\n\n"
                        "Symptoms of an IP conflict include:\n"
                        "• Communication faults that come and go unpredictably\n"
                        "• Two devices alternately responding to the same address\n"
                        "• PLC connection timeouts that seem random\n\n"
                        "The device's built-in Address Conflict Detection (ACD) has identified the "
                        f"conflicting device.{conflict_detail}",
            recommendation="1. URGENT: Find the other device using this IP address.\n"
                           "2. Use the conflicting MAC address shown above to identify the device — "
                           "search for it in this tool's scan results.\n"
                           "3. Change one of the two devices to a unique IP address.\n"
                           "4. After fixing the conflict, power-cycle both devices to clear ARP caches.",
            raw_value=f"ACD Conflict: True, MAC: {diag.acd_conflict_mac}, "
                      f"IP: {diag.acd_conflict_ip}",
            category="Network Configuration",
        ))
    elif diag.acd_enabled == 1:
        report.findings.append(DiagnosticFinding(
            title="IP Conflict Detection (ACD)",
            severity=Severity.OK,
            summary="Address Conflict Detection is enabled and no conflicts found.",
            explanation="ACD is a safety feature that detects if another device on the network "
                        "is using the same IP address. It's enabled and hasn't detected any "
                        "conflicts — this is good.",
            recommendation="No action needed.",
            raw_value="ACD: Enabled, No Conflicts",
            category="Network Configuration",
        ))
    elif diag.acd_enabled == 0:
        report.findings.append(DiagnosticFinding(
            title="IP Conflict Detection (ACD) Disabled",
            severity=Severity.INFO,
            summary="Address Conflict Detection is turned off on this device.",
            explanation="ACD is a feature that can detect if another device accidentally has the same "
                        "IP address. It's currently disabled, which means IP conflicts won't be "
                        "automatically detected. While not critical, enabling ACD can help catch "
                        "configuration mistakes faster.",
            recommendation="Consider enabling ACD through the device's web page or in Studio 5000.\n"
                           "In RSLinx: Right-click the module → Module Properties → Port Configuration → "
                           "Enable ACD.",
            raw_value="ACD: Disabled",
            category="Network Configuration",
        ))

    # ── 18. Connection Manager Health ────────────────────────────────────────
    if diag.cm_open_requests >= 0:
        total_rejects = (diag.cm_open_format_rejects +
                         diag.cm_open_resource_rejects +
                         diag.cm_open_other_rejects)
        cm_timeouts = diag.cm_connection_timeouts

        # Connection timeouts — the big one
        if cm_timeouts > 0:
            timeout_sev = Severity.CRITICAL if cm_timeouts > 20 else Severity.WARNING
            deduction = 25 if cm_timeouts > 20 else 10
            score -= deduction
            report.findings.append(DiagnosticFinding(
                title="CIP Connection Timeouts",
                severity=timeout_sev,
                summary=f"{cm_timeouts} CIP connections have timed out — this means the device "
                        f"has been losing communication.",
                explanation="A CIP connection timeout means the device stopped hearing from a "
                            "connected controller (PLC, HMI, or scanner) within the expected time "
                            "window. This is what causes the 'I/O connection faulted' or "
                            "'Communication loss' alarms in your PLC.\n\n"
                            "Every timeout shown here represents a real communication interruption. "
                            "Common causes include:\n"
                            "• Network congestion or bandwidth overload\n"
                            "• Bad cables causing packet loss\n"
                            "• The PLC or scanner being overloaded\n"
                            "• Switch problems or network loops\n"
                            "• RPI set too aggressively for the network conditions",
                recommendation="1. Check ALL cables and connections between the PLC and this device.\n"
                               "2. Look at the CRC/collision findings above — physical layer problems "
                               "cause most timeouts.\n"
                               "3. Check the RPI (Requested Packet Interval) — try increasing it.\n"
                               "4. Verify the switch isn't overloaded with traffic.\n"
                               "5. Check if the PLC task is overrunning (maxing out scan time).",
                raw_value=f"Connection Timeouts: {cm_timeouts}, Total Opens: {diag.cm_open_requests}",
                category="CIP Connections",
            ))

        # Resource rejects — device is running out of connections
        if diag.cm_open_resource_rejects > 0:
            score -= 15
            report.findings.append(DiagnosticFinding(
                title="CIP Connection Limit Reached",
                severity=Severity.CRITICAL,
                summary=f"{diag.cm_open_resource_rejects} connection requests rejected — "
                        f"the device has run out of available connections.",
                explanation="This device has rejected incoming connection requests because it "
                            "doesn't have enough resources (connection slots) available. Every "
                            "EtherNet/IP device has a maximum number of CIP connections it can "
                            "handle simultaneously.\n\n"
                            "If connection requests are being rejected, it means something is "
                            "trying to connect but failing — which usually shows up as a "
                            "'Forward Open rejected' error in the PLC.",
                recommendation="1. Check how many connections are going to this device.\n"
                               "2. Review the device's connection limit (shown in module properties).\n"
                               "3. Remove any unnecessary connections (unused HMI polling, extra "
                               "scanners, duplicate connections).\n"
                               "4. If you need more connections, you may need a higher-capacity module.\n"
                               "5. Consider using multicast instead of point-to-point for I/O if applicable.",
                raw_value=f"Resource Rejects: {diag.cm_open_resource_rejects}, "
                          f"Total Opens: {diag.cm_open_requests}",
                category="CIP Connections",
            ))

        # Format rejects — something is misconfigured
        if diag.cm_open_format_rejects > 0:
            score -= 5
            report.findings.append(DiagnosticFinding(
                title="CIP Connection Configuration Errors",
                severity=Severity.WARNING,
                summary=f"{diag.cm_open_format_rejects} connection requests rejected due to "
                        f"incorrect format or parameters.",
                explanation="Something has been trying to open a CIP connection to this device "
                            "with the wrong parameters. This usually means a module configuration "
                            "doesn't match what the device expects — wrong connection size, wrong "
                            "data format, or incompatible firmware revision.\n\n"
                            "This typically happens after replacing a module with a different "
                            "revision, or when the module profile in Studio 5000 doesn't match "
                            "the physical module.",
                recommendation="1. Verify the module configuration in Studio 5000 matches the "
                               "physical device (catalog number, series, revision).\n"
                               "2. Right-click the module → Properties → check the Connection "
                               "settings (size, RPI, type).\n"
                               "3. Try removing and re-adding the module in the I/O tree.\n"
                               "4. Check for firmware mismatches between the project and device.",
                raw_value=f"Format Rejects: {diag.cm_open_format_rejects}",
                category="CIP Connections",
            ))

        # Connection summary if everything is clean
        if total_rejects == 0 and cm_timeouts == 0 and diag.cm_open_requests > 0:
            report.findings.append(DiagnosticFinding(
                title="CIP Connection Manager",
                severity=Severity.OK,
                summary=f"Connection Manager healthy — {diag.cm_open_requests} total connection "
                        f"requests processed with no rejects or timeouts.",
                explanation="The Connection Manager handles all CIP connections to this device "
                            "(from PLCs, HMIs, scanners, etc.). No connections have been rejected "
                            "or timed out, which means all connections are being established and "
                            "maintained successfully.",
                recommendation="No action needed.",
                raw_value=f"Opens: {diag.cm_open_requests}, Rejects: 0, Timeouts: 0",
                category="CIP Connections",
            ))

    # ── 19. TCP Retransmission Analysis ──────────────────────────────────────
    if diag.tcp_segments_sent > 0 and diag.tcp_retransmissions > 0:
        retx_pct = (diag.tcp_retransmissions / diag.tcp_segments_sent) * 100
        if retx_pct > 5:
            score -= 20
            severity = Severity.CRITICAL
        elif retx_pct > 1:
            score -= 10
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        if severity != Severity.INFO:
            report.findings.append(DiagnosticFinding(
                title="TCP Retransmissions",
                severity=severity,
                summary=f"{diag.tcp_retransmissions:,} TCP segments retransmitted "
                        f"({retx_pct:.1f}% of all sent segments).",
                explanation="TCP retransmissions happen when a device sends data and doesn't get an "
                            "acknowledgment back in time, so it sends the data again. A high "
                            "retransmission rate indicates the network is consistently losing "
                            "packets or delivering them too slowly.\n\n"
                            "While TCP recovers from these losses automatically (unlike CIP I/O "
                            "connections), high retransmission rates slow down explicit messaging, "
                            "HMI updates, program uploads/downloads, and any TCP-based communication.",
                recommendation="1. Check the physical layer — most retransmissions are caused by "
                               "packet loss from bad cables or connectors.\n"
                               "2. Look at the CRC/collision findings for underlying causes.\n"
                               "3. Check for network congestion — too much traffic on the same segment.\n"
                               "4. Verify the switch isn't dropping packets due to buffer overflows.",
                raw_value=f"Retransmissions: {diag.tcp_retransmissions:,} / "
                          f"{diag.tcp_segments_sent:,} segments ({retx_pct:.1f}%)",
                category="TCP/IP Health",
            ))

    # ── 20. Multicast Configuration Review ───────────────────────────────────
    if diag.mcast_num_mcast > 0 and diag.mcast_start_addr:
        # High multicast address count can indicate excessive multicast traffic
        if diag.mcast_num_mcast > 32:
            score -= 5
            report.findings.append(DiagnosticFinding(
                title="High Multicast Address Count",
                severity=Severity.WARNING,
                summary=f"This device has {diag.mcast_num_mcast} multicast groups configured "
                        f"(starting at {diag.mcast_start_addr}).",
                explanation="EtherNet/IP uses multicast for I/O data distribution. A high number "
                            "of multicast groups can flood the network with traffic if the switches "
                            "aren't configured with IGMP Snooping to limit where multicast traffic "
                            "goes.\n\n"
                            "Without IGMP Snooping, every multicast packet is sent to EVERY port "
                            "on the switch, even ports that don't need it. This wastes bandwidth "
                            "and can slow down devices that have to process and discard all that "
                            "extra traffic.",
                recommendation="1. Enable IGMP Snooping on all managed switches in the network.\n"
                               "2. Verify IGMP Querier is configured on exactly one switch.\n"
                               "3. Consider using unicast connections where possible to reduce "
                               "multicast traffic.\n"
                               "4. On Stratix switches: Smartport configuration usually enables "
                               "IGMP snooping automatically.",
                raw_value=f"Multicast Groups: {diag.mcast_num_mcast}, "
                          f"Start: {diag.mcast_start_addr}",
                category="Network Configuration",
            ))
        else:
            report.findings.append(DiagnosticFinding(
                title="Multicast Configuration",
                severity=Severity.INFO,
                summary=f"Multicast I/O configured with {diag.mcast_num_mcast} group(s) "
                        f"starting at {diag.mcast_start_addr}.",
                explanation="This device is using multicast addressing for CIP I/O data. "
                            "Multicast is efficient when switches have IGMP Snooping enabled.",
                recommendation="Verify IGMP Snooping is enabled on your switches to prevent "
                               "unnecessary multicast flooding.",
                raw_value=f"Multicast Groups: {diag.mcast_num_mcast}, "
                          f"Start: {diag.mcast_start_addr}",
                category="Network Configuration",
            ))

    # ── 21. Device Info Summary (hostname, gateway, interface) ───────────────
    info_parts = []
    if diag.hostname:
        info_parts.append(f"Hostname: {diag.hostname}")
    if diag.gateway_address:
        info_parts.append(f"Gateway: {diag.gateway_address}")
    if diag.interface_type and diag.interface_type != "Unknown":
        info_parts.append(f"Interface: {diag.interface_type}")
    if diag.interface_label:
        info_parts.append(f"Port: {diag.interface_label}")
    if diag.mac_address:
        info_parts.append(f"MAC: {diag.mac_address}")
    if diag.ttl_value >= 0:
        info_parts.append(f"TTL: {diag.ttl_value}")

    if info_parts:
        report.findings.append(DiagnosticFinding(
            title="Device Network Identity",
            severity=Severity.INFO,
            summary=" | ".join(info_parts),
            explanation="Additional network identity information read from the device's "
                        "TCP/IP and Ethernet Link objects via CIP. This information can help "
                        "identify and document the device.",
            recommendation="For reference only — no action needed.",
            raw_value=", ".join(info_parts),
            category="Device Info",
        ))

    # ── Finalize Report ──────────────────────────────────────────────────────
    score = max(0, min(100, score))
    report.health_score = score

    if score >= 90:
        report.overall_status = "Healthy"
        report.overall_summary = (
            "This device's network connection looks healthy. No significant problems were detected."
        )
    elif score >= 70:
        report.overall_status = "Minor Issues"
        report.overall_summary = (
            "This device has some minor network issues that should be investigated "
            "but are unlikely to cause immediate communication faults."
        )
    elif score >= 50:
        report.overall_status = "Needs Attention"
        report.overall_summary = (
            "This device has network problems that could cause intermittent communication "
            "issues. Review the warnings below and address them soon."
        )
    elif score >= 30:
        report.overall_status = "Significant Problems"
        report.overall_summary = (
            "This device has significant network problems that are likely contributing to "
            "communication faults. The issues below should be addressed as soon as possible."
        )
    else:
        report.overall_status = "Critical"
        report.overall_summary = (
            "This device has critical network problems. Communication faults are expected "
            "with this level of errors. Immediate attention is needed."
        )

    return report


def _analyze_counter(report: DiagnosticReport, title: str, current: int,
                     previous: Optional[int], threshold_warn: int, threshold_crit: int,
                     category: str, ok_summary: str, ok_explanation: str,
                     warn_summary: str, crit_summary: str,
                     explanation: str, recommendation: str,
                     score_tracker: int = 100):
    """Helper to analyze a single counter value and add a finding."""
    delta_note = ""
    if previous is not None and current > previous:
        delta = current - previous
        delta_note = f" ({delta:,} new since last check)"

    if current == 0:
        report.findings.append(DiagnosticFinding(
            title=title, severity=Severity.OK, summary=ok_summary,
            explanation=ok_explanation, recommendation="No action needed.",
            raw_value=f"{title}: {current:,}", category=category,
        ))
    elif current < threshold_warn:
        report.findings.append(DiagnosticFinding(
            title=title, severity=Severity.OK,
            summary=f"Very low count ({current:,}){delta_note} — not a concern.",
            explanation=ok_explanation + " The small number detected is normal and not a problem.",
            recommendation="Monitor periodically. If this number grows rapidly, investigate.",
            raw_value=f"{title}: {current:,}", category=category,
        ))
    elif current < threshold_crit:
        report.findings.append(DiagnosticFinding(
            title=title, severity=Severity.WARNING,
            summary=f"{warn_summary} Count: {current:,}{delta_note}.",
            explanation=explanation,
            recommendation=recommendation,
            raw_value=f"{title}: {current:,}", category=category,
        ))
    else:
        report.findings.append(DiagnosticFinding(
            title=title, severity=Severity.CRITICAL,
            summary=f"{crit_summary} Count: {current:,}{delta_note}.",
            explanation=explanation,
            recommendation=recommendation,
            raw_value=f"{title}: {current:,}", category=category,
        ))


def _get_adjusted_score(base_score: int, counter: int,
                        warn_thresh: int, crit_thresh: int,
                        warn_deduct: int, crit_deduct: int) -> int:
    """Calculate adjusted health score based on a counter value."""
    if counter >= crit_thresh:
        return base_score - crit_deduct
    elif counter >= warn_thresh:
        return base_score - warn_deduct
    return base_score


def continuous_ping_test(ip: str, count: int = 20, interval: float = 0.5,
                         progress_callback=None) -> Tuple[float, float, List[float]]:
    """
    Run a series of pings and calculate average response time and packet loss.
    Returns (avg_ms, loss_percent, list_of_times).
    """
    from core.network_utils import ping_host

    times = []
    successes = 0

    for i in range(count):
        if progress_callback:
            progress_callback(i + 1, count)

        reachable, rtt = ping_host(ip, timeout=2.0)
        if reachable:
            successes += 1
            times.append(rtt)

        if i < count - 1:
            import time
            time.sleep(interval)

    loss_pct = ((count - successes) / count) * 100
    avg_ms = sum(times) / len(times) if times else 0.0

    return avg_ms, loss_pct, times
