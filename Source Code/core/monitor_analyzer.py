"""
SAS Network Diagnostics Tool — Monitor Data Analyzer
Analyzes monitoring data to detect patterns and provide plain-language
diagnostic recommendations for people with basic networking knowledge.

Detects:
  - Packet loss severity and patterns
  - Periodic / recurring dropout cycles
  - Response time degradation trends
  - Response time spikes and jitter
  - Time-of-day correlations
  - Burst error clusters
  - Complete outages vs intermittent drops
  - Device status changes

Each finding includes:
  - Severity (info / warning / critical)
  - Plain-language description of what was found
  - What it likely means
  - Suggested actions to resolve
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from collections import Counter

logger = logging.getLogger(__name__)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single diagnostic finding with a recommendation."""
    severity: str          # "info", "warning", "critical"
    title: str             # Short headline
    description: str       # What was observed (plain language)
    likely_cause: str      # What this typically means
    suggestion: str        # What to do about it
    category: str = ""     # "availability", "latency", "pattern", "stability"
    metric_value: str = "" # Key metric (e.g., "12.3% packet loss")

    @property
    def icon(self) -> str:
        return {"info": "ℹ️", "warning": "⚠️", "critical": "🔴"}.get(
            self.severity, "ℹ️")


@dataclass
class AnalysisReport:
    """Complete analysis of a monitoring session."""
    target_ip: str
    product_name: str = ""
    monitoring_duration: str = ""
    sample_count: int = 0
    generated_at: str = ""

    # Summary
    health_score: int = 100         # 0-100 overall health
    health_label: str = "Healthy"   # "Healthy", "Degraded", "Unstable", "Critical"
    summary: str = ""               # 2-3 sentence plain-language summary

    # Detailed findings
    findings: List[Finding] = field(default_factory=list)

    # Key metrics for display
    uptime_pct: float = 100.0
    avg_response_ms: float = 0.0
    packet_loss_pct: float = 0.0
    outage_count: int = 0
    longest_outage: str = ""


# ── Analyzer Engine ──────────────────────────────────────────────────────────

class MonitorAnalyzer:
    """
    Analyzes collected monitoring samples and produces a diagnostic report
    with plain-language findings and recommendations.
    """

    def __init__(self):
        pass

    def analyze(self, samples, outages, stats, target_ip: str) -> AnalysisReport:
        """
        Run full analysis on monitoring data.

        Args:
            samples: List of PollSample from the monitor engine
            outages: List of OutageEvent from the monitor engine
            stats: MonitorStats from the monitor engine
            target_ip: IP address being monitored

        Returns:
            AnalysisReport with findings and recommendations
        """
        report = AnalysisReport(
            target_ip=target_ip,
            sample_count=stats.total_samples,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        if not samples:
            report.summary = "No data collected. Start monitoring to collect diagnostic data."
            report.health_label = "No Data"
            report.health_score = 0
            return report

        # Device identity
        for s in reversed(samples):
            if s.product_name:
                report.product_name = s.product_name
                break

        # Duration
        duration_sec = stats.duration_seconds
        report.monitoring_duration = self._format_duration(duration_sec)

        # Key metrics
        report.uptime_pct = stats.uptime_pct
        report.avg_response_ms = stats.ping_avg_ms if stats.ping_avg_ms > 0 else stats.cip_avg_ms
        report.packet_loss_pct = stats.ping_loss_pct if stats.ping_sent > 0 else stats.cip_loss_pct
        report.outage_count = stats.outage_count
        report.longest_outage = self._format_duration(stats.longest_outage_sec)

        # ── Run all detection checks ──
        findings = []

        findings.extend(self._check_availability(samples, stats, outages))
        findings.extend(self._check_packet_loss(samples, stats))
        findings.extend(self._check_response_times(samples, stats))
        findings.extend(self._check_response_time_trend(samples, stats))
        findings.extend(self._check_jitter(samples, stats))
        findings.extend(self._check_periodic_drops(samples, stats))
        findings.extend(self._check_burst_errors(samples))
        findings.extend(self._check_time_of_day(samples))
        findings.extend(self._check_device_status_changes(samples))
        findings.extend(self._check_outage_patterns(outages))

        # If nothing wrong, add a clean bill of health
        if not findings:
            findings.append(Finding(
                severity="info",
                title="Connection Healthy",
                description=(
                    f"Over {report.monitoring_duration} of monitoring, the device "
                    f"responded to every poll with an average response time of "
                    f"{report.avg_response_ms:.1f}ms."
                ),
                likely_cause="The network path to this device is stable.",
                suggestion="No action needed. Save this as a baseline for future comparison.",
                category="availability",
            ))

        # Sort findings: critical first, then warning, then info
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 3))

        report.findings = findings

        # ── Health Score ──
        report.health_score = self._calculate_health_score(stats, findings)
        report.health_label = self._health_label(report.health_score)

        # ── Summary ──
        report.summary = self._build_summary(report, stats, findings)

        return report

    # ── Availability Checks ──────────────────────────────────────────────

    def _check_availability(self, samples, stats, outages) -> List[Finding]:
        findings = []
        uptime = stats.uptime_pct

        if uptime >= 99.9:
            return []  # No issues

        if uptime < 50:
            findings.append(Finding(
                severity="critical",
                title="Device Mostly Unreachable",
                description=(
                    f"The device was only reachable {uptime:.1f}% of the time during "
                    f"monitoring. Out of {stats.total_samples} polls, "
                    f"{stats.total_samples - stats.ping_success} failed."
                ),
                likely_cause=(
                    "This level of unavailability usually means a fundamental "
                    "connectivity problem — bad cable, wrong IP address, device powered off, "
                    "or a firewall/VLAN blocking traffic."
                ),
                suggestion=(
                    "1. Verify the IP address is correct and the device is powered on\n"
                    "2. Check the cable run end-to-end — look for damage, loose connectors\n"
                    "3. Verify you're on the same subnet (or that routing is correct)\n"
                    "4. Check if a managed switch port shows link/activity LEDs\n"
                    "5. Try pinging from a different PC on the same network to isolate the issue"
                ),
                category="availability",
                metric_value=f"{uptime:.1f}% uptime",
            ))

        elif uptime < 90:
            findings.append(Finding(
                severity="critical",
                title="Significant Communication Failures",
                description=(
                    f"The device was reachable only {uptime:.1f}% of the time. "
                    f"There were {stats.outage_count} outage event(s), with the "
                    f"longest lasting {self._format_duration(stats.longest_outage_sec)}."
                ),
                likely_cause=(
                    "Frequent drops at this rate often indicate a physical layer problem: "
                    "a cable with an intermittent short or break, a bad patch cable, "
                    "a failing switch port, or a loose connector on the device."
                ),
                suggestion=(
                    "1. Inspect the Ethernet cable from the device to the switch — "
                    "look for kinks, crushed sections, and loose RJ45 connectors\n"
                    "2. Try swapping the patch cable\n"
                    "3. Try a different port on the switch\n"
                    "4. Check the switch port error counters (CRC errors, runts, giants)\n"
                    "5. If the cable run is long (>50m), consider a cable tester"
                ),
                category="availability",
                metric_value=f"{uptime:.1f}% uptime",
            ))

        elif uptime < 99:
            findings.append(Finding(
                severity="warning",
                title="Intermittent Communication Drops",
                description=(
                    f"The device was reachable {uptime:.1f}% of the time. "
                    f"{stats.outage_count} brief dropout(s) were detected."
                ),
                likely_cause=(
                    "Occasional drops like this are often caused by: EMI from nearby "
                    "VFDs/motors, marginal cable connections, network congestion or "
                    "broadcast storms, or the device briefly going busy (firmware updates, "
                    "heavy processing)."
                ),
                suggestion=(
                    "1. Check if drops correlate with machinery starting/stopping (see timing analysis below)\n"
                    "2. Inspect cable connections at both ends\n"
                    "3. Check switch port counters for errors\n"
                    "4. If near VFDs, ensure shielded cable is used with proper grounding"
                ),
                category="availability",
                metric_value=f"{uptime:.1f}% uptime",
            ))

        return findings

    # ── Packet Loss ──────────────────────────────────────────────────────

    def _check_packet_loss(self, samples, stats) -> List[Finding]:
        findings = []
        loss = stats.ping_loss_pct if stats.ping_sent > 0 else stats.cip_loss_pct

        if loss <= 0.5:
            return []

        if loss > 0.5 and loss <= 3:
            findings.append(Finding(
                severity="warning",
                title="Low-Level Packet Loss Detected",
                description=(
                    f"Packet loss is at {loss:.1f}%. While the device is mostly reachable, "
                    f"some polls are being lost."
                ),
                likely_cause=(
                    "Low-level loss like this is often caused by network congestion, "
                    "marginal cable quality, or EMI. It may not cause visible problems "
                    "yet, but it indicates the connection is not clean."
                ),
                suggestion=(
                    "1. Check the switch port for CRC errors or collisions\n"
                    "2. Verify the cable is Cat5e or better and not running alongside power cables\n"
                    "3. Check if the device and switch are set to the same speed/duplex\n"
                    "4. Monitor over a longer period to see if it worsens"
                ),
                category="availability",
                metric_value=f"{loss:.1f}% loss",
            ))

        elif loss > 3 and loss <= 10:
            findings.append(Finding(
                severity="warning",
                title="Moderate Packet Loss",
                description=(
                    f"Packet loss is {loss:.1f}%, which is high enough to cause "
                    f"noticeable communication issues — PLC tag reads may fail, "
                    f"HMI screens may flash 'comm loss' intermittently."
                ),
                likely_cause=(
                    "Moderate loss is commonly caused by: duplex mismatch (one side "
                    "at half-duplex), a failing network cable, an overloaded switch, "
                    "or significant EMI interference."
                ),
                suggestion=(
                    "1. Check speed/duplex settings on both the device and switch port — force both to the same setting\n"
                    "2. Replace the Ethernet cable\n"
                    "3. Check the switch CPU utilization and port error counters\n"
                    "4. Ensure network segmentation — keep control traffic separate from office traffic"
                ),
                category="availability",
                metric_value=f"{loss:.1f}% loss",
            ))

        return findings

    # ── Response Times ───────────────────────────────────────────────────

    def _check_response_times(self, samples, stats) -> List[Finding]:
        findings = []

        avg = stats.ping_avg_ms if stats.ping_avg_ms > 0 else stats.cip_avg_ms
        p95 = stats.ping_p95_ms if stats.ping_p95_ms > 0 else stats.cip_p95_ms
        max_rt = stats.ping_max_ms if stats.ping_max_ms > 0 else stats.cip_max_ms

        if avg <= 0:
            return []

        # Check for high average response time
        if avg > 100:
            findings.append(Finding(
                severity="critical",
                title="Very High Response Times",
                description=(
                    f"Average response time is {avg:.0f}ms (normal for industrial "
                    f"Ethernet is under 10ms). The 95th percentile is {p95:.0f}ms."
                ),
                likely_cause=(
                    "Response times this high on a local industrial network usually indicate: "
                    "network congestion (too much traffic), the device is overloaded, "
                    "traffic is being routed through too many hops, or there's a "
                    "speed/duplex mismatch causing retransmissions."
                ),
                suggestion=(
                    "1. Check if the device and switch are both at 100Mbps Full Duplex\n"
                    "2. Use a managed switch to check port utilization — look for ports over 50% utilized\n"
                    "3. Check if broadcast storms are present (broadcast traffic > 5% of total)\n"
                    "4. Verify the device isn't overloaded (check its CPU/memory if accessible)\n"
                    "5. Consider network segmentation with VLANs"
                ),
                category="latency",
                metric_value=f"{avg:.0f}ms avg",
            ))

        elif avg > 20:
            findings.append(Finding(
                severity="warning",
                title="Elevated Response Times",
                description=(
                    f"Average response time is {avg:.0f}ms. For a local industrial "
                    f"network, this is higher than expected. Peak was {max_rt:.0f}ms."
                ),
                likely_cause=(
                    "Slightly elevated times can be caused by: network congestion during "
                    "peak production, the device being busy with other tasks, or "
                    "suboptimal network architecture (too many devices on one subnet)."
                ),
                suggestion=(
                    "1. Compare with other devices on the same network — if all are slow, it's network-wide\n"
                    "2. Check switch port utilization during production hours\n"
                    "3. Ensure industrial and office traffic are on separate VLANs\n"
                    "4. This may be acceptable if the device functions normally — save as baseline"
                ),
                category="latency",
                metric_value=f"{avg:.0f}ms avg",
            ))

        # Check for large gap between average and peak
        if max_rt > avg * 10 and max_rt > 50 and avg > 0:
            findings.append(Finding(
                severity="warning",
                title="Response Time Spikes",
                description=(
                    f"While the average response time is {avg:.1f}ms, there were spikes "
                    f"up to {max_rt:.0f}ms — that's {max_rt/avg:.0f}x the average."
                ),
                likely_cause=(
                    "Occasional spikes with a low average usually mean something is "
                    "temporarily congesting the network or the device is briefly "
                    "busy. Common causes: large file transfers, firmware updates, "
                    "PLC scan time spikes, or broadcast storms."
                ),
                suggestion=(
                    "1. Look at when the spikes occurred — do they correlate with specific events?\n"
                    "2. Check if someone is uploading/downloading programs during production\n"
                    "3. Check for broadcast storms using the switch's traffic counters\n"
                    "4. If spikes are rare and the device works fine, this may be acceptable"
                ),
                category="latency",
                metric_value=f"{max_rt:.0f}ms peak",
            ))

        return findings

    # ── Response Time Trend (Degradation) ────────────────────────────────

    def _check_response_time_trend(self, samples, stats) -> List[Finding]:
        """Check if response times are getting worse over the monitoring period."""
        findings = []

        successful = [s for s in samples if s.ping_success or s.cip_success]
        if len(successful) < 20:
            return []  # Need enough data for trend analysis

        # Split into first quarter and last quarter
        quarter = len(successful) // 4
        first_q = successful[:quarter]
        last_q = successful[-quarter:]

        def avg_rt(slist):
            times = [s.ping_time_ms if s.ping_success else s.cip_time_ms for s in slist]
            return sum(times) / len(times) if times else 0

        first_avg = avg_rt(first_q)
        last_avg = avg_rt(last_q)

        if first_avg <= 0:
            return []

        pct_change = ((last_avg - first_avg) / first_avg) * 100

        if pct_change > 50 and last_avg > 10:
            findings.append(Finding(
                severity="warning",
                title="Response Times Getting Worse Over Time",
                description=(
                    f"Response times increased {pct_change:.0f}% during the monitoring period. "
                    f"Early average: {first_avg:.1f}ms → Recent average: {last_avg:.1f}ms."
                ),
                likely_cause=(
                    "A steady increase in response times over time can indicate: "
                    "growing network congestion (more traffic), a device memory leak "
                    "or resource exhaustion, thermal issues causing hardware degradation, "
                    "or cable quality degradation from heat/vibration."
                ),
                suggestion=(
                    "1. Check if network traffic is increasing — new devices added? Large data transfers?\n"
                    "2. Monitor the device's built-in diagnostics (if available) for memory/CPU trends\n"
                    "3. Check the ambient temperature near the device and switch\n"
                    "4. If the trend continues, schedule maintenance to inspect cables and hardware\n"
                    "5. Run a longer monitoring session to confirm the trend"
                ),
                category="stability",
                metric_value=f"+{pct_change:.0f}% over session",
            ))

        return findings

    # ── Jitter ───────────────────────────────────────────────────────────

    def _check_jitter(self, samples, stats) -> List[Finding]:
        """Check for excessive response time variability."""
        findings = []

        jitter = stats.ping_jitter_ms
        avg = stats.ping_avg_ms

        if avg <= 0 or jitter <= 0:
            return []

        # Jitter > 50% of average is concerning for industrial
        if jitter > avg * 0.5 and jitter > 5:
            findings.append(Finding(
                severity="warning",
                title="High Response Time Variability (Jitter)",
                description=(
                    f"Response time jitter is {jitter:.1f}ms with an average of {avg:.1f}ms. "
                    f"Response times are varying a lot from poll to poll."
                ),
                likely_cause=(
                    "High jitter usually means the network is experiencing variable "
                    "congestion. This is common on flat (unsegmented) networks where "
                    "control traffic competes with other traffic. It can also be caused "
                    "by QoS misconfigurations or an overloaded device."
                ),
                suggestion=(
                    "1. Segment the network — put control devices on a dedicated VLAN\n"
                    "2. Enable QoS on managed switches to prioritize CIP/EtherNet/IP traffic\n"
                    "3. Check for bandwidth hogs (cameras, file transfers) on the same switch\n"
                    "4. Verify all ports are running at full duplex"
                ),
                category="latency",
                metric_value=f"{jitter:.1f}ms jitter",
            ))

        return findings

    # ── Periodic Drop Detection ──────────────────────────────────────────

    def _check_periodic_drops(self, samples, stats) -> List[Finding]:
        """Detect if drops happen at regular intervals (suggesting a recurring cause)."""
        findings = []

        # Get timestamps of failed samples
        fail_times = [s.elapsed_seconds for s in samples if not s.is_reachable]

        if len(fail_times) < 3:
            return []

        # Calculate intervals between consecutive failures
        intervals = []
        for i in range(1, len(fail_times)):
            interval = fail_times[i] - fail_times[i - 1]
            # Only consider gaps > poll interval (skip consecutive failures)
            if interval > stats.duration_seconds / stats.total_samples * 2:
                intervals.append(interval)

        if len(intervals) < 2:
            return []

        # Check for periodicity: are intervals clustered around a common value?
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval <= 0:
            return []

        # Calculate coefficient of variation
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / avg_interval if avg_interval > 0 else 999

        # If CV < 0.3, the intervals are fairly regular → periodic pattern
        if cv < 0.3 and len(intervals) >= 3:
            period_str = self._format_duration(avg_interval)
            findings.append(Finding(
                severity="warning",
                title="Drops Occurring at Regular Intervals",
                description=(
                    f"Communication drops are happening approximately every "
                    f"{period_str}. This periodic pattern was detected across "
                    f"{len(intervals) + 1} failure events."
                ),
                likely_cause=(
                    f"Periodic drops every ~{period_str} strongly suggest a recurring "
                    "cause rather than random cable issues. Common causes:\n"
                    "• A machine or motor cycling on/off at that interval (EMI)\n"
                    "• A scheduled network task (backup, polling cycle)\n"
                    "• A PLC program scan or scheduled task timing\n"
                    "• Spanning Tree Protocol reconvergence"
                ),
                suggestion=(
                    f"1. Ask the operators: 'Is there anything that cycles every ~{period_str}?'\n"
                    "2. Check for VFDs, compressors, or heaters that cycle near the device\n"
                    "3. Look at switch logs for Spanning Tree topology changes\n"
                    "4. Check if any scheduled tasks (backups, polling) match the interval\n"
                    "5. If EMI is suspected, check cable routing and shielding"
                ),
                category="pattern",
                metric_value=f"~{period_str} cycle",
            ))

        return findings

    # ── Burst Error Detection ────────────────────────────────────────────

    def _check_burst_errors(self, samples) -> List[Finding]:
        """Detect clusters of failures (as opposed to evenly distributed)."""
        findings = []

        if len(samples) < 10:
            return []

        # Identify contiguous failure blocks
        blocks = []
        in_block = False
        block_start = 0
        block_count = 0

        for i, s in enumerate(samples):
            if not s.is_reachable:
                if not in_block:
                    in_block = True
                    block_start = i
                    block_count = 1
                else:
                    block_count += 1
            else:
                if in_block:
                    blocks.append((block_start, block_count))
                    in_block = False
                    block_count = 0

        if in_block:
            blocks.append((block_start, block_count))

        if not blocks:
            return []

        # Check for large burst blocks (many consecutive failures)
        large_bursts = [b for b in blocks if b[1] >= 3]  # 3+ consecutive failures
        total_failures = sum(1 for s in samples if not s.is_reachable)

        if large_bursts and total_failures >= 5:
            max_burst = max(b[1] for b in large_bursts)
            burst_time = max_burst * (
                samples[1].elapsed_seconds - samples[0].elapsed_seconds
                if len(samples) > 1 else 2
            )

            findings.append(Finding(
                severity="warning",
                title="Failures Happening in Bursts",
                description=(
                    f"Instead of random individual drops, failures cluster into bursts. "
                    f"The longest burst was {max_burst} consecutive failures "
                    f"(~{self._format_duration(burst_time)}). "
                    f"There were {len(large_bursts)} burst(s) of 3+ failures."
                ),
                likely_cause=(
                    "Burst failures (as opposed to scattered random drops) usually indicate "
                    "a temporary but complete loss of connection: a loose cable being "
                    "disturbed by vibration, a switch port flapping, a device rebooting, "
                    "or a power interruption to the device or switch."
                ),
                suggestion=(
                    "1. Check for loose cable connections — gently wiggle each end while monitoring\n"
                    "2. Check switch port logs for link up/down events\n"
                    "3. Check if the device has a power monitoring feature — look for brownouts\n"
                    "4. If the device is on a vibrating machine, secure the cable with strain relief\n"
                    "5. Check if the device's Link LED flickers during an outage"
                ),
                category="pattern",
                metric_value=f"{max_burst} consecutive failures",
            ))

        return findings

    # ── Time-of-Day Analysis ─────────────────────────────────────────────

    def _check_time_of_day(self, samples) -> List[Finding]:
        """Check if failures correlate with specific times of day."""
        findings = []

        if len(samples) < 30:
            return []

        # Need at least 30 min of data to see time patterns
        duration = (samples[-1].timestamp - samples[0].timestamp).total_seconds()
        if duration < 1800:
            return []

        # Bucket failures by hour
        fail_by_hour = Counter()
        total_by_hour = Counter()

        for s in samples:
            hour = s.timestamp.hour
            total_by_hour[hour] += 1
            if not s.is_reachable:
                fail_by_hour[hour] += 1

        # Find hours with significantly higher failure rates
        total_fail_rate = sum(fail_by_hour.values()) / len(samples) if samples else 0

        if total_fail_rate <= 0:
            return []

        problem_hours = []
        for hour in sorted(total_by_hour.keys()):
            count = total_by_hour[hour]
            fails = fail_by_hour.get(hour, 0)
            if count >= 5:  # Need enough samples in that hour
                rate = fails / count
                if rate > total_fail_rate * 2 and fails >= 3:
                    problem_hours.append((hour, rate * 100, fails))

        if problem_hours:
            hour_strs = [f"{h[0]:02d}:00 ({h[1]:.0f}% fail rate)" for h in problem_hours]
            findings.append(Finding(
                severity="warning",
                title="Failures Concentrated at Specific Times",
                description=(
                    f"Communication failures are more frequent during certain hours:\n"
                    f"{', '.join(hour_strs)}\n"
                    f"This is significantly above the overall failure rate of "
                    f"{total_fail_rate*100:.1f}%."
                ),
                likely_cause=(
                    "Time-correlated failures often indicate:\n"
                    "• Shift changes (doors opening/closing, machines starting up)\n"
                    "• Scheduled processes (backups, report generation, large data transfers)\n"
                    "• Thermal issues (equipment warming up during the day)\n"
                    "• Peak production causing more EMI from motors/VFDs"
                ),
                suggestion=(
                    "1. Ask operators what changes at those times — shift changes? Specific machines?\n"
                    "2. Check if IT runs backups or updates during those hours\n"
                    "3. Check ambient temperature trends — does the panel get hot in the afternoon?\n"
                    "4. Monitor switch traffic levels during problem hours vs quiet hours"
                ),
                category="pattern",
                metric_value=f"Peak at {problem_hours[0][0]:02d}:00",
            ))

        return findings

    # ── Device Status Changes ────────────────────────────────────────────

    def _check_device_status_changes(self, samples) -> List[Finding]:
        """Check if the device's CIP status word changed during monitoring."""
        findings = []

        statuses = [(s.timestamp, s.device_status, s.device_status_text)
                     for s in samples if s.cip_success and s.device_status_text]

        if len(statuses) < 2:
            return []

        # Find unique status values
        unique_statuses = set(s[1] for s in statuses)
        if len(unique_statuses) <= 1:
            return []

        # Build timeline of changes
        changes = []
        last_status = statuses[0][1]
        for ts, status, text in statuses[1:]:
            if status != last_status:
                changes.append((ts, status, text))
                last_status = status

        if changes:
            change_list = [f"  {c[0].strftime('%H:%M:%S')}: {c[2]}" for c in changes[:5]]
            findings.append(Finding(
                severity="warning",
                title="Device Status Changed During Monitoring",
                description=(
                    f"The device's internal status changed {len(changes)} time(s):\n"
                    + "\n".join(change_list)
                    + ("\n  ..." if len(changes) > 5 else "")
                ),
                likely_cause=(
                    "Status changes can indicate the device is experiencing faults, "
                    "losing and regaining I/O connections, or transitioning between "
                    "operating modes. Check the specific status messages above."
                ),
                suggestion=(
                    "1. Review the status messages — 'Major Fault' or 'Minor Fault' need attention\n"
                    "2. Check the device's own diagnostic page or faceplate LEDs\n"
                    "3. If status oscillates between 'Run' and 'Idle', check the controller program\n"
                    "4. Document these changes to share with Rockwell tech support if needed"
                ),
                category="stability",
                metric_value=f"{len(changes)} changes",
            ))

        return findings

    # ── Outage Pattern Analysis ──────────────────────────────────────────

    def _check_outage_patterns(self, outages) -> List[Finding]:
        """Analyze outage events for patterns."""
        findings = []

        if not outages:
            return []

        # Report on recovery times
        recovered = [o for o in outages if not o.is_ongoing and o.recovery_time_ms > 0]
        if recovered:
            avg_recovery = sum(o.recovery_time_ms for o in recovered) / len(recovered)
            max_outage = max(o.duration_seconds for o in outages)

            if max_outage > 60:
                findings.append(Finding(
                    severity="critical",
                    title=f"Extended Outage Detected ({self._format_duration(max_outage)})",
                    description=(
                        f"The longest continuous outage lasted {self._format_duration(max_outage)}. "
                        f"During this time, neither ping nor CIP Identity succeeded."
                    ),
                    likely_cause=(
                        "An outage lasting over a minute is typically caused by: "
                        "device reboot, power loss, cable disconnection, or a network "
                        "infrastructure failure (switch/router issue)."
                    ),
                    suggestion=(
                        "1. Check device power supply — is it on a UPS?\n"
                        "2. Check switch power and uptime\n"
                        "3. Review device event logs for reboot or fault events\n"
                        "4. If the device has a web interface, check its uptime counter\n"
                        "5. Install a UPS or add power monitoring to catch future power events"
                    ),
                    category="availability",
                    metric_value=self._format_duration(max_outage),
                ))

        return findings

    # ── Health Score ─────────────────────────────────────────────────────

    def _calculate_health_score(self, stats, findings) -> int:
        """Calculate a 0-100 health score based on findings."""
        score = 100

        # Deduct for packet loss
        if stats.ping_loss_pct > 0:
            score -= min(40, stats.ping_loss_pct * 4)

        # Deduct for high response times
        avg_rt = stats.ping_avg_ms if stats.ping_avg_ms > 0 else stats.cip_avg_ms
        if avg_rt > 100:
            score -= 20
        elif avg_rt > 50:
            score -= 10
        elif avg_rt > 20:
            score -= 5

        # Deduct for outages
        score -= min(30, stats.outage_count * 5)

        # Deduct for critical findings
        critical_count = sum(1 for f in findings if f.severity == "critical")
        warning_count = sum(1 for f in findings if f.severity == "warning")
        score -= critical_count * 15
        score -= warning_count * 5

        return max(0, min(100, int(score)))

    def _health_label(self, score: int) -> str:
        if score >= 90:
            return "Healthy"
        elif score >= 70:
            return "Degraded"
        elif score >= 40:
            return "Unstable"
        else:
            return "Critical"

    # ── Summary Builder ──────────────────────────────────────────────────

    def _build_summary(self, report, stats, findings) -> str:
        """Build a 2-3 sentence plain-language summary."""
        critical = [f for f in findings if f.severity == "critical"]
        warnings = [f for f in findings if f.severity == "warning"]

        device_str = f" ({report.product_name})" if report.product_name else ""
        duration_str = report.monitoring_duration

        if not critical and not warnings:
            return (
                f"After monitoring {report.target_ip}{device_str} for {duration_str}, "
                f"the connection appears healthy. Average response time is "
                f"{report.avg_response_ms:.1f}ms with no significant issues detected."
            )

        parts = [f"Monitored {report.target_ip}{device_str} for {duration_str}."]

        if report.uptime_pct < 100:
            parts.append(
                f"Uptime was {report.uptime_pct:.1f}% with "
                f"{report.outage_count} outage event(s)."
            )

        if critical:
            parts.append(
                f"Found {len(critical)} critical issue(s): "
                + "; ".join(f.title for f in critical[:2]) + "."
            )
        elif warnings:
            parts.append(
                f"Found {len(warnings)} issue(s) worth investigating: "
                + "; ".join(f.title for f in warnings[:2]) + "."
            )

        return " ".join(parts)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds into human-readable duration."""
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
