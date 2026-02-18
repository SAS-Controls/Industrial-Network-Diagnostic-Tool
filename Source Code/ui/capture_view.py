"""
SAS Network Diagnostics Tool — Packet Capture View
Live packet capture with automated traffic analysis.

Features:
  - Interface selection and capture configuration
  - Timed capture with live progress
  - Protocol breakdown donut chart
  - Top talkers horizontal bar chart
  - Timeline of notable events during capture
  - Findings cards with plain-English explanations
  - Health score gauge
  - PDF export
"""

import logging
import math
import os
import threading
import tkinter as tk
from datetime import datetime
from typing import Optional, List, Dict

import customtkinter as ctk

from core.capture_engine import (
    CaptureEngine, CaptureConfig, CaptureResult,
    CaptureInterface,
)
from core.capture_analyzer import (
    analyze_capture, CaptureAnalysis, CaptureFinding,
    TimelineEvent, Severity,
)
from ui.theme import *
from ui.widgets import HealthGauge, FindingCard, InfoCard, ScanProgressBar, enable_touch_scroll

logger = logging.getLogger(__name__)

# ── Chart Colors ──────────────────────────────────────────────────────────────

PROTOCOL_COLORS = [
    "#3B82F6",  # Blue
    "#22C55E",  # Green
    "#F59E0B",  # Amber
    "#EF4444",  # Red
    "#8B5CF6",  # Purple
    "#EC4899",  # Pink
    "#06B6D4",  # Cyan
    "#F97316",  # Orange
    "#14B8A6",  # Teal
    "#6366F1",  # Indigo
    "#A855F7",  # Violet
    "#84CC16",  # Lime
]

CHART_BG = ("#E0E3E8", "#0D1117")

SEVERITY_COLORS_MAP = {
    Severity.CRITICAL: STATUS_ERROR,
    Severity.WARNING: STATUS_WARN,
    Severity.INFO: STATUS_INFO,
    Severity.OK: STATUS_GOOD,
}

TIMELINE_ICONS = {
    "broadcast_burst": "📡",
    "arp_conflict": "⚠️",
    "stp_topology_change": "🔄",
    "retransmission_burst": "🔁",
    "multicast_burst": "📢",
}


class PacketCaptureView(ctk.CTkFrame):
    """
    Packet Capture tab — capture traffic and analyze it automatically.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._engine = CaptureEngine()
        self._interfaces: List[CaptureInterface] = []
        self._analysis: Optional[CaptureAnalysis] = None
        self._capturing = False
        self._capture_iface = None  # Interface used for last capture

        self._build_ui()
        self._interfaces_loaded = False

    def on_show(self):
        """Called when view becomes visible — safe to use self.after()."""
        if not self._interfaces_loaded:
            self._update_status()
            self._load_interfaces()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        """Build the complete capture view."""
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BG_MEDIUM,
            scrollbar_button_hover_color=SAS_BLUE)
        self._scroll.pack(fill="both", expand=True)
        enable_touch_scroll(self._scroll)
        inner = self._scroll

        # ── Header ──────────────────────────────────────────────────────────
        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 0))

        ctk.CTkLabel(header, text="Packet Capture & Analysis",
                     font=(FONT_FAMILY, FONT_SIZE_TITLE, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            side="left", fill="x", expand=True)

        ctk.CTkLabel(header,
                     text="Capture network traffic and automatically detect problems",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w").pack(
            side="left", padx=(12, 0))

        # ── Status Bar ────────────────────────────────────────────────────
        self._status_frame = ctk.CTkFrame(inner, fg_color=BG_CARD,
                                           corner_radius=CARD_CORNER_RADIUS,
                                           border_width=1, border_color=BORDER_COLOR)
        self._status_frame.pack(fill="x", padx=20, pady=(12, 0))

        self._status_label = ctk.CTkLabel(
            self._status_frame, text="Ready",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY, anchor="w")
        self._status_label.pack(fill="x", padx=CARD_PADDING, pady=12)

        # ── Configuration Panel ─────────────────────────────────────────────
        config_card = ctk.CTkFrame(inner, fg_color=BG_CARD,
                                    corner_radius=CARD_CORNER_RADIUS,
                                    border_width=1, border_color=BORDER_COLOR)
        config_card.pack(fill="x", padx=20, pady=(12, 0))

        ctk.CTkLabel(config_card, text="CAPTURE SETTINGS",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(12, 8))

        # Row 1: Interface + Duration
        row1 = ctk.CTkFrame(config_card, fg_color="transparent")
        row1.pack(fill="x", padx=CARD_PADDING, pady=(0, 4))

        # Interface
        iface_frame = ctk.CTkFrame(row1, fg_color="transparent")
        iface_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(iface_frame, text="Network Interface",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w").pack(fill="x")

        self._iface_var = ctk.StringVar(value="Select interface...")
        iface_row = ctk.CTkFrame(iface_frame, fg_color="transparent")
        iface_row.pack(fill="x", pady=(4, 0))

        self._iface_dropdown = ctk.CTkComboBox(
            iface_row, variable=self._iface_var,
            values=["Loading..."],
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            dropdown_font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            button_color=SAS_BLUE, button_hover_color=SAS_BLUE_DARK,
            width=400, height=INPUT_HEIGHT, state="readonly",
        )
        self._iface_dropdown.pack(side="left")

        self._iface_refresh_btn = ctk.CTkButton(
            iface_row, text="↻ Refresh", font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY, hover_color=BG_CARD_HOVER,
            width=100, height=INPUT_HEIGHT,
            command=self._refresh_interfaces,
        )
        self._iface_refresh_btn.pack(side="left", padx=(8, 0))

        # Duration
        dur_frame = ctk.CTkFrame(row1, fg_color="transparent")
        dur_frame.pack(side="left", padx=(24, 0))

        ctk.CTkLabel(dur_frame, text="Capture Duration",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w").pack(fill="x")

        dur_row = ctk.CTkFrame(dur_frame, fg_color="transparent")
        dur_row.pack(fill="x", pady=4)

        self._duration_var = ctk.StringVar(value="30")
        self._duration_dropdown = ctk.CTkComboBox(
            dur_row, variable=self._duration_var,
            values=["15", "30", "60", "120", "300"],
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            button_color=SAS_BLUE, button_hover_color=SAS_BLUE_DARK,
            width=100, height=INPUT_HEIGHT, state="readonly",
        )
        self._duration_dropdown.pack(side="left")

        ctk.CTkLabel(dur_row, text="seconds",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_MUTED).pack(side="left", padx=(6, 0))

        # Row 2: Buttons
        row2 = ctk.CTkFrame(config_card, fg_color="transparent")
        row2.pack(fill="x", padx=CARD_PADDING, pady=(8, 12))

        self._start_btn = ctk.CTkButton(
            row2, text="▶  Start Capture",
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            height=BUTTON_HEIGHT, corner_radius=BUTTON_CORNER_RADIUS,
            width=180, command=self._start_capture,
        )
        self._start_btn.pack(side="left")

        self._stop_btn = ctk.CTkButton(
            row2, text="⬛  Stop",
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=STATUS_ERROR, hover_color="#DC2626",
            height=BUTTON_HEIGHT, corner_radius=BUTTON_CORNER_RADIUS,
            width=120, command=self._stop_capture, state="disabled",
        )
        self._stop_btn.pack(side="left", padx=(8, 0))

        self._export_btn = ctk.CTkButton(
            row2, text="📄  Export Report",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_MEDIUM, hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY,
            height=BUTTON_HEIGHT, corner_radius=BUTTON_CORNER_RADIUS,
            width=160, command=self._export_report, state="disabled",
        )
        self._export_btn.pack(side="right")

        # Progress bar
        self._progress_frame = ctk.CTkFrame(config_card, fg_color="transparent")
        self._progress_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, 12))
        self._progress_frame.pack_forget()  # Hidden initially

        self._progress_label = ctk.CTkLabel(
            self._progress_frame, text="Capturing...",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_SECONDARY, anchor="w")
        self._progress_label.pack(fill="x", pady=(0, 4))

        self._progress_bar = ctk.CTkProgressBar(
            self._progress_frame, fg_color=BG_INPUT, progress_color=SAS_BLUE,
            height=8, corner_radius=4)
        self._progress_bar.pack(fill="x")
        self._progress_bar.set(0)

        # ── Results Container (hidden until capture completes) ──────────────
        self._results_frame = ctk.CTkFrame(inner, fg_color="transparent")

    # ── Status & Interface Loading ────────────────────────────────────────────

    def _update_status(self):
        """Show which capture backend is active."""
        desc = self._engine.backend_description
        if self._engine.backend_name == "tshark":
            self._status_label.configure(
                text=f"✅ {desc}", text_color=STATUS_GOOD)
        else:
            self._status_label.configure(
                text=f"✅ {desc}", text_color=STATUS_GOOD)

    def _load_interfaces(self):
        """Load available capture interfaces in background."""
        self._iface_var.set("Detecting...")
        self._iface_dropdown.configure(values=["Detecting..."])

        def _load():
            self._interfaces = self._engine.list_interfaces()
            self.after(0, self._populate_interfaces)

        threading.Thread(target=_load, daemon=True).start()

    def _refresh_interfaces(self):
        """Refresh interface list (called from button)."""
        self._load_interfaces()

    def _populate_interfaces(self):
        """Populate the interface dropdown (runs on UI thread)."""
        self._interfaces_loaded = True
        if not self._interfaces:
            self._iface_dropdown.configure(values=["No interfaces found"])
            self._iface_var.set("No interfaces found")
            return

        names = [str(iface) for iface in self._interfaces]
        self._iface_dropdown.configure(values=names)
        self._iface_var.set(names[0])

    # ── Capture Control ───────────────────────────────────────────────────────

    def _start_capture(self):
        """Start a packet capture."""
        if self._capturing:
            return

        # Get selected interface
        selected_name = self._iface_var.get()
        iface = None
        for i in self._interfaces:
            if str(i) == selected_name:
                iface = i
                break

        if not iface:
            logger.warning("No interface selected")
            return

        self._capture_iface = iface  # Save for PDF report

        # Get duration
        try:
            duration = int(self._duration_var.get())
        except ValueError:
            duration = 30

        # Clear previous results
        self._results_frame.pack_forget()
        for child in self._results_frame.winfo_children():
            child.destroy()
        self._analysis = None

        # Update UI state
        self._capturing = True
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._export_btn.configure(state="disabled")
        self._iface_dropdown.configure(state="disabled")
        self._duration_dropdown.configure(state="disabled")

        # Show progress
        self._progress_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, 12))
        self._progress_bar.set(0)
        self._progress_label.configure(text=f"Capturing on {iface.friendly_name}...")

        # Build config
        config = CaptureConfig(
            interface=iface.name,
            duration_seconds=duration,
            promiscuous=True,
            snap_length=256,
        )

        # Start capture
        self._engine.start_capture(
            config,
            on_progress=self._on_capture_progress,
            on_complete=self._on_capture_complete,
        )

    def _stop_capture(self):
        """Stop the current capture early."""
        self._engine.stop_capture()
        self._progress_label.configure(text="Stopping capture...")

    def _on_capture_progress(self, elapsed: int, total: int):
        """Progress callback from capture thread."""
        def _update():
            if elapsed < 0:
                # Parsing phase
                self._progress_bar.set(1.0)
                self._progress_label.configure(text="Analyzing captured packets...")
            else:
                pct = elapsed / total if total > 0 else 0
                self._progress_bar.set(pct)
                remaining = total - elapsed
                self._progress_label.configure(
                    text=f"Capturing... {elapsed}s / {total}s "
                         f"({remaining}s remaining)")
        self.after(0, _update)

    def _on_capture_complete(self, result: CaptureResult):
        """Completion callback from capture thread."""
        def _finish():
            self._capturing = False
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            self._iface_dropdown.configure(state="readonly")
            self._duration_dropdown.configure(state="readonly")
            self._progress_frame.pack_forget()

            if result.error:
                self._show_error(result.error)
                return

            # Analyze the capture
            self._analysis = analyze_capture(result)

            # Show results
            self._build_results()
            self._export_btn.configure(state="normal")

        self.after(0, _finish)

    def _show_error(self, error: str):
        """Display a capture error."""
        self._results_frame.pack(fill="x", padx=20, pady=(12, 20))

        err_card = ctk.CTkFrame(self._results_frame, fg_color=BG_CARD,
                                 corner_radius=CARD_CORNER_RADIUS,
                                 border_width=1, border_color=STATUS_ERROR)
        err_card.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(err_card, text="❌  Capture Failed",
                     font=(FONT_FAMILY, FONT_SIZE_HEADING, "bold"),
                     text_color=STATUS_ERROR, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(12, 4))

        ctk.CTkLabel(err_card, text=error,
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, anchor="w",
                     wraplength=700, justify="left").pack(
            fill="x", padx=CARD_PADDING, pady=(0, 12))

    # ── Results Display ───────────────────────────────────────────────────────

    def _build_results(self):
        """Build the full results display after a successful capture."""
        if not self._analysis:
            return

        a = self._analysis

        # Clear and show results frame
        for child in self._results_frame.winfo_children():
            child.destroy()
        self._results_frame.pack(fill="x", padx=20, pady=(12, 20))

        # ── Summary Stats Row ─────────────────────────────────────────────
        stats_row = ctk.CTkFrame(self._results_frame, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 12))

        # Health gauge
        gauge_card = ctk.CTkFrame(stats_row, fg_color=BG_CARD,
                                   corner_radius=CARD_CORNER_RADIUS,
                                   border_width=1, border_color=BORDER_COLOR,
                                   width=200)
        gauge_card.pack(side="left", fill="y", padx=(0, 8))
        gauge_card.pack_propagate(False)

        ctk.CTkLabel(gauge_card, text="NETWORK HEALTH",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED).pack(pady=(10, 4))

        gauge = HealthGauge(gauge_card, size=130)
        gauge.pack(pady=(0, 4))
        gauge.set_score(a.health_score)

        label_text = get_health_label(a.health_score)
        label_color = get_health_color(a.health_score)
        ctk.CTkLabel(gauge_card, text=label_text,
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=label_color).pack(pady=(0, 8))

        # Stat cards
        stats_grid = ctk.CTkFrame(stats_row, fg_color="transparent")
        stats_grid.pack(side="left", fill="both", expand=True)

        # Top row of stats
        top_stats = ctk.CTkFrame(stats_grid, fg_color="transparent")
        top_stats.pack(fill="x", pady=(0, 8))

        InfoCard(top_stats, label="Total Packets",
                 value=f"{a.total_packets:,}",
                 icon="📦", color=SAS_BLUE).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        InfoCard(top_stats, label="Total Bytes",
                 value=_format_bytes(a.total_bytes),
                 icon="💾", color=SAS_BLUE).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        InfoCard(top_stats, label="Duration",
                 value=f"{a.duration_seconds:.0f}s",
                 icon="⏱", color=SAS_BLUE).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        InfoCard(top_stats, label="Unique Hosts",
                 value=f"{a.unique_hosts}",
                 icon="🖥", color=SAS_BLUE).pack(
            side="left", fill="both", expand=True)

        # Bottom row of stats
        bot_stats = ctk.CTkFrame(stats_grid, fg_color="transparent")
        bot_stats.pack(fill="x")

        # Broadcast percentage
        bc_color = STATUS_GOOD if a.broadcast_pct < 5 else (
            STATUS_WARN if a.broadcast_pct < 15 else STATUS_ERROR)
        InfoCard(bot_stats, label="Broadcast",
                 value=f"{a.broadcast_pct:.1f}%",
                 icon="📡", color=bc_color).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        # Multicast percentage
        mc_color = STATUS_GOOD if a.multicast_pct < 10 else STATUS_WARN
        InfoCard(bot_stats, label="Multicast",
                 value=f"{a.multicast_pct:.1f}%",
                 icon="📢", color=mc_color).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        # TCP retransmissions
        rt_color = STATUS_GOOD if a.tcp_retransmission_pct < 1 else (
            STATUS_WARN if a.tcp_retransmission_pct < 5 else STATUS_ERROR)
        InfoCard(bot_stats, label="TCP Retransmissions",
                 value=f"{a.tcp_retransmission_pct:.1f}%",
                 icon="🔁", color=rt_color).pack(
            side="left", fill="both", expand=True, padx=(0, 8))

        # Packets per second
        InfoCard(bot_stats, label="Packets/sec",
                 value=f"{a.packets_per_second:.0f}",
                 icon="📈", color=SAS_BLUE).pack(
            side="left", fill="both", expand=True)

        # ── Charts Row ────────────────────────────────────────────────────
        charts_row = ctk.CTkFrame(self._results_frame, fg_color="transparent")
        charts_row.pack(fill="x", pady=(0, 12))

        # Protocol donut chart
        proto_card = ctk.CTkFrame(charts_row, fg_color=BG_CARD,
                                   corner_radius=CARD_CORNER_RADIUS,
                                   border_width=1, border_color=BORDER_COLOR)
        proto_card.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ctk.CTkLabel(proto_card, text="PROTOCOL BREAKDOWN",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(12, 4))

        self._draw_protocol_chart(proto_card, a.protocol_breakdown)

        # Top talkers bar chart
        talker_card = ctk.CTkFrame(charts_row, fg_color=BG_CARD,
                                    corner_radius=CARD_CORNER_RADIUS,
                                    border_width=1, border_color=BORDER_COLOR)
        talker_card.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(talker_card, text="TOP TALKERS (BY BYTES)",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(12, 4))

        self._draw_top_talkers_chart(talker_card, a.top_talkers_by_bytes)

        # ── Timeline ──────────────────────────────────────────────────────
        if a.timeline:
            self._build_timeline(a.timeline)

        # ── Findings Cards ────────────────────────────────────────────────
        ctk.CTkLabel(self._results_frame, text="DIAGNOSTIC FINDINGS",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", pady=(8, 6))

        for finding in a.findings:
            FindingCard(
                self._results_frame,
                title=finding.title,
                severity=finding.severity,
                summary=finding.summary,
                explanation=finding.explanation,
                recommendation=finding.recommendation,
                raw_value=finding.raw_value,
            ).pack(fill="x", pady=(0, 8))

    # ── Protocol Donut Chart ──────────────────────────────────────────────────

    def _draw_protocol_chart(self, parent, protocol_data: Dict[str, int]):
        """Draw a donut chart showing protocol distribution."""
        if not protocol_data:
            ctk.CTkLabel(parent, text="No protocol data",
                         font=(FONT_FAMILY, FONT_SIZE_BODY),
                         text_color=TEXT_MUTED).pack(pady=20)
            return

        chart_frame = ctk.CTkFrame(parent, fg_color="transparent")
        chart_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, 12))

        # Canvas for donut
        canvas_size = 200
        canvas = tk.Canvas(chart_frame, width=canvas_size, height=canvas_size,
                           bg=resolve_color(BG_CARD), highlightthickness=0)
        canvas.pack(side="left", padx=(0, 16))

        total = sum(protocol_data.values())
        if total == 0:
            return

        # Draw donut arcs
        cx, cy = canvas_size // 2, canvas_size // 2
        outer_r = 88
        inner_r = 55
        start_angle = 90  # Start from top

        sorted_protos = sorted(protocol_data.items(), key=lambda x: -x[1])
        top_protos = sorted_protos[:len(PROTOCOL_COLORS)]

        for i, (proto, count) in enumerate(top_protos):
            extent = (count / total) * 360
            color = PROTOCOL_COLORS[i % len(PROTOCOL_COLORS)]

            # Draw arc using polygon approximation for donut shape
            self._draw_donut_arc(canvas, cx, cy, outer_r, inner_r,
                                 start_angle, extent, color)
            start_angle -= extent

        # Center circle (donut hole)
        canvas.create_oval(cx - inner_r, cy - inner_r,
                           cx + inner_r, cy + inner_r,
                           fill=resolve_color(BG_CARD), outline="")

        # Center text
        canvas.create_text(cx, cy - 8, text=f"{total:,}",
                           font=(FONT_FAMILY, 16, "bold"),
                           fill=resolve_color(TEXT_PRIMARY))
        canvas.create_text(cx, cy + 12, text="packets",
                           font=(FONT_FAMILY, 10),
                           fill=resolve_color(TEXT_MUTED))

        # Legend
        legend = ctk.CTkFrame(chart_frame, fg_color="transparent")
        legend.pack(side="left", fill="both", expand=True)

        for i, (proto, count) in enumerate(top_protos[:10]):
            pct = (count / total * 100)
            color = PROTOCOL_COLORS[i % len(PROTOCOL_COLORS)]

            row = ctk.CTkFrame(legend, fg_color="transparent", height=22)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            # Color dot
            dot = tk.Canvas(row, width=10, height=10,
                            bg=resolve_color(BG_CARD), highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline="")
            dot.pack(side="left", padx=(0, 6), pady=5)

            ctk.CTkLabel(row, text=proto,
                         font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_PRIMARY, anchor="w",
                         width=80).pack(side="left")

            ctk.CTkLabel(row, text=f"{count:,}",
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL),
                         text_color=TEXT_SECONDARY, anchor="e",
                         width=60).pack(side="left", padx=(4, 0))

            ctk.CTkLabel(row, text=f"({pct:.1f}%)",
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED, anchor="w").pack(
                side="left", padx=(4, 0))

    def _draw_donut_arc(self, canvas, cx, cy, outer_r, inner_r,
                         start_angle, extent, color):
        """Draw a donut segment using a polygon."""
        if abs(extent) < 0.5:
            return

        # Generate points along outer arc
        points = []
        steps = max(int(abs(extent) / 3), 8)

        for i in range(steps + 1):
            angle = math.radians(start_angle - (extent * i / steps))
            x = cx + outer_r * math.cos(angle)
            y = cy - outer_r * math.sin(angle)
            points.append((x, y))

        # Generate points along inner arc (reversed)
        for i in range(steps, -1, -1):
            angle = math.radians(start_angle - (extent * i / steps))
            x = cx + inner_r * math.cos(angle)
            y = cy - inner_r * math.sin(angle)
            points.append((x, y))

        # Flatten for Canvas.create_polygon
        flat = []
        for p in points:
            flat.extend(p)

        canvas.create_polygon(*flat, fill=color, outline=resolve_color(BG_CARD),
                               width=1, smooth=False)

    # ── Top Talkers Bar Chart ─────────────────────────────────────────────────

    def _draw_top_talkers_chart(self, parent, talkers: List):
        """Draw horizontal bar chart of top talkers."""
        if not talkers:
            ctk.CTkLabel(parent, text="No host data",
                         font=(FONT_FAMILY, FONT_SIZE_BODY),
                         text_color=TEXT_MUTED).pack(pady=20)
            return

        chart = ctk.CTkFrame(parent, fg_color="transparent")
        chart.pack(fill="x", padx=CARD_PADDING, pady=(0, 12))

        # Show top 8
        display_talkers = talkers[:8]
        max_bytes = display_talkers[0][1] if display_talkers else 1

        for i, (ip, total_bytes) in enumerate(display_talkers):
            row = ctk.CTkFrame(chart, fg_color="transparent", height=26)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            # IP label
            ctk.CTkLabel(row, text=ip,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL),
                         text_color=TEXT_PRIMARY, anchor="w",
                         width=130).pack(side="left")

            # Bar background
            bar_bg = ctk.CTkFrame(row, fg_color=BG_MEDIUM,
                                   corner_radius=3, height=16)
            bar_bg.pack(side="left", fill="x", expand=True, padx=(8, 8), pady=5)
            bar_bg.pack_propagate(False)

            # Bar fill
            pct = total_bytes / max_bytes if max_bytes > 0 else 0
            color = PROTOCOL_COLORS[i % len(PROTOCOL_COLORS)]

            bar_fill = ctk.CTkFrame(bar_bg, fg_color=color,
                                     corner_radius=3, height=16)
            bar_fill.place(relx=0, rely=0, relwidth=max(0.02, pct),
                           relheight=1.0)

            # Bytes label
            ctk.CTkLabel(row, text=_format_bytes(total_bytes),
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=TEXT_SECONDARY, anchor="e",
                         width=70).pack(side="right")

    # ── Timeline ──────────────────────────────────────────────────────────────

    def _build_timeline(self, events: List[TimelineEvent]):
        """Build a timeline view of notable events during capture."""
        tl_card = ctk.CTkFrame(self._results_frame, fg_color=BG_CARD,
                                corner_radius=CARD_CORNER_RADIUS,
                                border_width=1, border_color=BORDER_COLOR)
        tl_card.pack(fill="x", pady=(0, 12))

        # Header
        header = ctk.CTkFrame(tl_card, fg_color="transparent")
        header.pack(fill="x", padx=CARD_PADDING, pady=(12, 8))

        ctk.CTkLabel(header, text="CAPTURE TIMELINE",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(side="left")

        ctk.CTkLabel(header, text=f"{len(events)} events detected",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED, anchor="e").pack(side="right")

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Show events (limit to 50 for performance)
        display_events = sorted_events[:50]

        for event in display_events:
            ev_row = ctk.CTkFrame(tl_card, fg_color="transparent", height=32)
            ev_row.pack(fill="x", padx=CARD_PADDING, pady=1)
            ev_row.pack_propagate(False)

            # Timestamp
            ts_text = f"{event.timestamp:6.1f}s"
            ctk.CTkLabel(ev_row, text=ts_text,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL),
                         text_color=TEXT_MUTED, width=60,
                         anchor="e").pack(side="left")

            # Severity dot
            sev_color = SEVERITY_COLORS_MAP.get(event.severity, TEXT_MUTED)
            dot = tk.Canvas(ev_row, width=10, height=10,
                            bg=resolve_color(BG_CARD), highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=sev_color, outline="")
            dot.pack(side="left", padx=(8, 6), pady=10)

            # Icon
            icon = TIMELINE_ICONS.get(event.event_type, "•")
            ctk.CTkLabel(ev_row, text=icon,
                         font=(FONT_FAMILY, FONT_SIZE_BODY)).pack(
                side="left", padx=(0, 4))

            # Description
            ctk.CTkLabel(ev_row, text=event.description,
                         font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_PRIMARY, anchor="w").pack(
                side="left", fill="x", expand=True)

        if len(sorted_events) > 50:
            ctk.CTkLabel(tl_card,
                         text=f"... and {len(sorted_events) - 50} more events",
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED).pack(pady=(4, 12))
        else:
            ctk.CTkFrame(tl_card, fg_color="transparent", height=8).pack()

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_report(self):
        """Export analysis results to a branded PDF report."""
        if not self._analysis:
            return

        from tkinter import filedialog

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        default_name = f"Capture_Report_{timestamp}.pdf"

        output_path = filedialog.asksaveasfilename(
            title="Save Capture Analysis Report",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
            initialfile=default_name,
            initialdir=os.path.join(os.path.expanduser("~"), "Documents"),
        )
        if not output_path:
            return  # User cancelled

        self._export_btn.configure(text="⏳ Generating...", state="disabled")
        self.update_idletasks()

        iface_name = str(self._capture_iface) if self._capture_iface else ""
        iface_ip = getattr(self._capture_iface, "ip_address", "")

        def _generate():
            try:
                from core.pdf_report import generate_capture_report
                generate_capture_report(
                    analysis=self._analysis,
                    interface_name=iface_name,
                    interface_ip=iface_ip,
                    output_path=output_path,
                )
                self.after(0, lambda: self._export_success(output_path))
            except Exception as e:
                logger.error(f"PDF export failed: {e}", exc_info=True)
                self.after(0, lambda: self._export_failure(str(e)))

        threading.Thread(target=_generate, daemon=True).start()

    def _export_success(self, path: str):
        """Handle successful PDF export."""
        filename = os.path.basename(path)
        self._export_btn.configure(text=f"✅ Saved: {filename}", state="normal")
        self.after(3000, lambda: self._export_btn.configure(
            text="📄  Export Report"))

        # Open the PDF
        try:
            import platform
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                import subprocess
                subprocess.Popen(["open", path])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    def _export_failure(self, error: str):
        """Handle PDF export failure."""
        if "reportlab" in error.lower() or "No module" in error:
            self._export_btn.configure(
                text="⚠ Install reportlab", state="normal")
        else:
            self._export_btn.configure(
                text="❌ Export failed", state="normal")
        self.after(3000, lambda: self._export_btn.configure(
            text="📄  Export Report"))


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
