"""
SAS Network Diagnostics Tool — Device Monitor View
Continuous monitoring tab for catching intermittent network issues.

Features:
  - Target device input (IP address)
  - Live response time chart (scrolling sparkline)
  - Real-time statistics cards (uptime, loss, avg RT, outages)
  - Start/Stop/Export controls
  - Analysis report panel with findings and recommendations
  - CSV export for archiving
"""

import logging
import threading
import time
import tkinter as tk
from datetime import datetime
from typing import Optional, List

import customtkinter as ctk

from core.monitor_engine import DeviceMonitor, PollSample, MonitorStats
from core.monitor_analyzer import MonitorAnalyzer, AnalysisReport, Finding
from ui.theme import *
from ui.widgets import ScanProgressBar, enable_touch_scroll

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

import math

CHART_HEIGHT = 160
CHART_BG = ("#E0E3E8", "#0D1117")
CHART_GRID = ("#C0C5CC", "#1B2332")
CHART_LINE_PING = "#22C55E"     # Green for ping
CHART_LINE_CIP = "#3B82F6"      # Blue for CIP
CHART_FAIL_COLOR = "#EF4444"    # Red for failures
CHART_VISIBLE = 200              # Default number of samples visible in window
CHART_LEFT_MARGIN = 48
CHART_RIGHT_MARGIN = 12
CHART_TOP_MARGIN = 14
CHART_BOTTOM_MARGIN = 24         # Room for time labels

HEALTH_COLORS = {
    "Healthy": "#22C55E",
    "Degraded": "#F59E0B",
    "Unstable": "#EF4444",
    "Critical": "#DC2626",
    "No Data": TEXT_MUTED,
}

SEVERITY_COLORS = {
    "critical": "#EF4444",
    "warning": "#F59E0B",
    "info": "#3B82F6",
}


class DeviceMonitorView(ctk.CTkFrame):
    """
    Device Monitor tab — lock onto a device and watch it over time.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._monitor: Optional[DeviceMonitor] = None
        self._analyzer = MonitorAnalyzer()
        self._monitoring = False
        self._last_report: Optional[AnalysisReport] = None

        # Chart data — full history (not truncated)
        self._all_samples: List[PollSample] = []
        self._ping_times: List[Optional[float]] = []    # None = fail
        self._cip_times: List[Optional[float]] = []

        # Chart viewport slider
        self._slider_auto_follow = True  # When True, slider tracks latest data
        self._slider_position = 0        # Right edge of visible window (sample index)
        self._chart_last_w = 600         # Cached canvas width

        # Update timer
        self._update_job = None

        self._build_ui()

    def _build_ui(self):
        """Build the complete monitor view."""
        # Scrollable container
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BG_MEDIUM,
            scrollbar_button_hover_color=SAS_BLUE)
        self._scroll.pack(fill="both", expand=True)
        enable_touch_scroll(self._scroll)

        inner = self._scroll

        # ── Header ──
        self._build_header(inner)

        # ── Connection Bar ──
        self._build_connection_bar(inner)

        # ── Live Stats Row ──
        self._build_stats_row(inner)

        # ── Response Time Chart ──
        self._build_chart(inner)

        # ── Event Log (compact) ──
        self._build_event_log(inner)

        # ── Analysis Report ──
        self._build_analysis_section(inner)

    # ── Header ───────────────────────────────────────────────────────────

    def _build_header(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 4))

        ctk.CTkLabel(hdr, text="📡  Device Monitor",
                     font=(FONT_FAMILY, 22, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        ctk.CTkLabel(hdr,
            text="Lock onto a device and monitor it over time to catch intermittent issues.\n"
                 "Polls with ICMP ping and CIP Identity reads, then analyzes the data for patterns.",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w", justify="left").pack(
                side="left", padx=(16, 0))

    # ── Connection Bar ───────────────────────────────────────────────────

    def _build_connection_bar(self, parent):
        bar = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        bar.pack(fill="x", padx=24, pady=(8, 4))

        # Top row: IP, poll interval, probes
        row1 = ctk.CTkFrame(bar, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(8, 4))

        # Target IP
        ctk.CTkLabel(row1, text="Target IP:",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))

        self._ip_entry = ctk.CTkEntry(
            row1, placeholder_text="192.168.1.10",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=160, height=INPUT_HEIGHT)
        self._ip_entry.pack(side="left", padx=(0, 16))

        # Poll interval
        ctk.CTkLabel(row1, text="Poll every:",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))

        self._interval_combo = ctk.CTkComboBox(
            row1, values=["1 sec", "2 sec", "5 sec", "10 sec", "30 sec", "60 sec"],
            width=100, height=INPUT_HEIGHT,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, dropdown_fg_color=BG_CARD,
            dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_CARD_HOVER)
        self._interval_combo.set("2 sec")
        self._interval_combo.pack(side="left", padx=(0, 16))

        # Probes
        self._ping_var = ctk.BooleanVar(value=True)
        self._cip_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(row1, text="Ping", variable=self._ping_var,
                        font=(FONT_FAMILY, FONT_SIZE_SMALL),
                        text_color=TEXT_SECONDARY, fg_color=SAS_BLUE,
                        hover_color=SAS_BLUE_DARK, height=24,
                        checkbox_width=18, checkbox_height=18).pack(
            side="left", padx=(0, 8))
        ctk.CTkCheckBox(row1, text="CIP Identity", variable=self._cip_var,
                        font=(FONT_FAMILY, FONT_SIZE_SMALL),
                        text_color=TEXT_SECONDARY, fg_color=SAS_BLUE,
                        hover_color=SAS_BLUE_DARK, height=24,
                        checkbox_width=18, checkbox_height=18).pack(
            side="left", padx=(0, 16))

        # Bottom row: action buttons
        row2 = ctk.CTkFrame(bar, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 8))

        self._start_btn = ctk.CTkButton(
            row2, text="▶  Start Monitor", width=150,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_ORANGE, hover_color=SAS_ORANGE_DARK,
            text_color="white", command=self._toggle_monitor)
        self._start_btn.pack(side="left", padx=(0, 8))

        self._analyze_btn = ctk.CTkButton(
            row2, text="🔍 Analyze", width=100,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            text_color="white", command=self._run_analysis)
        self._analyze_btn.pack(side="left", padx=(0, 8))

        self._export_btn = ctk.CTkButton(
            row2, text="💾 Export CSV", width=110,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_MEDIUM, hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY, command=self._export_csv)
        self._export_btn.pack(side="left")

    # ── Live Stats Row ───────────────────────────────────────────────────

    def _build_stats_row(self, parent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(8, 0))

        # Create stat cards
        self._stat_cards = {}
        cards = [
            ("status", "Status", "Idle", TEXT_MUTED),
            ("uptime", "Uptime", "—", TEXT_MUTED),
            ("samples", "Samples", "0", TEXT_MUTED),
            ("ping_loss", "Ping Loss", "—", TEXT_MUTED),
            ("avg_rt", "Avg Response", "—", TEXT_MUTED),
            ("outages", "Outages", "0", TEXT_MUTED),
            ("duration", "Duration", "0:00", TEXT_MUTED),
            ("health", "Health", "—", TEXT_MUTED),
        ]

        for i, (key, label, default, color) in enumerate(cards):
            card = ctk.CTkFrame(row, fg_color=BG_CARD, corner_radius=6, height=64)
            card.pack(side="left", fill="both", expand=True,
                      padx=(0 if i == 0 else 3, 0 if i == len(cards) - 1 else 3),
                      pady=0)
            card.pack_propagate(False)

            ctk.CTkLabel(card, text=label,
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED, anchor="w").pack(
                fill="x", padx=10, pady=(8, 0))

            val_label = ctk.CTkLabel(card, text=default,
                                      font=(FONT_FAMILY_MONO, 16, "bold"),
                                      text_color=color, anchor="w")
            val_label.pack(fill="x", padx=10, pady=(0, 8))

            self._stat_cards[key] = val_label

    # ── Response Time Chart ──────────────────────────────────────────────

    def _build_chart(self, parent):
        chart_frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        chart_frame.pack(fill="x", padx=24, pady=(8, 0))

        # Chart header
        hdr = ctk.CTkFrame(chart_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(hdr, text="Response Time",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        # Viewport info (sample range shown)
        self._chart_range_label = ctk.CTkLabel(
            hdr, text="",
            font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
            text_color=TEXT_MUTED)
        self._chart_range_label.pack(side="left", padx=(12, 0))

        # Legend
        legend = ctk.CTkFrame(hdr, fg_color="transparent")
        legend.pack(side="right")

        ctk.CTkFrame(legend, fg_color=CHART_LINE_PING, width=12, height=3,
                     corner_radius=1).pack(side="left", padx=(0, 4), pady=1)
        ctk.CTkLabel(legend, text="Ping",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED).pack(side="left", padx=(0, 12))

        ctk.CTkFrame(legend, fg_color=CHART_LINE_CIP, width=12, height=3,
                     corner_radius=1).pack(side="left", padx=(0, 4), pady=1)
        ctk.CTkLabel(legend, text="CIP",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED).pack(side="left", padx=(0, 12))

        ctk.CTkFrame(legend, fg_color=CHART_FAIL_COLOR, width=8, height=8,
                     corner_radius=4).pack(side="left", padx=(0, 4))
        ctk.CTkLabel(legend, text="Fail",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED).pack(side="left")

        # Canvas
        self._chart_canvas = tk.Canvas(
            chart_frame, height=CHART_HEIGHT, bg=resolve_color(CHART_BG),
            highlightthickness=0, bd=0)
        self._chart_canvas.pack(fill="x", padx=8, pady=(4, 2))
        self._chart_canvas.bind("<Configure>", self._on_chart_resize)

        # ── Timeline slider row ──
        slider_row = ctk.CTkFrame(chart_frame, fg_color="transparent")
        slider_row.pack(fill="x", padx=8, pady=(0, 8))

        self._slider_left_label = ctk.CTkLabel(
            slider_row, text="",
            font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
            text_color=TEXT_MUTED, width=70)
        self._slider_left_label.pack(side="left")

        self._timeline_slider = ctk.CTkSlider(
            slider_row, from_=0, to=1,
            number_of_steps=1,
            height=14,
            fg_color=BG_MEDIUM,
            progress_color=SAS_BLUE,
            button_color=SAS_BLUE_LIGHT,
            button_hover_color="white",
            command=self._on_slider_moved)
        self._timeline_slider.pack(side="left", fill="x", expand=True, padx=4)
        self._timeline_slider.set(1.0)

        self._slider_right_label = ctk.CTkLabel(
            slider_row, text="",
            font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
            text_color=TEXT_MUTED, width=70)
        self._slider_right_label.pack(side="left")

        # Auto-follow button
        self._follow_btn = ctk.CTkButton(
            slider_row, text="▶ LIVE", width=60, height=20,
            font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            fg_color=SAS_ORANGE, hover_color=SAS_ORANGE_DARK,
            text_color="white",
            command=self._snap_to_live)
        self._follow_btn.pack(side="left", padx=(4, 0))

        self._draw_empty_chart()

    def _on_chart_resize(self, event):
        """Track actual canvas width on resize."""
        if event.width > 50:
            self._chart_last_w = event.width
            self._draw_chart()

    def _on_slider_moved(self, value):
        """User dragged the timeline slider."""
        total = len(self._ping_times)
        if total <= CHART_VISIBLE:
            # Not enough data to scroll — stay in auto-follow
            self._slider_auto_follow = True
            return

        # Map slider 0.0-1.0 to sample index for right edge of window
        max_pos = total
        min_pos = CHART_VISIBLE
        self._slider_position = int(min_pos + value * (max_pos - min_pos))
        self._slider_position = max(min_pos, min(total, self._slider_position))

        # If slider is at or near the end, snap to auto-follow
        if self._slider_position >= total - 2:
            self._slider_auto_follow = True
            self._follow_btn.configure(fg_color=SAS_ORANGE, text="▶ LIVE")
        else:
            self._slider_auto_follow = False
            self._follow_btn.configure(fg_color=BG_MEDIUM, text="▶ LIVE")

        self._draw_chart()

    def _snap_to_live(self):
        """Snap the slider to live (latest data)."""
        self._slider_auto_follow = True
        self._slider_position = len(self._ping_times)
        self._timeline_slider.set(1.0)
        self._follow_btn.configure(fg_color=SAS_ORANGE, text="▶ LIVE")
        self._draw_chart()

    def _draw_empty_chart(self):
        """Draw empty chart grid."""
        c = self._chart_canvas
        c.delete("all")
        w = self._chart_last_w
        h = CHART_HEIGHT

        # Grid lines
        for y_pct in [0.25, 0.5, 0.75]:
            y = int(h * y_pct)
            c.create_line(CHART_LEFT_MARGIN, y, w - CHART_RIGHT_MARGIN, y,
                           fill=resolve_color(CHART_GRID), dash=(2, 4))

        # "Waiting for data" message
        c.create_text(w // 2, h // 2,
                       text="Start monitoring to see response times",
                       fill=resolve_color(TEXT_MUTED), font=(FONT_FAMILY, 11))

    def _get_chart_viewport(self):
        """Get the start/end indices for the visible chart window."""
        total = max(len(self._ping_times), len(self._cip_times))
        if total == 0:
            return 0, 0

        if self._slider_auto_follow:
            end = total
        else:
            end = self._slider_position

        start = max(0, end - CHART_VISIBLE)
        end = min(total, start + CHART_VISIBLE)
        return start, end

    def _draw_chart(self):
        """Redraw the response time chart with current viewport."""
        c = self._chart_canvas
        c.delete("all")

        w = self._chart_last_w
        h = CHART_HEIGHT
        if w < 100:
            return

        start, end = self._get_chart_viewport()
        if end <= start:
            self._draw_empty_chart()
            return

        # Slice data to viewport
        ping_data = self._ping_times[start:end]
        cip_data = self._cip_times[start:end]
        sample_data = self._all_samples[start:end] if start < len(self._all_samples) else []

        if not ping_data and not cip_data:
            self._draw_empty_chart()
            return

        # ── Y-axis auto-scale from visible data ──
        all_times = ([t for t in ping_data if t is not None] +
                     [t for t in cip_data if t is not None])

        if not all_times:
            max_val = 100.0
        else:
            max_val = max(all_times) * 1.15
            max_val = max(max_val, 1.0)  # Minimum 1ms scale

        # Round to nice values
        if max_val <= 5:
            max_val = 5
        elif max_val <= 10:
            max_val = 10
        elif max_val <= 20:
            max_val = 20
        elif max_val <= 50:
            max_val = 50
        elif max_val <= 100:
            max_val = 100
        elif max_val <= 200:
            max_val = 200
        elif max_val <= 500:
            max_val = 500
        elif max_val <= 1000:
            max_val = 1000
        else:
            max_val = math.ceil(max_val / 500) * 500

        plot_x0 = CHART_LEFT_MARGIN
        plot_x1 = w - CHART_RIGHT_MARGIN
        plot_w = plot_x1 - plot_x0
        plot_y0 = CHART_TOP_MARGIN
        plot_y1 = h - CHART_BOTTOM_MARGIN
        plot_h = plot_y1 - plot_y0

        if plot_w < 20 or plot_h < 20:
            return

        # ── Grid lines + Y-axis labels ──
        grid_fracs = [0.0, 0.25, 0.5, 0.75, 1.0]
        for frac in grid_fracs:
            y = plot_y0 + int(plot_h * frac)
            label_val = max_val * (1 - frac)
            c.create_line(plot_x0, y, plot_x1, y, fill=resolve_color(CHART_GRID), dash=(2, 4))

            if label_val >= 100:
                label = f"{label_val:.0f}"
            elif label_val >= 1:
                label = f"{label_val:.1f}"
            else:
                label = f"{label_val:.2f}"
            c.create_text(plot_x0 - 4, y, text=label, fill=resolve_color(TEXT_MUTED),
                           anchor="e", font=("Consolas", 8))

        c.create_text(plot_x0 - 4, plot_y0 - 8, text="ms", fill=resolve_color(TEXT_MUTED),
                       anchor="e", font=("Consolas", 8))

        # ── X-axis time labels ──
        n_points = max(len(ping_data), len(cip_data))
        if n_points < 2:
            return

        x_step = plot_w / max(n_points - 1, 1)

        # Draw ~5 time labels along X axis
        if sample_data:
            label_count = min(6, n_points)
            label_step = max(1, n_points // label_count)
            for idx in range(0, n_points, label_step):
                x = plot_x0 + idx * x_step
                if idx < len(sample_data):
                    ts = sample_data[idx].timestamp.strftime("%H:%M:%S")
                    c.create_text(x, plot_y1 + 10, text=ts,
                                   fill=resolve_color(TEXT_MUTED), anchor="n",
                                   font=("Consolas", 7))

        # ── Plot data series ──
        def plot_series(data, color):
            points = []
            for i, val in enumerate(data):
                x = plot_x0 + i * x_step
                if val is not None and max_val > 0:
                    y = plot_y0 + plot_h * (1 - val / max_val)
                    y = max(plot_y0, min(plot_y1, y))
                    points.append((x, y))
                else:
                    # Fail marker
                    c.create_rectangle(
                        x - 2, plot_y1 - 6, x + 2, plot_y1 - 2,
                        fill=CHART_FAIL_COLOR, outline="")

                    # Break line segment at failure
                    if len(points) >= 2:
                        flat = [coord for p in points for coord in p]
                        c.create_line(*flat, fill=color, width=1.5, smooth=True)
                    points = []

            if len(points) >= 2:
                flat = [coord for p in points for coord in p]
                c.create_line(*flat, fill=color, width=1.5, smooth=True)

        if cip_data:
            plot_series(cip_data, CHART_LINE_CIP)
        if ping_data:
            plot_series(ping_data, CHART_LINE_PING)

        # ── Update slider labels ──
        total = max(len(self._ping_times), len(self._cip_times))
        if sample_data and len(sample_data) >= 2:
            left_ts = sample_data[0].timestamp.strftime("%H:%M:%S")
            right_ts = sample_data[-1].timestamp.strftime("%H:%M:%S")
            self._slider_left_label.configure(text=left_ts)
            self._slider_right_label.configure(text=right_ts)

            range_text = f"Showing {start+1}–{end} of {total}"
            if self._slider_auto_follow:
                range_text += "  ● LIVE"
            self._chart_range_label.configure(text=range_text)

        # Update slider range
        if total > CHART_VISIBLE:
            steps = total - CHART_VISIBLE
            self._timeline_slider.configure(number_of_steps=max(1, steps))
            if self._slider_auto_follow:
                self._timeline_slider.set(1.0)

    # ── Event Log ────────────────────────────────────────────────────────

    def _build_event_log(self, parent):
        log_frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        log_frame.pack(fill="x", padx=24, pady=(8, 0))

        hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(hdr, text="Event Log",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        self._event_count_label = ctk.CTkLabel(
            hdr, text="", font=(FONT_FAMILY, FONT_SIZE_TINY),
            text_color=TEXT_MUTED)
        self._event_count_label.pack(side="right")

        self._event_text = ctk.CTkTextbox(
            log_frame, height=100, fg_color=CHART_BG,
            text_color=TEXT_SECONDARY,
            font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
            activate_scrollbars=True, wrap="none")
        self._event_text.pack(fill="x", padx=8, pady=(4, 10))
        self._event_text.configure(state="disabled")

    def _log_event(self, text: str):
        """Append a line to the event log."""
        ts = datetime.now().strftime("%H:%M:%S")
        self._event_text.configure(state="normal")
        self._event_text.insert("end", f"[{ts}] {text}\n")
        self._event_text.see("end")
        self._event_text.configure(state="disabled")

    # ── Analysis Section ─────────────────────────────────────────────────

    def _build_analysis_section(self, parent):
        self._analysis_frame = ctk.CTkFrame(parent, fg_color=BG_CARD,
                                              corner_radius=8)
        self._analysis_frame.pack(fill="x", padx=24, pady=(8, 20))

        # Header
        hdr = ctk.CTkFrame(self._analysis_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(hdr, text="📋  Analysis Report",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        self._report_status = ctk.CTkLabel(
            hdr, text="Click 'Analyze' after collecting some data",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED)
        self._report_status.pack(side="right")

        # Report content area
        self._report_container = ctk.CTkFrame(
            self._analysis_frame, fg_color="transparent")
        self._report_container.pack(fill="x", padx=12, pady=(0, 12))

        # Placeholder
        ctk.CTkLabel(self._report_container,
                     text="Start monitoring a device and collect data for at least 1-2 minutes,\n"
                          "then click 'Analyze' to generate a diagnostic report.",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_MUTED, anchor="w", justify="left").pack(
            padx=4, pady=12)

    # ── Monitor Control ──────────────────────────────────────────────────

    def _toggle_monitor(self):
        if self._monitoring:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        ip = self._ip_entry.get().strip()
        if not ip:
            self._log_event("⚠ Enter a target IP address")
            return

        if not self._ping_var.get() and not self._cip_var.get():
            self._log_event("⚠ Enable at least one probe (Ping or CIP)")
            return

        # Parse interval
        interval_text = self._interval_combo.get()
        interval = float(interval_text.split()[0])

        # Create monitor
        self._monitor = DeviceMonitor(
            target_ip=ip,
            poll_interval=interval,
            enable_ping=self._ping_var.get(),
            enable_cip=self._cip_var.get(),
        )

        # Set callbacks
        self._monitor.set_on_status_change(self._on_status_change)

        # Clear chart data
        self._all_samples.clear()
        self._ping_times.clear()
        self._cip_times.clear()
        self._slider_auto_follow = True
        self._slider_position = 0

        # Start
        self._monitor.start()
        self._monitoring = True

        # Update UI
        self._start_btn.configure(text="■  Stop Monitor", fg_color=STATUS_ERROR,
                                   hover_color="#DC2626")
        self._ip_entry.configure(state="disabled")
        self._interval_combo.configure(state="disabled")

        self._log_event(f"▶ Started monitoring {ip} (interval: {interval}s)")
        self._update_stat("status", "Monitoring...", SAS_ORANGE)

        # Start UI update timer
        self._schedule_update()

    def _stop_monitor(self):
        if self._monitor:
            self._monitor.stop()
            self._log_event(
                f"■ Stopped — {self._monitor.sample_count} samples collected")

        self._monitoring = False

        # Cancel update timer
        if self._update_job:
            self.after_cancel(self._update_job)
            self._update_job = None

        # Update UI
        self._start_btn.configure(text="▶  Start Monitor", fg_color=SAS_ORANGE,
                                   hover_color=SAS_ORANGE_DARK)
        self._ip_entry.configure(state="normal")
        self._interval_combo.configure(state="normal")

        self._update_stat("status", "Stopped", TEXT_MUTED)

        # Final stats update
        self._update_stats()
        self._draw_chart()

    def _on_status_change(self, came_online: bool, sample: PollSample):
        """Called when device transitions online/offline (from monitor thread)."""
        if came_online:
            msg = f"✅ Device came back online (RT: {sample.best_response_ms:.1f}ms)"
        else:
            error = sample.ping_error or sample.cip_error or "No response"
            msg = f"❌ Device went OFFLINE — {error}"

        self.after(0, lambda: self._log_event(msg))

    # ── Periodic UI Update ───────────────────────────────────────────────

    def _schedule_update(self):
        """Schedule the next UI update."""
        if self._monitoring:
            self._do_update()
            self._update_job = self.after(1000, self._schedule_update)

    def _do_update(self):
        """Pull latest data from monitor and update UI."""
        if not self._monitor:
            return

        # Get ALL samples — we keep full history for slider scrollback
        all_samples = self._monitor.get_samples_snapshot()

        # Rebuild chart buffers from all data
        self._all_samples = all_samples
        self._ping_times = [
            s.ping_time_ms if s.ping_success else None
            for s in all_samples
        ]
        self._cip_times = [
            s.cip_time_ms if s.cip_success else None
            for s in all_samples
        ]

        # If auto-following, keep slider position at end
        if self._slider_auto_follow:
            self._slider_position = len(self._ping_times)

        # Update chart
        self._draw_chart()

        # Update stats
        self._update_stats()

    def _update_stats(self):
        """Refresh the stats cards."""
        if not self._monitor:
            return

        stats = self._monitor.get_stats()

        # Sample count
        self._update_stat("samples", f"{stats.total_samples:,}", TEXT_PRIMARY)

        # Duration
        elapsed = self._monitor.elapsed_seconds
        if elapsed < 60:
            dur_str = f"{elapsed:.0f}s"
        elif elapsed < 3600:
            dur_str = f"{int(elapsed//60)}:{int(elapsed%60):02d}"
        else:
            dur_str = f"{int(elapsed//3600)}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
        self._update_stat("duration", dur_str, TEXT_PRIMARY)

        # Uptime
        if stats.total_samples > 0:
            up = stats.uptime_pct
            up_color = STATUS_GOOD if up >= 99 else STATUS_WARN if up >= 90 else STATUS_ERROR
            self._update_stat("uptime", f"{up:.1f}%", up_color)

        # Ping loss
        if stats.ping_sent > 0:
            loss = stats.ping_loss_pct
            loss_color = STATUS_GOOD if loss < 1 else STATUS_WARN if loss < 5 else STATUS_ERROR
            self._update_stat("ping_loss", f"{loss:.1f}%", loss_color)

        # Avg response
        avg = stats.ping_avg_ms if stats.ping_avg_ms > 0 else stats.cip_avg_ms
        if avg > 0:
            rt_color = STATUS_GOOD if avg < 20 else STATUS_WARN if avg < 100 else STATUS_ERROR
            self._update_stat("avg_rt", f"{avg:.1f}ms", rt_color)

        # Outages
        outages = stats.outage_count
        out_color = STATUS_GOOD if outages == 0 else STATUS_WARN if outages < 3 else STATUS_ERROR
        self._update_stat("outages", str(outages), out_color)

        # Status indicator
        if stats.total_samples > 0:
            last_samples = self._monitor.get_recent_samples(1)
            if last_samples and last_samples[-1].is_reachable:
                self._update_stat("status", "● Online", STATUS_GOOD)
            else:
                self._update_stat("status", "● Offline", STATUS_ERROR)

        # Event count
        self._event_count_label.configure(
            text=f"{stats.outage_count} outages, {stats.total_samples} samples")

    def _update_stat(self, key: str, value: str, color: str = TEXT_PRIMARY):
        """Update a stat card value."""
        if key in self._stat_cards:
            self._stat_cards[key].configure(text=value, text_color=color)

    # ── Analysis ─────────────────────────────────────────────────────────

    def _run_analysis(self):
        """Run the analyzer on collected data and display the report."""
        if not self._monitor or self._monitor.sample_count < 5:
            self._log_event("⚠ Need at least 5 samples for analysis — let it run longer")
            return

        self._analyze_btn.configure(state="disabled", text="⏳ Analyzing...")

        def _analyze():
            samples = self._monitor.get_samples_snapshot()
            outages = self._monitor.get_outages_snapshot()
            stats = self._monitor.get_stats()
            report = self._analyzer.analyze(
                samples, outages, stats, self._monitor.target_ip)
            self.after(0, lambda: self._display_report(report))

        threading.Thread(target=_analyze, daemon=True).start()

    def _display_report(self, report: AnalysisReport):
        """Render the analysis report in the UI."""
        self._analyze_btn.configure(state="normal", text="🔍 Analyze")
        self._last_report = report

        # Update health stat card
        health_color = HEALTH_COLORS.get(report.health_label, TEXT_MUTED)
        self._update_stat("health", f"{report.health_score}", health_color)

        # Update report status
        self._report_status.configure(
            text=f"Generated at {report.generated_at}",
            text_color=TEXT_SECONDARY)

        # Clear report container
        for w in self._report_container.winfo_children():
            w.destroy()

        # ── Health Score Banner ──
        banner_color = HEALTH_COLORS.get(report.health_label, BG_MEDIUM)
        banner = ctk.CTkFrame(self._report_container, fg_color=banner_color,
                               corner_radius=8, height=52)
        banner.pack(fill="x", pady=(4, 8))
        banner.pack_propagate(False)

        banner_inner = ctk.CTkFrame(banner, fg_color="transparent")
        banner_inner.pack(fill="both", expand=True, padx=16)

        ctk.CTkLabel(banner_inner,
                     text=f"Health Score: {report.health_score}/100 — {report.health_label}",
                     font=(FONT_FAMILY, 16, "bold"),
                     text_color="white").pack(side="left", pady=12)

        if report.product_name:
            ctk.CTkLabel(banner_inner,
                         text=report.product_name,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL),
                         text_color="white").pack(side="right", pady=12)

        # ── Summary ──
        summary_frame = ctk.CTkFrame(self._report_container, fg_color=BG_MEDIUM,
                                      corner_radius=6)
        summary_frame.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(summary_frame, text=report.summary,
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, anchor="w",
                     justify="left", wraplength=700).pack(
            fill="x", padx=12, pady=10)

        # ── Key Metrics Bar ──
        metrics_frame = ctk.CTkFrame(self._report_container, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=(0, 8))

        metrics = [
            ("Uptime", f"{report.uptime_pct:.1f}%"),
            ("Avg Response", f"{report.avg_response_ms:.1f}ms"),
            ("Packet Loss", f"{report.packet_loss_pct:.1f}%"),
            ("Outages", str(report.outage_count)),
            ("Longest Outage", report.longest_outage or "—"),
            ("Duration", report.monitoring_duration),
            ("Samples", f"{report.sample_count:,}"),
        ]

        for i, (label, value) in enumerate(metrics):
            m = ctk.CTkFrame(metrics_frame, fg_color=BG_CARD, corner_radius=4)
            m.pack(side="left", fill="x", expand=True,
                   padx=(0 if i == 0 else 2, 0 if i == len(metrics) - 1 else 2))

            ctk.CTkLabel(m, text=label,
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED).pack(padx=6, pady=(4, 0))
            ctk.CTkLabel(m, text=value,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL, "bold"),
                         text_color=TEXT_PRIMARY).pack(padx=6, pady=(0, 4))

        # ── Findings ──
        if report.findings:
            ctk.CTkLabel(self._report_container,
                         text=f"Findings ({len(report.findings)})",
                         font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                         text_color=TEXT_PRIMARY, anchor="w").pack(
                fill="x", padx=4, pady=(8, 4))

            for finding in report.findings:
                self._render_finding(self._report_container, finding)

    def _render_finding(self, parent, finding: Finding):
        """Render a single finding card."""
        border_color = SEVERITY_COLORS.get(finding.severity, BORDER_COLOR)

        card = ctk.CTkFrame(parent, fg_color=BG_MEDIUM, corner_radius=6,
                             border_width=1, border_color=border_color)
        card.pack(fill="x", pady=3)

        # Header row
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 2))

        severity_label = ctk.CTkLabel(
            hdr, text=f"{finding.icon} {finding.severity.upper()}",
            font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            text_color=border_color)
        severity_label.pack(side="left")

        if finding.metric_value:
            ctk.CTkLabel(hdr, text=finding.metric_value,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=border_color).pack(side="right")

        # Title
        ctk.CTkLabel(card, text=finding.title,
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=12, pady=(0, 2))

        # Description
        ctk.CTkLabel(card, text=finding.description,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=680).pack(
            fill="x", padx=12, pady=(0, 4))

        # Likely cause
        cause_frame = ctk.CTkFrame(card, fg_color=BG_CARD, corner_radius=4)
        cause_frame.pack(fill="x", padx=12, pady=(0, 4))

        ctk.CTkLabel(cause_frame, text="Likely Cause:",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=8, pady=(4, 0))
        ctk.CTkLabel(cause_frame, text=finding.likely_cause,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=660).pack(
            fill="x", padx=8, pady=(0, 4))

        # Suggestion
        sug_frame = ctk.CTkFrame(card, fg_color=BG_CARD, corner_radius=4)
        sug_frame.pack(fill="x", padx=12, pady=(0, 8))

        ctk.CTkLabel(sug_frame, text="What To Do:",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=SAS_ORANGE, anchor="w").pack(
            fill="x", padx=8, pady=(4, 0))
        ctk.CTkLabel(sug_frame, text=finding.suggestion,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=660).pack(
            fill="x", padx=8, pady=(0, 6))

    # ── CSV Export ───────────────────────────────────────────────────────

    def _export_csv(self):
        """Export monitoring data to CSV file."""
        if not self._monitor or self._monitor.sample_count == 0:
            self._log_event("⚠ No data to export")
            return

        # Generate filename
        ip_safe = self._monitor.target_ip.replace(".", "-")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monitor_{ip_safe}_{ts}.csv"

        # Use Documents folder on Windows, fallback to home
        try:
            docs = Path.home() / "Documents"
            if not docs.exists():
                docs = Path.home()
            filepath = str(docs / filename)
        except Exception:
            filepath = filename

        ok, msg = self._monitor.export_csv(filepath)
        if ok:
            self._log_event(f"💾 Exported to: {filepath}")
        else:
            self._log_event(f"⚠ Export failed: {msg}")
