"""
SAS Network Diagnostics Tool — DeviceNet Network Monitor View
Network-wide monitoring for catching intermittent DeviceNet issues.

Features:
  - Initial discovery scan to find all online nodes
  - Live node status grid (green/red per MAC ID per cycle)
  - Bus-off counter tracking with alerts
  - Per-node reliability bars
  - Event log (offline/online transitions, bus-off events)
  - Analysis report with root cause identification
  - CSV export
"""

import logging
import threading
import time
from datetime import datetime
from typing import Optional, Dict, List

import customtkinter as ctk
import tkinter as tk

from core.devicenet_monitor import (
    DeviceNetNetworkMonitor, NetworkPollCycle, NetworkEvent,
    DeviceNetMonitorStats,
)
from core.devicenet_monitor_analyzer import (
    DeviceNetMonitorAnalyzer, DeviceNetAnalysisReport, DeviceNetFinding,
)
from ui.theme import *
from ui.widgets import enable_touch_scroll

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

NODE_CELL_SIZE = 14       # Heatmap cell size in pixels
NODE_CELL_GAP = 2
HEATMAP_ROWS = 64         # One row per MAC ID
HEATMAP_COLS = 80         # Visible poll cycles
HEATMAP_HEIGHT = 180

COLOR_ONLINE = "#22C55E"
COLOR_OFFLINE = "#EF4444"
COLOR_UNKNOWN = "#1B2332"
COLOR_BUS_OFF = "#F59E0B"

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


class DeviceNetMonitorView(ctk.CTkFrame):
    """DeviceNet network-wide monitor tab."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._monitor: Optional[DeviceNetNetworkMonitor] = None
        self._analyzer = DeviceNetMonitorAnalyzer()
        self._monitoring = False
        self._discovered_nodes: Dict[int, dict] = {}
        self._monitored_mac_ids: List[int] = []
        self._heatmap_data: List[Dict[int, bool]] = []  # List of {mac_id: online}
        self._bus_off_history: List[int] = []
        self._update_job = None

        self._build_ui()

    def _build_ui(self):
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BG_MEDIUM,
            scrollbar_button_hover_color=SAS_BLUE)
        self._scroll.pack(fill="both", expand=True)
        enable_touch_scroll(self._scroll)

        inner = self._scroll
        self._build_header(inner)
        self._build_connection_bar(inner)
        self._build_discovery_panel(inner)
        self._build_stats_row(inner)
        self._build_heatmap(inner)
        self._build_node_reliability(inner)
        self._build_event_log(inner)
        self._build_analysis_section(inner)

    # ── Header ───────────────────────────────────────────────────────────

    def _build_header(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 4))

        ctk.CTkLabel(hdr, text="🔗  DeviceNet Network Monitor",
                     font=(FONT_FAMILY, 22, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        ctk.CTkLabel(hdr,
            text="Monitor the entire DeviceNet bus to catch intermittent faults, bus-off events,\n"
                 "and identify which device is causing problems.",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w", justify="left").pack(
                side="left", padx=(16, 0))

    # ── Connection Bar ───────────────────────────────────────────────────

    def _build_connection_bar(self, parent):
        bar = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        bar.pack(fill="x", padx=24, pady=(8, 4))

        # Top row: PLC IP, scanner slot, poll interval
        row1 = ctk.CTkFrame(bar, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(8, 4))

        # PLC IP
        ctk.CTkLabel(row1, text="PLC IP:",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))
        self._ip_entry = ctk.CTkEntry(
            row1, placeholder_text="192.168.1.10",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=140, height=INPUT_HEIGHT)
        self._ip_entry.pack(side="left", padx=(0, 12))

        # Scanner Slot
        ctk.CTkLabel(row1, text="Scanner Slot:",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))
        self._slot_entry = ctk.CTkEntry(
            row1, placeholder_text="3",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=50, height=INPUT_HEIGHT)
        self._slot_entry.pack(side="left", padx=(0, 12))

        # Poll interval
        ctk.CTkLabel(row1, text="Poll every:",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))
        self._interval_combo = ctk.CTkComboBox(
            row1, values=["5 sec", "10 sec", "15 sec", "30 sec", "60 sec"],
            width=100, height=INPUT_HEIGHT,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, dropdown_fg_color=BG_CARD,
            dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_CARD_HOVER)
        self._interval_combo.set("10 sec")
        self._interval_combo.pack(side="left", padx=(0, 12))

        # Bottom row: action buttons
        row2 = ctk.CTkFrame(bar, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 8))

        self._start_btn = ctk.CTkButton(
            row2, text="▶  Start Monitor", width=140,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_ORANGE, hover_color=SAS_ORANGE_DARK,
            text_color="white", command=self._toggle_monitor)
        self._start_btn.pack(side="left", padx=(0, 6))

        self._analyze_btn = ctk.CTkButton(
            row2, text="🔍 Analyze", width=100,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            text_color="white", command=self._run_analysis)
        self._analyze_btn.pack(side="left", padx=(0, 6))

        self._export_btn = ctk.CTkButton(
            row2, text="💾 Export", width=90,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_MEDIUM, hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY, command=self._export_csv)
        self._export_btn.pack(side="left")

    # ── Discovery Panel ──────────────────────────────────────────────────

    def _build_discovery_panel(self, parent):
        self._discovery_frame = ctk.CTkFrame(parent, fg_color=BG_CARD,
                                               corner_radius=8)
        self._discovery_frame.pack(fill="x", padx=24, pady=(4, 0))

        inner = ctk.CTkFrame(self._discovery_frame, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=10)

        self._discover_btn = ctk.CTkButton(
            inner, text="🔍  Discover Nodes",
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            text_color="white", width=160, height=INPUT_HEIGHT,
            command=self._discover_nodes)
        self._discover_btn.pack(side="left", padx=(0, 12))

        self._discovery_status = ctk.CTkLabel(
            inner,
            text="Step 1: Enter PLC IP and scanner slot, then click Discover to find online nodes.",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w")
        self._discovery_status.pack(side="left", fill="x", expand=True)

        # Node list (shown after discovery)
        self._node_list_frame = ctk.CTkFrame(self._discovery_frame,
                                               fg_color="transparent")
        # Not packed yet — shown after discovery

    # ── Stats Row ────────────────────────────────────────────────────────

    def _build_stats_row(self, parent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(8, 0))

        self._stat_cards = {}
        cards = [
            ("status", "Status", "Idle", TEXT_MUTED),
            ("cycles", "Cycles", "0", TEXT_MUTED),
            ("net_uptime", "Network Uptime", "—", TEXT_MUTED),
            ("nodes_online", "Nodes Online", "—", TEXT_MUTED),
            ("bus_off", "Bus-Off Count", "0", TEXT_MUTED),
            ("dropouts", "Total Dropouts", "0", TEXT_MUTED),
            ("duration", "Duration", "0:00", TEXT_MUTED),
            ("health", "Health", "—", TEXT_MUTED),
        ]

        for i, (key, label, default, color) in enumerate(cards):
            card = ctk.CTkFrame(row, fg_color=BG_CARD, corner_radius=6, height=64)
            card.pack(side="left", fill="both", expand=True,
                      padx=(0 if i == 0 else 3, 0 if i == len(cards) - 1 else 3))
            card.pack_propagate(False)

            ctk.CTkLabel(card, text=label,
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED, anchor="w").pack(
                fill="x", padx=10, pady=(8, 0))

            val = ctk.CTkLabel(card, text=default,
                               font=(FONT_FAMILY_MONO, 16, "bold"),
                               text_color=color, anchor="w")
            val.pack(fill="x", padx=10, pady=(0, 8))
            self._stat_cards[key] = val

    # ── Node Status Heatmap ──────────────────────────────────────────────

    def _build_heatmap(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        frame.pack(fill="x", padx=24, pady=(8, 0))

        hdr = ctk.CTkFrame(frame, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(hdr, text="Node Status Timeline",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        # Legend
        legend = ctk.CTkFrame(hdr, fg_color="transparent")
        legend.pack(side="right")

        for color, label in [(COLOR_ONLINE, "Online"), (COLOR_OFFLINE, "Offline"),
                              (COLOR_BUS_OFF, "Bus-Off")]:
            ctk.CTkFrame(legend, fg_color=color, width=10, height=10,
                         corner_radius=2).pack(side="left", padx=(8, 3))
            ctk.CTkLabel(legend, text=label,
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED).pack(side="left")

        ctk.CTkLabel(hdr, text="← older    newer →",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED).pack(side="right", padx=(0, 12))

        # Canvas for heatmap
        self._heatmap_canvas = tk.Canvas(
            frame, height=HEATMAP_HEIGHT, bg=resolve_color(BG_INPUT),
            highlightthickness=0, bd=0)
        self._heatmap_canvas.pack(fill="x", padx=8, pady=(4, 10))

        self._draw_empty_heatmap()

    def _draw_empty_heatmap(self):
        c = self._heatmap_canvas
        c.delete("all")
        w = c.winfo_width() or 600
        h = HEATMAP_HEIGHT
        c.create_text(w // 2, h // 2,
                       text="Discover nodes and start monitoring to see the status timeline",
                       fill=resolve_color(TEXT_MUTED), font=(FONT_FAMILY, 11))

    def _draw_heatmap(self):
        """Draw the node status heatmap from collected data."""
        c = self._heatmap_canvas
        c.delete("all")

        if not self._monitored_mac_ids or not self._heatmap_data:
            self._draw_empty_heatmap()
            return

        w = c.winfo_width() or 700
        h = HEATMAP_HEIGHT

        nodes = self._monitored_mac_ids
        num_nodes = len(nodes)
        if num_nodes == 0:
            return

        # Layout
        label_width = 52
        plot_w = w - label_width - 8
        cell_h = max(3, min(14, (h - 10) // max(num_nodes, 1)))
        cell_w = max(3, min(10, plot_w // max(len(self._heatmap_data), 1)))

        visible_cols = min(len(self._heatmap_data), plot_w // (cell_w + 1))
        data_slice = self._heatmap_data[-visible_cols:] if visible_cols > 0 else []
        bus_off_slice = self._bus_off_history[-visible_cols:] if visible_cols > 0 else []

        # Draw node labels (left side)
        for row, mac_id in enumerate(nodes):
            y = 4 + row * (cell_h + 1)
            name = self._discovered_nodes.get(mac_id, {}).get("product_name", "")
            label = f"{mac_id:2d}"
            c.create_text(label_width - 4, y + cell_h // 2, text=label,
                           fill=resolve_color(TEXT_MUTED), anchor="e",
                           font=("Consolas", max(7, min(9, cell_h - 1))))

        # Draw cells
        for col, cycle_data in enumerate(data_slice):
            x = label_width + col * (cell_w + 1)
            had_bus_off = col < len(bus_off_slice) and bus_off_slice[col] > 0

            for row, mac_id in enumerate(nodes):
                y = 4 + row * (cell_h + 1)
                online = cycle_data.get(mac_id)

                if online is None:
                    color = COLOR_UNKNOWN
                elif online:
                    color = COLOR_ONLINE
                else:
                    color = COLOR_OFFLINE

                c.create_rectangle(x, y, x + cell_w, y + cell_h,
                                    fill=color, outline="")

            # Bus-off marker (yellow line at bottom)
            if had_bus_off:
                y_bottom = 4 + num_nodes * (cell_h + 1)
                c.create_rectangle(x, y_bottom, x + cell_w, y_bottom + 3,
                                    fill=COLOR_BUS_OFF, outline="")

    # ── Node Reliability Bars ────────────────────────────────────────────

    def _build_node_reliability(self, parent):
        self._reliability_frame = ctk.CTkFrame(parent, fg_color=BG_CARD,
                                                 corner_radius=8)
        self._reliability_frame.pack(fill="x", padx=24, pady=(8, 0))

        hdr = ctk.CTkFrame(self._reliability_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(hdr, text="Node Reliability",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        self._reliability_container = ctk.CTkFrame(
            self._reliability_frame, fg_color="transparent")
        self._reliability_container.pack(fill="x", padx=12, pady=(4, 10))

        ctk.CTkLabel(self._reliability_container,
                     text="Run monitoring to see per-node reliability",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_MUTED).pack(padx=4, pady=8)

    def _update_reliability_bars(self, stats: DeviceNetMonitorStats):
        """Update the per-node reliability bars."""
        for w in self._reliability_container.winfo_children():
            w.destroy()

        if not stats.node_histories:
            return

        # Sort by uptime (worst first)
        sorted_nodes = sorted(
            stats.node_histories.items(),
            key=lambda x: x[1].uptime_pct)

        for mac_id, hist in sorted_nodes:
            info = self._discovered_nodes.get(mac_id, {})
            name = info.get("product_name", f"Node {mac_id}")

            row = ctk.CTkFrame(self._reliability_container, fg_color="transparent",
                               height=22)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            # Label
            label = f"MAC {mac_id:2d} — {name}"
            ctk.CTkLabel(row, text=label,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=TEXT_SECONDARY, anchor="w",
                         width=250).pack(side="left", padx=(4, 8))

            # Bar background
            bar_bg = ctk.CTkFrame(row, fg_color="#1B2332", corner_radius=3,
                                   height=12)
            bar_bg.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=5)
            bar_bg.pack_propagate(False)

            # Bar fill
            pct = hist.uptime_pct
            color = COLOR_ONLINE if pct >= 99 else COLOR_BUS_OFF if pct >= 90 else COLOR_OFFLINE

            if pct > 0:
                bar_fill = ctk.CTkFrame(bar_bg, fg_color=color, corner_radius=3)
                bar_fill.place(relx=0, rely=0, relwidth=max(0.01, pct / 100),
                               relheight=1)

            # Percentage + dropouts
            stats_text = f"{pct:.1f}%"
            if hist.went_offline_count > 0:
                stats_text += f"  ({hist.went_offline_count} drops)"
            ctk.CTkLabel(row, text=stats_text,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=color, anchor="e",
                         width=120).pack(side="right")

    # ── Event Log ────────────────────────────────────────────────────────

    def _build_event_log(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        frame.pack(fill="x", padx=24, pady=(8, 0))

        hdr = ctk.CTkFrame(frame, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(hdr, text="Event Log",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        self._event_count_label = ctk.CTkLabel(
            hdr, text="", font=(FONT_FAMILY, FONT_SIZE_TINY),
            text_color=TEXT_MUTED)
        self._event_count_label.pack(side="right")

        self._event_text = ctk.CTkTextbox(
            frame, height=120, fg_color="#0D1117",
            text_color=TEXT_SECONDARY,
            font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
            activate_scrollbars=True, wrap="none")
        self._event_text.pack(fill="x", padx=8, pady=(4, 10))
        self._event_text.configure(state="disabled")

    def _log_event(self, text: str, color: str = None):
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

        hdr = ctk.CTkFrame(self._analysis_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(hdr, text="📋  Network Analysis Report",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        self._report_status = ctk.CTkLabel(
            hdr, text="Collect data then click Analyze",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED)
        self._report_status.pack(side="right")

        self._report_container = ctk.CTkFrame(
            self._analysis_frame, fg_color="transparent")
        self._report_container.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(self._report_container,
                     text="Discover nodes, start monitoring, and collect data for at least 2-3 minutes.\n"
                          "Then click 'Analyze' for a full network diagnostic report.",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_MUTED, anchor="w", justify="left").pack(
            padx=4, pady=12)

    # ── Discovery ────────────────────────────────────────────────────────

    def _discover_nodes(self):
        ip = self._ip_entry.get().strip()
        slot_str = self._slot_entry.get().strip()

        if not ip:
            self._log_event("⚠ Enter the PLC IP address")
            return
        try:
            slot = int(slot_str)
        except (ValueError, TypeError):
            self._log_event("⚠ Enter a valid scanner slot number")
            return

        self._discover_btn.configure(state="disabled", text="⏳ Scanning...")
        self._discovery_status.configure(text="Scanning all 64 MAC IDs...",
                                          text_color=SAS_ORANGE)
        self._log_event(f"🔍 Discovering nodes on {ip}, slot {slot}...")

        def _do_discover():
            monitor = DeviceNetNetworkMonitor(ip, slot)

            def progress(current, total, status):
                self.after(0, lambda: self._discovery_status.configure(
                    text=f"Scanning: {status} ({current}/{total})"))

            ok, msg, nodes = monitor.discover_nodes(progress_callback=progress)
            self.after(0, lambda: self._on_discovery_complete(ok, msg, nodes, monitor))

        threading.Thread(target=_do_discover, daemon=True).start()

    def _on_discovery_complete(self, ok, msg, nodes, monitor):
        self._discover_btn.configure(state="normal", text="🔍  Discover Nodes")

        if ok:
            self._discovered_nodes = nodes
            self._monitor = monitor
            self._monitored_mac_ids = sorted(nodes.keys())

            self._discovery_status.configure(
                text=f"✅ {msg}", text_color=STATUS_GOOD)
            self._log_event(f"✅ {msg}")

            # Show discovered nodes
            self._show_discovered_nodes()
        else:
            self._discovery_status.configure(
                text=f"❌ {msg}", text_color=STATUS_ERROR)
            self._log_event(f"❌ Discovery failed: {msg}")

    def _show_discovered_nodes(self):
        """Display discovered nodes in the discovery panel."""
        for w in self._node_list_frame.winfo_children():
            w.destroy()

        self._node_list_frame.pack(fill="x", padx=0, pady=(8, 4))

        if not self._discovered_nodes:
            return

        # Compact node list
        row = ctk.CTkFrame(self._node_list_frame, fg_color="transparent")
        row.pack(fill="x", padx=16)

        for mac_id in sorted(self._discovered_nodes.keys()):
            info = self._discovered_nodes[mac_id]
            name = info.get("product_name", "?")

            chip = ctk.CTkFrame(row, fg_color=BG_MEDIUM, corner_radius=4)
            chip.pack(side="left", padx=(0, 4), pady=2)

            ctk.CTkLabel(chip, text=f"{mac_id}",
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY, "bold"),
                         text_color=SAS_BLUE_LIGHT).pack(side="left", padx=(6, 2))
            ctk.CTkLabel(chip, text=name,
                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 6))

    # ── Monitor Control ──────────────────────────────────────────────────

    def _toggle_monitor(self):
        if self._monitoring:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        if not self._monitor or not self._monitored_mac_ids:
            self._log_event("⚠ Discover nodes first before starting the monitor")
            return

        interval = float(self._interval_combo.get().split()[0])
        self._monitor.poll_interval = interval

        # Set callbacks
        self._monitor.set_on_event(lambda e: self.after(0, lambda: self._on_network_event(e)))

        # Clear data
        self._heatmap_data.clear()
        self._bus_off_history.clear()

        # Start
        self._monitor.start()
        self._monitoring = True

        self._start_btn.configure(text="■  Stop Monitor", fg_color=STATUS_ERROR,
                                   hover_color="#DC2626")
        self._ip_entry.configure(state="disabled")
        self._slot_entry.configure(state="disabled")

        self._log_event(f"▶ Started monitoring {len(self._monitored_mac_ids)} nodes "
                         f"(interval: {interval}s)")
        self._update_stat("status", "Monitoring...", SAS_ORANGE)

        self._schedule_update()

    def _stop_monitor(self):
        if self._monitor:
            self._monitor.stop()
            self._log_event(f"■ Stopped — {self._monitor.cycle_count} cycles collected")

        self._monitoring = False

        if self._update_job:
            self.after_cancel(self._update_job)
            self._update_job = None

        self._start_btn.configure(text="▶  Start Monitor", fg_color=SAS_ORANGE,
                                   hover_color=SAS_ORANGE_DARK)
        self._ip_entry.configure(state="normal")
        self._slot_entry.configure(state="normal")

        self._update_stat("status", "Stopped", TEXT_MUTED)
        self._update_stats()
        self._draw_heatmap()

    def _on_network_event(self, event: NetworkEvent):
        """Handle a network event from the monitor."""
        icon = {"critical": "🔴", "warning": "⚠️", "info": "ℹ️"}.get(
            event.severity, "")
        self._log_event(f"{icon} {event.description}")

    # ── Periodic UI Update ───────────────────────────────────────────────

    def _schedule_update(self):
        if self._monitoring:
            self._do_update()
            self._update_job = self.after(2000, self._schedule_update)

    def _do_update(self):
        if not self._monitor:
            return

        # Get recent cycles for heatmap
        recent = self._monitor.get_recent_cycles(HEATMAP_COLS)

        self._heatmap_data = [
            {mac_id: r.online for mac_id, r in c.node_results.items()}
            for c in recent
        ]
        self._bus_off_history = [c.bus_off_delta for c in recent]

        self._draw_heatmap()
        self._update_stats()

    def _update_stats(self):
        if not self._monitor:
            return

        stats = self._monitor.get_stats()

        self._update_stat("cycles", f"{stats.total_cycles:,}", TEXT_PRIMARY)

        # Duration
        elapsed = self._monitor.elapsed_seconds
        if elapsed < 60:
            dur = f"{elapsed:.0f}s"
        elif elapsed < 3600:
            dur = f"{int(elapsed//60)}:{int(elapsed%60):02d}"
        else:
            dur = f"{int(elapsed//3600)}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
        self._update_stat("duration", dur, TEXT_PRIMARY)

        # Network uptime
        up = stats.network_uptime_pct
        up_color = STATUS_GOOD if up >= 99 else STATUS_WARN if up >= 90 else STATUS_ERROR
        self._update_stat("net_uptime", f"{up:.1f}%", up_color)

        # Nodes online (from latest cycle)
        recent = self._monitor.get_recent_cycles(1)
        if recent:
            latest = recent[-1]
            online = latest.nodes_online
            total = latest.nodes_monitored
            color = STATUS_GOOD if online == total else STATUS_WARN if online > 0 else STATUS_ERROR
            self._update_stat("nodes_online", f"{online}/{total}", color)

        # Bus-off
        bo = stats.bus_off_final
        bo_color = STATUS_GOOD if stats.bus_off_total == 0 else STATUS_ERROR
        self._update_stat("bus_off", str(bo), bo_color)

        # Dropouts
        drops = sum(h.went_offline_count for h in stats.node_histories.values())
        d_color = STATUS_GOOD if drops == 0 else STATUS_WARN if drops < 5 else STATUS_ERROR
        self._update_stat("dropouts", str(drops), d_color)

        # Status
        if recent and recent[-1].nodes_offline == 0:
            self._update_stat("status", "● All Online", STATUS_GOOD)
        elif recent:
            self._update_stat("status", f"● {recent[-1].nodes_offline} Offline", STATUS_ERROR)

        # Event count
        events = self._monitor.get_events_snapshot()
        self._event_count_label.configure(
            text=f"{len(events)} events, {stats.total_cycles} cycles")

        # Reliability bars (update every 5 cycles to avoid flicker)
        if stats.total_cycles % 5 == 0 or not self._monitoring:
            self._update_reliability_bars(stats)

    def _update_stat(self, key: str, value: str, color: str = TEXT_PRIMARY):
        if key in self._stat_cards:
            self._stat_cards[key].configure(text=value, text_color=color)

    # ── Analysis ─────────────────────────────────────────────────────────

    def _run_analysis(self):
        if not self._monitor or self._monitor.cycle_count < 3:
            self._log_event("⚠ Need at least 3 cycles — let it run longer")
            return

        self._analyze_btn.configure(state="disabled", text="⏳ Analyzing...")

        def _analyze():
            cycles = list(self._monitor.cycles)
            events = self._monitor.get_events_snapshot()
            stats = self._monitor.get_stats()

            report = self._analyzer.analyze(
                cycles, events, stats, self._discovered_nodes,
                self._ip_entry.get().strip(),
                int(self._slot_entry.get().strip()),
            )
            self.after(0, lambda: self._display_report(report))

        threading.Thread(target=_analyze, daemon=True).start()

    def _display_report(self, report: DeviceNetAnalysisReport):
        self._analyze_btn.configure(state="normal", text="🔍 Analyze")

        health_color = HEALTH_COLORS.get(report.health_label, TEXT_MUTED)
        self._update_stat("health", str(report.health_score), health_color)
        self._report_status.configure(
            text=f"Generated at {report.generated_at}",
            text_color=TEXT_SECONDARY)

        for w in self._report_container.winfo_children():
            w.destroy()

        # Health banner
        banner = ctk.CTkFrame(self._report_container, fg_color=health_color,
                               corner_radius=8, height=52)
        banner.pack(fill="x", pady=(4, 8))
        banner.pack_propagate(False)

        banner_inner = ctk.CTkFrame(banner, fg_color="transparent")
        banner_inner.pack(fill="both", expand=True, padx=16)

        ctk.CTkLabel(banner_inner,
                     text=f"Health Score: {report.health_score}/100 — {report.health_label}",
                     font=(FONT_FAMILY, 16, "bold"),
                     text_color="white").pack(side="left", pady=12)

        ctk.CTkLabel(banner_inner,
                     text=f"{report.monitored_nodes} nodes monitored",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color="white").pack(side="right", pady=12)

        # Summary
        summary = ctk.CTkFrame(self._report_container, fg_color=BG_MEDIUM,
                                corner_radius=6)
        summary.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(summary, text=report.summary,
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, anchor="w",
                     justify="left", wraplength=700).pack(
            fill="x", padx=12, pady=10)

        # Key metrics
        metrics_frame = ctk.CTkFrame(self._report_container, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=(0, 8))

        metrics = [
            ("Net Uptime", f"{report.network_uptime_pct:.1f}%"),
            ("Bus-Off Events", str(report.bus_off_events)),
            ("Node Dropouts", str(report.total_node_dropouts)),
            ("Duration", report.monitoring_duration),
            ("Cycles", f"{report.cycle_count:,}"),
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

        # Node reliability table
        if report.node_table:
            ctk.CTkLabel(self._report_container,
                         text="Node Reliability Ranking (worst first)",
                         font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                         text_color=TEXT_PRIMARY, anchor="w").pack(
                fill="x", padx=4, pady=(8, 4))

            table_frame = ctk.CTkFrame(self._report_container, fg_color=BG_MEDIUM,
                                        corner_radius=6)
            table_frame.pack(fill="x", pady=(0, 8))

            # Header
            hdr_row = ctk.CTkFrame(table_frame, fg_color="transparent")
            hdr_row.pack(fill="x", padx=8, pady=(6, 2))
            for text, width in [("MAC", 40), ("Device", 180), ("Uptime", 70),
                                 ("Drops", 50), ("Avg RT", 70), ("Bus-Off Corr", 90)]:
                ctk.CTkLabel(hdr_row, text=text, width=width,
                             font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                             text_color=TEXT_MUTED, anchor="w").pack(side="left", padx=2)

            for entry in report.node_table:
                row = ctk.CTkFrame(table_frame, fg_color="transparent")
                row.pack(fill="x", padx=8, pady=1)

                up = entry["uptime_pct"]
                color = COLOR_ONLINE if up >= 99 else COLOR_BUS_OFF if up >= 90 else COLOR_OFFLINE

                ctk.CTkLabel(row, text=str(entry["mac_id"]), width=40,
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=TEXT_PRIMARY, anchor="w").pack(side="left", padx=2)
                ctk.CTkLabel(row, text=entry["product_name"], width=180,
                             font=(FONT_FAMILY, FONT_SIZE_TINY),
                             text_color=TEXT_SECONDARY, anchor="w").pack(side="left", padx=2)
                ctk.CTkLabel(row, text=f"{up:.1f}%", width=70,
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=color, anchor="w").pack(side="left", padx=2)
                ctk.CTkLabel(row, text=str(entry["dropouts"]), width=50,
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=TEXT_PRIMARY, anchor="w").pack(side="left", padx=2)
                ctk.CTkLabel(row, text=f"{entry['avg_rt_ms']:.0f}ms", width=70,
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=TEXT_PRIMARY, anchor="w").pack(side="left", padx=2)
                ctk.CTkLabel(row, text=str(entry["bus_off_corr"]), width=90,
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=STATUS_ERROR if entry["bus_off_corr"] > 0 else TEXT_MUTED,
                             anchor="w").pack(side="left", padx=2)

            # Bottom padding
            ctk.CTkFrame(table_frame, fg_color="transparent", height=4).pack()

        # Findings
        if report.findings:
            ctk.CTkLabel(self._report_container,
                         text=f"Findings ({len(report.findings)})",
                         font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                         text_color=TEXT_PRIMARY, anchor="w").pack(
                fill="x", padx=4, pady=(8, 4))

            for finding in report.findings:
                self._render_finding(self._report_container, finding)

    def _render_finding(self, parent, finding: DeviceNetFinding):
        border_color = SEVERITY_COLORS.get(finding.severity, BORDER_COLOR)

        card = ctk.CTkFrame(parent, fg_color=BG_MEDIUM, corner_radius=6,
                             border_width=1, border_color=border_color)
        card.pack(fill="x", pady=3)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(8, 2))

        ctk.CTkLabel(hdr, text=f"{finding.icon} {finding.severity.upper()}",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=border_color).pack(side="left")

        if finding.metric_value:
            ctk.CTkLabel(hdr, text=finding.metric_value,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=border_color).pack(side="right")

        ctk.CTkLabel(card, text=finding.title,
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=12, pady=(0, 2))

        ctk.CTkLabel(card, text=finding.description,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=680).pack(
            fill="x", padx=12, pady=(0, 4))

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
        if not self._monitor or self._monitor.cycle_count == 0:
            self._log_event("⚠ No data to export")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_safe = self._ip_entry.get().strip().replace(".", "-")
        filename = f"dnet_monitor_{ip_safe}_{ts}.csv"

        try:
            from pathlib import Path
            docs = Path.home() / "Documents"
            if not docs.exists():
                docs = Path.home()
            filepath = str(docs / filename)
        except Exception:
            filepath = filename

        ok, msg = self._monitor.export_csv(filepath)
        if ok:
            self._log_event(f"💾 {msg}")
        else:
            self._log_event(f"⚠ {msg}")
