"""
SAS Network Diagnostics Tool — DeviceNet Diagnostics View
Phase 2: Browse and diagnose DeviceNet networks via backplane punch-through
or 1784-U2DN USB adapter.

Features:
  - Connection method selection (backplane / U2DN)
  - Visual 8×8 MAC ID grid (like RSNetWorx)
  - Node detail panel with CIP Identity info
  - Scanner diagnostics card
  - Error code lookup reference
"""

import logging
import threading
import time
import tkinter as tk
from typing import Optional, List

import customtkinter as ctk

from core.devicenet_diag import (
    DeviceNetNode, DeviceNetScanResult, ScannerDiagnostics,
    DeviceNetBackplaneScanner, U2DNAdapter,
    CIP_VENDORS, CIP_PRODUCT_TYPES, BAUD_RATES,
    DNB_ERROR_CODES, get_error_info,
    run_devicenet_scan, run_u2dn_scan,
)
from ui.theme import *
from ui.widgets import ScanProgressBar, InfoCard, enable_touch_scroll

logger = logging.getLogger(__name__)


# ── Node status colors ───────────────────────────────────────────────────────
NODE_ONLINE = STATUS_GOOD       # green — device responding
NODE_OFFLINE = ("#C8CCD2", "#2A3550")        # empty cell — light grey / dark
NODE_ERROR = STATUS_ERROR       # red — device faulted
NODE_WARN = STATUS_WARN         # amber — warning / keying issue
NODE_SCANNER = SAS_BLUE         # blue — the scanner itself
NODE_SELECTED = SAS_ORANGE      # highlight when clicked


# ── Severity badge colors ────────────────────────────────────────────────────
SEV_COLORS = {
    "info": SAS_BLUE_LIGHT,
    "warning": STATUS_WARN,
    "error": STATUS_ERROR,
    "critical": "#DC2626",
    "unknown": TEXT_MUTED,
}


class MACIDGrid(ctk.CTkFrame):
    """
    Visual 8×8 grid of DeviceNet MAC IDs (0-63).
    Each cell shows the MAC ID number and is color-coded by status.
    Clicking a cell selects it and fires the callback.
    """

    CELL_SIZE = 52
    CELL_PAD = 3

    def __init__(self, master, on_select=None, **kwargs):
        super().__init__(master, fg_color=BG_CARD, corner_radius=CARD_CORNER_RADIUS,
                         border_width=1, border_color=BORDER_COLOR, **kwargs)
        self._on_select = on_select
        self._cells = {}          # mac_id → canvas item references
        self._node_data = {}      # mac_id → DeviceNetNode
        self._selected_mac = -1

        self._build_grid()

    def _build_grid(self):
        """Build the 8×8 grid canvas."""
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(hdr, text="DeviceNet Node Map",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(side="left")
        self._count_label = ctk.CTkLabel(
            hdr, text="0 / 64 online",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_SECONDARY, anchor="e")
        self._count_label.pack(side="right")

        cols = 8
        rows = 8
        w = cols * (self.CELL_SIZE + self.CELL_PAD) + self.CELL_PAD + 8
        h = rows * (self.CELL_SIZE + self.CELL_PAD) + self.CELL_PAD + 8

        self._canvas = tk.Canvas(self, width=w, height=h,
                                 bg=resolve_color(BG_CARD), highlightthickness=0)
        self._canvas.pack(padx=12, pady=(2, 12))

        # Draw empty cells
        for mac_id in range(64):
            row = mac_id // cols
            col = mac_id % cols
            x0 = self.CELL_PAD + col * (self.CELL_SIZE + self.CELL_PAD) + 4
            y0 = self.CELL_PAD + row * (self.CELL_SIZE + self.CELL_PAD) + 4
            x1 = x0 + self.CELL_SIZE
            y1 = y0 + self.CELL_SIZE

            rect = self._canvas.create_rectangle(
                x0, y0, x1, y1, fill=resolve_color(NODE_OFFLINE), outline=resolve_color(BORDER_COLOR), width=1)
            text = self._canvas.create_text(
                (x0 + x1) // 2, (y0 + y1) // 2 - 4,
                text=str(mac_id), font=(FONT_FAMILY_MONO, 11, "bold"),
                fill=resolve_color(TEXT_MUTED))
            subtext = self._canvas.create_text(
                (x0 + x1) // 2, (y0 + y1) // 2 + 10,
                text="", font=(FONT_FAMILY, 7), fill=resolve_color(TEXT_MUTED))

            self._cells[mac_id] = {"rect": rect, "text": text, "subtext": subtext,
                                    "x0": x0, "y0": y0, "x1": x1, "y1": y1}

        self._canvas.bind("<Button-1>", self._on_click)

        # Legend
        legend = ctk.CTkFrame(self, fg_color="transparent")
        legend.pack(fill="x", padx=12, pady=(0, 8))
        for color, label in [(NODE_ONLINE, "Online"), (NODE_SCANNER, "Scanner"),
                              (NODE_ERROR, "Faulted"), (NODE_WARN, "Warning"),
                              (NODE_OFFLINE, "Empty")]:
            item = ctk.CTkFrame(legend, fg_color="transparent")
            item.pack(side="left", padx=(0, 14))
            dot_c = tk.Canvas(item, width=10, height=10,
                              bg=resolve_color(BG_CARD), highlightthickness=0)
            dot_c.create_oval(1, 1, 9, 9, fill=resolve_color(color), outline="")
            dot_c.pack(side="left", padx=(0, 4))
            ctk.CTkLabel(item, text=label, font=(FONT_FAMILY, FONT_SIZE_TINY),
                         text_color=TEXT_SECONDARY).pack(side="left")

    def update_nodes(self, nodes: List[DeviceNetNode], scanner_mac: int = -1):
        """Update all cells from scan results."""
        online = 0
        self._node_data.clear()
        for node in nodes:
            self._node_data[node.mac_id] = node
            cell = self._cells.get(node.mac_id)
            if not cell:
                continue

            if node.mac_id == scanner_mac:
                color = NODE_SCANNER
                text_color = "white"
                sublabel = "SCAN"
            elif node.is_online:
                # Check for faults
                if node.device_status and (node.device_status & 0x0C00):
                    color = NODE_ERROR
                elif node.device_status and (node.device_status & 0x0300):
                    color = NODE_WARN
                else:
                    color = NODE_ONLINE
                text_color = "white"
                sublabel = (node.product_name[:6] if node.product_name
                            else node.vendor_name[:6] if node.vendor_name else "")
                online += 1
            else:
                color = resolve_color(NODE_OFFLINE)
                text_color = resolve_color(TEXT_MUTED)
                sublabel = ""

            self._canvas.itemconfig(cell["rect"], fill=color)
            self._canvas.itemconfig(cell["text"], fill=text_color)
            self._canvas.itemconfig(cell["subtext"], text=sublabel, fill=text_color)

        self._count_label.configure(text=f"{online} / 64 online")

    def clear(self):
        """Reset all cells to offline state."""
        self._node_data.clear()
        self._selected_mac = -1
        for mac_id, cell in self._cells.items():
            self._canvas.itemconfig(cell["rect"], fill=resolve_color(NODE_OFFLINE), outline=resolve_color(BORDER_COLOR))
            self._canvas.itemconfig(cell["text"], fill=resolve_color(TEXT_MUTED))
            self._canvas.itemconfig(cell["subtext"], text="")
        self._count_label.configure(text="0 / 64 online")

    def select_node(self, mac_id: int):
        """Highlight a specific node."""
        # Deselect previous
        if self._selected_mac >= 0 and self._selected_mac in self._cells:
            # Restore original color
            node = self._node_data.get(self._selected_mac)
            if node and node.is_online:
                color = NODE_ONLINE
            else:
                color = resolve_color(NODE_OFFLINE)
            self._canvas.itemconfig(self._cells[self._selected_mac]["rect"],
                                     outline=resolve_color(BORDER_COLOR), width=1)

        # Select new
        self._selected_mac = mac_id
        if mac_id in self._cells:
            self._canvas.itemconfig(self._cells[mac_id]["rect"],
                                     outline=SAS_ORANGE, width=2)

    def _on_click(self, event):
        """Handle click on the grid — find which cell was clicked."""
        for mac_id, cell in self._cells.items():
            if cell["x0"] <= event.x <= cell["x1"] and cell["y0"] <= event.y <= cell["y1"]:
                self.select_node(mac_id)
                if self._on_select:
                    node = self._node_data.get(mac_id)
                    self._on_select(mac_id, node)
                return


class NodeDetailPanel(ctk.CTkFrame):
    """Panel showing detailed information about a selected DeviceNet node."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_CARD, corner_radius=CARD_CORNER_RADIUS,
                         border_width=1, border_color=BORDER_COLOR, **kwargs)
        self._build_ui()

    def _build_ui(self):
        # Title
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 4))
        ctk.CTkLabel(hdr, text="Node Details",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(side="left")
        self._mac_label = ctk.CTkLabel(
            hdr, text="", font=(FONT_FAMILY_MONO, FONT_SIZE_BODY, "bold"),
            text_color=SAS_BLUE_LIGHT, anchor="e")
        self._mac_label.pack(side="right")

        # Scrollable detail area
        self._detail_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent", height=350)
        self._detail_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        enable_touch_scroll(self._detail_frame)

        self._show_placeholder()

    def _show_placeholder(self):
        """Show placeholder when no node is selected."""
        for w in self._detail_frame.winfo_children():
            w.destroy()
        self._mac_label.configure(text="")
        ctk.CTkLabel(self._detail_frame,
                     text="Click a node in the grid to view its details.",
                     font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_MUTED).pack(pady=40)

    def show_node(self, mac_id: int, node: Optional[DeviceNetNode]):
        """Display details for a selected node."""
        for w in self._detail_frame.winfo_children():
            w.destroy()

        self._mac_label.configure(text=f"MAC ID {mac_id}")

        if node is None or not node.is_online:
            self._show_offline(mac_id)
            return

        # Identity info rows
        rows = [
            ("Product Name", node.product_name or "N/A"),
            ("Vendor", f"{node.vendor_name}  (ID {node.vendor_id})"),
            ("Product Type", f"{node.product_type_name}  (Code {node.product_type})"),
            ("Product Code", str(node.product_code)),
            ("Revision", f"{node.revision_major}.{node.revision_minor}"),
            ("Serial Number", node.serial_number or "N/A"),
            ("Status", node.status_text or "OK"),
            ("Response Time", f"{node.response_time_ms:.1f} ms"),
        ]

        if node.baud_rate >= 0:
            rows.append(("Baud Rate", node.baud_rate_text or BAUD_RATES.get(node.baud_rate, "?")))
        if node.bus_off_count > 0:
            rows.append(("Bus-Off Count", str(node.bus_off_count)))
        if node.error_text:
            rows.append(("Error", node.error_text))

        for label, value in rows:
            row = ctk.CTkFrame(self._detail_frame, fg_color="transparent")
            row.pack(fill="x", pady=(0, 2))
            ctk.CTkLabel(row, text=label, font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_SECONDARY, width=130,
                         anchor="w").pack(side="left", padx=(4, 4))

            # Color-code status
            val_color = TEXT_PRIMARY
            if label == "Status":
                if "fault" in value.lower() or "major" in value.lower():
                    val_color = STATUS_ERROR
                elif "minor" in value.lower() or "warning" in value.lower():
                    val_color = STATUS_WARN
                elif "ok" in value.lower() or "run" in value.lower():
                    val_color = STATUS_GOOD
            elif label == "Response Time":
                ms = node.response_time_ms
                val_color = STATUS_GOOD if ms < 100 else (STATUS_WARN if ms < 500 else STATUS_ERROR)
            elif label == "Error":
                val_color = STATUS_ERROR

            ctk.CTkLabel(row, text=value, font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=val_color, anchor="w",
                         wraplength=250).pack(side="left", fill="x", expand=True)

        # Raw identity hex if available
        if node.raw_identity:
            ctk.CTkFrame(self._detail_frame, fg_color=BORDER_COLOR,
                         height=1).pack(fill="x", pady=8)
            ctk.CTkLabel(self._detail_frame, text="Raw Identity Data:",
                         font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                         text_color=TEXT_MUTED, anchor="w").pack(fill="x", padx=4)
            hex_str = " ".join(f"{b:02X}" for b in node.raw_identity[:48])
            ctk.CTkLabel(self._detail_frame, text=hex_str,
                         font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                         text_color=TEXT_MUTED, anchor="w",
                         wraplength=350).pack(fill="x", padx=4, pady=(2, 4))

    def _show_offline(self, mac_id: int):
        """Show info for an offline/empty node."""
        ctk.CTkLabel(self._detail_frame, text=f"MAC ID {mac_id} — No Response",
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=TEXT_MUTED).pack(pady=(20, 8))
        ctk.CTkLabel(self._detail_frame,
                     text="No device responded at this address.\n\n"
                          "Possible causes:\n"
                          "• No device assigned to this MAC ID\n"
                          "• Device powered off or disconnected\n"
                          "• Baud rate mismatch\n"
                          "• Wiring fault or missing termination",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=350).pack(fill="x", padx=8)


class ScannerInfoPanel(ctk.CTkFrame):
    """Card showing DeviceNet scanner module diagnostics."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_CARD, corner_radius=CARD_CORNER_RADIUS,
                         border_width=1, border_color=BORDER_COLOR, **kwargs)
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Scanner Module",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 6))

        self._info_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._info_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        self._placeholder = ctk.CTkLabel(
            self._info_frame, text="Connect to view scanner info",
            font=(FONT_FAMILY, FONT_SIZE_SMALL), text_color=TEXT_MUTED)
        self._placeholder.pack(pady=12)

    def update_info(self, diag: Optional[ScannerDiagnostics]):
        """Update the scanner info from diagnostics."""
        for w in self._info_frame.winfo_children():
            w.destroy()

        if diag is None:
            ctk.CTkLabel(self._info_frame, text="Scanner info not available",
                         font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_MUTED).pack(pady=12)
            return

        rows = [
            ("Module", diag.scanner_product_name or "Unknown"),
            ("Vendor", diag.scanner_vendor or "Unknown"),
            ("MAC ID", str(diag.scanner_mac_id)),
            ("Baud Rate", diag.scanner_baud_rate or "Unknown"),
            ("Revision", diag.scanner_revision or "—"),
            ("Serial", diag.scanner_serial or "—"),
        ]

        if diag.bus_off_count > 0:
            rows.append(("Bus-Off Count", str(diag.bus_off_count)))

        for label, value in rows:
            row = ctk.CTkFrame(self._info_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=label, font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_SECONDARY, width=90,
                         anchor="w").pack(side="left")

            val_color = TEXT_PRIMARY
            if label == "Bus-Off Count" and diag.bus_off_count > 0:
                val_color = STATUS_ERROR

            ctk.CTkLabel(row, text=value, font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=val_color, anchor="w").pack(side="left")


class ErrorCodeLookup(ctk.CTkFrame):
    """Quick reference lookup for DeviceNet scanner error codes."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_CARD, corner_radius=CARD_CORNER_RADIUS,
                         border_width=1, border_color=BORDER_COLOR, **kwargs)
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 8))
        ctk.CTkLabel(hdr, text="🔎 Error Code Lookup",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(side="left")

        # Input row
        input_row = ctk.CTkFrame(self, fg_color="transparent")
        input_row.pack(fill="x", padx=CARD_PADDING, pady=(0, 8))

        self._code_entry = ctk.CTkEntry(
            input_row, placeholder_text="Error code (e.g. 79)",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=140, height=INPUT_HEIGHT)
        self._code_entry.pack(side="left", padx=(0, 8))
        self._code_entry.bind("<Return>", lambda e: self._lookup())

        ctk.CTkButton(
            input_row, text="Lookup", width=80, height=INPUT_HEIGHT,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            command=self._lookup).pack(side="left")

        # Quick-select common codes
        common_row = ctk.CTkFrame(self, fg_color="transparent")
        common_row.pack(fill="x", padx=CARD_PADDING, pady=(0, 6))
        ctk.CTkLabel(common_row, text="Common:",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED).pack(side="left", padx=(0, 6))
        for code in [72, 73, 79, 81]:
            ctk.CTkButton(
                common_row, text=str(code), width=36, height=24,
                font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                fg_color=BG_MEDIUM, hover_color=BG_CARD_HOVER,
                text_color=TEXT_SECONDARY, corner_radius=4,
                command=lambda c=code: self._show_code(c)).pack(side="left", padx=2)

        # Result area
        self._result_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._result_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, CARD_PADDING))

    def _lookup(self):
        """Lookup the code from the entry field."""
        text = self._code_entry.get().strip()
        try:
            code = int(text)
            self._show_code(code)
        except ValueError:
            self._show_error("Enter a valid number")

    def _show_code(self, code: int):
        """Display info for an error code."""
        for w in self._result_frame.winfo_children():
            w.destroy()

        self._code_entry.delete(0, "end")
        self._code_entry.insert(0, str(code))

        info = get_error_info(code)

        # Severity badge
        sev = info.get("severity", "unknown")
        sev_color = SEV_COLORS.get(sev, TEXT_MUTED)

        title_row = ctk.CTkFrame(self._result_frame, fg_color="transparent")
        title_row.pack(fill="x", pady=(4, 2))

        badge = ctk.CTkLabel(title_row, text=f" {sev.upper()} ",
                              font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                              text_color="white", fg_color=sev_color,
                              corner_radius=4, height=20)
        badge.pack(side="left", padx=(0, 8))

        ctk.CTkLabel(title_row, text=f"Error {code}: {info['name']}",
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(side="left")

        # Description
        ctk.CTkLabel(self._result_frame, text=info["description"],
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     wraplength=400, justify="left").pack(fill="x", pady=(4, 6))

        # Fix
        fix_frame = ctk.CTkFrame(self._result_frame, fg_color=BG_MEDIUM, corner_radius=6)
        fix_frame.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(fix_frame, text="Recommended Fix:",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=SAS_ORANGE, anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(fix_frame, text=info["fix"],
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     wraplength=380, justify="left").pack(fill="x", padx=10, pady=(0, 8))

    def _show_error(self, msg: str):
        for w in self._result_frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._result_frame, text=msg,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=STATUS_ERROR).pack(pady=4)


# ─── Main DeviceNet View ────────────────────────────────────────────────────

class DeviceNetView(ctk.CTkFrame):
    """
    Main DeviceNet diagnostics view.

    Layout:
      ┌──────────────────────────────────────────────────────────┐
      │ Header + Connection Controls                             │
      ├────────────────────────┬─────────────────────────────────┤
      │  MAC ID Grid (8×8)     │  Node Detail Panel              │
      │                        │  Scanner Info                   │
      │                        │  Error Code Lookup              │
      └────────────────────────┴─────────────────────────────────┘
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_DARK, **kwargs)

        self._scanning = False
        self._cancel_event = threading.Event()
        self._scan_result: Optional[DeviceNetScanResult] = None
        self._connection_method = "backplane"  # or "u2dn"

        self._build_ui()

    def _build_ui(self):
        """Build the complete DeviceNet diagnostics view."""
        # ── Top Section: Header + Connection Config ──────────────────────
        self._build_header()
        self._build_connection_bar()
        self._build_progress()

        # ── Main Content: Grid + Details ─────────────────────────────────
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=24, pady=(0, 16))

        # Left column: MAC ID grid
        left = ctk.CTkFrame(content, fg_color="transparent", width=480)
        left.pack(side="left", fill="y", padx=(0, 16))
        left.pack_propagate(False)

        self._mac_grid = MACIDGrid(left, on_select=self._on_node_selected)
        self._mac_grid.pack(fill="x")

        # Online node list (below grid)
        self._node_list_frame = ctk.CTkFrame(left, fg_color=BG_CARD,
                                              corner_radius=CARD_CORNER_RADIUS,
                                              border_width=1, border_color=BORDER_COLOR)
        self._node_list_frame.pack(fill="both", expand=True, pady=(12, 0))

        ctk.CTkLabel(self._node_list_frame, text="Online Devices",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 4))

        self._node_list_scroll = ctk.CTkScrollableFrame(
            self._node_list_frame, fg_color="transparent")
        self._node_list_scroll.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        enable_touch_scroll(self._node_list_scroll)

        self._node_list_placeholder = ctk.CTkLabel(
            self._node_list_scroll, text="Run a scan to discover devices",
            font=(FONT_FAMILY, FONT_SIZE_SMALL), text_color=TEXT_MUTED)
        self._node_list_placeholder.pack(pady=20)

        # Right column: Details + Scanner + Error Lookup
        right = ctk.CTkScrollableFrame(content, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True)
        enable_touch_scroll(right)

        self._node_detail = NodeDetailPanel(right)
        self._node_detail.pack(fill="x", pady=(0, 12))

        self._scanner_info = ScannerInfoPanel(right)
        self._scanner_info.pack(fill="x", pady=(0, 12))

        self._error_lookup = ErrorCodeLookup(right)
        self._error_lookup.pack(fill="x", pady=(0, 12))

        # U2DN info panel (hidden by default)
        self._u2dn_panel = ctk.CTkFrame(right, fg_color=BG_CARD,
                                         corner_radius=CARD_CORNER_RADIUS,
                                         border_width=1, border_color=BORDER_COLOR)
        # Will be shown when U2DN method is selected

    def _build_header(self):
        """Build the title bar."""
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=24, pady=(20, 8))

        title_row = ctk.CTkFrame(top, fg_color="transparent")
        title_row.pack(fill="x")

        ctk.CTkLabel(
            title_row, text="🔗 DeviceNet Diagnostics",
            font=(FONT_FAMILY, FONT_SIZE_HEADING, "bold"),
            text_color=TEXT_PRIMARY, anchor="w").pack(side="left")

        ctk.CTkLabel(
            top,
            text="Browse DeviceNet nodes via PLC backplane punch-through or 1784-U2DN adapter.\n"
                 "Reads CIP Identity from all 64 MAC IDs — like RSNetWorx browse.",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY, anchor="w", justify="left").pack(fill="x", pady=(6, 0))

    def _build_connection_bar(self):
        """Build the connection configuration bar."""
        bar = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8, height=70)
        bar.pack(fill="x", padx=24, pady=(4, 8))
        bar.pack_propagate(False)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=10)

        # Connection method selector
        method_frame = ctk.CTkFrame(inner, fg_color="transparent")
        method_frame.pack(side="left")

        ctk.CTkLabel(method_frame, text="Method",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w")

        self._method_var = tk.StringVar(value="backplane")
        self._method_menu = ctk.CTkSegmentedButton(
            method_frame, values=["Backplane", "1784-U2DN"],
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            fg_color=BG_INPUT, selected_color=SAS_BLUE,
            selected_hover_color=SAS_BLUE_DARK,
            unselected_color=BG_MEDIUM, unselected_hover_color=BG_CARD_HOVER,
            text_color=TEXT_PRIMARY, height=INPUT_HEIGHT,
            command=self._on_method_changed)
        self._method_menu.set("Backplane")
        self._method_menu.pack()

        # Separator
        ctk.CTkFrame(inner, fg_color=BORDER_COLOR, width=1).pack(
            side="left", fill="y", padx=16, pady=2)

        # Backplane config fields
        self._bp_config = ctk.CTkFrame(inner, fg_color="transparent")
        self._bp_config.pack(side="left", fill="y")

        # PLC IP
        ip_frame = ctk.CTkFrame(self._bp_config, fg_color="transparent")
        ip_frame.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(ip_frame, text="PLC IP Address",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w")
        self._ip_entry = ctk.CTkEntry(
            ip_frame, placeholder_text="192.168.1.10",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=160, height=INPUT_HEIGHT)
        self._ip_entry.pack()

        # Scanner Slot
        slot_frame = ctk.CTkFrame(self._bp_config, fg_color="transparent")
        slot_frame.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(slot_frame, text="Scanner Slot",
                     font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w")
        self._slot_entry = ctk.CTkEntry(
            slot_frame, placeholder_text="2",
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, width=60, height=INPUT_HEIGHT)
        self._slot_entry.pack()

        # U2DN config (hidden initially) — RSLinx driver selection
        self._u2dn_config = ctk.CTkFrame(inner, fg_color="transparent")
        self._u2dn_detected_drivers = []  # Populated by detect

        # Detect RSLinx button
        self._detect_btn = ctk.CTkButton(
            self._u2dn_config, text="🔍 Detect RSLinx", width=140,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            command=self._detect_u2dn)
        self._detect_btn.pack(side="left", padx=(0, 8))

        # Driver dropdown (populated after detect)
        drv_label = ctk.CTkLabel(
            self._u2dn_config, text="RSLinx Driver:",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_SECONDARY)
        drv_label.pack(side="left", padx=(4, 4))
        self._driver_combo = ctk.CTkComboBox(
            self._u2dn_config, values=["(click Detect RSLinx)"],
            width=180, height=INPUT_HEIGHT,
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, dropdown_fg_color=BG_CARD,
            dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_CARD_HOVER)
        self._driver_combo.pack(side="left", padx=(0, 8))
        self._driver_combo.set("(click Detect RSLinx)")

        # Status indicator
        self._u2dn_status = ctk.CTkLabel(
            self._u2dn_config, text="",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w")
        self._u2dn_status.pack(side="left")

        # Separator before scan button
        ctk.CTkFrame(inner, fg_color=BORDER_COLOR, width=1).pack(
            side="left", fill="y", padx=16, pady=2)

        # Scan / Cancel button
        btn_frame = ctk.CTkFrame(inner, fg_color="transparent")
        btn_frame.pack(side="right")

        self._scan_btn = ctk.CTkButton(
            btn_frame, text="▶  Scan Network", width=160,
            height=INPUT_HEIGHT, font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_ORANGE, hover_color=SAS_ORANGE_DARK,
            text_color="white", command=self._start_scan)
        self._scan_btn.pack()

    def _build_progress(self):
        """Build progress bar under the connection bar."""
        self._progress = ScanProgressBar(self)
        self._progress.pack(fill="x", padx=24, pady=(0, 8))
        self._progress.reset()

    # ── Connection Method Switching ──────────────────────────────────────

    def _on_method_changed(self, value: str):
        """Switch between Backplane and U2DN connection modes."""
        if value == "Backplane":
            self._connection_method = "backplane"
            self._u2dn_config.pack_forget()
            self._bp_config.pack(side="left", fill="y")
        else:
            self._connection_method = "u2dn"
            self._bp_config.pack_forget()
            self._u2dn_config.pack(side="left", fill="y")

    # ── U2DN / RSLinx Detection ─────────────────────────────────────────

    def _detect_u2dn(self):
        """Run U2DN adapter + RSLinx detection."""
        self._detect_btn.configure(state="disabled", text="⏳ Detecting...")
        self._u2dn_status.configure(text="Scanning...", text_color=TEXT_MUTED)

        def _detect():
            result = U2DNAdapter.detect()
            self.after(0, lambda: self._on_u2dn_detected(result))

        threading.Thread(target=_detect, daemon=True).start()

    def _on_u2dn_detected(self, result: dict):
        """Handle U2DN / RSLinx detection results."""
        self._detect_btn.configure(state="normal", text="🔍 Detect RSLinx")

        # Update driver dropdown with discovered DeviceNet drivers
        drivers = result.get("devicenet_drivers", [])
        self._u2dn_detected_drivers = drivers

        if drivers:
            self._driver_combo.configure(values=drivers)
            self._driver_combo.set(drivers[0])
            self._u2dn_status.configure(
                text=f"✅ {len(drivers)} driver(s) found",
                text_color=STATUS_GOOD)
        elif result.get("rslinx_running"):
            self._driver_combo.configure(values=["(no drivers found)"])
            self._driver_combo.set("(no drivers found)")
            self._u2dn_status.configure(
                text="⚠ RSLinx running — no DeviceNet driver found",
                text_color=STATUS_WARN)
        elif result.get("rslinx_installed"):
            self._driver_combo.configure(values=["(RSLinx not running)"])
            self._driver_combo.set("(RSLinx not running)")
            self._u2dn_status.configure(
                text="⚠ Start RSLinx Classic first",
                text_color=STATUS_WARN)
        else:
            self._driver_combo.configure(values=["(RSLinx not found)"])
            self._driver_combo.set("(RSLinx not found)")
            self._u2dn_status.configure(
                text="❌ Install RSLinx Classic",
                text_color=STATUS_ERROR)

        # Show detailed info panel
        self._show_u2dn_info(result)

    def _show_u2dn_info(self, result: dict):
        """Show U2DN / RSLinx detection details and setup instructions."""
        for w in self._u2dn_panel.winfo_children():
            w.destroy()

        ctk.CTkLabel(self._u2dn_panel, text="1784-U2DN via RSLinx",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 6))

        drivers = result.get("devicenet_drivers", [])
        can_scan = (result.get("rslinx_running") and len(drivers) > 0)

        if can_scan:
            status_text = result.get("message", "Ready to scan")
        elif result.get("rslinx_running"):
            status_text = (
                result.get("message", "") + "\n\n"
                "Ensure the 1784-U2DN is connected:\n"
                "1. Plug the U2DN into a USB port\n"
                "2. RSLinx should auto-detect it as a USB driver\n"
                "3. Verify the adapter appears in RSWho under 'USB'\n"
                "4. Click 'Detect RSLinx' again"
            )
        else:
            status_text = U2DNAdapter.get_setup_instructions()

        ctk.CTkLabel(self._u2dn_panel, text=status_text,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY, anchor="w",
                     justify="left", wraplength=450).pack(
            fill="x", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        # Show the panel
        self._u2dn_panel.pack(fill="x", pady=(0, 12))

    # ── Scan Execution ───────────────────────────────────────────────────

    def _start_scan(self):
        """Start a DeviceNet network scan."""
        if self._scanning:
            self._cancel_scan()
            return

        if self._connection_method == "u2dn":
            self._start_u2dn_scan()
            return

        # ── Backplane mode ──
        plc_ip = self._ip_entry.get().strip()
        slot_text = self._slot_entry.get().strip()

        if not plc_ip:
            self._progress.update_progress(0, "⚠ Enter the PLC IP address")
            return
        try:
            scanner_slot = int(slot_text) if slot_text else 2
        except ValueError:
            self._progress.update_progress(0, "⚠ Scanner slot must be a number")
            return

        # Start scan
        self._scanning = True
        self._cancel_event.clear()
        self._scan_btn.configure(text="■  Cancel Scan", fg_color=STATUS_ERROR,
                                  hover_color="#DC2626")
        self._mac_grid.clear()
        self._progress.reset()

        # Clear node list
        for w in self._node_list_scroll.winfo_children():
            w.destroy()

        def _run():
            result = run_devicenet_scan(
                plc_ip=plc_ip,
                scanner_slot=scanner_slot,
                progress_callback=self._scan_progress,
                cancel_event=self._cancel_event,
            )
            self.after(0, lambda: self._scan_complete(result))

        threading.Thread(target=_run, daemon=True).start()

    def _start_u2dn_scan(self):
        """Start a DeviceNet scan via 1784-U2DN / RSLinx."""
        driver_name = self._driver_combo.get().strip()

        # Validate driver selection
        if not driver_name or driver_name.startswith("("):
            self._progress.update_progress(
                0, "⚠ Click 'Detect RSLinx' first to find available drivers")
            return

        if driver_name not in self._u2dn_detected_drivers:
            self._progress.update_progress(
                0, f"⚠ Driver '{driver_name}' not recognized — click Detect RSLinx")
            return

        # Start scan
        self._scanning = True
        self._cancel_event.clear()
        self._scan_btn.configure(text="■  Cancel Scan", fg_color=STATUS_ERROR,
                                  hover_color="#DC2626")
        self._mac_grid.clear()
        self._progress.reset()

        # Clear node list
        for w in self._node_list_scroll.winfo_children():
            w.destroy()

        def _run():
            result = run_u2dn_scan(
                driver_name=driver_name,
                progress_callback=self._scan_progress,
                cancel_event=self._cancel_event,
            )
            self.after(0, lambda: self._scan_complete(result))

        threading.Thread(target=_run, daemon=True).start()

    def _cancel_scan(self):
        """Cancel the running scan."""
        self._cancel_event.set()
        self._progress.update_progress(0, "Cancelling scan...")

    def _scan_progress(self, current: int, total: int, status: str):
        """Callback for scan progress updates (from background thread)."""
        self.after(0, lambda: self._progress.update_progress(
            current / total, f"[{current}/{total}] {status}"))

    def _scan_complete(self, result: DeviceNetScanResult):
        """Handle scan completion."""
        self._scanning = False
        self._scan_result = result
        self._scan_btn.configure(text="▶  Scan Network", fg_color=SAS_ORANGE,
                                  hover_color=SAS_ORANGE_DARK)

        if result.errors:
            self._progress.update_progress(
                1.0, f"⚠ Scan completed with errors: {result.errors[0]}")
            self._progress._status_label.configure(text_color=STATUS_WARN)
        else:
            self._progress.set_complete(
                f"Scan complete — {result.nodes_online} devices found "
                f"in {result.scan_time_seconds}s")

        # Update grid
        scanner_mac = result.scanner_diag.scanner_mac_id if result.scanner_diag else -1
        self._mac_grid.update_nodes(result.nodes, scanner_mac)

        # Update scanner info
        self._scanner_info.update_info(result.scanner_diag)

        # Build online node list
        self._build_node_list(result)

    def _build_node_list(self, result: DeviceNetScanResult):
        """Build the scrollable list of online nodes."""
        for w in self._node_list_scroll.winfo_children():
            w.destroy()

        online_nodes = [n for n in result.nodes if n.is_online]
        if not online_nodes:
            ctk.CTkLabel(self._node_list_scroll, text="No devices found",
                         font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_MUTED).pack(pady=20)
            return

        for node in online_nodes:
            row = ctk.CTkFrame(self._node_list_scroll, fg_color=BG_MEDIUM,
                               corner_radius=4, height=36, cursor="hand2")
            row.pack(fill="x", pady=1, padx=4)
            row.pack_propagate(False)

            # MAC ID badge
            mac_color = NODE_SCANNER if "scanner" in (node.status_text or "").lower() else SAS_BLUE
            mac_badge = ctk.CTkLabel(
                row, text=f" {node.mac_id:2d} ",
                font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL, "bold"),
                text_color="white", fg_color=mac_color,
                corner_radius=3, width=32, height=22)
            mac_badge.pack(side="left", padx=(6, 8), pady=6)

            # Product name
            name = node.product_name or node.vendor_name or "Unknown"
            ctk.CTkLabel(row, text=name,
                         font=(FONT_FAMILY, FONT_SIZE_SMALL),
                         text_color=TEXT_PRIMARY, anchor="w").pack(
                side="left", fill="x", expand=True, padx=(0, 4))

            # Response time
            if node.response_time_ms > 0:
                rt_color = (STATUS_GOOD if node.response_time_ms < 100
                            else STATUS_WARN if node.response_time_ms < 500
                            else STATUS_ERROR)
                ctk.CTkLabel(row, text=f"{node.response_time_ms:.0f}ms",
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=rt_color, width=50,
                             anchor="e").pack(side="right", padx=(0, 6))

            # Bind click
            mac_id = node.mac_id
            for widget in [row] + row.winfo_children():
                widget.bind("<Button-1>",
                            lambda e, m=mac_id, n=node: self._on_node_list_click(m, n))
                widget.bind("<Enter>", lambda e, r=row: r.configure(fg_color=BG_CARD_HOVER))
                widget.bind("<Leave>", lambda e, r=row: r.configure(fg_color=BG_MEDIUM))

    def _on_node_selected(self, mac_id: int, node: Optional[DeviceNetNode]):
        """Handle node selection from the MAC ID grid."""
        self._node_detail.show_node(mac_id, node)

    def _on_node_list_click(self, mac_id: int, node: DeviceNetNode):
        """Handle clicking a node in the list — sync with grid."""
        self._mac_grid.select_node(mac_id)
        self._node_detail.show_node(mac_id, node)
