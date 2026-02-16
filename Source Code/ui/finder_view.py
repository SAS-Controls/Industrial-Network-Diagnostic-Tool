"""
SAS Network Diagnostics Tool — Device Finder View
Discovers devices on the local wire regardless of subnet configuration.
Like Siemens "Accessible Devices" but works with all vendors.
"""

import logging
import threading
import tkinter as tk
from typing import Callable, List, Optional

import customtkinter as ctk

from core.device_discovery import DiscoveredEndpoint, run_device_discovery
from core.mac_vendors import get_category_label
from core.network_utils import get_network_interfaces, NetworkInterface
from core.settings_manager import get_settings
from ui.theme import *
from ui.widgets import ScanProgressBar, enable_touch_scroll

logger = logging.getLogger(__name__)


# ── Category colors ──────────────────────────────────────────────────────────
CAT_COLORS = {
    "automation": SAS_ORANGE,
    "networking": SAS_BLUE,
    "computing": "#8B5CF6",  # purple
    "other": TEXT_MUTED,
}

CAT_ICONS = {
    "automation": "⚙",
    "networking": "🔀",
    "computing": "🖥",
    "other": "❓",
}


class DeviceFinderView(ctk.CTkFrame):
    """
    View for discovering unknown devices on the local network.

    Finds devices even when the laptop is on a different subnet.
    Shows MAC vendor identification and suggests network settings
    the user needs to communicate with each device.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_DARK, **kwargs)

        self._scanning = False
        self._cancel_event = threading.Event()
        self._results: List[DiscoveredEndpoint] = []
        self._selected_iface: Optional[NetworkInterface] = None
        self._interfaces: List[NetworkInterface] = []

        self._build_ui()
        self._interfaces_loaded = False

    def on_show(self):
        """Called when view becomes visible — safe to use self.after()."""
        if not self._interfaces_loaded:
            self._refresh_interfaces()

    def _build_ui(self):
        """Build the complete finder view."""
        # ── Top Section: Header + Controls ────────────────────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=24, pady=(20, 12))

        # Title row
        title_row = ctk.CTkFrame(top, fg_color="transparent")
        title_row.pack(fill="x")

        ctk.CTkLabel(
            title_row, text="📡 Device Finder",
            font=(FONT_FAMILY, FONT_SIZE_HEADING, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(side="left")

        # Refresh interfaces button
        self._refresh_btn = ctk.CTkButton(
            title_row, text="↻ Refresh NICs", width=120, height=30,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY,
            command=self._refresh_interfaces,
        )
        self._refresh_btn.pack(side="right")

        # Description
        ctk.CTkLabel(
            top,
            text="Find devices on the wire even when you're on a different subnet.\n"
                 "⚠ Run as Administrator for cross-subnet discovery.  Plug in, select adapter, and hit Discover.\n"
                 "Works with all manufacturers — Allen-Bradley, Siemens, Schneider, WAGO, and more.",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY, anchor="w", justify="left",
        ).pack(fill="x", pady=(6, 0))

        # ── Controls Row ─────────────────────────────────────────────────
        controls = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8)
        controls.pack(fill="x", padx=24, pady=(0, 12))

        # Top row: adapter selector
        row1 = ctk.CTkFrame(controls, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(10, 4))

        ctk.CTkLabel(
            row1, text="Network Adapter:",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self._iface_var = ctk.StringVar(value="Detecting...")
        self._iface_dropdown = ctk.CTkOptionMenu(
            row1, variable=self._iface_var,
            values=["Detecting..."],
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_MEDIUM, button_color=SAS_BLUE,
            button_hover_color=SAS_BLUE_DARK,
            dropdown_fg_color=BG_MEDIUM,
            width=300, height=32,
            command=self._on_iface_change,
        )
        self._iface_dropdown.pack(side="left", padx=(0, 16))

        # Current adapter status
        self._adapter_status = ctk.CTkLabel(
            row1, text="",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED,
        )
        self._adapter_status.pack(side="left", padx=(0, 16))

        # Bottom row: Discover button
        row2 = ctk.CTkFrame(controls, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 10))

        # Discover button
        self._discover_btn = ctk.CTkButton(
            row2, text="▶ Discover Devices", width=180, height=32,
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_ORANGE, hover_color="#D0621A",
            text_color="white",
            command=self._toggle_discovery,
        )
        self._discover_btn.pack(side="left")

        # ── Scan Options ──────────────────────────────────────────────────
        scan_opts_frame = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8)
        scan_opts_frame.pack(fill="x", padx=24, pady=(0, 12))

        opts_inner = ctk.CTkFrame(scan_opts_frame, fg_color="transparent")
        opts_inner.pack(fill="x", padx=16, pady=10)

        ctk.CTkLabel(
            opts_inner, text="Scan Options",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        # Row 1: Common subnets checkbox
        self._common_subnets_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts_inner,
            text="Scan common factory-default subnets  (AB, Siemens, Schneider, Beckhoff, WAGO, etc.)",
            variable=self._common_subnets_var,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY,
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            border_color=BORDER_COLOR,
            height=26,
        ).pack(fill="x", pady=(0, 6))

        # Row 2: Custom ranges checkbox + entry
        custom_row = ctk.CTkFrame(opts_inner, fg_color="transparent")
        custom_row.pack(fill="x", pady=(0, 4))

        self._custom_subnets_var = ctk.BooleanVar(value=False)
        self._custom_cb = ctk.CTkCheckBox(
            custom_row,
            text="Scan custom subnet ranges",
            variable=self._custom_subnets_var,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY,
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            border_color=BORDER_COLOR,
            height=26,
            command=self._on_custom_toggle,
        )
        self._custom_cb.pack(side="left")

        ctk.CTkLabel(
            custom_row,
            text="CIDR notation, one per line  (e.g. 10.50.100.0/24)",
            font=(FONT_FAMILY, FONT_SIZE_TINY),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=(12, 0))

        # Custom range text entry (initially hidden)
        self._custom_entry_frame = ctk.CTkFrame(opts_inner, fg_color="transparent")
        # Don't pack yet — toggled by checkbox

        self._custom_entry = ctk.CTkTextbox(
            self._custom_entry_frame,
            height=72,
            font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
            fg_color=BG_INPUT,
            text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR,
            border_width=1,
            corner_radius=6,
        )
        self._custom_entry.pack(fill="x", padx=(28, 0), pady=(2, 0))

        # Pre-populate with saved custom subnets
        saved = get_settings().custom_subnets
        if saved:
            self._custom_entry.insert("1.0", "\n".join(saved))
            self._custom_subnets_var.set(True)
            self._custom_entry_frame.pack(fill="x", pady=(0, 4))

        # ── Progress Bar ─────────────────────────────────────────────────
        self._progress = ScanProgressBar(self)
        self._progress.pack(fill="x", padx=24, pady=(0, 8))

        # ── Results Header ───────────────────────────────────────────────
        results_header = ctk.CTkFrame(self, fg_color="transparent")
        results_header.pack(fill="x", padx=24, pady=(0, 4))

        self._results_label = ctk.CTkLabel(
            results_header,
            text="Discovered Devices",
            font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        )
        self._results_label.pack(side="left")

        self._count_label = ctk.CTkLabel(
            results_header,
            text="",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="e",
        )
        self._count_label.pack(side="right")

        # ── Column headers ───────────────────────────────────────────────
        header_frame = ctk.CTkFrame(self, fg_color=BG_MEDIUM, corner_radius=6, height=32)
        header_frame.pack(fill="x", padx=24, pady=(0, 4))
        header_frame.pack_propagate(False)

        header_inner = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_inner.pack(fill="both", expand=True, padx=12, pady=4)

        cols = [
            ("", 36),
            ("IP Address", 140),
            ("MAC Address", 160),
            ("Manufacturer", 200),
            ("Category", 130),
            ("Found By", 180),
        ]
        for text, width in cols:
            lbl = ctk.CTkLabel(
                header_inner, text=text, width=width,
                font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                text_color=TEXT_MUTED, anchor="w",
            )
            lbl.pack(side="left")

        # ── Scrollable Results ───────────────────────────────────────────
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=BG_DARK, corner_radius=0,
        )
        self._scroll.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        enable_touch_scroll(self._scroll)

        # Placeholder
        self._placeholder = ctk.CTkLabel(
            self._scroll,
            text="Connect your laptop to the network, set your adapter to\n"
                 "DHCP / Automatic IP, then click 'Discover Devices'.\n\n"
                 "The tool will send Layer 2 broadcasts and ARP probes to\n"
                 "find devices on common factory-default IP ranges:\n\n"
                 "  • 192.168.1.x   — Allen-Bradley, WAGO, Phoenix Contact, Moxa\n"
                 "  • 192.168.0.x   — Siemens, generic defaults\n"
                 "  • 10.10.0.x     — Schneider Electric\n"
                 "  • 172.17.0.x    — Beckhoff TwinCAT\n"
                 "  • 169.254.x.x   — Link-local (auto-IP)\n"
                 "  • ... and many more\n\n"
                 "Once a device is found, you'll see its MAC address,\n"
                 "manufacturer, and what subnet settings you need to\n"
                 "configure your adapter to in order to communicate with it.",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_MUTED, justify="left",
        )
        self._placeholder.pack(pady=30)

    # ── Interface Management ─────────────────────────────────────────────

    def _refresh_interfaces(self):
        def _detect():
            interfaces = get_network_interfaces()
            # Filter by settings
            interfaces = get_settings().filter_interfaces(interfaces)
            self.after(0, lambda: self._update_interface_list(interfaces))
        threading.Thread(target=_detect, daemon=True).start()

    def _on_custom_toggle(self):
        """Show/hide the custom subnet text entry."""
        if self._custom_subnets_var.get():
            self._custom_entry_frame.pack(fill="x", pady=(0, 4))
        else:
            self._custom_entry_frame.pack_forget()

    def _update_interface_list(self, interfaces: List[NetworkInterface]):
        self._interfaces = interfaces
        self._interfaces_loaded = True
        if not interfaces:
            self._iface_dropdown.configure(values=["No network adapters found"])
            self._iface_var.set("No network adapters found")
            self._adapter_status.configure(text="")
            return

        display_names = [
            f"{iface.display_name} ({iface.ip_address})"
            for iface in interfaces
        ]
        self._iface_dropdown.configure(values=display_names)
        self._iface_var.set(display_names[0])
        self._selected_iface = interfaces[0]
        self._update_adapter_status(interfaces[0])

    def _on_iface_change(self, value: str):
        for iface in self._interfaces:
            if f"{iface.display_name} ({iface.ip_address})" == value:
                self._selected_iface = iface
                self._update_adapter_status(iface)
                break

    def _update_adapter_status(self, iface: NetworkInterface):
        """Show adapter status — especially helpful for DHCP / link-local."""
        ip = iface.ip_address
        if ip.startswith("169.254."):
            self._adapter_status.configure(
                text="⚠ Link-local (DHCP, no server) — good for discovery!",
                text_color=SAS_ORANGE,
            )
        elif ip.startswith("0.0.0."):
            self._adapter_status.configure(
                text="⚠ No IP assigned — cable may not be connected",
                text_color=STATUS_ERROR,
            )
        else:
            self._adapter_status.configure(
                text=f"Subnet: {iface.network}",
                text_color=TEXT_MUTED,
            )

    # ── Discovery Control ────────────────────────────────────────────────

    def _toggle_discovery(self):
        if self._scanning:
            self._cancel_discovery()
        else:
            self._start_discovery()

    def _start_discovery(self):
        if not self._selected_iface:
            logger.warning("Discovery started with no adapter selected")
            return

        logger.info(f"Discovery starting on {self._selected_iface.name} "
                     f"({self._selected_iface.ip_address})")
        self._scanning = True
        self._cancel_event.clear()
        self._discover_btn.configure(
            text="⏹ Stop", fg_color=STATUS_ERROR, hover_color="#AA2222",
        )
        self._clear_results()

        # Get scan options
        probe_common = self._common_subnets_var.get()
        custom_ranges = None
        if self._custom_subnets_var.get():
            raw = self._custom_entry.get("1.0", "end").strip()
            if raw:
                custom_ranges = [
                    line.strip() for line in raw.split("\n")
                    if line.strip()
                ]
                # Save custom ranges for next time
                settings = get_settings()
                settings.custom_subnets = custom_ranges
                settings.save()

        logger.info(f"Discovery options: probe_common={probe_common}, "
                     f"custom_ranges={custom_ranges}")

        def _run():
            try:
                results = run_device_discovery(
                    progress_callback=lambda pct, msg: self.after(
                        0, lambda p=pct, m=msg: self._progress.update_progress(p, m)),
                    cancel_event=self._cancel_event,
                    probe_all_subnets=probe_common,
                    custom_ranges=custom_ranges,
                    adapter_name=self._selected_iface.name if self._selected_iface else "",
                    adapter_ip=self._selected_iface.ip_address if self._selected_iface else "",
                )
                logger.info(f"Discovery completed: {len(results)} devices found")
                self.after(0, lambda: self._discovery_complete(results))
            except Exception as e:
                logger.error(f"Discovery failed: {e}", exc_info=True)
                self.after(0, lambda: self._discovery_error(str(e)))

        threading.Thread(target=_run, daemon=True).start()

    def _cancel_discovery(self):
        logger.info("Discovery cancelled by user")
        self._cancel_event.set()
        self._scanning = False
        self._discover_btn.configure(
            text="▶ Discover Devices", fg_color=SAS_ORANGE, hover_color="#D0621A",
        )
        self._progress.update_progress(0, "Discovery cancelled")

    def _discovery_complete(self, results: List[DiscoveredEndpoint]):
        self._scanning = False
        self._results = results
        self._discover_btn.configure(
            text="▶ Discover Devices", fg_color=SAS_ORANGE, hover_color="#D0621A",
        )

        auto_count = sum(1 for r in results if r.vendor_category == "automation")
        net_count = sum(1 for r in results if r.vendor_category == "networking")

        self._progress.set_complete(
            f"Found {len(results)} devices — "
            f"{auto_count} automation, {net_count} networking"
        )
        self._count_label.configure(
            text=f"{len(results)} devices  •  {auto_count} automation  •  {net_count} networking"
        )
        self._populate_results()

    def _discovery_error(self, error: str):
        self._scanning = False
        self._discover_btn.configure(
            text="▶ Discover Devices", fg_color=SAS_ORANGE, hover_color="#D0621A",
        )
        self._progress.update_progress(0, f"Error: {error}")

    # ── Results Display ──────────────────────────────────────────────────

    def _clear_results(self):
        for widget in self._scroll.winfo_children():
            widget.destroy()

    def _populate_results(self):
        self._clear_results()

        if not self._results:
            ctk.CTkLabel(
                self._scroll,
                text="No devices discovered.\n\n"
                     "Verify that:\n"
                     "  • The app is running as Administrator (required for cross-subnet)\n"
                     "  • The network cable is connected\n"
                     "  • The correct adapter is selected above\n"
                     "  • There are powered-on devices on the same switch/cable\n\n"
                     "Cross-subnet discovery requires admin privileges to temporarily\n"
                     "add IP addresses on your adapter.  Right-click the app → Run as Administrator.",
                font=(FONT_FAMILY, FONT_SIZE_BODY),
                text_color=TEXT_MUTED, justify="left",
            ).pack(pady=30)
            return

        for device in self._results:
            self._add_device_row(device)

    def _add_device_row(self, device: DiscoveredEndpoint):
        """Add a single device result row with expand/collapse details."""
        # ── Main row (always visible) ────────────────────────────────────
        row_frame = ctk.CTkFrame(
            self._scroll, fg_color=BG_CARD, corner_radius=8,
            border_width=1, border_color=BORDER_COLOR,
        )
        row_frame.pack(fill="x", pady=(0, 4))

        # Clickable row content
        row_inner = ctk.CTkFrame(row_frame, fg_color="transparent", cursor="hand2")
        row_inner.pack(fill="x", padx=12, pady=8)

        cat_color = CAT_COLORS.get(device.vendor_category, TEXT_MUTED)
        cat_icon = CAT_ICONS.get(device.vendor_category, "?")

        # Category icon
        ctk.CTkLabel(
            row_inner, text=cat_icon, width=36,
            font=(FONT_FAMILY, 18),
            text_color=cat_color, anchor="w",
        ).pack(side="left")

        # IP address
        ip_label = ctk.CTkLabel(
            row_inner, text=device.ip_address, width=140,
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        )
        ip_label.pack(side="left")

        # MAC address
        mac_text = device.mac_address or "—"
        ctk.CTkLabel(
            row_inner, text=mac_text, width=160,
            font=("Consolas", FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY, anchor="w",
        ).pack(side="left")

        # Manufacturer + product info
        vendor_text = device.vendor_name or "Unknown"
        if device.eip_product_name:
            vendor_text = f"{device.vendor_name} — {device.eip_product_name}"
        ctk.CTkLabel(
            row_inner, text=vendor_text,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=cat_color, anchor="w",
        ).pack(side="left", fill="x", expand=True)

        # Category badge
        cat_text = get_category_label(device.vendor_category)
        ctk.CTkLabel(
            row_inner, text=cat_text, width=130,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=cat_color, anchor="w",
        ).pack(side="left")

        # Discovery method
        ctk.CTkLabel(
            row_inner, text=device.discovery_method, width=180,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w",
        ).pack(side="left")

        # ── Expandable detail panel ──────────────────────────────────────
        detail_frame = ctk.CTkFrame(row_frame, fg_color=BG_MEDIUM, corner_radius=4)
        detail_visible = [False]

        def toggle_detail(event=None):
            if detail_visible[0]:
                detail_frame.pack_forget()
                detail_visible[0] = False
            else:
                detail_frame.pack(fill="x", padx=8, pady=(0, 8))
                detail_visible[0] = True

        # Bind click to toggle
        for widget in [row_inner] + list(row_inner.winfo_children()):
            widget.bind("<Button-1>", toggle_detail)

        # Build detail content
        detail_inner = ctk.CTkFrame(detail_frame, fg_color="transparent")
        detail_inner.pack(fill="x", padx=16, pady=12)

        # ── Two-column layout ────────────────────────────────────────────
        left_col = ctk.CTkFrame(detail_inner, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True)

        right_col = ctk.CTkFrame(detail_inner, fg_color="transparent")
        right_col.pack(side="right", fill="both", expand=True)

        # LEFT: Device info
        ctk.CTkLabel(
            left_col, text="DEVICE INFORMATION",
            font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        info_items = [
            ("IP Address", device.ip_address),
            ("MAC Address", device.mac_address or "Unknown"),
            ("Manufacturer", device.vendor_name or "Unknown"),
            ("Category", get_category_label(device.vendor_category)),
            ("Found By", device.discovery_method),
        ]

        if device.is_eip:
            info_items.extend([
                ("EIP Product", device.eip_product_name or "—"),
                ("EIP Vendor", device.eip_vendor_name or "—"),
                ("Firmware", device.eip_firmware or "—"),
                ("Serial", device.eip_serial or "—"),
                ("Device Type", device.eip_device_type or "—"),
            ])

        if device.is_profinet:
            info_items.extend([
                ("PROFINET Name", device.profinet_name or "—"),
            ])

        if device.open_ports:
            ports_str = ", ".join(str(p) for p in device.open_ports)
            info_items.append(("Open Ports", ports_str))
        if device.port_info:
            info_items.append(("Protocols", device.port_info))

        for label, value in info_items:
            row = ctk.CTkFrame(left_col, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(
                row, text=f"{label}:", width=120,
                font=(FONT_FAMILY, FONT_SIZE_SMALL),
                text_color=TEXT_MUTED, anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=value,
                font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                text_color=TEXT_PRIMARY, anchor="w",
            ).pack(side="left")

        # RIGHT: Network configuration instructions
        ctk.CTkLabel(
            right_col, text="TO COMMUNICATE WITH THIS DEVICE",
            font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            text_color=SAS_ORANGE, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        if device.suggested_subnet and device.suggested_ip:
            instructions = (
                f"Set your network adapter to a static IP:\n\n"
                f"  IP Address:    {device.suggested_ip}\n"
                f"  Subnet Mask:   255.255.255.0\n"
                f"  Gateway:       (leave blank)\n\n"
                f"This puts you on {device.suggested_subnet}\n"
                f"which is the same subnet as this device ({device.ip_address})."
            )
        else:
            instructions = (
                "Could not determine suggested settings.\n"
                "Try setting your adapter to an IP on the\n"
                "same subnet as this device."
            )

        ctk.CTkLabel(
            right_col, text=instructions,
            font=("Consolas", FONT_SIZE_SMALL),
            text_color=TEXT_PRIMARY, anchor="nw", justify="left",
        ).pack(fill="x")

        # Copy settings button
        def _copy_settings():
            text = (
                f"Device: {device.vendor_name} at {device.ip_address} "
                f"(MAC: {device.mac_address})\n"
                f"Set adapter to: IP={device.suggested_ip}, "
                f"Mask=255.255.255.0"
            )
            self.clipboard_clear()
            self.clipboard_append(text)

        ctk.CTkButton(
            right_col, text="📋 Copy Settings", width=140, height=28,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            command=_copy_settings,
        ).pack(anchor="w", pady=(8, 0))
