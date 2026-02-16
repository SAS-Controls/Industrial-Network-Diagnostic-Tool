"""
SAS Network Diagnostics Tool — Scan View
The main scanning interface where users select an interface and scan the network.
"""

import logging
import threading
import time
import tkinter as tk
from typing import Callable, Dict, List, Optional

import customtkinter as ctk

from core.network_utils import (
    DiscoveredDevice, NetworkInterface, get_network_interfaces,
    ping_sweep, scan_industrial_ports, identify_device_type,
)
from core.eip_scanner import discover_eip_devices, EIPIdentity
from core.settings_manager import get_settings
from ui.theme import *
from ui.widgets import DeviceRow, InfoCard, ScanProgressBar, StatusBadge, enable_touch_scroll

logger = logging.getLogger(__name__)


class ScanView(ctk.CTkFrame):
    """Network scanning interface — scan and discover devices."""

    def __init__(self, master, on_device_select: Callable = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._on_device_select = on_device_select
        self._interfaces: List[NetworkInterface] = []
        self._devices: List[DiscoveredDevice] = []
        self._eip_devices: Dict[str, EIPIdentity] = {}
        self._scanning = False
        self._cancel_event = threading.Event()

        self._build_ui()
        self._interfaces_loaded = False

    def on_show(self):
        """Called when view becomes visible — safe to use self.after()."""
        if not self._interfaces_loaded:
            self._refresh_interfaces()

    def _build_ui(self):
        # ── Header Section ───────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 12))

        ctk.CTkLabel(header, text="Network Scanner",
                     font=(FONT_FAMILY, FONT_SIZE_TITLE, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        ctk.CTkLabel(header, text="Scan the network to discover devices and check their health",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(16, 0))

        # ── Controls Row ─────────────────────────────────────────────────────
        controls = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=CARD_CORNER_RADIUS,
                                border_width=1, border_color=BORDER_COLOR)
        controls.pack(fill="x", padx=20, pady=(0, 12))

        controls_inner = ctk.CTkFrame(controls, fg_color="transparent")
        controls_inner.pack(fill="x", padx=CARD_PADDING, pady=CARD_PADDING)

        # Interface selector
        iface_frame = ctk.CTkFrame(controls_inner, fg_color="transparent")
        iface_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(iface_frame, text="Network Interface:",
                     font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY).pack(anchor="w")

        self._iface_var = ctk.StringVar(value="Select interface...")
        self._iface_dropdown = ctk.CTkComboBox(
            iface_frame, variable=self._iface_var,
            values=["Detecting..."],
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            dropdown_font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            button_color=SAS_BLUE, button_hover_color=SAS_BLUE_DARK,
            dropdown_fg_color=BG_MEDIUM, dropdown_hover_color=BG_CARD_HOVER,
            width=400, height=INPUT_HEIGHT, state="readonly",
        )
        self._iface_dropdown.pack(anchor="w", pady=(4, 0))

        # Buttons
        btn_frame = ctk.CTkFrame(controls_inner, fg_color="transparent")
        btn_frame.pack(side="right", padx=(20, 0))

        self._refresh_btn = ctk.CTkButton(
            btn_frame, text="↻ Refresh", font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY, hover_color=BG_CARD_HOVER,
            width=100, height=BUTTON_HEIGHT,
            command=self._refresh_interfaces,
        )
        self._refresh_btn.pack(side="left", padx=(0, 8))

        self._scan_btn = ctk.CTkButton(
            btn_frame, text="▶ Scan Network", font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            fg_color=SAS_BLUE, hover_color=SAS_BLUE_DARK,
            text_color="white", width=160, height=BUTTON_HEIGHT,
            corner_radius=BUTTON_CORNER_RADIUS,
            command=self._start_scan,
        )
        self._scan_btn.pack(side="left")

        # ── Progress Bar ─────────────────────────────────────────────────────
        self._progress = ScanProgressBar(self)
        self._progress.pack(fill="x", padx=20, pady=(0, 12))

        # ── Stats Cards ──────────────────────────────────────────────────────
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill="x", padx=20, pady=(0, 12))

        self._stat_total = InfoCard(stats_frame, "Devices Found", "—", icon="🖧", color=SAS_BLUE)
        self._stat_total.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._stat_eip = InfoCard(stats_frame, "Automation", "—", icon="⚡", color=SAS_ORANGE)
        self._stat_eip.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._stat_healthy = InfoCard(stats_frame, "Responding", "—", icon="✓", color=STATUS_GOOD)
        self._stat_healthy.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._stat_issues = InfoCard(stats_frame, "Slow / Issues", "—", icon="⚠", color=STATUS_WARN)
        self._stat_issues.pack(side="left", fill="x", expand=True)

        # ── Device List ──────────────────────────────────────────────────────
        list_header = ctk.CTkFrame(self, fg_color="transparent")
        list_header.pack(fill="x", padx=20, pady=(0, 6))
        ctk.CTkLabel(list_header, text="Discovered Devices",
                     font=(FONT_FAMILY, FONT_SIZE_SUBHEADING, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left")
        self._sort_label = ctk.CTkLabel(list_header, text="",
                                         font=(FONT_FAMILY, FONT_SIZE_TINY),
                                         text_color=TEXT_MUTED)
        self._sort_label.pack(side="right")

        # Scrollable device list
        self._device_list_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BORDER_COLOR,
            scrollbar_button_hover_color=SAS_BLUE,
        )
        self._device_list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        enable_touch_scroll(self._device_list_frame)

        # Placeholder
        self._placeholder = ctk.CTkLabel(
            self._device_list_frame,
            text="Select a network interface and click 'Scan Network' to begin.\n\n"
                 "The scanner will find all devices on the network, identify\n"
                 "manufacturers by MAC address, and discover EtherNet/IP devices.\n"
                 "Supports Allen-Bradley, Siemens, Schneider, WAGO, Phoenix Contact,\n"
                 "Beckhoff, Turck, ABB, Moxa, Cisco, and many more.",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_MUTED, justify="center",
        )
        self._placeholder.pack(pady=60)

    def _refresh_interfaces(self):
        """Detect and list available network interfaces."""
        def _detect():
            interfaces = get_network_interfaces()
            # Filter by settings
            interfaces = get_settings().filter_interfaces(interfaces)
            self.after(0, lambda: self._update_interface_list(interfaces))

        threading.Thread(target=_detect, daemon=True).start()

    def _update_interface_list(self, interfaces: List[NetworkInterface]):
        self._interfaces = interfaces
        self._interfaces_loaded = True
        if interfaces:
            # Annotate with host count so user knows scan size
            values = []
            for iface in interfaces:
                host_count = iface.host_count
                if host_count > 1022:
                    values.append(f"{iface}  ⚠ {host_count:,} hosts")
                else:
                    values.append(str(iface))
            self._iface_dropdown.configure(values=values)
            self._iface_var.set(values[0])
        else:
            self._iface_dropdown.configure(values=["No interfaces found"])
            self._iface_var.set("No interfaces found")

    def _get_selected_interface(self) -> Optional[NetworkInterface]:
        selected = self._iface_var.get()
        for iface in self._interfaces:
            # Match against both annotated and plain strings
            if str(iface) == selected or selected.startswith(str(iface)):
                return iface
        return None

    def _start_scan(self):
        if self._scanning:
            self._cancel_scan()
            return

        iface = self._get_selected_interface()
        if not iface:
            return

        self._scanning = True
        self._cancel_event.clear()
        self._scan_btn.configure(text="⏹ Stop Scan", fg_color=STATUS_ERROR,
                                 hover_color="#C53030")
        self._progress.reset()
        self._devices.clear()
        self._eip_devices.clear()
        self._clear_device_list()

        def run_scan():
            try:
                logger.info(f"Scan started on {iface.name} ({iface.ip_address}/{iface.subnet_mask}) "
                            f"— {iface.host_count:,} hosts to sweep")

                # Phase 1: Ping sweep
                self.after(0, lambda: self._progress.update_progress(0.0, "Scanning network (ping sweep)..."))

                def ping_progress(current, total, ip):
                    pct = current / total * 0.5  # Ping sweep is first 50%
                    self.after(0, lambda: self._progress.update_progress(
                        pct, f"Pinging {ip}... ({current}/{total})"))

                devices = ping_sweep(iface.network, ping_progress, self._cancel_event,
                                     source_ip=iface.ip_address)

                if self._cancel_event.is_set():
                    logger.info("Scan cancelled by user during ping sweep")
                    self.after(0, self._scan_cancelled)
                    return

                logger.info(f"Ping sweep complete: {len(devices)} devices found")

                # Phase 2: EtherNet/IP discovery
                self.after(0, lambda: self._progress.update_progress(
                    0.55, "Discovering EtherNet/IP devices..."))

                eip_devices = discover_eip_devices(timeout=3.0, interface_ip=iface.ip_address)

                # Also try pycomm3 if available
                try:
                    from core.eip_scanner import try_pycomm3_discover
                    pycomm_devices = try_pycomm3_discover()
                    seen = {d.ip_address for d in eip_devices}
                    for d in pycomm_devices:
                        if d.ip_address not in seen:
                            eip_devices.append(d)
                            seen.add(d.ip_address)
                except Exception:
                    pass

                # Map EIP data by IP
                for eip_dev in eip_devices:
                    self._eip_devices[eip_dev.ip_address] = eip_dev
                    # Add to device list if not found by ping
                    found_ips = {d.ip_address for d in devices}
                    if eip_dev.ip_address not in found_ips:
                        devices.append(DiscoveredDevice(
                            ip_address=eip_dev.ip_address,
                            is_reachable=True,
                            product_name=eip_dev.product_name,
                            device_type=eip_dev.vendor_name,
                        ))

                if self._cancel_event.is_set():
                    self.after(0, self._scan_cancelled)
                    return

                # Phase 3: Port scanning and device identification
                self.after(0, lambda: self._progress.update_progress(
                    0.65, "Identifying devices (port scanning)..."))

                for i, device in enumerate(devices):
                    if self._cancel_event.is_set():
                        break

                    pct = 0.65 + (i / len(devices)) * 0.30
                    self.after(0, lambda ip=device.ip_address, p=pct:
                               self._progress.update_progress(p, f"Scanning ports on {ip}..."))

                    # Scan key ports
                    device.open_ports = scan_industrial_ports(device.ip_address, timeout=0.3)

                    # Enrich with EIP identity data
                    eip_data = self._eip_devices.get(device.ip_address)
                    if eip_data:
                        device.product_name = eip_data.product_name
                        device.serial_number = eip_data.serial_hex
                        device.firmware_rev = eip_data.firmware_version
                        device.device_type = eip_data.vendor_name
                        device.eip_identity = eip_data.to_dict()
                    else:
                        device.device_type = identify_device_type(
                            device.open_ports, device.mac_address)

                self._devices = sorted(devices, key=lambda d: tuple(
                    int(p) for p in d.ip_address.split(".")))

                # Done
                self.after(0, self._scan_complete)

            except Exception as e:
                logger.error(f"Scan failed: {e}", exc_info=True)
                self.after(0, lambda: self._scan_error(str(e)))

        threading.Thread(target=run_scan, daemon=True).start()

    def _cancel_scan(self):
        self._cancel_event.set()

    def _scan_cancelled(self):
        self._scanning = False
        self._scan_btn.configure(text="▶ Scan Network", fg_color=SAS_BLUE,
                                 hover_color=SAS_BLUE_DARK)
        self._progress.update_progress(0, "Scan cancelled")

    def _scan_complete(self):
        self._scanning = False
        self._scan_btn.configure(text="▶ Scan Network", fg_color=SAS_BLUE,
                                 hover_color=SAS_BLUE_DARK)

        total = len(self._devices)
        eip_count = len(self._eip_devices)

        # Count devices identified by vendor (MAC or EIP)
        from core.mac_vendors import lookup_vendor_category
        auto_count = 0
        for d in self._devices:
            cat = "other"
            if d.ip_address in self._eip_devices:
                cat = "automation"
            elif d.mac_address:
                cat = lookup_vendor_category(d.mac_address)
            if cat == "automation":
                auto_count += 1

        responding = sum(1 for d in self._devices if d.response_time_ms < 20)
        slow = sum(1 for d in self._devices if d.response_time_ms >= 20)
        identified = sum(1 for d in self._devices
                         if d.device_type and d.device_type != "Unknown")

        self._progress.set_complete(f"Scan complete — found {total} devices")
        self._stat_total.set_value(str(total))
        self._stat_eip.set_value(str(auto_count),
                                  SAS_ORANGE if auto_count > 0 else TEXT_SECONDARY)
        self._stat_healthy.set_value(str(responding), STATUS_GOOD)
        self._stat_issues.set_value(str(slow),
                                     STATUS_WARN if slow > 0 else TEXT_SECONDARY)
        self._sort_label.configure(
            text=f"Sorted by IP address • {total} devices "
                 f"• {identified} identified by manufacturer")

        self._populate_device_list()

    def _scan_error(self, error_msg: str):
        self._scanning = False
        self._scan_btn.configure(text="▶ Scan Network", fg_color=SAS_BLUE,
                                 hover_color=SAS_BLUE_DARK)
        self._progress.update_progress(0, f"Error: {error_msg}")

    def _clear_device_list(self):
        for widget in self._device_list_frame.winfo_children():
            widget.destroy()

    def _populate_device_list(self):
        self._clear_device_list()

        if not self._devices:
            ctk.CTkLabel(
                self._device_list_frame,
                text="No devices found.\n\nMake sure your laptop is connected to the network\n"
                     "and the correct interface is selected.",
                font=(FONT_FAMILY, FONT_SIZE_BODY),
                text_color=TEXT_MUTED, justify="center",
            ).pack(pady=40)
            return

        for device in self._devices:
            status_color = STATUS_GOOD
            if device.response_time_ms >= 50:
                status_color = STATUS_ERROR
            elif device.response_time_ms >= 20:
                status_color = STATUS_WARN

            name = device.display_name
            dev_type = device.device_type or "Unknown"

            # Show EIP-specific info if available
            eip = self._eip_devices.get(device.ip_address)
            if eip:
                if eip.vendor_name:
                    dev_type = eip.vendor_name
                elif eip.device_type_name:
                    dev_type = eip.device_type_name

            # Show vendor from MAC if we have it and device_type is still generic
            if dev_type == "Unknown" and device.vendor:
                dev_type = device.vendor

            # Append MAC address hint for identification
            mac_hint = ""
            if device.mac_address:
                mac_hint = f"  [{device.mac_address}]"

            row = DeviceRow(
                self._device_list_frame,
                ip=device.ip_address,
                name=name,
                device_type=dev_type,
                status_color=status_color,
                ping_ms=device.response_time_ms,
                on_click=lambda d=device: self._select_device(d),
            )
            row.pack(fill="x", pady=(0, 4))

    def _select_device(self, device: DiscoveredDevice):
        """Handle device selection — navigate to detail view."""
        eip_identity = self._eip_devices.get(device.ip_address)
        if self._on_device_select:
            self._on_device_select(device, eip_identity)

    def get_devices(self) -> List[DiscoveredDevice]:
        return self._devices

    def get_eip_identities(self) -> Dict[str, EIPIdentity]:
        return self._eip_devices
