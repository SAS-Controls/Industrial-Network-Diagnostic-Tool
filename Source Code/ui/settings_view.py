"""
SAS Network Diagnostics Tool — Settings View
Global application settings for theme, adapter filtering, etc.
"""

import logging
import threading
from typing import Dict, List, Optional

import customtkinter as ctk

from core.settings_manager import get_settings
from core.network_utils import get_network_interfaces, NetworkInterface
from ui.theme import *
from ui.widgets import enable_touch_scroll

logger = logging.getLogger(__name__)


class SettingsView(ctk.CTkFrame):
    """Settings page — theme, adapter filtering, and other global options."""

    def __init__(self, parent, on_theme_change=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._settings = get_settings()
        self._on_theme_change = on_theme_change  # Callback when theme changes
        self._adapter_switches: Dict[str, ctk.CTkSwitch] = {}
        self._all_adapters: List[NetworkInterface] = []

        self._build_ui()
        self._adapters_loaded = False

    def on_show(self):
        """Called when view becomes visible — safe to use self.after()."""
        if not self._adapters_loaded:
            self._detect_adapters()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BG_MEDIUM,
            scrollbar_button_hover_color=SAS_BLUE)
        scroll.pack(fill="both", expand=True)
        enable_touch_scroll(scroll)

        inner = scroll

        # ── Header ────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(inner, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 4))

        ctk.CTkLabel(
            hdr, text="⚙  Settings",
            font=(FONT_FAMILY, FONT_SIZE_HEADING, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(side="left")

        ctk.CTkLabel(
            inner,
            text="Customize application behavior. Changes are saved automatically.",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_SECONDARY, anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 16))

        # ── Appearance Section ────────────────────────────────────────────
        self._build_section_header(inner, "Appearance")

        theme_card = ctk.CTkFrame(inner, fg_color=BG_CARD, corner_radius=8)
        theme_card.pack(fill="x", padx=24, pady=(0, 16))

        theme_row = ctk.CTkFrame(theme_card, fg_color="transparent")
        theme_row.pack(fill="x", padx=16, pady=12)

        left = ctk.CTkFrame(theme_row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left, text="Theme",
            font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x")
        ctk.CTkLabel(
            left, text="Switch between dark and light mode",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w",
        ).pack(fill="x")

        self._theme_var = ctk.StringVar(value=self._settings.theme.capitalize())
        self._theme_menu = ctk.CTkOptionMenu(
            theme_row, variable=self._theme_var,
            values=["Dark", "Light"],
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color=BG_MEDIUM, button_color=SAS_BLUE,
            button_hover_color=SAS_BLUE_DARK,
            dropdown_fg_color=BG_MEDIUM,
            width=120, height=32,
            command=self._on_theme_selected,
        )
        self._theme_menu.pack(side="right", padx=(12, 0))

        # ── Network Adapters Section ──────────────────────────────────────
        self._build_section_header(inner, "Network Adapters")

        ctk.CTkLabel(
            inner,
            text="Disable adapters you don't use (VMware, VPN, etc.) to keep dropdowns clean.\n"
                 "Disabled adapters won't appear in any tool's adapter selection.",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w", justify="left",
        ).pack(fill="x", padx=24, pady=(0, 8))

        # Refresh button
        refresh_row = ctk.CTkFrame(inner, fg_color="transparent")
        refresh_row.pack(fill="x", padx=24, pady=(0, 8))

        self._adapter_status = ctk.CTkLabel(
            refresh_row, text="Detecting adapters...",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._adapter_status.pack(side="left")

        ctk.CTkButton(
            refresh_row, text="↻  Refresh", width=100, height=28,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY,
            command=self._detect_adapters,
        ).pack(side="right")

        # Adapter list container
        self._adapter_frame = ctk.CTkFrame(inner, fg_color=BG_CARD, corner_radius=8)
        self._adapter_frame.pack(fill="x", padx=24, pady=(0, 16))

        # Placeholder while detecting
        self._adapter_placeholder = ctk.CTkLabel(
            self._adapter_frame, text="Detecting network adapters...",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            text_color=TEXT_MUTED, height=60,
        )
        self._adapter_placeholder.pack(fill="x", padx=16, pady=12)

        # ── About Section ─────────────────────────────────────────────────
        self._build_section_header(inner, "About")

        about_card = ctk.CTkFrame(inner, fg_color=BG_CARD, corner_radius=8)
        about_card.pack(fill="x", padx=24, pady=(0, 16))

        about_inner = ctk.CTkFrame(about_card, fg_color="transparent")
        about_inner.pack(fill="x", padx=16, pady=12)

        info_lines = [
            (APP_FULL_NAME, TEXT_PRIMARY, ("bold",)),
            (f"Version {APP_VERSION}", TEXT_SECONDARY, ()),
            (APP_COMPANY, TEXT_SECONDARY, ()),
            ("", TEXT_MUTED, ()),
            (f"Development Phase: {APP_PHASE}", TEXT_MUTED, ()),
        ]
        for text, color, style in info_lines:
            if not text:
                ctk.CTkFrame(about_inner, fg_color=BORDER_COLOR, height=1).pack(
                    fill="x", pady=6)
                continue
            font_args = (FONT_FAMILY, FONT_SIZE_BODY) + style
            ctk.CTkLabel(
                about_inner, text=text,
                font=font_args,
                text_color=color, anchor="w",
            ).pack(fill="x", pady=1)

    def _build_section_header(self, parent, title: str):
        """Create a section header label."""
        ctk.CTkLabel(
            parent, text=title.upper(),
            font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 6))

    # ── Theme ─────────────────────────────────────────────────────────────

    def _on_theme_selected(self, value: str):
        """Handle theme selection change."""
        theme = value.lower()
        self._settings.theme = theme
        self._settings.save()
        ctk.set_appearance_mode(theme)
        if self._on_theme_change:
            self._on_theme_change(theme)

    # ── Adapter Detection & Display ───────────────────────────────────────

    def _detect_adapters(self):
        """Detect all adapters on a background thread."""
        self._adapter_status.configure(text="Detecting adapters...")

        def _run():
            try:
                interfaces = get_network_interfaces()
                # Also get adapters that are down (psutil shows all)
                import psutil
                import socket
                all_names = set()
                stats = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                extra = []
                for name, addr_list in addrs.items():
                    if name in [i.name for i in interfaces]:
                        continue
                    for addr in addr_list:
                        if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                            stat = stats.get(name)
                            extra.append(NetworkInterface(
                                name=name, display_name=name,
                                ip_address=addr.address,
                                subnet_mask=addr.netmask or "255.255.255.0",
                                mac_address="",
                                is_up=stat.isup if stat else False,
                                speed_mbps=stat.speed if stat and stat.speed else 0,
                            ))
                            break
                all_ifaces = interfaces + extra
                self.after(0, lambda: self._populate_adapters(all_ifaces))
            except Exception as e:
                logger.error(f"Adapter detection failed: {e}")
                self.after(0, lambda: self._adapter_status.configure(
                    text=f"Detection failed: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    def _populate_adapters(self, interfaces: List[NetworkInterface]):
        """Build the adapter toggle list."""
        self._all_adapters = interfaces
        self._adapters_loaded = True

        # Clear existing
        for widget in self._adapter_frame.winfo_children():
            widget.destroy()
        self._adapter_switches.clear()

        if not interfaces:
            ctk.CTkLabel(
                self._adapter_frame, text="No network adapters detected",
                font=(FONT_FAMILY, FONT_SIZE_BODY),
                text_color=TEXT_MUTED, height=60,
            ).pack(fill="x", padx=16, pady=12)
            self._adapter_status.configure(text="No adapters found")
            return

        hidden = self._settings.hidden_adapters

        for i, iface in enumerate(interfaces):
            row = ctk.CTkFrame(self._adapter_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=(8 if i == 0 else 2, 2))

            # Switch (on = visible/enabled, off = hidden)
            var = ctk.BooleanVar(value=(iface.name not in hidden))
            sw = ctk.CTkSwitch(
                row, text="",
                variable=var,
                width=44, height=22,
                switch_width=36, switch_height=18,
                fg_color=BG_MEDIUM,
                progress_color=SAS_BLUE,
                command=lambda name=iface.name, v=var: self._on_adapter_toggle(name, v),
            )
            sw.pack(side="left", padx=(4, 8))
            self._adapter_switches[iface.name] = sw

            # Info
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True)

            name_text = iface.display_name
            # Flag common non-physical adapters
            tag = ""
            name_lower = iface.name.lower()
            if "vmware" in name_lower or "vmnet" in name_lower:
                tag = "  (VMware)"
            elif "virtualbox" in name_lower or "vbox" in name_lower:
                tag = "  (VirtualBox)"
            elif "vpn" in name_lower or "tap" in name_lower or "tun" in name_lower:
                tag = "  (VPN)"
            elif "loopback" in name_lower:
                tag = "  (Loopback)"
            elif "hyper-v" in name_lower or "vethernet" in name_lower:
                tag = "  (Hyper-V)"
            elif "docker" in name_lower:
                tag = "  (Docker)"
            elif "wsl" in name_lower:
                tag = "  (WSL)"

            ctk.CTkLabel(
                info, text=f"{name_text}{tag}",
                font=(FONT_FAMILY, FONT_SIZE_BODY),
                text_color=TEXT_PRIMARY if iface.is_up else TEXT_MUTED,
                anchor="w",
            ).pack(fill="x")

            status_parts = [iface.ip_address]
            if iface.speed_mbps:
                status_parts.append(f"{iface.speed_mbps} Mbps")
            if not iface.is_up:
                status_parts.append("DOWN")

            ctk.CTkLabel(
                info, text="  ·  ".join(status_parts),
                font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                text_color=TEXT_MUTED, anchor="w",
            ).pack(fill="x")

            # Divider (except last)
            if i < len(interfaces) - 1:
                ctk.CTkFrame(self._adapter_frame, fg_color=BORDER_COLOR, height=1).pack(
                    fill="x", padx=12, pady=(4, 0))

        # Bottom padding
        ctk.CTkFrame(self._adapter_frame, fg_color="transparent", height=8).pack()

        enabled = len(interfaces) - len(hidden & {i.name for i in interfaces})
        self._adapter_status.configure(
            text=f"{len(interfaces)} adapters found · {enabled} enabled")

    def _on_adapter_toggle(self, adapter_name: str, var: ctk.BooleanVar):
        """Handle adapter enable/disable toggle."""
        is_visible = var.get()
        self._settings.set_adapter_hidden(adapter_name, not is_visible)
        self._settings.save()

        # Update status label
        hidden = self._settings.hidden_adapters
        enabled = len(self._all_adapters) - len(
            hidden & {i.name for i in self._all_adapters})
        self._adapter_status.configure(
            text=f"{len(self._all_adapters)} adapters found · {enabled} enabled")
