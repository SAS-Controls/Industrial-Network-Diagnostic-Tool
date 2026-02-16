"""
SAS Network Diagnostics Tool — Main Application
The main window with sidebar navigation and view management.
"""

import logging
import os
import sys
import tkinter as tk
from typing import Optional

import customtkinter as ctk
from PIL import Image

from core.network_utils import DiscoveredDevice
from core.eip_scanner import EIPIdentity
from core.settings_manager import get_settings
from ui.theme import *
from ui.scan_view import ScanView
from ui.device_view import DeviceDetailView
from ui.finder_view import DeviceFinderView
from ui.devicenet_view import DeviceNetView
from ui.monitor_view import DeviceMonitorView
from ui.devicenet_monitor_view import DeviceNetMonitorView
from ui.capture_view import PacketCaptureView
from ui.settings_view import SettingsView
from ui.help_view import HelpView

logger = logging.getLogger(__name__)


class App(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # ── Load Settings ─────────────────────────────────────────────────────
        self._settings = get_settings()

        # ── Window Configuration ─────────────────────────────────────────────
        self.title(APP_FULL_NAME)
        self.geometry("1280x800")
        self.minsize(1024, 600)
        self.configure(fg_color=BG_DARK)

        # Set appearance from saved settings
        ctk.set_appearance_mode(self._settings.theme)
        ctk.set_default_color_theme("blue")

        # Try to set window icon
        try:
            ico_path = get_asset_path("icon.ico")
            png_path = get_asset_path("icon.png")
            if os.path.exists(ico_path):
                self.iconbitmap(ico_path)
            elif os.path.exists(png_path):
                icon_img = tk.PhotoImage(file=png_path)
                self.iconphoto(True, icon_img)
                self._icon_ref = icon_img
        except Exception as e:
            logger.debug(f"Could not set icon: {e}")

        # ── Build Layout ─────────────────────────────────────────────────────
        self._build_sidebar()
        self._build_main_area()

        # ── Initialize Views ─────────────────────────────────────────────────
        self._current_view = None
        self._show_scan_view()

    def _build_sidebar(self):
        """Build the left sidebar with logo and navigation."""
        self._sidebar = ctk.CTkFrame(
            self, width=SIDEBAR_WIDTH, corner_radius=0,
            fg_color=BG_MEDIUM, border_width=0,
        )
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        # ── Logo Area ────────────────────────────────────────────────────────
        logo_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent", height=100)
        logo_frame.pack(fill="x", padx=16, pady=(20, 8))
        logo_frame.pack_propagate(False)

        try:
            dark_logo_path = get_asset_path("logo.png")
            light_logo_path = get_asset_path("logo_light.png")

            if os.path.exists(dark_logo_path):
                dark_img = Image.open(dark_logo_path).convert("RGBA")
                # Use light logo if available, otherwise same as dark
                if os.path.exists(light_logo_path):
                    light_img = Image.open(light_logo_path).convert("RGBA")
                else:
                    light_img = dark_img

                aspect = dark_img.width / dark_img.height
                logo_w = SIDEBAR_WIDTH - 40
                logo_h = int(logo_w / aspect)
                if logo_h > 80:
                    logo_h = 80
                    logo_w = int(logo_h * aspect)
                ctk_logo = ctk.CTkImage(
                    light_image=light_img,
                    dark_image=dark_img,
                    size=(logo_w, logo_h),
                )
                logo_label = ctk.CTkLabel(logo_frame, text="", image=ctk_logo,
                                           fg_color="transparent")
                logo_label.pack(pady=(5, 0))
                self._logo_ref = ctk_logo
        except Exception as e:
            logger.debug(f"Could not load logo: {e}")
            ctk.CTkLabel(logo_frame, text="SAS",
                         font=(FONT_FAMILY, 28, "bold"),
                         text_color=SAS_BLUE).pack(pady=(5, 0))

        # App title — single line, consistent font
        ctk.CTkLabel(self._sidebar, text=APP_NAME,
                     font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                     text_color=TEXT_PRIMARY).pack(padx=16, pady=(4, 4))

        # Divider
        ctk.CTkFrame(self._sidebar, fg_color=BORDER_COLOR, height=1).pack(
            fill="x", padx=16, pady=12)

        # ── Navigation Buttons ───────────────────────────────────────────────
        nav_label = ctk.CTkLabel(self._sidebar, text="TOOLS",
                                  font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
                                  text_color=TEXT_MUTED, anchor="w")
        nav_label.pack(fill="x", padx=20, pady=(0, 6))

        self._nav_buttons = {}

        self._add_nav_button("scan", "🔍  Network Scanner", self._show_scan_view)
        self._add_nav_button("finder", "📡  Device Finder", self._show_finder_view)
        self._add_nav_button("monitor", "📊  Ethernet Device Monitor", self._show_monitor_view)
        self._add_nav_button("devicenet", "🔗  DeviceNet Scan", self._show_devicenet_view)
        self._add_nav_button("dn_monitor", "📈  DeviceNet Network Monitor", self._show_dn_monitor_view)
        self._add_nav_button("capture", "🦈  Packet Capture", self._show_capture_view)

        # ── Bottom Area ──────────────────────────────────────────────────────
        spacer = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        bottom = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        # Help button
        self._help_btn = ctk.CTkButton(
            bottom, text="📖  Help",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=BG_CARD_HOVER, anchor="w",
            height=36, corner_radius=6,
            command=self._show_help_view,
        )
        self._help_btn.pack(fill="x", pady=(0, 2))

        # Settings button
        self._settings_btn = ctk.CTkButton(
            bottom, text="⚙  Settings",
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=BG_CARD_HOVER, anchor="w",
            height=36, corner_radius=6,
            command=self._show_settings_view,
        )
        self._settings_btn.pack(fill="x", pady=(0, 2))

        # Divider
        ctk.CTkFrame(bottom, fg_color=BORDER_COLOR, height=1).pack(
            fill="x", padx=4, pady=8)

        # Version & company info
        ctk.CTkLabel(bottom, text=APP_COMPANY,
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED, anchor="w").pack(fill="x", padx=4)
        ctk.CTkLabel(bottom, text=f"v{APP_VERSION}",
                     font=(FONT_FAMILY, FONT_SIZE_TINY),
                     text_color=TEXT_MUTED, anchor="w").pack(fill="x", padx=4)

    def _add_nav_button(self, key: str, text: str, command):
        """Add a navigation button to the sidebar."""
        btn = ctk.CTkButton(
            self._sidebar, text=text,
            font=(FONT_FAMILY, FONT_SIZE_BODY),
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=BG_CARD_HOVER, anchor="w",
            height=40, corner_radius=6,
            command=command,
        )
        btn.pack(fill="x", padx=12, pady=(0, 2))
        self._nav_buttons[key] = btn

    def _set_active_nav(self, key: str):
        """Highlight the active navigation button."""
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(fg_color=BG_CARD, text_color=SAS_BLUE_LIGHT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_SECONDARY)

    def _build_main_area(self):
        """Build the main content area."""
        self._main_area = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self._main_area.pack(side="right", fill="both", expand=True)

        # Create views
        self._scan_view = ScanView(self._main_area, on_device_select=self._on_device_selected)
        self._device_view = DeviceDetailView(self._main_area, on_back=self._show_scan_view)
        self._finder_view = DeviceFinderView(self._main_area)
        self._monitor_view = DeviceMonitorView(self._main_area)
        self._devicenet_view = DeviceNetView(self._main_area)
        self._dn_monitor_view = DeviceNetMonitorView(self._main_area)
        self._capture_view = PacketCaptureView(self._main_area)
        self._settings_view = SettingsView(
            self._main_area, on_theme_change=self._on_theme_change)
        self._help_view = HelpView(self._main_area)

    def _hide_all_views(self):
        """Hide all views."""
        self._scan_view.pack_forget()
        self._device_view.pack_forget()
        self._finder_view.pack_forget()
        self._monitor_view.pack_forget()
        self._devicenet_view.pack_forget()
        self._dn_monitor_view.pack_forget()
        self._capture_view.pack_forget()
        self._settings_view.pack_forget()
        self._help_view.pack_forget()

    def _show_scan_view(self):
        self._hide_all_views()
        self._scan_view.pack(fill="both", expand=True)
        self._scan_view.on_show()
        self._set_active_nav("scan")

    def _show_finder_view(self):
        self._hide_all_views()
        self._finder_view.pack(fill="both", expand=True)
        self._finder_view.on_show()
        self._set_active_nav("finder")

    def _show_monitor_view(self):
        self._hide_all_views()
        self._monitor_view.pack(fill="both", expand=True)
        self._set_active_nav("monitor")

    def _show_devicenet_view(self):
        self._hide_all_views()
        self._devicenet_view.pack(fill="both", expand=True)
        self._set_active_nav("devicenet")

    def _show_dn_monitor_view(self):
        self._hide_all_views()
        self._dn_monitor_view.pack(fill="both", expand=True)
        self._set_active_nav("dn_monitor")

    def _show_capture_view(self):
        self._hide_all_views()
        self._capture_view.pack(fill="both", expand=True)
        self._capture_view.on_show()
        self._set_active_nav("capture")

    def _show_settings_view(self):
        self._hide_all_views()
        self._settings_view.pack(fill="both", expand=True)
        self._settings_view.on_show()
        self._set_active_nav("")

    def _show_help_view(self):
        self._hide_all_views()
        self._help_view.pack(fill="both", expand=True)
        self._set_active_nav("")

    def _on_device_selected(self, device: DiscoveredDevice,
                             eip_identity: Optional[EIPIdentity] = None):
        """Handle device selection from scan results."""
        self._hide_all_views()
        self._device_view.pack(fill="both", expand=True)
        self._device_view.load_device(device, eip_identity)
        self._set_active_nav("")

    def _show_device_view(self):
        self._hide_all_views()
        self._device_view.pack(fill="both", expand=True)

    def _on_theme_change(self, theme: str):
        """Called when theme is changed in settings."""
        logger.info(f"Theme changed to: {theme}")
