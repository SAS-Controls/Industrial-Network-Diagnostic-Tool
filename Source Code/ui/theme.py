"""
SAS Network Diagnostics Tool — Theme & Branding
Defines all visual constants for the application using SAS brand identity.
"""

import os
import sys

# ── SAS Brand Colors ─────────────────────────────────────────────────────────
SAS_BLUE = "#0070BB"
SAS_BLUE_DARK = "#005A96"
SAS_BLUE_LIGHT = "#4F81BD"
SAS_BLUE_ACCENT = "#365F91"
SAS_ORANGE = "#E8722A"
SAS_ORANGE_DARK = "#C45E1F"
SAS_ORANGE_LIGHT = "#F09050"

# ── UI Colors ────────────────────────────────────────────────────────────────
# Each constant is a (light_mode, dark_mode) tuple.
# CustomTkinter automatically selects the correct value based on
# ctk.set_appearance_mode("Light" / "Dark").
BG_DARK = ("#D5D8DC", "#1A1A2E")          # Main background
BG_MEDIUM = ("#C8CCD0", "#16213E")        # Sidebar / section backgrounds
BG_CARD = ("#EAECF0", "#1E2A45")          # Card backgrounds
BG_CARD_HOVER = ("#DCE0E5", "#253352")    # Card hover state
BG_INPUT = ("#FFFFFF", "#0F1628")          # Input field backgrounds
TEXT_PRIMARY = ("#1A1A2E", "#EAEAEA")      # Primary text
TEXT_SECONDARY = ("#4A5568", "#8892A8")    # Secondary text
TEXT_MUTED = ("#718096", "#5A6478")        # Muted / hint text
BORDER_COLOR = ("#B0B8C4", "#2A3550")     # Borders
BORDER_ACTIVE = SAS_BLUE

# ── Status Colors ────────────────────────────────────────────────────────────
STATUS_GOOD = "#22C55E"
STATUS_WARN = "#F59E0B"
STATUS_ERROR = "#EF4444"
STATUS_INFO = SAS_BLUE_LIGHT
STATUS_OFFLINE = "#6B7280"

# ── Health Score Colors (gradient from red to green) ─────────────────────────
HEALTH_CRITICAL = "#EF4444"
HEALTH_POOR = "#F97316"
HEALTH_FAIR = "#F59E0B"
HEALTH_GOOD = "#84CC16"
HEALTH_EXCELLENT = "#22C55E"

# ── Typography ───────────────────────────────────────────────────────────────
FONT_FAMILY = "Segoe UI"
FONT_FAMILY_MONO = "Consolas"
FONT_SIZE_TITLE = 20
FONT_SIZE_HEADING = 16
FONT_SIZE_SUBHEADING = 14
FONT_SIZE_BODY = 12
FONT_SIZE_SMALL = 11
FONT_SIZE_TINY = 10

# ── Layout ───────────────────────────────────────────────────────────────────
SIDEBAR_WIDTH = 250
CARD_CORNER_RADIUS = 8
CARD_PADDING = 16
BUTTON_CORNER_RADIUS = 6
BUTTON_HEIGHT = 36
INPUT_HEIGHT = 36

# ── Application Info ─────────────────────────────────────────────────────────
APP_NAME = "SAS Network Diagnostic Tool"
APP_FULL_NAME = "SAS Network Diagnostic Tool"
APP_VERSION = "2.5.2"
APP_COMPANY = "Southern Automation Solutions"
APP_PHASE = "Phase 3 — Packet Capture & Analysis"


def get_asset_path(filename: str) -> str:
    """Get the absolute path to an asset file, handling both dev and PyInstaller modes."""
    if getattr(sys, 'frozen', False):
        # Running as compiled exe — assets bundled by PyInstaller
        base_path = sys._MEIPASS
    else:
        # Running as script — assets relative to this file's parent
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, "assets", filename)


def resolve_color(color) -> str:
    """
    Resolve a theme color to a single string for raw tkinter widgets.

    CustomTkinter handles (light, dark) tuples automatically, but raw
    tkinter widgets (Canvas, tag_config, etc.) need a plain string.
    This function returns the correct value based on the current
    appearance mode.
    """
    if isinstance(color, (list, tuple)) and len(color) == 2:
        try:
            import customtkinter as ctk
            mode = ctk.get_appearance_mode()
            return color[0] if mode == "Light" else color[1]
        except Exception:
            return color[1]  # default to dark
    # Safety: if somehow a space-separated pair slips through (CTk internal
    # format), split and return the appropriate half.
    if isinstance(color, str) and " " in color and color.startswith("#"):
        parts = color.split()
        if len(parts) == 2 and all(p.startswith("#") for p in parts):
            try:
                import customtkinter as ctk
                mode = ctk.get_appearance_mode()
                return parts[0] if mode == "Light" else parts[1]
            except Exception:
                return parts[1]
    return color


def get_health_color(score: int) -> str:
    """Return the appropriate color for a health score (0-100)."""
    if score >= 90:
        return HEALTH_EXCELLENT
    elif score >= 70:
        return HEALTH_GOOD
    elif score >= 50:
        return HEALTH_FAIR
    elif score >= 30:
        return HEALTH_POOR
    else:
        return HEALTH_CRITICAL


def get_health_label(score: int) -> str:
    """Return a human-readable label for a health score."""
    if score >= 90:
        return "Excellent"
    elif score >= 70:
        return "Good"
    elif score >= 50:
        return "Fair"
    elif score >= 30:
        return "Poor"
    else:
        return "Critical"
