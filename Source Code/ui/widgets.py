"""
SAS Network Diagnostics Tool — Custom Widgets
Reusable UI components with SAS branding.
"""

import math
import tkinter as tk
from typing import Callable, Optional

import customtkinter as ctk
from ui.theme import *


class StatusBadge(ctk.CTkFrame):
    """A colored badge showing status text."""

    def __init__(self, master, text: str = "", color: str = STATUS_GOOD, **kwargs):
        super().__init__(master, corner_radius=12, height=26, **kwargs)
        self.configure(fg_color=color)
        self._label = ctk.CTkLabel(
            self, text=text, font=(FONT_FAMILY, FONT_SIZE_TINY, "bold"),
            text_color="white", height=22,
        )
        self._label.pack(padx=10, pady=2)

    def set_status(self, text: str, color: str):
        self.configure(fg_color=color)
        self._label.configure(text=text)


class HealthGauge(ctk.CTkFrame):
    """A circular health score gauge widget."""

    def __init__(self, master, size: int = 160, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._size = size
        self._score = 0
        self._canvas = tk.Canvas(
            self, width=size, height=size,
            bg=resolve_color(BG_CARD), highlightthickness=0,
        )
        self._canvas.pack()
        self._draw_gauge(0)

    def _draw(self, no_color_updates=False):
        """Override CTkFrame._draw so CustomTkinter doesn't crash.
        CTkFrame.__init__ calls self._draw(no_color_updates=True) internally.
        Without this override, a naming collision causes a TypeError."""
        super()._draw(no_color_updates=no_color_updates)

    def set_score(self, score: int):
        self._score = max(0, min(100, score))
        self._draw_gauge(self._score)

    def _draw_gauge(self, score: int):
        c = self._canvas
        c.delete("all")
        cx, cy = self._size // 2, self._size // 2
        r = self._size // 2 - 12
        thickness = 10

        # Background arc
        c.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=225, extent=-270, style="arc",
            outline=resolve_color(BORDER_COLOR), width=thickness,
        )

        # Score arc
        color = get_health_color(score)
        extent = -270 * (score / 100)
        if score > 0:
            c.create_arc(
                cx - r, cy - r, cx + r, cy + r,
                start=225, extent=extent, style="arc",
                outline=color, width=thickness,
            )

        # Score text
        c.create_text(cx, cy - 8, text=str(score),
                       font=(FONT_FAMILY, self._size // 5, "bold"),
                       fill=color)
        c.create_text(cx, cy + self._size // 7,
                       text=get_health_label(score),
                       font=(FONT_FAMILY, FONT_SIZE_SMALL),
                       fill=resolve_color(TEXT_SECONDARY))


class InfoCard(ctk.CTkFrame):
    """A card displaying a label and value, like a KPI tile."""

    def __init__(self, master, label: str = "", value: str = "",
                 icon: str = "", color: str = SAS_BLUE, **kwargs):
        super().__init__(master, corner_radius=CARD_CORNER_RADIUS,
                         fg_color=BG_CARD, border_width=1,
                         border_color=BORDER_COLOR, **kwargs)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="x", padx=CARD_PADDING, pady=CARD_PADDING)

        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x")

        if icon:
            ctk.CTkLabel(header, text=icon, font=(FONT_FAMILY, 18),
                         text_color=color).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(header, text=label, font=(FONT_FAMILY, FONT_SIZE_SMALL),
                     text_color=TEXT_SECONDARY).pack(side="left")

        self._value_label = ctk.CTkLabel(
            inner, text=value, font=(FONT_FAMILY, FONT_SIZE_HEADING, "bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        )
        self._value_label.pack(fill="x", pady=(6, 0))

    def set_value(self, value: str, color: str = TEXT_PRIMARY):
        self._value_label.configure(text=value, text_color=color)


class FindingCard(ctk.CTkFrame):
    """Displays a single diagnostic finding with severity icon and expandable details."""

    def __init__(self, master, title: str, severity: str, summary: str,
                 explanation: str = "", recommendation: str = "",
                 raw_value: str = "", **kwargs):
        super().__init__(master, corner_radius=CARD_CORNER_RADIUS,
                         fg_color=BG_CARD, border_width=1,
                         border_color=BORDER_COLOR, **kwargs)

        severity_colors = {
            "ok": STATUS_GOOD,
            "warning": STATUS_WARN,
            "critical": STATUS_ERROR,
            "info": STATUS_INFO,
        }
        severity_icons = {
            "ok": "✅",
            "warning": "⚠️",
            "critical": "🔴",
            "info": "ℹ️",
        }

        color = severity_colors.get(severity, TEXT_SECONDARY)
        icon = severity_icons.get(severity, "")

        # Header row
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 4))

        ctk.CTkLabel(header, text=f"{icon}  {title}",
                     font=(FONT_FAMILY, FONT_SIZE_BODY, "bold"),
                     text_color=color, anchor="w").pack(side="left", fill="x", expand=True)

        # Summary
        ctk.CTkLabel(self, text=summary, font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, anchor="w", wraplength=600,
                     justify="left").pack(fill="x", padx=CARD_PADDING, pady=(0, 4))

        # Expandable details
        if explanation or recommendation:
            self._details_frame = ctk.CTkFrame(self, fg_color=BG_MEDIUM, corner_radius=6)
            self._details_visible = False

            if explanation:
                ctk.CTkLabel(self._details_frame, text="What This Means:",
                             font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                             text_color=SAS_BLUE_LIGHT, anchor="w").pack(
                    fill="x", padx=12, pady=(10, 2))
                ctk.CTkLabel(self._details_frame, text=explanation,
                             font=(FONT_FAMILY, FONT_SIZE_SMALL),
                             text_color=TEXT_SECONDARY, anchor="w",
                             wraplength=560, justify="left").pack(
                    fill="x", padx=12, pady=(0, 6))

            if recommendation:
                ctk.CTkLabel(self._details_frame, text="What To Do:",
                             font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
                             text_color=SAS_ORANGE, anchor="w").pack(
                    fill="x", padx=12, pady=(4, 2))
                ctk.CTkLabel(self._details_frame, text=recommendation,
                             font=(FONT_FAMILY, FONT_SIZE_SMALL),
                             text_color=TEXT_SECONDARY, anchor="w",
                             wraplength=560, justify="left").pack(
                    fill="x", padx=12, pady=(0, 6))

            if raw_value:
                ctk.CTkLabel(self._details_frame, text=f"Raw Data: {raw_value}",
                             font=(FONT_FAMILY_MONO, FONT_SIZE_TINY),
                             text_color=TEXT_MUTED, anchor="w").pack(
                    fill="x", padx=12, pady=(4, 10))

            toggle_btn = ctk.CTkButton(
                self, text="Show Details ▸", font=(FONT_FAMILY, FONT_SIZE_SMALL),
                fg_color="transparent", text_color=SAS_BLUE_LIGHT,
                hover_color=BG_CARD_HOVER, height=28, anchor="w",
                command=self._toggle_details,
            )
            toggle_btn.pack(fill="x", padx=CARD_PADDING, pady=(0, 8))
            self._toggle_btn = toggle_btn

        # Bottom padding
        ctk.CTkFrame(self, fg_color="transparent", height=4).pack()

    def _toggle_details(self):
        if self._details_visible:
            self._details_frame.pack_forget()
            self._toggle_btn.configure(text="Show Details ▸")
        else:
            self._details_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, 4),
                                     before=self._toggle_btn)
            self._toggle_btn.configure(text="Hide Details ▾")
        self._details_visible = not self._details_visible


class DeviceRow(ctk.CTkFrame):
    """A clickable row representing a discovered device in the device list."""

    def __init__(self, master, ip: str, name: str, device_type: str,
                 status_color: str = STATUS_GOOD, ping_ms: float = 0,
                 on_click: Optional[Callable] = None, **kwargs):
        super().__init__(master, corner_radius=6, fg_color=BG_CARD,
                         border_width=1, border_color=BORDER_COLOR,
                         cursor="hand2", height=56, **kwargs)
        self.pack_propagate(False)
        self._on_click = on_click

        # Status indicator dot
        dot_canvas = tk.Canvas(self, width=12, height=12, bg=resolve_color(BG_CARD),
                               highlightthickness=0)
        dot_canvas.create_oval(2, 2, 10, 10, fill=status_color, outline="")
        dot_canvas.pack(side="left", padx=(12, 6), pady=20)

        # IP Address
        ctk.CTkLabel(self, text=ip, font=(FONT_FAMILY_MONO, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, width=140,
                     anchor="w").pack(side="left", padx=(4, 8))

        # Device name
        ctk.CTkLabel(self, text=name, font=(FONT_FAMILY, FONT_SIZE_BODY),
                     text_color=TEXT_PRIMARY, anchor="w").pack(
            side="left", fill="x", expand=True, padx=(4, 8))

        # Device type badge
        if device_type and device_type != "Unknown":
            type_label = ctk.CTkLabel(
                self, text=device_type, font=(FONT_FAMILY, FONT_SIZE_TINY),
                text_color=SAS_BLUE_LIGHT, fg_color=BG_MEDIUM,
                corner_radius=4, height=22,
            )
            type_label.pack(side="left", padx=(4, 8), pady=16)

        # Ping time
        if ping_ms > 0:
            ping_color = STATUS_GOOD if ping_ms < 10 else (STATUS_WARN if ping_ms < 50 else STATUS_ERROR)
            ctk.CTkLabel(self, text=f"{ping_ms:.0f}ms",
                         font=(FONT_FAMILY_MONO, FONT_SIZE_SMALL),
                         text_color=ping_color, width=60,
                         anchor="e").pack(side="right", padx=(4, 12))

        # Arrow indicator
        ctk.CTkLabel(self, text="›", font=(FONT_FAMILY, 20),
                     text_color=TEXT_MUTED).pack(side="right", padx=(0, 8))

        # Bind click to entire frame
        self.bind("<Button-1>", self._handle_click)
        for child in self.winfo_children():
            child.bind("<Button-1>", self._handle_click)

        # Hover effect
        self.bind("<Enter>", lambda e: self.configure(fg_color=BG_CARD_HOVER))
        self.bind("<Leave>", lambda e: self.configure(fg_color=BG_CARD))

    def _handle_click(self, event=None):
        if self._on_click:
            self._on_click()


class ScanProgressBar(ctk.CTkFrame):
    """A branded progress bar with status text."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self._status_label = ctk.CTkLabel(
            self, text="Ready to scan", font=(FONT_FAMILY, FONT_SIZE_SMALL),
            text_color=TEXT_SECONDARY, anchor="w",
        )
        self._status_label.pack(fill="x", pady=(0, 4))

        self._progress = ctk.CTkProgressBar(
            self, fg_color=BG_INPUT, progress_color=SAS_BLUE,
            height=6, corner_radius=3,
        )
        self._progress.pack(fill="x")
        self._progress.set(0)

    def update_progress(self, value: float, status: str = ""):
        self._progress.set(value)
        if status:
            self._status_label.configure(text=status)

    def set_complete(self, message: str = "Scan complete"):
        self._progress.set(1.0)
        self._status_label.configure(text=message, text_color=STATUS_GOOD)

    def reset(self):
        self._progress.set(0)
        self._status_label.configure(text="Ready to scan", text_color=TEXT_SECONDARY)


# ── Touch Scroll Support ────────────────────────────────────────────────────

def enable_touch_scroll(scrollable_frame: ctk.CTkScrollableFrame):
    """
    Enable touch-drag-to-scroll on a CTkScrollableFrame.

    On touchscreen devices, users expect to drag content to scroll.
    CTkScrollableFrame only supports mouse wheel by default.
    This adds press-and-drag scrolling on the underlying canvas.
    """
    try:
        canvas = scrollable_frame._parent_canvas
    except AttributeError:
        return  # Not a standard CTkScrollableFrame

    state = {"y": 0, "scrolling": False}

    def _on_press(event):
        state["y"] = event.y_root
        state["scrolling"] = False

    def _on_motion(event):
        dy = state["y"] - event.y_root
        if abs(dy) > 3:  # Dead zone to avoid accidental scrolls
            state["scrolling"] = True
            canvas.yview_scroll(int(dy), "units")
            state["y"] = event.y_root

    def _bind_recursive(widget):
        """Bind touch events to widget and all children."""
        widget.bind("<ButtonPress-1>", _on_press, add="+")
        widget.bind("<B1-Motion>", _on_motion, add="+")
        for child in widget.winfo_children():
            _bind_recursive(child)

    # Bind to canvas and its internal frame
    canvas.bind("<ButtonPress-1>", _on_press, add="+")
    canvas.bind("<B1-Motion>", _on_motion, add="+")

    # Also bind to the inner frame that holds the content
    try:
        inner = scrollable_frame._scrollable_frame or scrollable_frame
        inner.bind("<ButtonPress-1>", _on_press, add="+")
        inner.bind("<B1-Motion>", _on_motion, add="+")
    except AttributeError:
        pass

    # Re-bind whenever new children are added (deferred)
    def _rebind_children(event=None):
        try:
            inner_frame = scrollable_frame._scrollable_frame or scrollable_frame
            _bind_recursive(inner_frame)
        except Exception:
            pass

    # Rebind periodically when content changes (after pack/grid operations)
    scrollable_frame.bind("<Configure>", _rebind_children, add="+")
