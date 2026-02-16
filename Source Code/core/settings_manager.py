"""
SAS Network Diagnostics Tool — Settings Manager
Persists user settings to a JSON file in the user's AppData folder.

Handles:
  - Theme (dark / light)
  - Hidden network adapters (by adapter name)
  - Custom subnet ranges for Device Finder
  - Window geometry
"""

import json
import logging
import os
import platform
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Default settings
_DEFAULTS: Dict[str, Any] = {
    "theme": "dark",                   # "dark" or "light"
    "hidden_adapters": [],             # List of adapter names to hide
    "custom_subnets": [],              # Saved custom subnet ranges
    "window_geometry": "",             # e.g. "1280x800+100+50"
}


def _settings_dir() -> str:
    """Get the platform-appropriate settings directory."""
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(base, "SAS NetDiag")
    elif platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/SAS NetDiag")
    else:
        return os.path.expanduser("~/.config/sas-netdiag")


def _settings_path() -> str:
    return os.path.join(_settings_dir(), "settings.json")


class SettingsManager:
    """Singleton-style settings manager with JSON persistence."""

    def __init__(self):
        self._data: Dict[str, Any] = dict(_DEFAULTS)
        self._path = _settings_path()
        self._load()

    # ── Core I/O ──────────────────────────────────────────────────────────

    def _load(self):
        """Load settings from disk, falling back to defaults."""
        try:
            if os.path.exists(self._path):
                with open(self._path, "r", encoding="utf-8") as f:
                    stored = json.load(f)
                # Merge with defaults (so new keys get default values)
                for key, default in _DEFAULTS.items():
                    self._data[key] = stored.get(key, default)
                logger.info(f"Settings loaded from {self._path}")
            else:
                logger.info("No settings file found — using defaults")
        except Exception as e:
            logger.warning(f"Failed to load settings: {e}")

    def save(self):
        """Persist current settings to disk."""
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            logger.info(f"Settings saved to {self._path}")
        except Exception as e:
            logger.warning(f"Failed to save settings: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any):
        self._data[key] = value

    # ── Theme ─────────────────────────────────────────────────────────────

    @property
    def theme(self) -> str:
        return self._data.get("theme", "dark")

    @theme.setter
    def theme(self, value: str):
        self._data["theme"] = value

    # ── Adapter Filtering ─────────────────────────────────────────────────

    @property
    def hidden_adapters(self) -> Set[str]:
        """Set of adapter names that should be hidden from dropdowns."""
        return set(self._data.get("hidden_adapters", []))

    def set_adapter_hidden(self, adapter_name: str, hidden: bool):
        """Show or hide an adapter."""
        adapters = set(self._data.get("hidden_adapters", []))
        if hidden:
            adapters.add(adapter_name)
        else:
            adapters.discard(adapter_name)
        self._data["hidden_adapters"] = sorted(adapters)

    def is_adapter_hidden(self, adapter_name: str) -> bool:
        return adapter_name in self.hidden_adapters

    def filter_interfaces(self, interfaces: list) -> list:
        """Filter a list of NetworkInterface objects based on hidden adapters."""
        hidden = self.hidden_adapters
        if not hidden:
            return interfaces
        return [iface for iface in interfaces if iface.name not in hidden]

    # ── Custom Subnets ────────────────────────────────────────────────────

    @property
    def custom_subnets(self) -> List[str]:
        return self._data.get("custom_subnets", [])

    @custom_subnets.setter
    def custom_subnets(self, value: List[str]):
        self._data["custom_subnets"] = value


# Module-level singleton
_instance: Optional[SettingsManager] = None


def get_settings() -> SettingsManager:
    """Get the global settings manager instance."""
    global _instance
    if _instance is None:
        _instance = SettingsManager()
    return _instance
