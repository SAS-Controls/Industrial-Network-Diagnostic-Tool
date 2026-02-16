# SAS Network Diagnostics Tool

**v2.5 — Ethernet/IP, DeviceNet & Packet Capture Diagnostics**

A portable Windows application for industrial network troubleshooting. Scans Ethernet/IP and DeviceNet networks, reads device diagnostic counters, captures and analyzes traffic, and presents findings in plain English.

Built for technicians who need to diagnose communication problems without being network engineers.

---

## Quick Start (End User)

1. Copy `SAS-NetDiag.exe` to any Windows 10/11 PC
2. Double-click to run — no installation needed
3. Select your network adapter and click **Scan Network**
4. Click any discovered device to view diagnostics

No Python, no drivers, no admin rights required. Single .exe, fully portable.

---

## Building the Executable

### Prerequisites

- Windows 10 or 11
- Python 3.10 or newer (with pip)
- Internet connection (to download packages)

### Steps

1. **Build the app:**
   ```
   build.bat
   ```

2. The executable is created at `dist\SAS-NetDiag.exe`
3. Copy the .exe to a USB drive — it runs anywhere standalone

### Optional: Packet Capture Support

The Packet Capture feature needs tshark and Npcap. These are **not** required
for the rest of the app — scanning, diagnostics, monitoring all work without them.

To enable capture, place a `tools\` folder **next to** the .exe:
```
SAS-NetDiag.exe
tools\
  tshark\
    tshark.exe    (+ DLLs from Wireshark install)
  npcap-installer.exe
```

Run `setup_tools.bat` in the source folder to set this up automatically,
then copy the `tools\` folder alongside the .exe when deploying.

If no `tools\` folder is present, the app also checks for a system-wide
Wireshark installation automatically.

---

## What It Does

### Network Scanning
- Discovers all devices on the connected subnet via ping sweep
- Identifies EtherNet/IP devices using CIP ListIdentity broadcast
- Shows device vendor, product name, firmware, and serial number
- Detects Allen-Bradley, Siemens, Turck, WAGO, and other industrial devices

### Diagnostic Analysis
- Reads Ethernet Link Object (CIP Class 0xF6) counters from devices
- Runs ping tests to measure response time and packet loss
- Falls back to HTTP web server scraping for devices that don't support CIP reads
- Translates raw counter data into plain-English findings

### What It Checks
- **CRC / Frame Errors** — damaged cables, loose connectors, EMI interference
- **Alignment Errors** — physical layer problems
- **Collisions** — hubs on the network or duplex mismatch
- **Late/Excessive Collisions** — cable too long or serious duplex issues
- **Carrier Sense Errors** — signal detection problems
- **Discarded Packets** — device overloaded
- **Link Speed & Duplex** — warns if running at 10Mbps or Half Duplex
- **Response Time** — flags slow responses that can cause PLC faults
- **Packet Loss** — even 0.1% can cause communication timeouts
- **Traffic Volume** — informational overview

### Health Score
Each device gets a 0–100 health score. Points are deducted for each problem found, weighted by severity. A score of 90+ is healthy, 70–89 has warnings, below 70 has problems that need attention.

### Continuous Monitoring
Click **Start Monitoring** to poll a device every 5 seconds and watch counters update in real time. Useful for catching intermittent problems.

---

## Project Structure

```
sas-netdiag/
├── main.py                Entry point (logging, error handling)
├── app.py                 Main window, sidebar, view management
├── requirements.txt       Python dependencies
├── build.bat              Windows build script
├── setup_tools.bat        Downloads tshark/Npcap for bundling
├── assets/                Logo, icons
├── tools/                 Bundled tools (created by setup_tools.bat)
│   ├── tshark/            tshark + DLLs (from Wireshark)
│   └── npcap-installer.exe
├── core/
│   ├── network_utils.py   Network scanning (ping, ARP, ports)
│   ├── eip_scanner.py     EtherNet/IP CIP device discovery
│   ├── analyzer.py        Diagnostic intelligence engine
│   ├── capture_engine.py  tshark wrapper for packet capture
│   ├── capture_analyzer.py Traffic analysis engine
│   ├── monitor_engine.py  Continuous device monitoring
│   └── settings_manager.py App settings persistence
└── ui/
    ├── theme.py           SAS branding, colors, fonts
    ├── widgets.py         Custom UI components
    ├── scan_view.py       Network scanner interface
    ├── device_view.py     Device detail & diagnostics
    ├── finder_view.py     Device Finder (cross-subnet)
    ├── monitor_view.py    Continuous monitoring
    ├── capture_view.py    Packet capture & analysis
    ├── devicenet_view.py  DeviceNet scanning
    ├── settings_view.py   App settings
    └── help_view.py       Built-in documentation
```

---

## Troubleshooting the Build

**"ModuleNotFoundError: customtkinter"**
→ Run `pip install customtkinter` manually

**"No module named _tkinter"**
→ Reinstall Python with the "tcl/tk" option checked

**Executable is very large (100MB+)**
→ Normal for PyInstaller with CustomTkinter. The --onefile flag bundles everything.

**Antivirus flags the exe**
→ PyInstaller executables are sometimes falsely flagged. Add an exception or sign the exe.

---

## Log Files

Logs are written to: `%USERPROFILE%\.sas-netdiag\netdiag.log`

If the application crashes, send this file to Contact@SASControls.com for support.

---

## Future Phases

- **Phase 2** — ControlNet diagnostics
- **Phase 3** — DeviceNet diagnostics
- **Phase 4** — Modbus TCP/RTU diagnostics

---

*Southern Automation Solutions — 111 Hemlock St. Ste A, Valdosta, GA 31601*
