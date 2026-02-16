"""
SAS Network Diagnostics Tool — MAC Vendor Database
Comprehensive offline OUI (Organizationally Unique Identifier) lookup table.

This database is baked into the application so it works without internet.
OUI prefixes are the first 3 bytes (6 hex chars) of a MAC address and identify
the manufacturer of the network interface.

Sources: IEEE OUI registry via maclookup.app, verified Feb 2026.
"""

# ─── Master OUI → Vendor Mapping ─────────────────────────────────────────────
# Key = first 3 octets, uppercase, colon-separated (e.g. "00:1D:9C")
# Value = (Vendor Display Name, Category)
#   Category is one of: "automation", "networking", "computing", "other"
#   "automation" = industrial automation / controls equipment
#   "networking" = switches, routers, firewalls, wireless APs
#   "computing"  = PCs, servers, embedded PCs, HMIs
#   "other"      = printers, phones, cameras, IoT, etc.

MAC_VENDOR_DB: dict[str, tuple[str, str]] = {

    # ═══════════════════════════════════════════════════════════════════════════
    # ROCKWELL AUTOMATION / ALLEN-BRADLEY  (13 registered OUIs)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:00:BC": ("Allen-Bradley (Rockwell)", "automation"),
    "00:0A:E4": ("Rockwell Automation", "automation"),
    "00:1D:9C": ("Rockwell Automation", "automation"),
    "08:61:95": ("Rockwell Automation", "automation"),
    "18:4C:08": ("Rockwell Automation", "automation"),
    "34:C0:F9": ("Rockwell Automation", "automation"),
    "40:41:01": ("Rockwell Automation", "automation"),
    "5C:21:67": ("Rockwell Automation", "automation"),
    "5C:88:16": ("Rockwell Automation", "automation"),
    "68:C8:EB": ("Rockwell Automation", "automation"),
    "BC:F4:99": ("Rockwell Automation", "automation"),
    "E4:8E:BB": ("Rockwell Automation", "automation"),
    "E4:90:69": ("Rockwell Automation", "automation"),
    "F4:54:33": ("Rockwell Automation", "automation"),
    # Allen-Bradley legacy (pre-Rockwell)
    "00:20:BD": ("Allen-Bradley (legacy)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SIEMENS AG  (21 registered OUIs — automation + industry)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:01:E3": ("Siemens AG", "automation"),
    "00:0B:A3": ("Siemens AG", "automation"),
    "00:0E:8C": ("Siemens AG", "automation"),
    "00:1B:1B": ("Siemens AG", "automation"),
    "08:00:06": ("Siemens AG", "automation"),
    "10:DF:FC": ("Siemens AG", "automation"),
    "20:87:56": ("Siemens AG", "automation"),
    "20:A8:B9": ("Siemens AG", "automation"),
    "28:63:36": ("Siemens AG", "automation"),
    "30:2F:1E": ("Siemens AG", "automation"),
    "30:B8:51": ("Siemens AG", "automation"),
    "38:4B:24": ("Siemens AG", "automation"),
    "40:EC:F8": ("Siemens AG", "automation"),
    "74:FC:45": ("Siemens AG", "automation"),
    "88:3F:99": ("Siemens AG", "automation"),
    "A8:6D:04": ("Siemens AG", "automation"),
    "AC:64:17": ("Siemens AG", "automation"),
    "D4:F5:27": ("Siemens AG", "automation"),
    "EC:1C:5D": ("Siemens AG", "automation"),
    # Siemens Industrial Automation (SIMATIC-specific registrations)
    "00:50:E2": ("Siemens (SIMATIC)", "automation"),
    "4C:EB:42": ("Siemens AG", "automation"),
    "6C:3B:E5": ("Siemens AG", "automation"),
    "98:80:BB": ("Siemens AG", "automation"),
    "A0:B5:DA": ("Siemens AG", "automation"),
    "E0:DC:A0": ("Siemens AG", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SCHNEIDER ELECTRIC / MODICON / TELEMECANIQUE  (6 + legacy)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:00:54": ("Schneider Electric", "automation"),
    "00:00:6C": ("Schneider Electric", "automation"),
    "00:04:17": ("Schneider Electric", "automation"),
    "00:11:00": ("Schneider Electric", "automation"),
    "9C:0E:51": ("Schneider Electric", "automation"),
    # APC by Schneider Electric (UPS, power)
    "28:29:86": ("APC (Schneider Electric)", "automation"),
    # Schneider / Modicon legacy
    "00:80:F4": ("Telemecanique (Schneider)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WAGO
    # ═══════════════════════════════════════════════════════════════════════════
    "00:30:DE": ("WAGO", "automation"),
    "00:C0:6F": ("WAGO", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PHOENIX CONTACT
    # ═══════════════════════════════════════════════════════════════════════════
    "00:A0:45": ("Phoenix Contact", "automation"),
    "D0:93:95": ("Phoenix Contact", "automation"),
    "0C:7B:C8": ("Phoenix Contact", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # BECKHOFF AUTOMATION
    # ═══════════════════════════════════════════════════════════════════════════
    "00:01:05": ("Beckhoff Automation", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TURCK
    # ═══════════════════════════════════════════════════════════════════════════
    "00:07:46": ("Turck", "automation"),
    "84:4B:F5": ("Turck", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ABB
    # ═══════════════════════════════════════════════════════════════════════════
    "00:21:99": ("ABB", "automation"),
    "00:24:AB": ("ABB", "automation"),
    "AC:64:DD": ("ABB", "automation"),
    "B0:90:D4": ("ABB", "automation"),
    "00:15:A8": ("ABB (Baldor)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # HMS INDUSTRIAL NETWORKS (ANYBUS)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:30:11": ("HMS Industrial (Anybus)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # OMRON
    # ═══════════════════════════════════════════════════════════════════════════
    "00:00:74": ("Omron", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # HONEYWELL
    # ═══════════════════════════════════════════════════════════════════════════
    "00:40:84": ("Honeywell", "automation"),
    "B8:2C:A0": ("Honeywell", "automation"),
    "00:1E:C4": ("Honeywell", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # EMERSON / FISHER-ROSEMOUNT / DELTAV
    # ═══════════════════════════════════════════════════════════════════════════
    "00:03:58": ("Emerson (Rosemount)", "automation"),
    "00:01:F4": ("Emerson (Fisher)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # GE AUTOMATION / FANUC / EMERSON (post-acquisition)
    # ═══════════════════════════════════════════════════════════════════════════
    "08:00:1B": ("GE Automation", "automation"),
    "00:10:95": ("GE Fanuc Automation", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MITSUBISHI ELECTRIC
    # ═══════════════════════════════════════════════════════════════════════════
    "00:01:C1": ("Mitsubishi Electric", "automation"),
    "00:80:4C": ("Mitsubishi Electric", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # YASKAWA / MOTOMAN
    # ═══════════════════════════════════════════════════════════════════════════
    "00:05:A6": ("Yaskawa Electric", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KEYENCE
    # ═══════════════════════════════════════════════════════════════════════════
    "00:01:91": ("Keyence", "automation"),
    "00:A0:E7": ("Keyence", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PILZ
    # ═══════════════════════════════════════════════════════════════════════════
    "00:06:03": ("Pilz GmbH", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SICK AG
    # ═══════════════════════════════════════════════════════════════════════════
    "00:06:B9": ("Sick AG", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IFM ELECTRONIC
    # ═══════════════════════════════════════════════════════════════════════════
    "00:01:49": ("IFM Electronic", "automation"),
    "00:0C:01": ("IFM Electronic", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PEPPERL+FUCHS / COMTROL
    # ═══════════════════════════════════════════════════════════════════════════
    "00:C0:4E": ("Pepperl+Fuchs (Comtrol)", "automation"),
    "00:07:BC": ("Pepperl+Fuchs", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # BALLUFF
    # ═══════════════════════════════════════════════════════════════════════════
    "00:07:95": ("Balluff", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ENDRESS+HAUSER
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0F:F5": ("Endress+Hauser", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # BANNER ENGINEERING
    # ═══════════════════════════════════════════════════════════════════════════
    "00:14:DC": ("Banner Engineering", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # RED LION / SIXNET
    # ═══════════════════════════════════════════════════════════════════════════
    "00:06:94": ("Red Lion Controls", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PROSOFT TECHNOLOGY / MOLEX
    # ═══════════════════════════════════════════════════════════════════════════
    "00:04:A3": ("ProSoft Technology", "automation"),
    "CC:3F:1D": ("Molex", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # B&R INDUSTRIAL AUTOMATION (now ABB)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:60:65": ("B&R Industrial Automation", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LENZE
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0C:89": ("Lenze", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DANFOSS
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0D:64": ("Danfoss", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SEW-EURODRIVE
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0A:09": ("SEW-Eurodrive", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # EATON
    # ═══════════════════════════════════════════════════════════════════════════
    "00:1C:B1": ("Eaton", "automation"),
    "00:A0:F8": ("Eaton (Powerware)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # FESTO
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0E:4D": ("Festo", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WEIDMULLER
    # ═══════════════════════════════════════════════════════════════════════════
    "00:12:F2": ("Weidmuller", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # COPA-DATA / ZENON
    # ═══════════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════════
    # INDUSTRIAL NETWORKING — MOXA, ADVANTECH, HIRSCHMANN, BELDEN, STRATIX
    # ═══════════════════════════════════════════════════════════════════════════
    "00:90:E8": ("Moxa", "networking"),
    "00:A0:12": ("Moxa", "networking"),
    "00:0C:DB": ("Advantech", "networking"),
    "00:D0:C9": ("Advantech", "computing"),
    "60:64:05": ("Advantech", "computing"),
    "00:80:63": ("Hirschmann (Belden)", "networking"),
    "EC:E5:55": ("Hirschmann (Belden)", "networking"),
    "00:0C:66": ("Belden", "networking"),
    "00:04:A5": ("Barracuda / Belden", "networking"),
    "00:0E:5C": ("RuggedCom (Siemens)", "networking"),
    "00:17:7B": ("RuggedCom (Siemens)", "networking"),
    "00:80:2D": ("Xylem / Westermo", "networking"),
    "00:07:7C": ("Westermo", "networking"),
    "00:10:E3": ("N-Tron (Red Lion)", "networking"),

    # ═══════════════════════════════════════════════════════════════════════════
    # VFD / DRIVE MANUFACTURERS
    # ═══════════════════════════════════════════════════════════════════════════
    # Many VFDs use OUIs from their parent company (Siemens, ABB, Rockwell).
    # Additional specific ones:
    "00:04:79": ("Baldor Electric (ABB)", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # CISCO (very common on industrial networks — Catalyst, IE series)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:00:0C": ("Cisco Systems", "networking"),
    "00:01:42": ("Cisco Systems", "networking"),
    "00:01:43": ("Cisco Systems", "networking"),
    "00:01:63": ("Cisco Systems", "networking"),
    "00:01:64": ("Cisco Systems", "networking"),
    "00:01:96": ("Cisco Systems", "networking"),
    "00:01:97": ("Cisco Systems", "networking"),
    "00:02:17": ("Cisco Systems", "networking"),
    "00:07:0D": ("Cisco Systems", "networking"),
    "00:0A:B7": ("Cisco Systems", "networking"),
    "00:0A:B8": ("Cisco Systems", "networking"),
    "00:0B:BE": ("Cisco Systems", "networking"),
    "00:0D:65": ("Cisco Systems", "networking"),
    "00:0E:D7": ("Cisco Systems", "networking"),
    "00:11:21": ("Cisco Systems", "networking"),
    "00:12:01": ("Cisco Systems", "networking"),
    "00:13:1A": ("Cisco Systems", "networking"),
    "00:16:46": ("Cisco Systems", "networking"),
    "00:17:94": ("Cisco Systems", "networking"),
    "00:17:95": ("Cisco Systems", "networking"),
    "00:18:B9": ("Cisco Systems", "networking"),
    "00:18:BA": ("Cisco Systems", "networking"),
    "00:19:55": ("Cisco Systems", "networking"),
    "00:1A:2F": ("Cisco Systems", "networking"),
    "00:1A:A1": ("Cisco Systems", "networking"),
    "00:1B:0C": ("Cisco Systems", "networking"),
    "00:1B:0D": ("Cisco Systems", "networking"),
    "00:1C:0E": ("Cisco Systems", "networking"),
    "00:1D:45": ("Cisco Systems", "networking"),
    "00:1D:46": ("Cisco Systems", "networking"),
    "00:1E:49": ("Cisco Systems", "networking"),
    "00:1E:F7": ("Cisco Systems", "networking"),
    "00:21:55": ("Cisco Systems", "networking"),
    "00:22:55": ("Cisco Systems", "networking"),
    "00:23:04": ("Cisco Systems", "networking"),
    "00:25:45": ("Cisco Systems", "networking"),
    "00:26:0A": ("Cisco Systems", "networking"),
    "00:26:0B": ("Cisco Systems", "networking"),
    "00:60:2F": ("Cisco Systems", "networking"),
    "00:60:3E": ("Cisco Systems", "networking"),
    "00:60:70": ("Cisco Systems", "networking"),
    "28:6F:7F": ("Cisco Systems", "networking"),
    "2C:31:24": ("Cisco Systems", "networking"),
    "68:86:A7": ("Cisco Systems", "networking"),
    "70:81:05": ("Cisco Systems", "networking"),
    "C8:00:84": ("Cisco Systems", "networking"),
    "D0:72:DC": ("Cisco Systems", "networking"),
    "F8:C2:88": ("Cisco Systems", "networking"),
    "FC:5B:39": ("Cisco Systems", "networking"),
    "F4:CF:E2": ("Cisco Systems", "networking"),
    "E8:B7:48": ("Cisco Systems", "networking"),

    # ═══════════════════════════════════════════════════════════════════════════
    # HP / HPE / ARUBA  (common managed switches on plant floors)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:08:02": ("HP / HPE", "networking"),
    "00:0B:CD": ("HP / HPE", "networking"),
    "00:10:E3": ("HP / HPE", "networking"),
    "00:11:0A": ("HP / HPE", "networking"),
    "00:11:85": ("HP / HPE", "networking"),
    "00:12:79": ("HP / HPE", "networking"),
    "00:14:38": ("HP / HPE", "networking"),
    "00:15:60": ("HP / HPE", "networking"),
    "00:17:A4": ("HP / HPE", "networking"),
    "00:18:FE": ("HP / HPE", "networking"),
    "00:1A:4B": ("HP / HPE", "networking"),
    "00:1B:78": ("HP / HPE", "networking"),
    "00:1C:C4": ("HP / HPE", "networking"),
    "00:1E:0B": ("HP / HPE", "networking"),
    "00:21:5A": ("HP / HPE", "networking"),
    "00:22:64": ("HP / HPE", "networking"),
    "00:23:7D": ("HP / HPE", "networking"),
    "00:25:B3": ("HP / HPE", "networking"),
    "00:26:55": ("HP / HPE", "networking"),
    "10:60:4B": ("HP / HPE", "networking"),
    "28:80:23": ("HP / HPE", "networking"),
    "2C:27:D7": ("HP / HPE", "networking"),
    "30:8D:99": ("HP / HPE", "networking"),
    "38:63:BB": ("HP / HPE", "networking"),
    "3C:D9:2B": ("HP / HPE", "networking"),
    "58:20:B1": ("HP / HPE", "networking"),
    "70:10:6F": ("HP / HPE", "networking"),
    "80:C1:6E": ("HP / HPE", "networking"),
    "94:57:A5": ("HP / HPE", "networking"),
    "98:E7:F4": ("HP / HPE", "networking"),
    "A0:1D:48": ("HP / HPE", "networking"),
    "A4:5D:36": ("HP / HPE", "networking"),
    "B4:99:BA": ("HP / HPE", "networking"),
    "D8:D3:85": ("HP / HPE", "networking"),
    "EC:B1:D7": ("HP / HPE", "networking"),
    "24:BE:05": ("HP / Aruba", "networking"),
    "00:0B:86": ("Aruba (HPE)", "networking"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NETGEAR (sometimes found as office switches bridged to plant networks)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:09:5B": ("Netgear", "networking"),
    "00:0F:B5": ("Netgear", "networking"),
    "00:14:6C": ("Netgear", "networking"),
    "00:1B:2F": ("Netgear", "networking"),
    "00:1E:2A": ("Netgear", "networking"),
    "00:1F:33": ("Netgear", "networking"),
    "00:22:3F": ("Netgear", "networking"),
    "00:24:B2": ("Netgear", "networking"),
    "00:26:F2": ("Netgear", "networking"),
    "20:E5:2A": ("Netgear", "networking"),
    "28:C6:8E": ("Netgear", "networking"),
    "6C:B0:CE": ("Netgear", "networking"),
    "84:1B:5E": ("Netgear", "networking"),
    "A4:2B:8C": ("Netgear", "networking"),
    "C0:FF:D4": ("Netgear", "networking"),
    "E0:91:F5": ("Netgear", "networking"),
    "E8:FC:AF": ("Netgear", "networking"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DELL (common for HMI PCs / industrial PCs)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:06:5B": ("Dell", "computing"),
    "00:08:74": ("Dell", "computing"),
    "00:0B:DB": ("Dell", "computing"),
    "00:0D:56": ("Dell", "computing"),
    "00:0F:1F": ("Dell", "computing"),
    "00:11:43": ("Dell", "computing"),
    "00:12:3F": ("Dell", "computing"),
    "00:13:72": ("Dell", "computing"),
    "00:14:22": ("Dell", "computing"),
    "00:15:C5": ("Dell", "computing"),
    "00:18:8B": ("Dell", "computing"),
    "00:19:B9": ("Dell", "computing"),
    "00:1A:A0": ("Dell", "computing"),
    "00:1E:C9": ("Dell", "computing"),
    "00:21:70": ("Dell", "computing"),
    "00:22:19": ("Dell", "computing"),
    "00:24:E8": ("Dell", "computing"),
    "00:25:64": ("Dell", "computing"),
    "00:26:B9": ("Dell", "computing"),
    "14:18:77": ("Dell", "computing"),
    "18:03:73": ("Dell", "computing"),
    "24:6E:96": ("Dell", "computing"),
    "34:17:EB": ("Dell", "computing"),
    "44:A8:42": ("Dell", "computing"),
    "B0:83:FE": ("Dell", "computing"),
    "D4:81:D7": ("Dell", "computing"),
    "F0:1F:AF": ("Dell", "computing"),
    "F4:8E:38": ("Dell", "computing"),

    # ═══════════════════════════════════════════════════════════════════════════
    # INTEL (common NIC chipset — often in HMIs, industrial PCs)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:02:B3": ("Intel", "computing"),
    "00:03:47": ("Intel", "computing"),
    "00:07:E9": ("Intel", "computing"),
    "00:0C:F1": ("Intel", "computing"),
    "00:0E:0C": ("Intel", "computing"),
    "00:11:11": ("Intel", "computing"),
    "00:12:F0": ("Intel", "computing"),
    "00:13:02": ("Intel", "computing"),
    "00:13:20": ("Intel", "computing"),
    "00:13:E8": ("Intel", "computing"),
    "00:15:00": ("Intel", "computing"),
    "00:15:17": ("Intel", "computing"),
    "00:16:6F": ("Intel", "computing"),
    "00:16:76": ("Intel", "computing"),
    "00:17:F2": ("Intel", "computing"),
    "00:18:DE": ("Intel", "computing"),
    "00:19:D1": ("Intel", "computing"),
    "00:19:D2": ("Intel", "computing"),
    "00:1B:21": ("Intel", "computing"),
    "00:1B:77": ("Intel", "computing"),
    "00:1C:BF": ("Intel", "computing"),
    "00:1D:E0": ("Intel", "computing"),
    "00:1E:65": ("Intel", "computing"),
    "00:1E:67": ("Intel", "computing"),
    "00:1F:3B": ("Intel", "computing"),
    "00:1F:3C": ("Intel", "computing"),
    "00:22:FA": ("Intel", "computing"),
    "00:24:D7": ("Intel", "computing"),
    "00:27:10": ("Intel", "computing"),
    "3C:97:0E": ("Intel", "computing"),
    "48:51:B7": ("Intel", "computing"),
    "68:05:CA": ("Intel", "computing"),
    "7C:76:35": ("Intel", "computing"),
    "A4:4C:C8": ("Intel", "computing"),
    "B4:96:91": ("Intel", "computing"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LENOVO (industrial PCs, laptops used as HMIs)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:09:2D": ("Lenovo", "computing"),
    "00:06:1B": ("Lenovo (IBM)", "computing"),
    "00:1A:6B": ("Lenovo", "computing"),
    "28:D2:44": ("Lenovo", "computing"),
    "54:EE:75": ("Lenovo", "computing"),
    "E8:2A:44": ("Lenovo", "computing"),

    # ═══════════════════════════════════════════════════════════════════════════
    # APPLE (iPhones/MacBooks sometimes on plant WiFi)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:1E:52": ("Apple", "computing"),
    "00:1F:5B": ("Apple", "computing"),
    "00:25:00": ("Apple", "computing"),
    "00:26:BB": ("Apple", "computing"),
    "3C:07:54": ("Apple", "computing"),
    "40:B3:95": ("Apple", "computing"),
    "60:03:08": ("Apple", "computing"),
    "7C:D1:C3": ("Apple", "computing"),
    "A4:83:E7": ("Apple", "computing"),
    "AC:BC:32": ("Apple", "computing"),
    "D8:30:62": ("Apple", "computing"),
    "F0:18:98": ("Apple", "computing"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TP-LINK / UBIQUITI / OTHER COMMON NETWORK GEAR
    # ═══════════════════════════════════════════════════════════════════════════
    "00:27:19": ("TP-Link", "networking"),
    "14:CF:E2": ("TP-Link", "networking"),
    "50:C7:BF": ("TP-Link", "networking"),
    "60:32:B1": ("TP-Link", "networking"),
    "6C:5A:B0": ("TP-Link", "networking"),
    "EC:08:6B": ("TP-Link", "networking"),
    "F4:F2:6D": ("TP-Link", "networking"),
    "00:15:6D": ("Ubiquiti", "networking"),
    "04:18:D6": ("Ubiquiti", "networking"),
    "24:5A:4C": ("Ubiquiti", "networking"),
    "44:D9:E7": ("Ubiquiti", "networking"),
    "68:D7:9A": ("Ubiquiti", "networking"),
    "78:8A:20": ("Ubiquiti", "networking"),
    "B4:FB:E4": ("Ubiquiti", "networking"),
    "DC:9F:DB": ("Ubiquiti", "networking"),
    "F0:9F:C2": ("Ubiquiti", "networking"),

    # ═══════════════════════════════════════════════════════════════════════════
    # CAMERAS / VISION SYSTEMS (common on inspection networks)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:04:4B": ("Cognex", "automation"),
    "00:80:2D": ("Cognex", "automation"),
    "00:02:4C": ("Basler AG (cameras)", "automation"),
    "00:05:55": ("FLIR Systems", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DATALOGIC / BARCODE
    # ═══════════════════════════════════════════════════════════════════════════
    "00:05:E3": ("Datalogic", "automation"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ZEBRA / MOTOROLA SOLUTIONS (scanners, printers)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:15:70": ("Zebra Technologies", "other"),
    "00:17:B0": ("Zebra Technologies", "other"),
    "00:23:68": ("Zebra Technologies", "other"),
    "00:A0:F8": ("Zebra Technologies", "other"),

    # ═══════════════════════════════════════════════════════════════════════════
    # VMWARE (virtual machines hosting HMI / SCADA servers)
    # ═══════════════════════════════════════════════════════════════════════════
    "00:0C:29": ("VMware", "computing"),
    "00:50:56": ("VMware", "computing"),
    "00:05:69": ("VMware", "computing"),
}


def lookup_vendor(mac_address: str) -> tuple[str, str]:
    """
    Look up the vendor for a MAC address.

    Args:
        mac_address: MAC in any common format (00:1D:9C:AB:CD:EF,
                     00-1D-9C-AB-CD-EF, 001D.9CAB.CDEF, or 001D9CABCDEF)

    Returns:
        (vendor_name, category)  or  ("Unknown", "other") if not found.
    """
    if not mac_address:
        return ("Unknown", "other")

    # Normalize: remove separators, uppercase
    clean = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")

    if len(clean) < 6:
        return ("Unknown", "other")

    # Build the OUI key in colon format
    oui = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"

    result = MAC_VENDOR_DB.get(oui)
    if result:
        return result

    return ("Unknown", "other")


def lookup_vendor_name(mac_address: str) -> str:
    """Convenience: returns just the vendor name string."""
    name, _ = lookup_vendor(mac_address)
    return name


def lookup_vendor_category(mac_address: str) -> str:
    """Convenience: returns just the category string."""
    _, cat = lookup_vendor(mac_address)
    return cat


def get_category_label(category: str) -> str:
    """Human-readable label for a category."""
    labels = {
        "automation": "Industrial Automation",
        "networking": "Network Infrastructure",
        "computing": "Computer / HMI",
        "other": "Other Device",
    }
    return labels.get(category, "Other Device")
