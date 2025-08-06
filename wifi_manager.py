import json
import os
import subprocess
import time
import string
from dataclasses import dataclass
from typing import List, Optional

# Third-party
import requests
from PyQt5 import QtCore, QtGui, QtWidgets

# ---- Windows Native Wi-Fi (WlanAPI) via ctypes
import ctypes
from ctypes import wintypes

# Some Python builds don't define wintypes.ULONGLONG
ULONGLONG = ctypes.c_ulonglong

ALIASES_FILE = "aliases.json"
VENDORS_FILE = "vendors.json"


def load_aliases() -> dict:
    if os.path.exists(ALIASES_FILE):
        with open(ALIASES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {normalize_bssid(k): v for k, v in data.items()}
    return {}


def save_aliases(aliases: dict) -> None:
    with open(ALIASES_FILE, "w", encoding="utf-8") as f:
        json.dump(aliases, f, indent=2)


def load_vendors() -> dict:
    if os.path.exists(VENDORS_FILE):
        with open(VENDORS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_vendors(vendors: dict) -> None:
    with open(VENDORS_FILE, "w", encoding="utf-8") as f:
        json.dump(vendors, f, indent=2)


def normalize_bssid(bssid: Optional[str]) -> str:
    """Return a canonical lower-case BSSID string using colons."""
    if not bssid:
        return ""
    return bssid.strip().replace("-", ":").lower()


@dataclass
class WiFiNetwork:
    ssid: Optional[str]
    bssid: Optional[str]
    signal: Optional[str]
    rssi: Optional[str]
    channel: Optional[str]
    vendor: Optional[str]
    auth: Optional[str]
    encryption: Optional[str]


# =======================================================================================
# Native Wi-Fi helpers (stable channel numbers like WifiInfoView)
# =======================================================================================

# GUID
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


# DOT11_SSID
DOT11_SSID_MAX_LENGTH = 32
class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", wintypes.BYTE * DOT11_SSID_MAX_LENGTH),
    ]


# WLAN_INTERFACE_STATE (enum, storage only)
WLAN_INTERFACE_STATE = wintypes.DWORD


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", wintypes.WCHAR * 256),
        ("isState", WLAN_INTERFACE_STATE),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),  # flexible array header
    ]


class DOT11_MAC_ADDRESS(ctypes.Structure):
    _fields_ = [("ucDot11MacAddress", wintypes.BYTE * 6)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", DOT11_MAC_ADDRESS),
        ("dot11BssType", wintypes.DWORD),
        ("dot11BssPhyType", wintypes.DWORD),
        ("lRssi", wintypes.LONG),
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", wintypes.BOOL),
        ("usBeaconPeriod", wintypes.USHORT),
        ("ullTimestamp", ULONGLONG),
        ("ullHostTimestamp", ULONGLONG),
        ("usCapabilityInformation", wintypes.USHORT),
        ("ulChCenterFrequency", wintypes.ULONG),  # kHz
        ("wlanRateSet", wintypes.BYTE * 126),
        ("ulIeOffset", wintypes.ULONG),
        ("ulIeSize", wintypes.ULONG),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),
        ("dwNumberOfItems", wintypes.DWORD),
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1),  # flexible array header
    ]


# Load wlanapi
try:
    wlanapi = ctypes.WinDLL("wlanapi")
except OSError:
    wlanapi = None  # fallback will be used


# Declare prototypes (0 == NO_ERROR)
if wlanapi is not None:
    WlanOpenHandle = wlanapi.WlanOpenHandle
    WlanOpenHandle.argtypes = [wintypes.DWORD, wintypes.LPVOID,
                               ctypes.POINTER(wintypes.DWORD),
                               ctypes.POINTER(wintypes.HANDLE)]
    WlanOpenHandle.restype = wintypes.DWORD

    WlanCloseHandle = wlanapi.WlanCloseHandle
    WlanCloseHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    WlanCloseHandle.restype = wintypes.DWORD

    WlanEnumInterfaces = wlanapi.WlanEnumInterfaces
    WlanEnumInterfaces.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                   ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST))]
    WlanEnumInterfaces.restype = wintypes.DWORD

    WlanScan = wlanapi.WlanScan
    WlanScan.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID),
                         wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID]
    WlanScan.restype = wintypes.DWORD

    WlanGetNetworkBssList = wlanapi.WlanGetNetworkBssList
    WlanGetNetworkBssList.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID),
                                      ctypes.POINTER(DOT11_SSID), wintypes.DWORD,
                                      wintypes.BOOL, wintypes.LPVOID,
                                      ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST))]
    WlanGetNetworkBssList.restype = wintypes.DWORD

    WlanFreeMemory = wlanapi.WlanFreeMemory
    WlanFreeMemory.argtypes = [wintypes.LPVOID]
    WlanFreeMemory.restype = None


# Channel validation sets
_VALID_24 = set(range(1, 14 + 1))
_VALID_5 = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
}


def _freq_to_channel(freq_khz: int) -> int:
    """Convert center frequency (kHz) to IEEE channel number with sanity checks."""
    f = int(round(freq_khz / 1000.0))  # MHz
    # 2.4 GHz
    if 2412 <= f <= 2472:
        ch = round((f - 2407) / 5)
        return int(ch) if ch in _VALID_24 else 0
    if f == 2484:
        return 14
    # 5 GHz
    if 5150 <= f <= 5925:
        ch = round((f - 5000) / 5)
        return int(ch) if ch in _VALID_5 else 0
    # 6 GHz
    if 5955 <= f <= 7115:
        ch = int(round((f - 5950) / 5))
        return ch if 1 <= ch <= 233 else 0
    return 0


def _bytes_to_bssid(mac_bytes: DOT11_MAC_ADDRESS) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes.ucDot11MacAddress)


_PRINTABLE = set(string.printable)


def _clean_ssid(raw: bytes) -> Optional[str]:
    """Decode SSID bytes, remove control chars; return None if mostly garbage/empty."""
    s = raw.decode("utf-8", errors="ignore").strip()
    if not s:
        return None
    bad = sum(1 for ch in s if ch not in _PRINTABLE or ord(ch) < 32)
    return None if bad > max(1, int(0.2 * len(s))) else s


def _ssid_bytes_to_str(dot11: DOT11_SSID) -> Optional[str]:
    return _clean_ssid(bytes(dot11.ucSSID[:dot11.uSSIDLength]))


def _is_valid_bssid(bssid: str) -> bool:
    if not bssid:
        return False
    if bssid in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return False
    return True


def _is_valid_channel(channel_str: str) -> bool:
    """Check if a channel string represents a valid WiFi channel number."""
    if not channel_str or not channel_str.strip().isdigit():
        return False
    
    chan = int(channel_str.strip())
    # Valid 2.4 GHz channels: 1-14
    if chan in {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}:
        return True
    # Valid 5 GHz channels (common ones)
    if chan in {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}:
        return True
    
    # Don't accept anything else for now
    return False


def _valid_for_display(n: 'WiFiNetwork') -> bool:
    # Must have a valid BSSID and a non-empty channel (stable view)
    b = normalize_bssid(n.bssid or '')
    if not _is_valid_bssid(b):
        return False
    if not _is_valid_channel(n.channel or ''):
        return False
    # Must have either signal or RSSI data
    if not (n.signal or n.rssi):
        return False
    return True

def _scan_native() -> List[WiFiNetwork]:
    """Scan via WlanAPI and return stable channel numbers (center frequency)."""
    if wlanapi is None:
        return []
    networks: List[WiFiNetwork] = []

    client = wintypes.HANDLE()
    negotiated = wintypes.DWORD(0)
    if WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(client)) != 0:
        return []

    try:
        p_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if WlanEnumInterfaces(client, None, ctypes.byref(p_list)) != 0 or not p_list:
            return []

        try:
            count = p_list.contents.dwNumberOfItems
            base_addr = ctypes.addressof(p_list.contents)
            header_size = ctypes.sizeof(WLAN_INTERFACE_INFO_LIST) - ctypes.sizeof(WLAN_INTERFACE_INFO)
            for i in range(count):
                iface_ptr = ctypes.cast(
                    base_addr + header_size + i * ctypes.sizeof(WLAN_INTERFACE_INFO),
                    ctypes.POINTER(WLAN_INTERFACE_INFO)
                )
                iface = iface_ptr.contents

                # Fresh scan + small settle delay
                WlanScan(client, ctypes.byref(iface.InterfaceGuid), None, None, None)
                time.sleep(0.35)

                pbss = ctypes.POINTER(WLAN_BSS_LIST)()
                rc = WlanGetNetworkBssList(client, ctypes.byref(iface.InterfaceGuid),
                                           None, 0, False, None, ctypes.byref(pbss))
                if rc != 0 or not pbss:
                    continue

                try:
                    n_items = pbss.contents.dwNumberOfItems
                    bss_base = ctypes.addressof(pbss.contents)
                    bss_header = ctypes.sizeof(WLAN_BSS_LIST) - ctypes.sizeof(WLAN_BSS_ENTRY)
                    for j in range(n_items):
                        entry_ptr = ctypes.cast(
                            bss_base + bss_header + j * ctypes.sizeof(WLAN_BSS_ENTRY),
                            ctypes.POINTER(WLAN_BSS_ENTRY)
                        )
                        entry = entry_ptr.contents
                        ssid = _ssid_bytes_to_str(entry.dot11Ssid)
                        bssid = normalize_bssid(_bytes_to_bssid(entry.dot11Bssid))
                        if not _is_valid_bssid(bssid) or entry.ulChCenterFrequency == 0:
                            continue

                        chan = _freq_to_channel(entry.ulChCenterFrequency)
                        signal_pct = entry.uLinkQuality
                        rssi_dbm = entry.lRssi

                        networks.append(WiFiNetwork(
                            ssid=ssid,
                            bssid=bssid,
                            signal=(f"{signal_pct}%" if signal_pct else None),
                            rssi=(f"{rssi_dbm} dBm" if rssi_dbm != 0 else None),
                            channel=(str(chan) if chan else None),
                            vendor=None,
                            auth=None,
                            encryption=None,
                        ))
                finally:
                    WlanFreeMemory(pbss)
        finally:
            WlanFreeMemory(p_list)
    finally:
        WlanCloseHandle(client, None)

    # De-dupe by BSSID, keep highest link quality
    best: dict[str, WiFiNetwork] = {}
    for n in networks:
        if not n.bssid:
            continue
        key = n.bssid
        try:
            new_q = int((n.signal or "0").strip("%"))
        except Exception:
            new_q = -1
        if key not in best:
            best[key] = n
        else:
            try:
                old_q = int((best[key].signal or "0").strip("%"))
            except Exception:
                old_q = -1
            if new_q > old_q:
                best[key] = n
    return list(best.values())


# =======================================================================================
# netsh-based helpers (fallback + populate auth/encryption/vendor)
# =======================================================================================

def list_interfaces() -> List[str]:
    """Return Wi-Fi interface names discovered by netsh."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return []

    names: List[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("name"):
            name = line.partition(":")[2].strip()
            if name:
                names.append(name)
    return names


def _scan_netsh() -> List[WiFiNetwork]:
    """Use netsh to scan Wi-Fi networks on all interfaces (legacy path)."""
    networks: List[WiFiNetwork] = []
    seen: set[str] = set()

    interfaces = list_interfaces() or [None]
    for iface in interfaces:
        cmd = ["netsh", "wlan", "show", "networks"]
        if iface:
            cmd.append(f"interface={iface}")
        cmd.append("mode=bssid")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except Exception:
            continue

        ssid: Optional[str] = None
        auth: Optional[str] = None
        encryption: Optional[str] = None
        current: Optional[WiFiNetwork] = None
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("SSID "):
                value = line.partition(":")[2].strip()
                ssid = value if value else None
                auth = None
                encryption = None
                current = None
            elif line.startswith("Authentication"):
                auth = line.partition(":")[2].strip()
            elif line.startswith("Encryption"):
                encryption = line.partition(":")[2].strip()
            elif line.startswith("BSSID"):
                bssid_raw = line.partition(":")[2].strip()
                bssid = normalize_bssid(bssid_raw)
                if bssid in seen or not _is_valid_bssid(bssid):
                    current = None
                    continue
                current = WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=None,
                    rssi=None,
                    channel=None,
                    vendor=None,
                    auth=auth,
                    encryption=encryption,
                )
                # Don't add to networks list yet - wait until we have complete data
                seen.add(bssid)
            elif current is not None and line.startswith("Signal"):
                signal = line.partition(":")[2].strip()
                current.signal = signal
                try:
                    pct = int(signal.strip().strip("%"))
                    current.rssi = f"{pct / 2 - 100:.0f} dBm"
                except ValueError:
                    current.rssi = None
            elif current is not None and line.strip().startswith("Channel") and ":" in line and "Utilization" not in line:
                # Only parse "Channel : XX" lines, not "Channel Utilization" lines
                chan_raw = line.partition(":")[2].strip()
                if chan_raw:
                    current.channel = chan_raw.split(",")[0].split("(")[0].strip()
                else:
                    current.channel = None
                # Now that we have channel info, check if we have enough data to add the network
                if (_is_valid_bssid(current.bssid) and 
                    _is_valid_channel(current.channel or '') and
                    (current.signal or current.rssi)):
                    networks.append(current)
        
        # Handle any remaining current network at the end
        if (current is not None and 
            _is_valid_bssid(current.bssid) and 
            _is_valid_channel(current.channel or '') and
            (current.signal or current.rssi) and
            current.bssid not in [n.bssid for n in networks]):
            networks.append(current)

    return networks


def _merge_native_and_netsh(native: List[WiFiNetwork], legacy: List[WiFiNetwork]) -> List[WiFiNetwork]:
    """Prefer Native values (stable channel & better RSSI), fill auth/encryption from netsh."""
    by_bssid = {n.bssid: n for n in native if n.bssid}
    for l in legacy:
        key = l.bssid
        if not key:
            continue
        if key in by_bssid:
            tgt = by_bssid[key]
            if not tgt.ssid and l.ssid:
                tgt.ssid = l.ssid
            if not tgt.signal and l.signal:
                tgt.signal = l.signal
            if not tgt.rssi and l.rssi:
                tgt.rssi = l.rssi
            # If native channel fails sanity (empty), use netsh one
            if (not tgt.channel or not str(tgt.channel).isdigit()) and l.channel:
                tgt.channel = l.channel
            tgt.auth = l.auth or tgt.auth
            tgt.encryption = l.encryption or tgt.encryption
        else:
            by_bssid[key] = l
    return list(by_bssid.values())


def _dedupe_keep_strongest(items: List[WiFiNetwork]) -> List[WiFiNetwork]:
    best: dict[str, WiFiNetwork] = {}
    for n in items:
        bssid = normalize_bssid(n.bssid)
        if not _is_valid_bssid(bssid):
            continue
        try:
            new_q = int((n.signal or "0").strip("%"))
        except Exception:
            new_q = -1
        if bssid not in best:
            best[bssid] = n
        else:
            old = best[bssid]
            try:
                old_q = int((old.signal or "0").strip("%"))
            except Exception:
                old_q = -1
            if new_q > old_q:
                best[bssid] = n
    return list(best.values())


def scan_networks() -> List[WiFiNetwork]:
    """
    Scan Wi-Fi networks. Prefer Native Wi-Fi (stable channels from center frequency).
    Fall back to netsh when native path fails, and enrich with netsh fields.
    """
    native = _scan_native()
    legacy = _scan_netsh()  # always run to enrich auth/encryption
    networks = _merge_native_and_netsh(native, legacy) if native else legacy
    networks = _dedupe_keep_strongest(networks)
    
    # Apply strict filtering using the same logic as display validation
    valid_networks = []
    for n in networks:
        if _valid_for_display(n):
            valid_networks.append(n)
    networks = valid_networks

    # Set vendor field to empty string for all networks (vendor lookup disabled for performance)
    for net in networks:
        net.vendor = ""

    return networks


def saved_profiles() -> set[str]:
    """Return the set of profile names saved on the system."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return set()

    profiles: set[str] = set()
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("All User Profile") or line.startswith("User Profile"):
            name = line.partition(":")[2].strip()
            if name:
                profiles.add(name)
    return profiles


def current_connections() -> set[str]:
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return set()

    connections: set[str] = set()
    bssid: Optional[str] = None
    connected = False
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            if bssid and connected:
                connections.add(bssid)
            bssid = None
            connected = False
        elif line.startswith("State") and "connected" in line.lower():
            connected = True
        elif line.startswith("BSSID"):
            bssid = normalize_bssid(line.partition(":")[2].strip())

    if bssid and connected:
        connections.add(bssid)

    return connections


class WifiManagerApp(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WiFi Manager")
        self.resize(900, 420)
        QtWidgets.QApplication.setStyle("Fusion")

        self.aliases = load_aliases()
        self.display_networks = []  # Initialize display networks list

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        self.table = QtWidgets.QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            "Name/SSID",
            "BSSID",
            "Signal",
            "RSSI",
            "Channel",
            "Vendor",
            "Auth",
            "Encryption",
            "Saved",
            "User",
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(btn_layout)

        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.connect_btn = QtWidgets.QPushButton("Connect")
        self.disconnect_btn = QtWidgets.QPushButton("Disconnect")
        self.alias_btn = QtWidgets.QPushButton("Add Name")

        for btn in [self.refresh_btn, self.connect_btn, self.disconnect_btn, self.alias_btn]:
            btn_layout.addWidget(btn)

        self.refresh_btn.clicked.connect(self.refresh_networks)
        self.connect_btn.clicked.connect(self.connect_selected)
        self.disconnect_btn.clicked.connect(self.disconnect_current)
        self.alias_btn.clicked.connect(self.add_alias)

        self.refresh_networks()

    # ------------------------------------------------------------------
    def refresh_networks(self) -> None:
        self.refresh_btn.setEnabled(False)
        try:
            self.networks = scan_networks()
            profiles = saved_profiles()
            connected_bssids = current_connections()

            # Keep only rows that are valid for the stable table view
            # Double-check filtering here as an extra safeguard
            display = [n for n in self.networks if _valid_for_display(n)]
            
            # Store the display networks for proper indexing
            self.display_networks = display
            self.table.setRowCount(len(display))
            for row, net in enumerate(display):
                alias = self.aliases.get(normalize_bssid(net.bssid or ""), None)
                display_name = alias or (net.ssid if net.ssid else "Hidden")
                self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(display_name))
                self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(net.bssid or ""))

                item = QtWidgets.QTableWidgetItem(net.signal or "")
                if net.signal:
                    try:
                        item.setData(QtCore.Qt.UserRole, int(net.signal.strip().strip("%")))
                    except ValueError:
                        pass
                self.table.setItem(row, 2, item)

                item = QtWidgets.QTableWidgetItem(net.rssi or "")
                if net.rssi:
                    try:
                        item.setData(QtCore.Qt.UserRole, float(net.rssi.split()[0]))
                    except ValueError:
                        pass
                self.table.setItem(row, 3, item)

                item = QtWidgets.QTableWidgetItem(net.channel or "")
                if net.channel:
                    try:
                        item.setData(QtCore.Qt.UserRole, int(str(net.channel).split()[0]))
                    except ValueError:
                        pass
                self.table.setItem(row, 4, item)

                self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(net.vendor or ""))
                self.table.setItem(row, 6, QtWidgets.QTableWidgetItem(net.auth or ""))
                self.table.setItem(row, 7, QtWidgets.QTableWidgetItem(net.encryption or ""))

                saved = (net.ssid and net.ssid in profiles) or (alias and alias in profiles)
                user = (
                    (net.bssid and normalize_bssid(net.bssid) in self.aliases)
                    or (not net.bssid and net.ssid in self.aliases.values())
                )
                user_flag = "Yes" if user else ""
                self.table.setItem(row, 8, QtWidgets.QTableWidgetItem("Yes" if saved else ""))
                self.table.setItem(row, 9, QtWidgets.QTableWidgetItem(user_flag))

                is_connected = net.bssid and normalize_bssid(net.bssid) in connected_bssids
                if (is_connected and user) or saved:
                    color = QtGui.QColor(200, 255, 200)  # green
                elif user:
                    color = QtGui.QColor(200, 220, 255)  # blue
                else:
                    color = None
                if color is not None:
                    for col in range(self.table.columnCount()):
                        item = self.table.item(row, col)
                        if item is not None:
                            item.setBackground(color)

                if is_connected:
                    for col in range(self.table.columnCount()):
                        item = self.table.item(row, col)
                        if item is not None:
                            font = item.font()
                            font.setBold(True)
                            item.setFont(font)

            self.table.resizeColumnsToContents()
        finally:
            self.refresh_btn.setEnabled(True)

    def current_network(self) -> Optional[WiFiNetwork]:
        row = self.table.currentRow()
        if row < 0 or not hasattr(self, 'display_networks') or row >= len(self.display_networks):
            return None
        return self.display_networks[row]

    def connect_selected(self) -> None:
        net = self.current_network()
        if net is None:
            return
        ssid = net.ssid
        if not ssid:
            ssid, ok = QtWidgets.QInputDialog.getText(
                self, "Connect to Hidden Network", "SSID:")
            if not ok or not ssid:
                return
        profile, ok = QtWidgets.QInputDialog.getText(
            self, "Profile Name", "Profile name:", text=ssid)
        if not ok or not profile:
            return
        subprocess.run(["netsh", "wlan", "connect", f"name={profile}", f"ssid={ssid}"])

    def disconnect_current(self) -> None:
        subprocess.run(["netsh", "wlan", "disconnect"])

    def add_alias(self) -> None:
        net = self.current_network()
        if net is None or not net.bssid:
            return
        alias, ok = QtWidgets.QInputDialog.getText(self, "Add Name", "Friendly name:")
        if not ok or not alias:
            return
        self.aliases[normalize_bssid(net.bssid)] = alias
        save_aliases(self.aliases)
        self.refresh_networks()


def main() -> None:
    app = QtWidgets.QApplication([])
    window = WifiManagerApp()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
