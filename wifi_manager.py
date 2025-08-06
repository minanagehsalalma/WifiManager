import json
import os
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import requests
from PyQt5 import QtCore, QtGui, QtWidgets

ALIASES_FILE = "aliases.json"
VENDORS_FILE = "vendors.json"


def load_aliases() -> dict:
    if os.path.exists(ALIASES_FILE):
        with open(ALIASES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
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


def scan_networks() -> List[WiFiNetwork]:
    """Use netsh to scan Wi-Fi networks on all interfaces."""
    networks: List[WiFiNetwork] = []
    seen: set[str] = set()

    interfaces = list_interfaces() or [None]
    for iface in interfaces:
        cmd = ["netsh", "wlan", "show", "networks"]
        if iface:
            cmd.append(f"interface={iface}")
        cmd.append("mode=bssid")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
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
            elif line.startswith("Authentication"):
                auth = line.partition(":")[2].strip()
            elif line.startswith("Encryption"):
                encryption = line.partition(":")[2].strip()
            elif line.startswith("BSSID"):
                bssid = line.partition(":")[2].strip()
                if bssid.lower() in seen:
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
                networks.append(current)
                seen.add(bssid.lower())
            elif current is not None and line.startswith("Signal"):
                signal = line.partition(":")[2].strip()
                current.signal = signal
                try:
                    pct = int(signal.strip().strip("%"))
                    current.rssi = f"{pct / 2 - 100:.0f} dBm"
                except ValueError:
                    current.rssi = None
            elif current is not None and line.startswith("Channel"):
                current.channel = line.partition(":")[2].strip()

    vendors = load_vendors()
    for net in networks:
        if net.bssid:
            prefix = net.bssid[:8].upper()
            vendor = vendors.get(prefix)
            if vendor is None:
                try:
                    resp = requests.get(
                        f"https://api.macvendors.com/{net.bssid}", timeout=5
                    )
                    if resp.status_code == 200:
                        vendor = resp.text.strip()
                        vendors[prefix] = vendor
                        save_vendors(vendors)
                except Exception:
                    vendor = ""
            net.vendor = vendor

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


def current_connection() -> Optional[str]:
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("BSSID"):
            return line.partition(":")[2].strip()
    return None


class WifiManagerApp(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WiFi Manager")
        self.resize(800, 400)
        QtWidgets.QApplication.setStyle("Fusion")

        self.aliases = load_aliases()

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
        self.networks = scan_networks()
        profiles = saved_profiles()
        connected = current_connection()

        self.table.setRowCount(len(self.networks))
        for row, net in enumerate(self.networks):
            alias = self.aliases.get(net.bssid or "", None)
            display = alias or (net.ssid if net.ssid else "Hidden")
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(display))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(net.bssid or ""))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(net.signal or ""))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(net.rssi or ""))
            self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(net.channel or ""))
            self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(net.vendor or ""))
            self.table.setItem(row, 6, QtWidgets.QTableWidgetItem(net.auth or ""))
            self.table.setItem(row, 7, QtWidgets.QTableWidgetItem(net.encryption or ""))
            saved = (net.ssid and net.ssid in profiles) or (
                alias and alias in profiles
            )
            user_flag = "Yes" if (
                (net.bssid and net.bssid in self.aliases)
                or (not net.bssid and net.ssid in self.aliases.values())
            ) else ""
            self.table.setItem(row, 8, QtWidgets.QTableWidgetItem("Yes" if saved else ""))
            self.table.setItem(row, 9, QtWidgets.QTableWidgetItem(user_flag))
            if saved:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item is not None:
                        item.setBackground(QtGui.QColor(200, 255, 200))
            if net.bssid and connected and net.bssid.lower() == connected.lower():
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item is not None:
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)

        self.table.resizeColumnsToContents()

    def current_network(self) -> Optional[WiFiNetwork]:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.networks):
            return None
        return self.networks[row]

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
        self.aliases[net.bssid] = alias
        save_aliases(self.aliases)
        self.refresh_networks()


def main() -> None:
    app = QtWidgets.QApplication([])
    window = WifiManagerApp()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
