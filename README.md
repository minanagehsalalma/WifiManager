# WifiManager

A minimal Python application for Windows 11 that enumerates nearby Wi‑Fi networks (including hidden ones) using the built‑in `netsh` command. The GUI allows you to refresh the list, connect or disconnect, assign friendly names to hidden networks, and view extra details about each access point.

## Features
* Scans each interface using `netsh wlan show networks mode=bssid` so all nearby networks are listed, not just the one currently connected.
* Lists each BSSID separately so you can see every access point, even if multiple share the same SSID.
* Displays hidden networks and lets you associate a friendly name with them (stored in `aliases.json`).
* Shows signal percentage, estimated RSSI, channel, authentication, encryption, and MAC vendor for each BSSID (cached in `vendors.json`).
* Highlights the currently connected network.
* Networks with saved Windows profiles are highlighted in light green, and entries with your custom names are tagged.
* Connects or disconnects via `netsh wlan connect` / `netsh wlan disconnect`.
* Simple PyQt5 interface styled with the Fusion theme for a modern look.

## Requirements
* Windows 11
* Python 3.8+
* [PyQt5](https://pypi.org/project/PyQt5/) (`pip install pyqt5`)
* [Requests](https://pypi.org/project/requests/) (`pip install requests`)

## Usage
```bash
python wifi_manager.py
```
> Only connect to networks you are authorised to use.

## Notes
* Hidden networks require you to know the actual SSID before connecting.
* Network profiles and passwords are managed by Windows; this tool simply invokes `netsh` commands.
