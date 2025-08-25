
# Firewall GUI

A simple GUI-based firewall management tool built with Python and Tkinter.
Supports nftables (modern Linux firewall) and falls back to iptables if nft is unavailable.


# ✨ Features


✅ Auto-detects firewall backend (nftables preferred, iptables fallback).

✅ Block/allow custom TCP ports (inbound & outbound).

✅ Block/allow domains (resolves all IPv4 addresses).

✅ Block/allow IP addresses.

✅ View current firewall rules in a table view.

✅ Delete rules directly from the GUI.

✅ Set default policy (ACCEPT or DROP) per chain.

✅ Reset firewall rules safely.

✅ Export and Import rulesets.

✅ Logging of all actions to firewall_log.txt.


## 📦 Requirements

Python 3

Tkinter (usually pre-installed with Python)

Linux system with nftables (v1.0+ installed by default on Kali, Ubuntu ≥20.04, Parrot OS)

Root privileges (must be run as sudo)


# 🚀 Installation

1-Clone the repository:

```bash
git clone https://github.com/Omar-bytee/firewall-gui.git
cd firewall-gui

```
2-Install dependencies (make sure nftables is available on your system):

```bash
sudo apt update
sudo apt install nftables

```

3-Run the program (must be root):

```bash
sudo python3 firewall_gui.py

```
## ▶️ Usage

```bash
sudo python3 firewall_gui.py
```


## 🛠 Example Workflow

1- Block a Port → Enter 80 → TCP port 80 (HTTP) is blocked

2- Verify:

```bash
sudo nft list ruleset
```
3- Test:

```bash
curl http://example.com #Connection should fail.
```
4- Allow the Port again → restores HTTP access.
## ⚠️ Notes

Domain blocking: implemented by resolving domains to IP addresses. If a domain uses many IPs (e.g., Google, YouTube), only the resolved IPs are blocked. For stronger DNS-level blocking, consider using /etc/hosts or dnsmasq.

Persistence: Rules added via GUI are not persistent across reboots unless you Export Rules and load them manually (or via systemd service).

Root required: Must run as root (sudo).


## 📤 Export & Import Rules

✅ Export rules:

```bash
# via GUI (choose a filename)
# or manually
sudo nft list ruleset > rules.nft

```

✅ Import rules:

```bash
sudo nft -f rules.nft

```