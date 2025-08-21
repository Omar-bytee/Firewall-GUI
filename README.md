Firewall GUI v2

A simple GUI-based firewall management tool built with Python and Tkinter.
Supports nftables (modern Linux firewall) and falls back to iptables if nft is unavailable.

This tool is designed for learning and demonstration purposes (tested on Kali Linux), but it provides real packet filtering capabilities.

✨ Features

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

📦 Requirements

Python 3
Tkinter (usually pre-installed with Python)
Linux system with nftables (v1.0+ installed by default on Kali, Ubuntu ≥20.04, Parrot OS)
Root privileges (must be run as sudo)
----------------------------------------------------------------------------------------------------------------------------------

🚀 Installation

Clone or copy the project folder, then install nftables if not already installed:

sudo apt update
sudo apt install nftables

▶️ Usage

Run the GUI as root:

sudo python3 firewall_gui_v2.py


This will open a window with all available actions.

🛠 Example Workflow

Block a Port → Enter 80 → TCP port 80 (HTTP) is blocked.

Verify:

sudo nft list ruleset


You should see a tcp dport 80 drop rule.

Test:

curl http://example.com


Connection should fail.

Allow the Port again → restores HTTP access.

📂 File Structure
firewall_gui_v2.py     # Main script
blocked_domains.txt    # Stores blocked domains/IPs for reference
firewall_log.txt       # Log file of all firewall actions
README.md              # Project documentation

⚠️ Notes & Limitations

Domain blocking: implemented by resolving domains to IP addresses. If a domain uses many IPs (e.g., Google, YouTube), only the resolved IPs are blocked. For stronger DNS-level blocking, consider using /etc/hosts or dnsmasq.

Persistence: Rules added via GUI are not persistent across reboots unless you Export Rules and load them manually (or via systemd service).

Root required: Must run as root (sudo).

📤 Export & Import Rules

Export rules:

# via GUI (choose a filename)
# or manually
sudo nft list ruleset > rules.nft


Import rules:

sudo nft -f rules.nft