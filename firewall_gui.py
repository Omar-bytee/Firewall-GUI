import os
import sys
import re
import socket
import time
import shutil
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk

LOG_FILE = "firewall_log.txt"
BACKEND = None  # "nft" or "iptables"

def is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def command_exists(cmd):
    return shutil.which(cmd) is not None

def detect_backend():
    
    if command_exists("nft"):
        return "nft"
    elif command_exists("iptables"):
        return "iptables"
    else:
        return None

def log_action(action, cmd):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as log:
        log.write(f"{timestamp} {action} - Command: {cmd}\n")

def run(cmd, check=True):
    
    try:
        if isinstance(cmd, list):
            subprocess.run(cmd, check=check)
            log_action("EXEC", " ".join(cmd))
        else:
            subprocess.run(cmd, shell=True, check=check)
            log_action("EXEC", cmd)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, str(e)

def resolve_all_ipv4(domain):
    """Resolve as many IPv4 addresses as getaddrinfo can provide."""
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []

# ---------------- Backends ---------------- #

class NftBackend:
    """Manage an nftables 'inet' table named 'gui_fw' with chains 'input' and 'output'."""
    table = "gui_fw"
    family = "inet"
    chain_input = "input"
    chain_output = "output"

    @classmethod
    def ensure_table_and_chains(cls):
        run(["nft", "add", "table", cls.family, cls.table], check=False)
        # Input chain with hook
        run(["nft", "add", "chain", cls.family, cls.table, cls.chain_input, 
             "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"], check=False)
        # Output chain with hook
        run(["nft", "add", "chain", cls.family, cls.table, cls.chain_output, 
             "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"], check=False)

    @classmethod
    def set_policy(cls, chain, policy):
        if chain not in ["INPUT", "OUTPUT"]:
            return False, "Invalid chain"
        c = cls.chain_input if chain == "INPUT" else cls.chain_output
        ok, err = run(["nft", "chain", cls.family, cls.table, c, "{", "policy", policy.lower(), ";", "}"])
        return ok, err

    @classmethod
    def block_port(cls, port, proto="tcp", chain="INPUT"):
        NftBackend.ensure_table_and_chains()
        c = cls.chain_input if chain == "INPUT" else cls.chain_output
        rule = ["nft", "add", "rule", cls.family, cls.table, c, proto, "dport", str(port), "drop"]
        return run(rule)

    @classmethod
    def allow_port(cls, port, proto="tcp", chain="INPUT"):
        NftBackend.ensure_table_and_chains()
        c = cls.chain_input if chain == "INPUT" else cls.chain_output
        rule = ["nft", "add", "rule", cls.family, cls.table, c, proto, "dport", str(port), "accept"]
        return run(rule)

    @classmethod
    def block_ip(cls, ip, chain="INPUT"):
        NftBackend.ensure_table_and_chains()
        c = cls.chain_input if chain == "INPUT" else cls.chain_output
        rule = ["nft", "add", "rule", cls.family, cls.table, c, "ip", "saddr", ip, "drop"]
        return run(rule)

    @classmethod
    def allow_ip(cls, ip, chain="INPUT"):
        NftBackend.ensure_table_and_chains()
        c = cls.chain_input if chain == "INPUT" else cls.chain_output
        rule = ["nft", "add", "rule", cls.family, cls.table, c, "ip", "saddr", ip, "accept"]
        return run(rule)

    @classmethod
    def list_rules(cls):
        
        rules = []
        for chain_name, display_chain in [(cls.chain_input, "INPUT"), (cls.chain_output, "OUTPUT")]:
            ok, _ = NftBackend.ensure_and_list_chain(chain_name)
            if not ok:
                continue
            success, out = NftBackend._capture(["nft", "-a", "list", "chain", cls.family, cls.table, chain_name])
            if not success:
                continue
            for line in out.splitlines():
                m_handle = re.search(r"handle\s+(\d+)", line)
                action = "ACCEPT" if " accept" in line else ("DROP" if " drop" in line else None)
                proto = "tcp" if "tcp dport" in line else ("udp" if "udp dport" in line else "any")
                port_match = re.search(r"(?:tcp|udp)\s+dport\s+(\d+)", line)
                port = port_match.group(1) if port_match else "any"
                src_match = re.search(r"ip\s+saddr\s+([0-9.]+)", line)
                source = src_match.group(1) if src_match else "any"
                if action and m_handle:
                    rules.append({
                        "backend": "nft",
                        "chain": display_chain,
                        "source": source,
                        "proto": proto,
                        "port": port,
                        "action": action,
                        "handle": m_handle.group(1),
                    })
        return rules

    @classmethod
    def _capture(cls, cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            return True, out
        except subprocess.CalledProcessError as e:
            return False, e.output.decode() if hasattr(e, "output") else str(e)

    @classmethod
    def ensure_and_list_chain(cls, chain_name):
        
        NftBackend.ensure_table_and_chains()
        ok, err = run(["nft", "list", "chain", cls.family, cls.table, chain_name], check=False)
        if not ok:
            return False, err
        return True, None

    @classmethod
    def delete_rule_handle(cls, chain, handle):
        chain_name = cls.chain_input if chain == "INPUT" else cls.chain_output
        return run(["nft", "delete", "rule", cls.family, cls.table, chain_name, "handle", str(handle)])

    @classmethod
    def reset(cls):
        
        run(["nft", "flush", "table", cls.family, cls.table], check=False)
        run(["nft", "delete", "table", cls.family, cls.table], check=False)
        return True, None

    @classmethod
    def export_rules(cls, path):
        ok, out = NftBackend._capture(["nft", "list", "ruleset"])
        if not ok:
            return False, "Failed to list ruleset"
        with open(path, "w") as f:
            f.write(out)
        return True, None

    @classmethod
    def import_rules(cls, path):
        return run(["nft", "-f", path])

class IptablesBackend:
    @classmethod
    def set_policy(cls, chain, policy):
        return run(["iptables", "-P", chain, policy.upper()])

    @classmethod
    def block_port(cls, port, proto="tcp", chain="INPUT"):
        return run(["iptables", "-A", chain, "-p", proto, "--dport", str(port), "-j", "DROP"])

    @classmethod
    def allow_port(cls, port, proto="tcp", chain="INPUT"):
        return run(["iptables", "-A", chain, "-p", proto, "--dport", str(port), "-j", "ACCEPT"])

    @classmethod
    def block_ip(cls, ip, chain="INPUT"):
        return run(["iptables", "-A", chain, "-s", ip, "-j", "DROP"])

    @classmethod
    def allow_ip(cls, ip, chain="INPUT"):
        return run(["iptables", "-A", chain, "-s", ip, "-j", "ACCEPT"])

    @classmethod
    def list_rules(cls):
        rules = []
        for chain in ["INPUT", "OUTPUT"]:
            try:
                out = subprocess.check_output(["iptables", "-L", chain, "-n", "-v", "--line-numbers"]).decode()
            except subprocess.CalledProcessError:
                continue
            for line in out.splitlines():
                if "DROP" in line or "ACCEPT" in line:
                    action_match = re.search(r"\b(DROP|ACCEPT)\b", line)
                    action = action_match.group(1) if action_match else "UNKNOWN"

                    proto_match = re.search(r"\b(tcp|udp|icmp|all)\b", line)
                    proto = proto_match.group(1) if proto_match else "any"

                    source_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                    source = source_match.group(1) if source_match else "any"

                    port_match = re.search(r'dpt:(\d+)', line)
                    port = port_match.group(1) if port_match else "any"

                    # Extract rule number for deletion
                    num_match = re.match(r"\s*(\d+)\s", line)
                    lineno = num_match.group(1) if num_match else None

                    rules.append({
                        "backend": "iptables",
                        "chain": chain,
                        "source": source,
                        "proto": proto,
                        "port": port,
                        "action": action,
                        "lineno": lineno
                    })
        return rules

    @classmethod
    def delete_rule_by_number(cls, chain, number):
        return run(["iptables", "-D", chain, str(number)])

    @classmethod
    def reset(cls):
        
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            run(["iptables", "-P", chain, "ACCEPT"], check=False)
            run(["iptables", "-F", chain], check=False)
        return True, None

    @classmethod
    def export_rules(cls, path):
        ok, out = IptablesBackend._capture(["iptables-save"])
        if not ok:
            return False, "iptables-save failed"
        with open(path, "w") as f:
            f.write(out)
        return True, None

    @classmethod
    def import_rules(cls, path):
        return run(["iptables-restore", path])

    @classmethod
    def _capture(cls, cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            return True, out
        except subprocess.CalledProcessError as e:
            return False, e.output.decode() if hasattr(e, "output") else str(e)

# --------------- GUI Actions --------------- #

def ensure_backend():
    global BACKEND
    BACKEND = detect_backend()
    if BACKEND is None:
        messagebox.showerror("Firewall GUI", "Neither nft nor iptables was found on this system.")
        sys.exit(1)
    if BACKEND == "nft":
        NftBackend.ensure_table_and_chains()

def require_root_or_exit():
    if not is_root():
        messagebox.showerror("Firewall GUI", "This tool must be run as root. Try: sudo python3 firewall_gui.py")
        sys.exit(1)

def ui_block_port():
    port = simpledialog.askinteger("Block Port", "Enter TCP port number to block:")
    if not port:
        return
    ensure_backend()
    if BACKEND == "nft":
        ok, err = NftBackend.block_port(port, "tcp", "INPUT")
        ok2, err2 = NftBackend.block_port(port, "tcp", "OUTPUT")
    else:
        ok, err = IptablesBackend.block_port(port, "tcp", "INPUT")
        ok2, err2 = IptablesBackend.block_port(port, "tcp", "OUTPUT")
    if ok and ok2:
        messagebox.showinfo("Success", f"Blocked TCP port {port} (in/out).")
    else:
        messagebox.showerror("Error", f"Failed to block port {port}.\n{err or ''}\n{err2 or ''}")

def ui_allow_port():
    port = simpledialog.askinteger("Allow Port", "Enter TCP port number to allow:")
    if not port:
        return
    ensure_backend()
    if BACKEND == "nft":
        ok, err = NftBackend.allow_port(port, "tcp", "INPUT")
        ok2, err2 = NftBackend.allow_port(port, "tcp", "OUTPUT")
    else:
        ok, err = IptablesBackend.allow_port(port, "tcp", "INPUT")
        ok2, err2 = IptablesBackend.allow_port(port, "tcp", "OUTPUT")
    if ok and ok2:
        messagebox.showinfo("Success", f"Allowed TCP port {port} (in/out).")
    else:
        messagebox.showerror("Error", f"Failed to allow port {port}.\n{err or ''}\n{err2 or ''}")

def clean_domain(domain):
    domain = domain.strip().replace("http://", "").replace("https://", "")
    return domain.strip("/")

def ui_block_domain():
    domain = simpledialog.askstring("Block Domain", "Enter domain to block (e.g., example.com):")
    if not domain:
        return
    domain = clean_domain(domain)
    ips = resolve_all_ipv4(domain)
    if not ips:
        messagebox.showerror("Error", f"Could not resolve any IPv4 for {domain}")
        return
    ensure_backend()
    failed = []
    for ip in ips:
        if BACKEND == "nft":
            ok, err = NftBackend.block_ip(ip, "INPUT")
            ok2, err2 = NftBackend.block_ip(ip, "OUTPUT")
        else:
            ok, err = IptablesBackend.block_ip(ip, "INPUT")
            ok2, err2 = IptablesBackend.block_ip(ip, "OUTPUT")
        if not (ok and ok2):
            failed.append((ip, err or err2 or "unknown error"))
    if failed:
        messagebox.showwarning("Partial", "Some IPs failed to block for {domain}:\n" + "\n".join(f"{ip}: {e}" for ip, e in failed))
    else:
        messagebox.showinfo("Success", f"Blocked domain {domain} ({', '.join(ips)})")
    with open("blocked_domains.txt", "a") as f:
        for ip in ips:
            f.write(f"{domain},{ip},all,any,DROP\n")

def ui_allow_domain():
    domain = simpledialog.askstring("Allow Domain", "Enter domain to allow (e.g., example.com):")
    if not domain:
        return
    domain = clean_domain(domain)
    ips = resolve_all_ipv4(domain)
    if not ips:
        messagebox.showerror("Error", f"Could not resolve any IPv4 for {domain}")
        return
    ensure_backend()
    failed = []
    for ip in ips:
        if BACKEND == "nft":
            ok, err = NftBackend.allow_ip(ip, "INPUT")
            ok2, err2 = NftBackend.allow_ip(ip, "OUTPUT")
        else:
            ok, err = IptablesBackend.allow_ip(ip, "INPUT")
            ok2, err2 = IptablesBackend.allow_ip(ip, "OUTPUT")
        if not (ok and ok2):
            failed.append((ip, err or err2 or "unknown error"))
    if failed:
        messagebox.showwarning("Partial", "Some IPs failed to allow for {domain}:\n" + "\n".join(f"{ip}: {e}" for ip, e in failed))
    else:
        messagebox.showinfo("Success", f"Allowed domain {domain} ({', '.join(ips)})")

def ui_block_ip():
    ip = simpledialog.askstring("Block IP", "Enter IPv4 address to block:")
    if not ip:
        return
    ensure_backend()
    if BACKEND == "nft":
        ok, err = NftBackend.block_ip(ip, "INPUT")
        ok2, err2 = NftBackend.block_ip(ip, "OUTPUT")
    else:
        ok, err = IptablesBackend.block_ip(ip, "INPUT")
        ok2, err2 = IptablesBackend.block_ip(ip, "OUTPUT")
    if ok and ok2:
        messagebox.showinfo("Success", f"Blocked IP {ip} (in/out).")
    else:
        messagebox.showerror("Error", f"Failed to block IP {ip}.\n{err or ''}\n{err2 or ''}")

def ui_view_rules():
    ensure_backend()
    window_table = tk.Toplevel()
    window_table.title(f"Firewall Rules ({BACKEND})")

    ttk.Label(window_table, text=f"Firewall Rules — {BACKEND}", font=("Arial", 12, "bold")).pack(pady=10)

    table = ttk.Treeview(window_table, columns=("Chain", "Source", "Protocol", "Port", "Action", "Id"), show="headings")
    table.heading("Chain", text="Chain", anchor="center")
    table.heading("Source", text="Source (IP)", anchor="center")
    table.heading("Protocol", text="Protocol", anchor="center")
    table.heading("Port", text="Port", anchor="center")
    table.heading("Action", text="Action", anchor="center")
    table.heading("Id", text="Rule ID", anchor="center")
    table.pack(fill="both", expand=True, padx=10, pady=10)

    for col in ("Chain", "Source", "Protocol", "Port", "Action", "Id"):
        table.column(col, anchor="center")

    rules = NftBackend.list_rules() if BACKEND == "nft" else IptablesBackend.list_rules()
    for r in rules:
        rid = r.get("handle") if BACKEND == "nft" else r.get("lineno")
        table.insert("", "end", values=(r["chain"], r["source"], r["proto"], r["port"], r["action"], rid))

    def delete_selected_rule():
        selected = table.selection()
        if not selected:
            messagebox.showwarning("Delete Rule", "Please select a rule to delete.")
            return
        for item in selected:
            chain, source, proto, port, action, rid = table.item(item, "values")
            if BACKEND == "iptables":
                if not rid:
                    messagebox.showerror("Error", "Missing rule number; cannot delete.")
                    continue
                ok, err = IptablesBackend.delete_rule_by_number(chain, rid)
            else:
                if not rid:
                    messagebox.showerror("Error", "Missing handle; cannot delete.")
                    continue
                ok, err = NftBackend.delete_rule_handle(chain, rid)
            if ok:
                table.delete(item)
            else:
                messagebox.showerror("Error", f"Failed to delete rule: {err or 'unknown error'}")

    style = ttk.Style()
    style.configure("Treeview", rowheight=24)
    style.map("Treeview", background=[("selected", "#002c42")])
    style.configure("Green.Treeview", foreground="green")
    style.configure("Red.Treeview", foreground="red")

    btns = tk.Frame(window_table)
    btns.pack(pady=8)
    ttk.Button(btns, text="Delete Selected Rule", command=delete_selected_rule).grid(row=0, column=0, padx=8)
    ttk.Button(btns, text="Close", command=window_table.destroy).grid(row=0, column=1, padx=8)

def ui_reset():
    ensure_backend()
    if BACKEND == "nft":
        NftBackend.reset()
    else:
        IptablesBackend.reset()
    messagebox.showinfo("Firewall", "Firewall rules reset. Default policy set to ACCEPT for iptables.")

def ui_set_policy():
    ensure_backend()
    chain = simpledialog.askstring("Set Policy", "Chain (INPUT or OUTPUT):")
    if not chain:
        return
    chain = chain.strip().upper()
    if chain not in ("INPUT", "OUTPUT"):
        messagebox.showerror("Error", "Chain must be INPUT or OUTPUT")
        return
    policy = simpledialog.askstring("Set Policy", "Policy (ACCEPT or DROP):")
    if not policy:
        return
    policy = policy.strip().upper()
    if policy not in ("ACCEPT", "DROP"):
        messagebox.showerror("Error", "Policy must be ACCEPT or DROP")
        return
    if BACKEND == "nft":
        ok, err = NftBackend.set_policy(chain, policy)
    else:
        ok, err = IptablesBackend.set_policy(chain, policy)
    if ok:
        messagebox.showinfo("Success", f"Set {chain} policy to {policy}")
    else:
        messagebox.showerror("Error", f"Failed to set policy: {err or 'unknown error'}")

def ui_export():
    ensure_backend()
    path = simpledialog.askstring("Export Rules", "Enter file path to export to (e.g., rules.txt):")
    if not path:
        return
    if BACKEND == "nft":
        ok, err = NftBackend.export_rules(path)
    else:
        ok, err = IptablesBackend.export_rules(path)
    if ok:
        messagebox.showinfo("Export", f"Exported rules to {path}")
    else:
        messagebox.showerror("Export", f"Failed to export: {err or 'unknown error'}")

def ui_import():
    ensure_backend()
    path = simpledialog.askstring("Import Rules", "Enter file path to import from:")
    if not path or not os.path.exists(path):
        messagebox.showerror("Import", "File not found.")
        return
    if BACKEND == "nft":
        ok, err = NftBackend.import_rules(path)
    else:
        ok, err = IptablesBackend.import_rules(path)
    if ok:
        messagebox.showinfo("Import", f"Imported rules from {path}")
    else:
        messagebox.showerror("Import", f"Failed to import: {err or 'unknown error'}")

def ui_view_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            content = f.read()
        messagebox.showinfo("Firewall Log", content if content.strip() else "Log file is empty.")
    else:
        messagebox.showwarning("Firewall Log", "Log file not found.")

def main():
    if not is_root():
        print("[!] This tool must be run as root. Try: sudo python3 firewall_gui.py")
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Firewall GUI", "This tool must be run as root. Try: sudo python3 firewall_gui.py")
        except Exception:
            pass
        sys.exit(1)

    ensure_backend()

    window = tk.Tk()
    window.title("Firewall GUI")

    tk.Button(window, text="Block Custom Port (TCP, In/Out)", width=60, command=ui_block_port).pack(pady=5)
    tk.Button(window, text="Allow Custom Port (TCP, In/Out)", width=60, command=ui_allow_port).pack(pady=5)
    tk.Button(window, text="Block Domain (all IPs, In/Out)", width=60, command=ui_block_domain).pack(pady=5)
    tk.Button(window, text="Allow Domain (all IPs, In/Out)", width=60, command=ui_allow_domain).pack(pady=5)
    tk.Button(window, text="Block IP Address (In/Out)", width=60, command=ui_block_ip).pack(pady=5)
    tk.Button(window, text="View Rules Table", width=60, command=ui_view_rules).pack(pady=5)
    tk.Button(window, text="Set Default Policy (ACCEPT/DROP)", width=60, command=ui_set_policy).pack(pady=5)
    tk.Button(window, text="Export Rules", width=60, command=ui_export).pack(pady=5)
    tk.Button(window, text="Import Rules", width=60, command=ui_import).pack(pady=5)
    tk.Button(window, text="Reset Firewall", width=60, command=ui_reset).pack(pady=5)
    tk.Button(window, text="View Log", width=60, command=ui_view_log).pack(pady=5)
    tk.Button(window, text="Exit", width=60, command=window.quit).pack(pady=5)

    window.mainloop()

if __name__ == "__main__":
    main()
