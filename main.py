#!/usr/bin/env python3
# MultiTool - Made by bear <3
import os
import sys
import importlib.util

R = '\033[1;31m'; B = '\033[1;34m'; C = '\033[1;37m'
G = '\033[1;32m'; Y = '\033[1;33m'; Q = '\033[1;36m'

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
VERSION = "1.0"

BANNER = C + r'''
██████╗ ███████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ███████║██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔══██╗
██████╔╝███████╗██║  ██║██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
       M U L T I   T O O L

              Made by bear <3
                 Version: 1.0
''' + Q

def menu_page(page):
    if page == 1:
        print(f"""{C}
┌───────────────────┐                       ┌───────────────────┐
├── Recon Tools ────┤────────────┬──────────┤ Network Tools     ├────────────┬───────────────┐
└───────────────────┘            │          └───────────────────┘            │               │
                                 │                                           │               │
├ [01] OSINT Recon Menu          ├ [02] Network Scanner Menu                  ├ [03] Web Tools Menu
├ [04] DNS Lookup                ├ [05] IP Intelligence                       ├ [06] Subdomain Finder
├ [07] Reverse DNS               ├ [08] Banner Grabber                        ├ [09] CVE Lookup
├ [10] Parameter Discovery       ├ [11] Telnet Service Audit                  ├ [12] HTTP Analyzer
│
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ [N] Next Page  |  [B] Back  |  [C] Credits  |  [Q] Quit                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
""")
    else:
        print(f"""{C}
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Extra Tools - Page 2 of 2                                     │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                            │
├ [13] TCP Ping (paping)        ├ [14] List Scripts                           ├ [15] Credits
│
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ [N] Next Page  |  [B] Back  |  [C] Credits  |  [Q] Quit                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
""")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def load_module(name):
    path = os.path.join(SCRIPTS_DIR, name + ".py")
    if not os.path.exists(path):
        print(f"{R}[!] Module not found: {path}")
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def ask(prompt, default=""):
    val = input(f"{C}[?] {prompt}{f' [{default}]' if default else ''}: {Y}").strip()
    return val or default

def pause():
    input(f"\n{C}[?] Press Enter to return to menu...")

def safe(fn, *args):
    """Run a tool, catch Ctrl+C and errors, always return to menu."""
    try:
        fn(*args)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Stopped by user.{C}")
    except Exception as e:
        print(f"{R}[!] Error: {e}")
    pause()

def get_target_file():
    path = ask("Path to target list (.txt)").strip('"')
    if not path.lower().endswith(".txt"):
        print(f"{R}[!] Invalid file: must be a .txt file.")
        return None
    if not os.path.isfile(path):
        print(f"{R}[!] File not found: {path}")
        return None
    return path

# ----------------------------- individual tools -----------------------------

def telnet_audit():
    print(f"\n{Q}--- Telnet Service Audit (Go) ---{C}")
    target_file = get_target_file()
    if not target_file:
        return
    threads = ask("Threads", "500")
    outfile = ask("Output file", "found.txt")
    if not outfile.lower().endswith(".txt"):
        outfile += ".txt"
    debug = ask("Debug mode? (y/N)", "n").lower() == "y"
    mod = load_module("telnet_bruter")
    if mod is None:
        return
    print(f"\n{Y}[*] Starting audit... CTRL+C stops and returns to menu.{C}\n")
    mod.run(target_file, int(threads) if threads.isdigit() else 500, outfile, debug)

def paping_tool():
    print(f"\n{Q}--- TCP Ping (paping) ---{C}")
    host = ask("Host")
    if not host:
        return
    port = ask("Port", "443")
    count = ask("Count (blank = infinite)")
    timeout = ask("Timeout sec", "2")
    interval = ask("Interval sec", "1")
    mod = load_module("paping")
    if mod is None:
        return
    mod.paping(host,
               int(port) if port.isdigit() else 443,
               int(count) if count.isdigit() else None,
               float(timeout) if timeout.replace(".", "", 1).isdigit() else 2,
               float(interval) if interval.replace(".", "", 1).isdigit() else 1)

def dns_tool():
    mod = load_module("dns_lookup")
    target = ask("Domain")
    if mod and target:
        mod.dns_lookup(target)

def reverse_dns_tool():
    mod = load_module("reverse_dns")
    target = ask("IP address")
    if mod and target:
        mod.reverse_dns(target)

def ip_tool():
    mod = load_module("ip_lookup")
    target = ask("IP address or hostname")
    if mod and target:
        mod.ip_lookup(target)

def subdomain_tool():
    mod = load_module("subdomain_finder")
    target = ask("Domain")
    if mod and target:
        mod.find_subdomains(target)

def param_tool():
    mod = load_module("param_discovery")
    target = ask("URL (with or without params)")
    if mod and target:
        mod.discover_params(target)

def cve_tool():
    mod = load_module("cve_lookup")
    target = ask("Keyword / product (e.g. 'apache 2.4.49')")
    if mod and target:
        mod.cve_lookup(target)

def banner_tool():
    mod = load_module("banner_grabber")
    host = ask("Host")
    if not mod or not host:
        return
    ports = ask("Ports", "21,22,25,80,110,143,443,445,3306,3389,8080")
    port_list = sorted({int(p) for p in ports.replace(" ", "").split(",") if p.isdigit()})
    mod.grab_banners(host, port_list or [80, 443])

def http_tool():
    mod = load_module("http_analyzer")
    target = ask("URL or host")
    if mod and target:
        mod.analyze(target)

def list_scripts():
    print(f"\n{G}[*] Scripts in scripts/:{C}")
    for f in sorted(os.listdir(SCRIPTS_DIR)):
        if f.endswith((".py", ".go")):
            print(f"    - {f}")

def credits():
    clear()
    print(BANNER)
    print(f"""{C}
  MultiTool v{VERSION}
  Made by bear <3

  Modules:
    telnet_bruter.py  (Go core: bruter.go)
    paping.py, dns_lookup.py, reverse_dns.py, ip_lookup.py,
    subdomain_finder.py, param_discovery.py, cve_lookup.py,
    banner_grabber.py, http_analyzer.py, osint.py, netscan.py

  Python deps: colorama, dnspython, requests
  Go required only for the Telnet Service Audit module.
""")
    pause()

# ----------------------------- sub menus -----------------------------

def sub_menu(title, options):
    clear()
    print(BANNER)
    print(f"\n{Q}--- {title} ---{C}\n")
    for key, label, _ in options:
        print(f"  [{key}] {label}")
    print(f"\n  [B] Back")
    ch = input(f"\n{C}[?] Select option: {Y}").strip().lower()
    if ch == "b":
        return
    for key, label, fn in options:
        if ch == key:
            safe(fn)
            return
    print(f"{R}[!] Invalid option.")
    pause()

# OSINT sub-tool functions
def osint_whois():
    mod = load_module("osint")
    target = ask("Domain")
    if mod and target:
        mod.whois_lookup(target)

def osint_dorks():
    mod = load_module("osint")
    target = ask("Domain")
    if mod and target:
        mod.dork_builder(target)

def osint_emails():
    mod = load_module("osint")
    target = ask("Domain")
    if mod and target:
        mod.email_patterns(target)

# Network scanner sub-tool functions
def net_portscan():
    mod = load_module("netscan")
    host = ask("Host / IP")
    if not mod or not host:
        return
    ports = ask("Ports", "21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443")
    port_list = sorted({int(p) for p in ports.replace(" ", "").split(",") if p.isdigit()})
    mod.port_scan(host, port_list or [80, 443])

def net_sweep():
    mod = load_module("netscan")
    target = ask("CIDR (e.g. 192.168.1.0/24)")
    if mod and target:
        mod.ping_sweep(target)

def osint_menu():
    sub_menu("OSINT Recon Menu", [
        ("1", "WHOIS / RDAP domain lookup", osint_whois),
        ("2", "Google dork builder", osint_dorks),
        ("3", "Email pattern generator", osint_emails),
    ])

def network_menu():
    sub_menu("Network Scanner Menu", [
        ("1", "TCP port scan", net_portscan),
        ("2", "Host discovery (CIDR sweep)", net_sweep),
        ("3", "TCP ping / paping", paping_tool),
        ("4", "Banner grabber", banner_tool),
    ])

def web_menu():
    sub_menu("Web Tools Menu", [
        ("1", "HTTP Analyzer", http_tool),
        ("2", "Parameter Discovery", param_tool),
        ("3", "Subdomain Finder", subdomain_tool),
        ("4", "CVE Lookup", cve_tool),
    ])

# ----------------------------- main loop -----------------------------

def main():
    page = 1
    while True:
        clear()
        print(BANNER)
        menu_page(page)
        raw = input(f"{C}[?] Select option: {Y}").strip()
        key = raw.lower()

        if key in ("q", "quit", "0"):
            print(f"{G}[*] Goodbye. Made by bear <3{C}")
            sys.exit(0)
        elif key == "n":
            page = 1 if page == 2 else 2
            continue
        elif key == "b":
            page = 1
            continue
        elif key == "c":
            credits()
            continue

        num = key.lstrip("0") or "0"
        if page == 1:
            actions = {
                "1": osint_menu,
                "2": network_menu,
                "3": web_menu,
                "4": dns_tool,
                "5": ip_tool,
                "6": subdomain_tool,
                "7": reverse_dns_tool,
                "8": banner_tool,
                "9": cve_tool,
                "10": param_tool,
                "11": telnet_audit,
                "12": http_tool,
            }
        else:
            actions = {
                "13": paping_tool,
                "14": list_scripts,
                "15": credits,
            }

        fn = actions.get(num)
        if fn:
            if fn in (osint_menu, network_menu, web_menu):
                fn()
            else:
                safe(fn)
        else:
            print(f"{R}[!] Invalid option.")
            pause()

if __name__ == "__main__":
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{G}[*] Goodbye. Made by bear <3{C}")
        sys.exit(0)