#!/usr/bin/env python3
# Subdomain Finder - dev by bear
# crt.sh (certificate transparency) + hackertarget + active DNS validation
import socket
import json
import urllib.request
import concurrent.futures as cf

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'

SUBS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
        "ns", "api", "cdn", "app", "dev", "staging", "admin", "git", "wiki",
        "cloud", "dashboard", "login", "sso", "jira", "confluence", "status"]

def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "MultiTool-dev-by-bear"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode()

def find_subdomains(domain):
    subs = set()

    # 1. Certificate Transparency logs (crt.sh)
    print(f"{Y}[*] Querying crt.sh certificate transparency...{C}")
    try:
        data = _fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
        for entry in json.loads(data):
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name)
        print(f"{G}[+] crt.sh: {len(subs)} subdomains{C}")
    except Exception as e:
        print(f"{R}[!] crt.sh failed: {e}")

    # 2. HackerTarget host search
    try:
        html = _fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        for line in html.splitlines():
            if "," in line and line.split(",")[0].endswith(domain):
                subs.add(line.split(",")[0].strip())
    except Exception:
        pass

    # 3. Brute common names via DNS
    print(f"{Y}[*] Probing {len(SUBS)} common names via DNS...{C}")
    def probe(name):
        fqdn = f"{name}.{domain}"
        try:
            return fqdn, socket.gethostbyname(fqdn)
        except Exception:
            return None
    with cf.ThreadPoolExecutor(30) as ex:
        for res in ex.map(probe, SUBS):
            if res:
                subs.add(res[0])

    if not subs:
        print(f"{R}[!] No subdomains found.")
        return

    # 4. Validate live + resolve IPs
    print(f"\n{Y}[*] Resolving {len(subs)} candidates...{C}\n")
    def resolve(fqdn):
        try:
            return fqdn, socket.gethostbyname(fqdn)
        except Exception:
            return fqdn, None
    live = 0
    with cf.ThreadPoolExecutor(30) as ex:
        for fqdn, ipaddr in ex.map(resolve, sorted(subs)):
            if ipaddr:
                live += 1
                print(f"{G}[+] {fqdn:<40}{C} -> {ipaddr}")
            else:
                print(f"{C}[ ] {fqdn:<40}{C} (no DNS record)")
    print(f"\n{G}[*] Found {len(subs)} total, {live} resolving. dev by bear{C}")
