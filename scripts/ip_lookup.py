#!/usr/bin/env python3
# Advanced IP Lookup - dev by bear
# Geolocation, ASN/org, RDAP ownership, reverse DNS, TCP port probe
import socket
import json
import urllib.request

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'; Q = '\033[1;36m'

PROBE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "MultiTool-dev-by-bear"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())

def ip_lookup(ip):
    print(f"\n{Q}=== IP Intelligence: {ip} ==={C}\n")
    try:
        socket.inet_aton(ip)
    except OSError:
        try:
            ip = socket.gethostbyname(ip)
            print(f"{Y}[*] Resolved to:{C} {ip}")
        except socket.gaierror:
            print(f"{R}[!] Could not resolve target.")
            return

    # Geolocation + ASN + org (ip-api pro fields)
    try:
        d = _fetch(f"http://ip-api.com/json/{ip}?fields=status,message,"
                   f"country,countryCode,regionName,city,zip,lat,lon,timezone,"
                   f"isp,org,as,asname,reverse,mobile,proxy,hosting,query")
        if d.get("status") == "success":
            rows = [
                ("Country", f'{d.get("country")} ({d.get("countryCode")})'),
                ("Region/City", f'{d.get("regionName")} / {d.get("city")} {d.get("zip")}'),
                ("Coords", f'{d.get("lat")}, {d.get("lon")}'),
                ("Timezone", d.get("timezone")),
                ("ISP", d.get("isp")),
                ("Org", d.get("org")),
                ("ASN", d.get("as")),
                ("AS Name", d.get("asname")),
                ("Reverse PTR", d.get("reverse") or "none"),
                ("Mobile", "YES" if d.get("mobile") else "no"),
                ("Proxy/VPN", f'{Y}YES{C}' if d.get("proxy") else "no"),
                ("Hosting/DC", f'{Y}YES{C}' if d.get("hosting") else "no"),
            ]
            for k, v in rows:
                print(f"{G}[+] {k:<13}{C} {v}")
        else:
            print(f"{R}[!] ip-api: {d.get('message')}")
    except Exception as e:
        print(f"{R}[!] Geolocation failed: {e}")

    # RDAP ownership (registrar, dates, abuse contact)
    try:
        rdap = _fetch(f"https://rdap.arin.net/registry/ip/{ip}")
        print(f"\n{Y}[*] RDAP Registration:{C}")
        name = None
        for ev in rdap.get("events", []):
            print(f"    {ev.get('eventAction')}: {ev.get('eventDate')}")
        for ent in rdap.get("entities", []):
            if "registrant" in ent.get("roles", []):
                for v in ent.get("vcardArray", [None, []])[1]:
                    if v[0] == "fn":
                        name = v[3]
        if name:
            print(f"    registrant: {name}")
        handle = rdap.get("handle")
        if handle:
            print(f"    handle: {handle}")
    except Exception:
        pass

    # TCP port probe
    print(f"\n{Y}[*] Quick TCP probe:{C}")
    for port in PROBE_PORTS:
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((ip, port))
            print(f"{G}[+] {port}/tcp open{C}")
        except Exception:
            pass
        finally:
            s.close()
