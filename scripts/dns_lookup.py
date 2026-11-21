#!/usr/bin/env python3
# DNS Lookup - dev by bear
import socket
import dns.resolver

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]

def dns_lookup(domain):
    print(f"\n{C}[*] Resolving {Y}{domain}{C}...\n")
    try:
        print(f"{G}[+] IP (socket):{C} {socket.gethostbyname(domain)}")
    except socket.gaierror:
        print(f"{R}[!] Domain does not resolve.")
        return

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                print(f"{G}[+] {rtype:<6}{C} {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"{R}[!] NXDOMAIN: domain does not exist.")
            return
        except Exception:
            continue

    # Basic mail server listing sorted by priority
    try:
        mx = sorted((r.preference, str(r.exchange)) for r in
                    dns.resolver.resolve(domain, "MX", lifetime=5))
        print(f"\n{Y}[*] Mail servers (priority order):{C}")
        for pref, exch in mx:
            print(f"    {pref:>5}  {exch}")
    except Exception:
        pass
