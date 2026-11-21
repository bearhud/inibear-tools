#!/usr/bin/env python3
# Reverse DNS - dev by bear
import socket

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'

def reverse_dns(ip):
    print(f"\n{C}[*] Reverse lookup for {Y}{ip}{C}...\n")
    try:
        name, aliases, addrs = socket.gethostbyaddr(ip)
        print(f"{G}[+] Hostname:{C} {name}")
        if aliases:
            print(f"{G}[+] Aliases:{C}  {', '.join(aliases)}")
        print(f"{G}[+] Addresses:{C} {', '.join(addrs)}")
    except socket.herror as e:
        print(f"{R}[!] No PTR record found: {e}")
    # Forward-confirmation check
    try:
        resolved = socket.gethostbyname(name)
        tag = f"{G}match (Forward-Confirmed PTR)" if resolved == ip else f"{Y}MISMATCH: {resolved}"
        print(f"{C}[*] Forward check:{C} {name} -> {resolved} [{tag}{C}]")
    except Exception:
        pass
