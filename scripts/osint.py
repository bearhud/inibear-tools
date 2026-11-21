#!/usr/bin/env python3
# OSINT Recon - Made by bear <3
import json
import urllib.request
import urllib.parse

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'; Q = '\033[1;36m'

def _fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "MultiTool-bear",
                                               "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def whois_lookup(domain):
    print(f"\n{Q}=== WHOIS / RDAP: {domain} ==={C}\n")
    try:
        d = _fetch_json(f"https://rdap.org/domain/{domain}")
    except Exception as e:
        print(f"{R}[!] RDAP lookup failed: {e}")
        return

    print(f"{G}[+] Handle:{C}        {d.get('handle', '-')}")
    print(f"{G}[+] Status:{C}        {', '.join(d.get('status', [])) or '-'}")

    for ev in d.get("events", []):
        print(f"{G}[+] {ev.get('eventAction','event'):<13}{C} {ev.get('eventDate','-')}")

    for ns in d.get("nameservers", []):
        print(f"{G}[+] Nameserver:{C}  {ns.get('ldhName', '-')}")

    print(f"\n{Y}[*] Entities:{C}")
    for ent in d.get("entities", []):
        roles = ",".join(ent.get("roles", []))
        name, email = None, None
        for v in ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []:
            if v[0] == "fn":
                name = v[3]
            if v[0] == "email":
                email = v[3]
        if name or email:
            print(f"    {roles:<14} {name or '-'} {('<'+email+'>') if email else ''}")

    for remark in d.get("remarks", []):
        for line in remark.get("description", []):
            print(f"{C}    note: {line[:120]}")

def dork_builder(domain):
    print(f"\n{Q}=== Google Dork Builder: {domain} ==={C}\n")
    dorks = [
        f'site:{domain}',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} ext:sql | ext:bak | ext:log | ext:env',
        f'site:{domain} inurl:".php?id="',
        f'site:{domain} "phpMyAdmin"',
        f'site:{domain} intext:"sql syntax near"',
        f'site:{domain} inurl:api | inurl:v1 | inurl:graphql',
        f'site:{domain} ext:pdf | ext:xls | ext:docx',
        f'"@{domain}" filetype:pdf',
        f'site:pastebin.com "{domain}"',
        f'site:github.com "{domain}" password',
        f'site:{domain} -www',
    ]
    for i, dk in enumerate(dorks, 1):
        print(f"{G}[{i:02d}]{C} {dk}")
        print(f"     {Q}https://www.google.com/search?q={urllib.parse.quote(dk)}{C}")

def email_patterns(domain):
    print(f"\n{Q}=== Email patterns: {domain} ==={C}\n")
    people = input(f"{C}[?] Names (comma separated, e.g. john doe): {Y}").strip()
    if not people:
        return
    for person in people.split(","):
        parts = [p for p in person.strip().lower().split() if p]
        if len(parts) < 2:
            continue
        f, l = parts[0], parts[-1]
        patterns = [
            f"{f}.{l}@{domain}", f"{f}{l}@{domain}", f"{f[0]}{l}@{domain}",
            f"{f}_{l}@{domain}", f"{l}@{domain}", f"{l}.{f}@{domain}",
            f"{f}@{domain}", f"{f[0]}.{l}@{domain}", f"{l}{f[0]}@{domain}",
        ]
        print(f"{G}[*] {person.strip()}{C}")
        for pat in patterns:
            print(f"    {pat}")
