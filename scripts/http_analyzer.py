#!/usr/bin/env python3
# HTTP Analyzer - Made by bear <3
# Headers, redirect chain, security headers, cookies, TLS, tech fingerprints
import re
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'; Q = '\033[1;36m'

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

TECH_HINTS = {
    "server": "Server",
    "x-powered-by": "Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "cf-ray": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
}

def _tls_info(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version()
        if not cert:
            return {"version": proto}
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return {
            "version": proto,
            "cn": subject.get("commonName", "-"),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "-")),
            "not_after": cert.get("notAfter", "-"),
            "sans": ", ".join(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")[:200],
        }
    except Exception as e:
        return {"error": str(e)}

def analyze(url):
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    host = p.hostname
    print(f"\n{Q}=== HTTP Analysis: {url} ==={C}\n")

    try:
        r = requests.get(url, timeout=15, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (MultiTool bear)"})
    except Exception as e:
        print(f"{R}[!] Request failed: {e}")
        return

    print(f"{G}[+] Final URL:{C}    {r.url}")
    print(f"{G}[+] Status:{C}       HTTP {r.status_code} {r.reason}")
    print(f"{G}[+] Elapsed:{C}      {r.elapsed.total_seconds()*1000:.0f} ms")
    print(f"{G}[+] Content:{C}      {r.headers.get('content-type', '?')} | {len(r.content)} bytes")

    if r.history:
        print(f"{Y}[*] Redirect chain:{C}")
        for h in r.history:
            print(f"    {h.status_code} -> {h.headers.get('location', '?')}")
        print(f"    {r.status_code} -> {r.url}")

    title = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
    if title:
        print(f"{G}[+] Title:{C}        {title.group(1).strip()[:100]}")

    print(f"\n{Y}[*] Response headers:{C}")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    print(f"\n{Y}[*] Security headers:{C}")
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        if val:
            print(f"    {G}[present]{C} {h}: {val[:90]}")
        else:
            print(f"    {R}[MISSING]{C} {h}")

    print(f"\n{Y}[*] Cookies:{C}")
    if not r.cookies:
        print(f"    {C}(none)")
    for ck in r.cookies:
        flags = []
        flags.append(f"Secure={G}yes{C}" if ck.secure else f"Secure={R}no{C}")
        extra = getattr(ck, "_rest", {}) or {}
        if "HttpOnly" in extra:
            flags.append(f"HttpOnly={G}yes{C}")
        else:
            flags.append(f"HttpOnly={R}no{C}")
        samesite = extra.get("SameSite", "unset")
        print(f"    {ck.name} = {ck.value[:40]}  |  {', '.join(flags)}, SameSite={samesite}")

    print(f"\n{Y}[*] Tech fingerprints:{C}")
    seen = False
    for hdr, label in TECH_HINTS.items():
        if hdr in r.headers:
            seen = True
            print(f"    {label}: {r.headers[hdr]}")
    body_sig = {
        "wp-content": "WordPress", "wp-includes": "WordPress",
        "Joomla": "Joomla", "Drupal": "Drupal",
        "csrf-token": "Rails/Laravel", "__NEXT_DATA__": "Next.js",
        "ng-version": "Angular", "react": "React", "django": "Django",
        "PHPSESSID": "PHP",
    }
    for sig, name in body_sig.items():
        if sig.lower() in r.text.lower():
            seen = True
            print(f"    Body signature: {name} ({sig})")
    if not seen:
        print(f"    {C}(no fingerprints detected)")

    if p.scheme == "https":
        print(f"\n{Y}[*] TLS:{C}")
        for k, v in _tls_info(host).items():
            print(f"    {k}: {v}")
    else:
        print(f"\n{Y}[*] TLS: not used (plain HTTP){C}")

    print(f"\n{C}[*] Done. Made by bear <3{C}")
