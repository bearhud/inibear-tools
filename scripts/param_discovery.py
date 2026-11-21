#!/usr/bin/env python3
# Parameter Discovery - dev by bear
# Probes common URL parameters and flags ones that change the response
import requests
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'

PARAMS = ["id", "user", "username", "page", "admin", "debug", "test", "lang",
          "file", "path", "cmd", "exec", "q", "search", "query", "s", "cat",
          "category", "sort", "order", "view", "edit", "delete", "action",
          "type", "url", "redirect", "next", "return", "goto", "include",
          "dir", "show", "item", "product", "ref", "token", "key", "email",
          "password", "pass", "login", "auth", "session", "msg", "error",
          "status", "year", "month", "date", "filter", "limit", "offset",
          "template", "preview", "feed", "json", "callback", "output"]

PROBE_VALS = ["1", "'\"", "<h1>xt</h1>", "../../etc/passwd"]

def discover_params(url):
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    base_params = parse_qsl(p.query)

    def build(extra=None):
        q = urlencode(base_params + (extra or []))
        return urlunparse((p.scheme, p.netloc, p.path, p.params, q, p.fragment))

    print(f"{Y}[*] Getting baseline response...{C}")
    try:
        base = requests.get(build(), timeout=10, allow_redirects=True)
    except Exception as e:
        print(f"{R}[!] Request failed: {e}")
        return
    base_len = len(base.content)
    print(f"{G}[+] Baseline: HTTP {base.status_code}, {base_len} bytes\n{C}")

    hits = []
    for param in PARAMS:
        for val in PROBE_VALS:
            try:
                r = requests.get(build([(param, val)]), timeout=10,
                                 allow_redirects=True)
                dl = len(r.content)
                diff = abs(dl - base_len)
                reflected = val in r.text
                if reflected or (diff > max(50, base_len * 0.05)) or \
                   r.status_code != base.status_code:
                    notes = []
                    if reflected:
                        notes.append(f"{R}REFLECTED{C}")
                    if diff > 50:
                        notes.append(f"delta={diff}b")
                    if r.status_code != base.status_code:
                        notes.append(f"status {base.status_code}->{r.status_code}")
                    hits.append((param, val, " | ".join(notes)))
                    break  # one hit per param is enough
            except Exception:
                continue

    if hits:
        print(f"{G}[+] Parameters that influence the response:{C}\n")
        for param, val, note in hits:
            print(f"  {Y}{param}{C} = {val!r:<22} {note}")
    else:
        print(f"{R}[!] No influencing parameters found from the {len(PARAMS)} tested.")
    print(f"\n{C}[*] Note: reflected values may indicate XSS; path values may indicate LFI. Verify manually.{C}")
