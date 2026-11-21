#!/usr/bin/env python3
# CVE Lookup - dev by bear
# Queries the NVD 2.0 API for public vulnerabilities
import json
import urllib.request
import urllib.parse

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'; Q = '\033[1;36m'

SEV_COLOR = {"CRITICAL": '\033[1;31m', "HIGH": '\033[1;31m',
             "MEDIUM": Y, "LOW": G}

def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "MultiTool-dev-by-bear"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def cve_lookup(query):
    print(f"\n{Q}=== NVD Search: {query} ==={C}\n")
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?"
           + urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 20}))
    try:
        data = _fetch(url)
    except Exception as e:
        print(f"{R}[!] NVD API error: {e}")
        return

    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"{R}[!] No CVEs found for '{query}'.")
        return

    print(f"{G}[*] {total} total matches, showing {len(vulns)}:{C}\n")
    for item in vulns:
        c = item["cve"]
        cid = c["id"]
        published = c.get("published", "?")[:10]
        desc = "?"
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"][:150]
                break

        # CVSS v3.1 metric (fall back to v2)
        score, severity, vector = None, "N/A", ""
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                score = m.get("baseScore")
                severity = m.get("baseSeverity", m.get("baseSeverity", "N/A"))
                vector = m.get("vectorString", "")
                break

        col = SEV_COLOR.get(severity, C)
        print(f"{R}{cid}{C}  [{col}{severity}{C} {score}]  {published}")
        print(f"  {desc}...")
        if vector:
            print(f"  {Q}vector:{C} {vector}")
        print()