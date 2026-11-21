#!/usr/bin/env python3
# Banner Grabber - dev by bear
# Connects to a port, sends a protocol-appropriate probe, prints the banner
import socket
import concurrent.futures as cf
import ssl

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'

PROBES = {
    21: None,                      # FTP banner on connect
    22: None,                      # SSH banner on connect
    23: None,
    25: b"EHLO probe.local\r\n",   # SMTP
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
    80: b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
    110: b"USER probe\r\n",        # POP3
    143: b"a001 LOGIN probe probe\r\n",  # IMAP
    443: "TLS",                    # TLS-wrapped HTTP probe
    445: None,                     # SMB
    3306: None,                    # MySQL greeting
    3389: None,
    8080: b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
    8443: "TLS",
}

def _grab(host, port):
    probe = PROBES.get(port, b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(5)
    except Exception as e:
        return port, None, str(e)

    try:
        if probe == "TLS":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
            cert = sock.getpeercert(binary_form=False) or {}
            cn = ""
            try:
                cn = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")
            except Exception:
                pass
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        elif probe:
            sock.sendall(probe)
        data = sock.recv(4096)
        banner = data.decode(errors="replace").strip()[:400]
        info = f"TLS-CNSE={cn}" if probe == "TLS" else ""
        return port, (banner + (f"  [{info}]" if info else "")), None
    except socket.timeout:
        return port, None, "connected, no banner (silent service)"
    except Exception as e:
        return port, None, str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

def grab_banners(host, ports):
    print(f"\n{Y}[*] Grabbing banners from {host}...{C}\n")
    with cf.ThreadPoolExecutor(len(ports)) as ex:
        for port, banner, err in ex.map(lambda p: _grab(host, p), ports):
            if banner:
                print(f"{G}[+] {port}/tcp:{C} {banner}")
            elif err:
                print(f"{R}[-] {port}/tcp: {err}{C}")
    print(f"\n{C}[*] Done. dev by bear{C}")
