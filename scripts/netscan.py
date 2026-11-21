#!/usr/bin/env python3
# Network Scanner - Made by bear <3
import ipaddress
import socket
import concurrent.futures as cf

G = '\033[1;32m'; C = '\033[1;37m'; R = '\033[1;31m'; Y = '\033[1;33m'; Q = '\033[1;36m'

def port_scan(host, ports, timeout=1.5, workers=100):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{R}[!] Could not resolve {host}")
        return

    print(f"\n{Q}=== TCP Port Scan: {ip} ({len(ports)} ports) ==={C}\n")

    def probe(port):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return port, "open"
        except socket.timeout:
            return port, "timeout"
        except ConnectionRefusedError:
            return port, "closed"
        except Exception:
            return port, "closed"
        finally:
            s.close()

    open_count = 0
    with cf.ThreadPoolExecutor(workers) as ex:
        for port, state in sorted(ex.map(probe, ports)):
            if state == "open":
                open_count += 1
                try:
                    svc = socket.getservbyport(port, "tcp")
                except Exception:
                    svc = "?"
                print(f"{G}[+] {port:<6}/tcp open{C}    service: {svc}")
    print(f"\n{G}[*] {open_count} open port(s) on {ip}. Made by bear <3{C}")

def ping_sweep(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"{R}[!] Invalid CIDR: {e}")
        return
    hosts = list(net.hosts())
    print(f"\n{Q}=== Host Discovery: {net} ({len(hosts)} hosts) ==={C}\n")

    def alive(ip):
        for port in (80, 443, 22, 445, 3389, 8080):
            s = socket.socket()
            s.settimeout(0.7)
            try:
                if s.connect_ex((str(ip), port)) == 0:
                    return str(ip), port
            except Exception:
                pass
            finally:
                s.close()
        return None

    live = []
    with cf.ThreadPoolExecutor(200) as ex:
        for res in ex.map(alive, hosts):
            if res:
                ip, port = res
                live.append(ip)
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    name = "-"
                print(f"{G}[+] {ip:<16}{C} reachable (port {port})  hostname: {name}")
    print(f"\n{G}[*] {len(live)} live host(s) of {len(hosts)}. Made by bear <3{C}")
