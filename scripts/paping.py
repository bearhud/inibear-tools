#!/usr/bin/env python3
# TCP Ping (paping-style) - dev by bear
import socket
import time
from colorama import Fore, Style, init

init(autoreset=True)

GREEN = Fore.GREEN
CYAN = Fore.CYAN
WHITE = Fore.WHITE
RED = Fore.RED
RESET = Style.RESET_ALL

def paping(host, port=443, count=None, timeout=2, interval=1):
    sent = 0
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Unable to resolve host: {host}")
        return

    while count is None or sent < count:
        sent += 1
        start = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            elapsed = (time.perf_counter() - start) * 1000

            if result == 0:
                print(f"{WHITE}Connected to {GREEN}{ip}{WHITE}: "
                      f"time={CYAN}{elapsed:.2f}ms{WHITE} "
                      f"protocol={GREEN}TCP{WHITE} port={CYAN}{port}")
            else:
                print(f"{WHITE}Connection failed to {GREEN}{ip}{WHITE}: "
                      f"protocol={GREEN}TCP{WHITE} port={CYAN}{port}")
            sock.close()
        except socket.timeout:
            print(f"{WHITE}Connection timed out to {GREEN}{ip}{WHITE}: "
                  f"protocol={GREEN}TCP{WHITE} port={CYAN}{port}")
        except OSError as e:
            print(f"{RED}Error: {e}")

        if count is None or sent < count:
            time.sleep(interval)