#!/usr/bin/env python3
# Telnet Bruteforcer (Go runner) - dev by bear
import os
import shutil
import subprocess
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
GO_SOURCE = os.path.join(SCRIPTS_DIR, "bruter.go")

R = '\033[1;31m'; G = '\033[1;32m'; C = '\033[1;37m'; Y = '\033[1;33m'


def build_binary():
    """Compile the Go bruter if the binary doesn't exist yet."""
    bin_name = "bruter.exe" if os.name == "nt" else "bruter"
    bin_path = os.path.join(SCRIPTS_DIR, bin_name)
    if os.path.exists(bin_path):
        return bin_path
    if shutil.which("go") is None:
        print(f"{R}[!] Go is not installed. Install Go or run the Python version.")
        return None
    print(f"{Y}[*] Compiling Go bruter (first run only)...{C}")
    try:
        subprocess.run(["go", "build", "-o", bin_path, GO_SOURCE],
                       check=True, cwd=SCRIPTS_DIR)
        print(f"{G}[+] Built: {bin_path}{C}")
        return bin_path
    except subprocess.CalledProcessError as e:
        print(f"{R}[!] Go build failed: {e}")
        return None


def run(target_file, threads=500, output_file="found.txt", debug=False):
    bin_path = build_binary()
    if bin_path is None:
        return
    cmd = [bin_path, target_file, str(threads), output_file]
    if debug:
        cmd.append("debug")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        # Ctrl+C: terminate the Go process immediately
        print(f"\n{R}[!] Stopping Go bruter...{C}")
        raise