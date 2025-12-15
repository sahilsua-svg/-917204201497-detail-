@#!/usr/bin/env python3
"""
cyber_wizard.py — Lightweight cybersecurity utility / learning wizard (Python 3)

Features:
- Generate cryptographically secure passwords
- Calculate Shannon entropy of a string
- Fetch and display TLS certificate info for a domain (port 443 by default)
- Fetch HTTP headers for a URL (non-invasive GET request)

Usage (CLI):
- python3 cyber_wizard.py password --length 20 --no-symbols
- python3 cyber_wizard.py entropy "Tr0ub4dor&3"
- python3 cyber_wizard.py cert example.com
- python3 cyber_wizard.py headers https://example.com

Interactive mode:
- Run without arguments to launch an interactive menu.

Note: Use these tools responsibly and only on systems/networks you own or have explicit permission to test.
"""
from __future__ import annotations
import argparse
import secrets
import string
import math
import ssl
import socket
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import Optional, Tuple, List


# -------------------------
# Utilities
# -------------------------
def gen_password(length: int = 16, upper: bool = True, digits: bool = True, symbols: bool = True) -> str:
    """Generate a cryptographically secure password."""
    if length <= 0:
        raise ValueError("Length must be a positive integer.")
    alphabet = list(string.ascii_lowercase)
    if upper:
        alphabet += list(string.ascii_uppercase)
    if digits:
        alphabet += list(string.digits)
    if symbols:
        # keep the set of symbols conservative to avoid shell/URL issues by default
        alphabet += list("!@#$%^&*()-_=+[]{};:,.<>?")
    # Ensure at least one char from each requested class where possible
    pwd = []
    if upper:
        pwd.append(secrets.choice(string.ascii_uppercase))
    if digits:
        pwd.append(secrets.choice(string.digits))
    if symbols:
        pwd.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.<>?"))
    # fill the rest
    while len(pwd) < length:
        pwd.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd[:length])


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy (bits per string)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
    # total bits = entropy * length
    return entropy * length


# -------------------------
# TLS Certificate inspection
# -------------------------
def get_tls_certificate(hostname: str, port: int = 443, timeout: int = 5) -> Optional[dict]:
    """
    Retrieve TLS certificate information from hostname:port.
    Returns a dict with basic fields or None on error.
    """
    try:
        context = ssl.create_default_context()
        # do not verify certificate validity here when retrieving; we're just inspecting
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        print(f"[!] Error getting certificate from {hostname}:{port} -> {e}")
        return None

    def parse_time(timestr: str) -> str:
        try:
            # Example format: 'Jun 10 12:00:00 2025 GMT'
            dt = datetime.strptime(timestr, "%b %d %H:%M:%S %Y %Z")
            return dt.isoformat()
        except Exception:
            return timestr

    # Extract SANs (if present)
    san = []
    for t in cert.get("subjectAltName", ()):
        san.append(f"{t[0]}: {t[1]}")

    subject = " / ".join("=".join(x for x in t[0]) if isinstance(t[0], tuple) else str(t) for t in cert.get("subject", ()))
    issuer = " / ".join("=".join(x for x in t[0]) if isinstance(t[0], tuple) else str(t) for t in cert.get("issuer", ()))

    return {
        "subject": subject or cert.get("subject"),
        "issuer": issuer or cert.get("issuer"),
        "notBefore": parse_time(cert.get("notBefore", "")),
        "notAfter": parse_time(cert.get("notAfter", "")),
        "serialNumber": cert.get("serialNumber", ""),
        "version": cert.get("version", ""),
        "subjectAltName": san,
        "raw": cert,
    }


# -------------------------
# HTTP headers fetch
# -------------------------
def fetch_http_headers(url: str, timeout: int = 10) -> Optional[List[Tuple[str, str]]]:
    """Fetch HTTP response headers for a URL. Performs a GET request (no body reading)."""
    try:
        req = Request(url, method="GET", headers={"User-Agent": "cyber_wizard/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            headers = list(resp.getheaders())
            return headers
    except HTTPError as he:
        # still may have headers in HTTPError
        try:
            return list(he.headers.items())
        except Exception:
            print(f"[!] HTTP error: {he}")
            return None
    except URLError as ue:
        print(f"[!] URL error: {ue}")
        return None
    except Exception as e:
        print(f"[!] Error fetching headers: {e}")
        return None


# -------------------------
# CLI and interactive
# -------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Cyber Wizard — safe security utility / learning tool")
    sub = p.add_subparsers(dest="command", required=False)

    # password subcommand
    sp = sub.add_parser("password", help="Generate a secure password")
    sp.add_argument("--length", "-l", type=int, default=16, help="Password length (default: 16)")
    sp.add_argument("--no-uppercase", action="store_true", help="Do not include uppercase letters")
    sp.add_argument("--no-digits", action="store_true", help="Do not include digits")
    sp.add_argument("--no-symbols", action="store_true", help="Do not include symbols")

    # entropy subcommand
    se = sub.add_parser("entropy", help="Calculate Shannon entropy (bits)")
    se.add_argument("text", type=str, help="Text to analyze")

    # cert subcommand
    sc = sub.add_parser("cert", help="Retrieve TLS certificate info for a host")
    sc.add_argument("host", type=str, help="Hostname (e.g. example.com)")
    sc.add_argument("--port", "-p", type=int, default=443, help="Port (default: 443)")

    # headers subcommand
    sh = sub.add_parser("headers", help="Fetch HTTP headers for a URL")
    sh.add_argument("url", type=str, help="URL (include scheme, e.g. https://example.com)")

    return p


def interactive_menu() -> None:
    print("Cyber Wizard — interactive mode")
    print("Choose an option:")
    print(" 1) Generate password")
    print(" 2) Calculate entropy")
    print(" 3) Inspect TLS certificate (hostname)")
    print(" 4) Fetch HTTP headers (URL)")
    print(" 0) Exit")
    while True:
        try:
            choice = input("Choice> ").strip()
            if choice == "0" or choice.lower() in ("q", "quit", "exit"):
                print("Goodbye.")
                return
            elif choice == "1":
                length = int(input("Length (16): ") or "16")
                use_upper = input("Include uppercase? [Y/n]: ")[:1].lower() != "n"
                use_digits = input("Include digits? [Y/n]: ")[:1].lower() != "n"
                use_symbols = input("Include symbols? [Y/n]: ")[:1].lower() != "n"
                pwd = gen_password(length, upper=use_upper, digits=use_digits, symbols=use_symbols)
                print(f"Password: {pwd}")
            elif choice == "2":
                txt = input("Text> ")
                bits = shannon_entropy(txt)
                print(f"Shannon entropy (total bits): {bits:.4f}")
            elif choice == "3":
                host = input("Hostname (example.com): ").strip()
                port = int(input("Port (443): ") or "443")
                cert = get_tls_certificate(host, port)
                if cert:
                    print("Certificate info:")
                    for k, v in cert.items():
                        if k == "raw":
                            continue
                        print(f"  {k}: {v}")
                else:
                    print("Failed to retrieve certificate.")
            elif choice == "4":
                url = input("URL (include https://): ").strip()
                headers = fetch_http_headers(url)
                if headers:
                    print("Headers:")
                    for k, v in headers:
                        print(f"  {k}: {v}")
                else:
                    print("Failed to fetch headers.")
            else:
                print("Unknown choice. Try again.")
        except Exception as e:
            print(f"[!] Error: {e}")


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        # interactive mode
        interactive_menu()
        return

    if args.command == "password":
        pwd = gen_password(
            length=args.length,
            upper=not args.no_uppercase,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
        )
        print(pwd)

    elif args.command == "entropy":
        bits = shannon_entropy(args.text)
        print(f"Shannon entropy (total bits): {bits:.4f}")

    elif args.command == "cert":
        info = get_tls_certificate(args.host, port=args.port)
        if info:
            for k, v in info.items():
                if k == "raw":
                    continue
                if isinstance(v, list):
                    print(f"{k}:")
                    for line in v:
                        print(f"  - {line}")
                else:
                    print(f"{k}: {v}")
        else:
            print("No certificate information available.")

    elif args.command == "headers":
        headers = fetch_http_headers(args.url)
        if headers:
            for k, v in headers:
                print(f"{k}: {v}")
        else:
            print("No headers retrieved.")


if __name__ == "__main__":
    main()