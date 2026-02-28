#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List


DEFAULT_SUBDOMAIN_WORDS = ["www", "api", "dev", "test", "staging", "admin"]
DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
]


@dataclass
class HostResult:
    host: str
    ip: str
    open_ports: List[int]
    findings: List[str]


def discover_subdomains(base_domain: str, words: List[str]) -> Dict[str, str]:
    discovered: Dict[str, str] = {}

    candidates = [base_domain] + [f"{w}.{base_domain}" for w in words]
    for name in candidates:
        try:
            ip = socket.gethostbyname(name)
            discovered[name] = ip
        except socket.gaierror:
            continue

    return discovered


def scan_ports(host: str, ports: List[int], timeout: float = 0.6) -> List[int]:
    open_ports: List[int] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports


def get_banner(host: str, port: int, timeout: float = 0.8) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def basic_localhost_vuln_checks(host: str, open_ports: List[int]) -> List[str]:
    findings: List[str] = []

    risky_ports = {
        21: "FTP open (often insecure/plaintext).",
        23: "Telnet open (plaintext remote access).",
        445: "SMB open (verify patching and access controls).",
        6379: "Redis open (ensure auth/bind settings).",
    }
    for p in open_ports:
        if p in risky_ports:
            findings.append(risky_ports[p])

    if 80 in open_ports or 8080 in open_ports:
        http_port = 80 if 80 in open_ports else 8080
        banner = get_banner(host, http_port)
        if not banner:
            findings.append(f"HTTP on {http_port} is open but no banner/headers were returned.")
        else:
            text = banner.lower()
            if "server:" in text and ("apache/2.2" in text or "iis/6" in text):
                findings.append("Potentially old HTTP server version seen in banner.")
            if "x-frame-options" not in text:
                findings.append("Missing X-Frame-Options header (basic clickjacking hardening).")
            if "x-content-type-options" not in text:
                findings.append("Missing X-Content-Type-Options header.")

    if 22 in open_ports:
        findings.append("SSH is open. Ensure key-only login and no weak credentials.")
    if 3389 in open_ports:
        findings.append("RDP is open. Ensure NLA and strong authentication.")

    return findings


def run_scan(
    base_domain: str,
    words: List[str],
    ports: List[int],
    output_file: Path,
) -> List[HostResult]:
    discovered = discover_subdomains(base_domain, words)

    results: List[HostResult] = []
    for host, ip in discovered.items():
        open_ports = scan_ports(host, ports)
        findings = basic_localhost_vuln_checks(host, open_ports)
        results.append(HostResult(host=host, ip=ip, open_ports=open_ports, findings=findings))

    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "base_domain": base_domain,
        "results": [asdict(r) for r in results],
    }
    output_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return results


def print_summary(results: List[HostResult]) -> None:
    if not results:
        print("[!] No resolvable hosts found.")
        return

    for r in results:
        print(f"\nHost: {r.host} ({r.ip})")
        print(f"Open ports: {r.open_ports if r.open_ports else 'None'}")
        if r.findings:
            print("Findings:")
            for f in r.findings:
                print(f"  - {f}")
        else:
            print("Findings: None")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple lab bug bounty script (subdomain + port + basic checks)."
    )
    parser.add_argument(
        "--domain",
        default="localhost",
        help="Base domain to test (default: localhost).",
    )
    parser.add_argument(
        "--interval-hours",
        type=float,
        default=24,
        help="Repeat interval in hours when not using --once (default: 24).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan (best for testing).",
    )
    parser.add_argument(
        "--output",
        default="scan_report.json",
        help="Output JSON report file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output = Path(args.output)

    words = DEFAULT_SUBDOMAIN_WORDS
    ports = DEFAULT_PORTS

    if args.once:
        results = run_scan(args.domain, words, ports, output)
        print_summary(results)
        print(f"\n[+] Report written to: {output.resolve()}")
        return

    interval_seconds = max(args.interval_hours, 0.01) * 3600
    print(
        f"[*] Starting scheduled scan for '{args.domain}' every {args.interval_hours} hour(s). "
        "Press Ctrl+C to stop."
    )

    while True:
        started = datetime.now().isoformat(timespec="seconds")
        print(f"\n=== Scan started at {started} ===")
        results = run_scan(args.domain, words, ports, output)
        print_summary(results)
        print(f"[+] Report written to: {output.resolve()}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
