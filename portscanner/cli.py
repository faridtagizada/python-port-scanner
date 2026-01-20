"""Command-line interface."""
import argparse
import csv
import json
import sys
import time
from datetime import datetime

from . import __version__
from .scanner import parse_ports, resolve_target, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscanner",
        description="Simple TCP port scanner. Only scan systems you have permission to scan!")
    p.add_argument("target", help="IP address or hostname")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Ports: '22,80', '1-1024' or 'common' (default: 1-1024)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    p.add_argument("-b", "--banner", action="store_true", help="Grab banners")
    p.add_argument("-o", "--output", help="Results file (.json or .csv)")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def print_table(results) -> None:
    print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<16}BANNER")
    print("-" * 60)
    for r in results:
        print(f"{r.port:<8}{r.state:<8}{r.service:<16}{r.banner or ''}")


def save(results, path: str, meta: dict) -> None:
    if path.endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            w.writeheader()
            w.writerows(r.to_dict() for r in results)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**meta, "results": [r.to_dict() for r in results]},
                      f, indent=2, ensure_ascii=False)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        ip = resolve_target(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Target: {args.target} ({ip}) | {len(ports)} ports | {datetime.now():%Y-%m-%d %H:%M:%S}")
    start = time.time()
    try:
        results = scan(ip, ports, args.threads, args.timeout, args.banner)
    except KeyboardInterrupt:
        print("\n[!] Stopped by the user.")
        return 130
    elapsed = time.time() - start

    if results:
        print_table(results)
    else:
        print("No open ports found.")
    print(f"\n[+] Open ports: {len(results)}, time: {elapsed:.2f}s")

    if args.output:
        meta = {"target": args.target, "ip": ip, "scanned_ports": len(ports),
                "duration_sec": round(elapsed, 2),
                "timestamp": datetime.now().isoformat(timespec="seconds")}
        save(results, args.output, meta)
        print(f"[+] Results written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
