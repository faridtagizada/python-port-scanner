"""Core scanner logic: port parsing, TCP connect scan, banner grabbing."""
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import List, Optional

from .services import COMMON_PORTS, service_name

HTTP_PORTS = {80, 8000, 8080, 8443}


@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed"
    service: str
    banner: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def parse_ports(spec: str) -> List[int]:
    """Turns '22,80,100-110' or 'common' into a list of ports."""
    spec = spec.strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {p}")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolves a hostname to an IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Host not found: {target}") from exc


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Tries to read a banner from an open port."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        text = data.decode("utf-8", errors="replace").strip()
        return text.splitlines()[0][:120] if text else None
    except (socket.timeout, OSError):
        return None


def scan_port(host: str, port: int, timeout: float = 1.0,
              banner: bool = False) -> PortResult:
    """Checks a single port with a TCP connect."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            info = grab_banner(sock, port) if banner else None
            return PortResult(port, "open", service_name(port), info)
        return PortResult(port, "closed", service_name(port))
    except OSError:
        return PortResult(port, "closed", service_name(port))
    finally:
        sock.close()


def scan(host: str, ports: List[int], threads: int = 100,
         timeout: float = 1.0, banner: bool = False) -> List[PortResult]:
    """Scans the ports in parallel and returns only the open ones."""
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda p: scan_port(host, p, timeout, banner), ports)
        return [r for r in results if r.state == "open"]
