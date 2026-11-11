"""Core scanner logic: port parsing, TCP connect scan, banner grabbing."""
import errno
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import List, Optional, Set

from .services import COMMON_PORTS, service_name

# Plain-HTTP ports that answer a HEAD request. 8443 is a TLS port, so it is not asked in clear text.
HTTP_PORTS = {80, 8000, 8080}
MAX_PORT = 65535
RESERVED_FDS = 32       # file descriptors left for stdout, the output file, the interpreter ...


@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed"
    service: str
    banner: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _port_number(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise ValueError(f"Not a port number: {text!r}") from None
    if not 1 <= port <= MAX_PORT:
        raise ValueError(f"Port must be between 1 and {MAX_PORT}: {port}")
    return port


def parse_ports(spec: str) -> List[int]:
    """Turns '22,80,100-110' or 'common' into a sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, last = part.split("-", 1)
            # Both ends are checked BEFORE the range is built: "1-999999999" must not eat the memory.
            start, end = _port_number(first.strip()), _port_number(last.strip())
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_port_number(part))
    if not ports:
        raise ValueError("No ports given (examples: 22,80 or 1-1024 or common)")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolves a hostname to an IP address. IPv4 is preferred when a name has both."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Host not found: {target}") from exc
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    return str(infos[0][4][0])


def clean_banner(text: str) -> str:
    """A banner is whatever the remote side chooses to send. Only printable characters are kept,
    so it cannot send escape codes to the terminal the result is shown in."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Tries to read a banner from an open port."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        text = data.decode("utf-8", errors="replace").strip()
        return clean_banner(text.splitlines()[0][:120]) if text else None
    except (socket.timeout, OSError):
        return None


def scan_port(host: str, port: int, timeout: float = 1.0,
              banner: bool = False) -> PortResult:
    """Checks a single port with a TCP connect. host is an IPv4 or IPv6 address."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            info = grab_banner(sock, port) if banner else None
            return PortResult(port, "open", service_name(port), info)
        return PortResult(port, "closed", service_name(port))
    except OSError as exc:
        if exc.errno in (errno.EMFILE, errno.ENFILE):
            raise       # out of file descriptors: "closed" would be a wrong answer, so stop instead
        return PortResult(port, "closed", service_name(port))
    finally:
        if sock is not None:
            sock.close()


def usable_threads(requested: int) -> int:
    """Every probe holds one socket, so more threads than free file descriptors only causes errors."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            return requested
    except (ImportError, ValueError, OSError):      # Windows has no resource module
        return requested
    return max(1, min(requested, soft - RESERVED_FDS))


def scan(host: str, ports: List[int], threads: int = 100,
         timeout: float = 1.0, banner: bool = False) -> List[PortResult]:
    """Scans the ports in parallel and returns only the open ones."""
    if threads < 1:
        raise ValueError("threads must be at least 1")
    if timeout <= 0:
        # settimeout(0) makes the socket non-blocking, and every port would look closed
        raise ValueError("timeout must be greater than 0")
    with ThreadPoolExecutor(max_workers=usable_threads(threads)) as pool:
        results = pool.map(lambda p: scan_port(host, p, timeout, banner), ports)
        return [r for r in results if r.state == "open"]
