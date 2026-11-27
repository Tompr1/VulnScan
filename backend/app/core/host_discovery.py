"""
Host discovery for a private IPv4 network.

Discovery only: it answers "which addresses are alive, and what are they
called?". It does not port-scan or fingerprint anything.

A host counts as alive when a TCP connection to one of a few common ports
either succeeds or is actively refused (a RST proves something answered).
That needs no raw sockets, so it works without root, unlike ICMP ping.
Hosts that drop every probe silently are missed; that is a known limit.
"""

import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

PROBE_PORTS = (22, 80, 443, 445, 3389, 8080)
PROBE_TIMEOUT = 0.5
REVERSE_DNS_TIMEOUT = 3.0
MAX_WORKERS = 256

_REFUSED = {errno.ECONNREFUSED, 111, 61}  # 111 = Linux, 61 = macOS/BSD


class NotPrivateNetworkError(ValueError):
    pass


def parse_private_network(raw: str) -> ipaddress.IPv4Network:
    """Parse a CIDR string and make sure it lies in private IPv4 space.

    Raises ValueError on a malformed range and NotPrivateNetworkError on a
    public one. IPv6 is out of scope for now.
    """
    net = ipaddress.ip_network(raw, strict=False)
    if net.version != 4:
        raise NotPrivateNetworkError("Only IPv4 private networks can be discovered")
    if not net.is_private or net.is_loopback or net.is_link_local:
        raise NotPrivateNetworkError(
            "Discovery is limited to private networks (RFC 1918 ranges such as 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
        )
    return net


def _probe(ip: str) -> bool:
    for port in PROBE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PROBE_TIMEOUT)
        try:
            code = sock.connect_ex((ip, port))
            if code == 0 or code in _REFUSED:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def _reverse_dns(ip: str) -> str | None:
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def discover_hosts(net: ipaddress.IPv4Network) -> list[dict]:
    """Return the live hosts of ``net`` as ``[{"ip": ..., "hostname": ...}]``,
    sorted by address. ``hostname`` is None when no reverse DNS record exists."""
    candidates = [str(a) for a in net.hosts()] if net.num_addresses > 2 else [str(a) for a in net]

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        alive = [ip for ip, ok in zip(candidates, pool.map(_probe, candidates)) if ok]

        names: dict[str, str | None] = {ip: None for ip in alive}
        futures = {pool.submit(_reverse_dns, ip): ip for ip in alive}
        try:
            for fut in as_completed(futures, timeout=REVERSE_DNS_TIMEOUT):
                names[futures[fut]] = fut.result()
        except TimeoutError:
            # Some reverse lookups are slow; keep the hosts we already have.
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return [
        {"ip": ip, "hostname": names.get(ip)}
        for ip in sorted(alive, key=lambda s: ipaddress.IPv4Address(s))
    ]
