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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice

PROBE_PORTS = (22, 80, 443, 445, 3389, 8080)
PROBE_TIMEOUT = 0.5
REVERSE_DNS_TIMEOUT = 3.0
MAX_WORKERS = 256
# Addresses probed per wave. Waves keep memory flat whatever the range size,
# and give the caller a point to report progress and to stop.
WAVE_SIZE = MAX_WORKERS
DNS_WORKERS = 32

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


def address_count(net: ipaddress.IPv4Network) -> int:
    """How many addresses :func:`discover_hosts` probes: all of them but the
    network and broadcast addresses, except on a /31 or /32."""
    return net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses


ProgressCallback = Callable[[int, list[dict]], None]
StopCheck = Callable[[], bool]


def discover_hosts(
    net: ipaddress.IPv4Network,
    *,
    on_progress: ProgressCallback | None = None,
    should_stop: StopCheck | None = None,
) -> list[dict]:
    """Return the live hosts of ``net`` as ``[{"ip": ..., "hostname": ...}]``,
    sorted by address. ``hostname`` is None when no reverse DNS record exists.

    The range is probed wave by wave (:data:`WAVE_SIZE` addresses). After each
    wave, ``on_progress(probed, hosts)`` receives the number of addresses
    probed so far and the live hosts found so far. Before each wave,
    ``should_stop()`` may end the run: the hosts found so far are returned."""
    addresses = net.hosts() if net.num_addresses > 2 else iter(net)
    hosts: list[dict] = []
    probed = 0

    probes = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    lookups = ThreadPoolExecutor(max_workers=DNS_WORKERS)
    try:
        while not (should_stop and should_stop()):
            wave = [str(a) for a in islice(addresses, WAVE_SIZE)]
            if not wave:
                break
            alive = [ip for ip, ok in zip(wave, probes.map(_probe, wave)) if ok]
            names = _reverse_dns_all(lookups, alive)
            hosts.extend({"ip": ip, "hostname": names[ip]} for ip in alive)
            probed += len(wave)
            if on_progress:
                on_progress(probed, list(hosts))
    finally:
        probes.shutdown(wait=False, cancel_futures=True)
        lookups.shutdown(wait=False, cancel_futures=True)

    # Waves follow the address order, so ``hosts`` is already sorted.
    return hosts


def _reverse_dns_all(pool: ThreadPoolExecutor, ips: list[str]) -> dict[str, str | None]:
    names: dict[str, str | None] = {ip: None for ip in ips}
    futures = {pool.submit(_reverse_dns, ip): ip for ip in ips}
    try:
        for fut in as_completed(futures, timeout=REVERSE_DNS_TIMEOUT):
            names[futures[fut]] = fut.result()
    except TimeoutError:
        # Some reverse lookups are slow; keep the names we already have.
        for fut in futures:
            fut.cancel()
    return names
