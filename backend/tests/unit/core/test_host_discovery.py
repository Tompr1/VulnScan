import socket

import pytest

from app.core import host_discovery
from app.core.host_discovery import NotPrivateNetworkError, parse_private_network


@pytest.mark.parametrize("raw", ["10.0.0.0/8", "172.16.0.0/12", "192.168.3.0/24", "192.168.3.7"])
def test_private_ranges_are_accepted(raw):
    assert parse_private_network(raw).is_private


@pytest.mark.parametrize("raw", ["8.8.8.0/24", "1.1.1.1", "127.0.0.0/8", "169.254.0.0/16"])
def test_public_loopback_and_link_local_are_refused(raw):
    with pytest.raises(NotPrivateNetworkError):
        parse_private_network(raw)


def test_ipv6_is_refused():
    with pytest.raises(NotPrivateNetworkError):
        parse_private_network("fd00::/64")


def test_malformed_range_is_a_value_error():
    with pytest.raises(ValueError):
        parse_private_network("192.168.3.0/99")


def test_probe_sees_a_listening_port_as_alive():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        original = host_discovery.PROBE_PORTS
        host_discovery.PROBE_PORTS = (port,)
        try:
            assert host_discovery._probe("127.0.0.1") is True
        finally:
            host_discovery.PROBE_PORTS = original


def test_probe_sees_a_closed_port_as_alive_when_refused():
    # Nothing listens on this port, so the kernel answers with a refusal:
    # that still proves a host is there.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    original = host_discovery.PROBE_PORTS
    host_discovery.PROBE_PORTS = (port,)
    try:
        assert host_discovery._probe("127.0.0.1") is True
    finally:
        host_discovery.PROBE_PORTS = original


def test_discover_hosts_returns_live_hosts_sorted_with_names(monkeypatch):
    alive = {"192.168.3.12", "192.168.3.2", "192.168.3.100"}
    names = {"192.168.3.2": "routeur.lan"}
    monkeypatch.setattr(host_discovery, "_probe", lambda ip: ip in alive)
    monkeypatch.setattr(host_discovery, "_reverse_dns", lambda ip: names.get(ip))

    hosts = host_discovery.discover_hosts(parse_private_network("192.168.3.0/24"))

    assert hosts == [
        {"ip": "192.168.3.2", "hostname": "routeur.lan"},
        {"ip": "192.168.3.12", "hostname": None},
        {"ip": "192.168.3.100", "hostname": None},
    ]


def test_discover_hosts_skips_network_and_broadcast_addresses(monkeypatch):
    probed = []
    monkeypatch.setattr(host_discovery, "_probe", lambda ip: probed.append(ip) or False)

    host_discovery.discover_hosts(parse_private_network("10.0.0.0/30"))

    assert probed == ["10.0.0.1", "10.0.0.2"]
