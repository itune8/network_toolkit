"""Subnet calculator and IP address utilities."""

import ipaddress


def calculate_subnet(cidr):
    """Calculate subnet details from CIDR notation."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)

        hosts = list(network.hosts())
        first_host = str(hosts[0]) if hosts else None
        last_host = str(hosts[-1]) if hosts else None

        return {
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "wildcard": str(network.hostmask),
            "cidr": str(network),
            "prefix_length": network.prefixlen,
            "total_hosts": network.num_addresses,
            "usable_hosts": max(0, network.num_addresses - 2),
            "first_host": first_host,
            "last_host": last_host,
            "is_private": network.is_private,
            "is_global": network.is_global,
            "version": network.version,
            "status": "success",
        }
    except ValueError as e:
        return {"status": "error", "error": str(e)}
