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


def check_ip_in_subnet(ip, cidr):
    """Check if an IP address belongs to a subnet."""
    try:
        address = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            "ip": ip,
            "subnet": str(network),
            "belongs": address in network,
            "status": "success",
        }
    except ValueError as e:
        return {"status": "error", "error": str(e)}


def get_ip_info(ip):
    """Get information about an IP address."""
    try:
        addr = ipaddress.ip_address(ip)
        return {
            "ip": str(addr),
            "version": addr.version,
            "is_private": addr.is_private,
            "is_global": addr.is_global,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_reserved": addr.is_reserved,
            "is_link_local": addr.is_link_local,
            "reverse_pointer": addr.reverse_pointer,
            "packed": addr.packed.hex(),
            "binary": format(int(addr), f"0{addr.max_prefixlen}b"),
            "status": "success",
        }
    except ValueError as e:
        return {"status": "error", "error": str(e)}


def split_subnet(cidr, new_prefix):
    """Split a subnet into smaller subnets."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if new_prefix <= network.prefixlen:
            return {"status": "error",
                    "error": "New prefix must be larger than current prefix"}

        subnets = list(network.subnets(new_prefix=new_prefix))
        return {
            "original": str(network),
            "new_prefix": new_prefix,
            "num_subnets": len(subnets),
            "subnets": [
                {
                    "network": str(s.network_address),
                    "cidr": str(s),
                    "broadcast": str(s.broadcast_address),
                    "usable_hosts": max(0, s.num_addresses - 2),
                }
                for s in subnets[:50]
            ],
            "status": "success",
        }
    except ValueError as e:
        return {"status": "error", "error": str(e)}
