"""Traceroute implementation using UDP/ICMP sockets."""

import socket
import time


def traceroute(dest, max_hops=30, timeout=2, port=33434):
    """Perform a traceroute to the destination host."""
    try:
        dest_ip = socket.gethostbyname(dest)
    except socket.gaierror:
        return {"status": "error", "error": f"Cannot resolve hostname: {dest}"}

    hops = []
    reached = False

    for ttl in range(1, max_hops + 1):
        hop = _probe_hop(dest_ip, ttl, timeout, port)
        hops.append(hop)

        if hop.get("reached"):
            reached = True
            break

    return {
        "destination": dest,
        "destination_ip": dest_ip,
        "hops": hops,
        "reached": reached,
        "total_hops": len(hops),
        "status": "success",
    }
