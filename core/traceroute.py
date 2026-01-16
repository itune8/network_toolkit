"""Traceroute implementation using UDP/ICMP sockets."""

import socket
import struct
import time
import select


def traceroute(dest, max_hops=30, timeout=2, port=33434):
    """Perform a traceroute to the destination host.

    Uses UDP probes with increasing TTL values. Falls back to
    TCP connect if raw sockets are unavailable (unprivileged mode).
    """
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


def _probe_hop(dest_ip, ttl, timeout, port):
    """Send a single probe with given TTL."""
    try:
        return _udp_probe(dest_ip, ttl, timeout, port)
    except (PermissionError, OSError):
        return _tcp_probe(dest_ip, ttl, timeout)


def _udp_probe(dest_ip, ttl, timeout, port):
    """UDP-based traceroute probe."""
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_sock.settimeout(timeout)

    start = time.time()
    send_sock.sendto(b"", (dest_ip, port))

    try:
        data, addr = recv_sock.recvfrom(512)
        elapsed = (time.time() - start) * 1000
        hop_ip = addr[0]

        try:
            hostname = socket.gethostbyaddr(hop_ip)[0]
        except socket.herror:
            hostname = hop_ip

        return {
            "ttl": ttl,
            "ip": hop_ip,
            "hostname": hostname,
            "rtt_ms": round(elapsed, 2),
            "reached": hop_ip == dest_ip,
        }
    except socket.timeout:
        return {"ttl": ttl, "ip": "*", "hostname": "*", "rtt_ms": None,
                "reached": False}
    finally:
        send_sock.close()
        recv_sock.close()


def _tcp_probe(dest_ip, ttl, timeout):
    """TCP connect-based traceroute probe (unprivileged fallback)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)

    start = time.time()
    try:
        sock.connect((dest_ip, 80))
        elapsed = (time.time() - start) * 1000
        sock.close()

        try:
            hostname = socket.gethostbyaddr(dest_ip)[0]
        except socket.herror:
            hostname = dest_ip

        return {
            "ttl": ttl,
            "ip": dest_ip,
            "hostname": hostname,
            "rtt_ms": round(elapsed, 2),
            "reached": True,
        }
    except socket.timeout:
        return {"ttl": ttl, "ip": "*", "hostname": "*", "rtt_ms": None,
                "reached": False}
    except OSError:
        return {"ttl": ttl, "ip": "*", "hostname": "*", "rtt_ms": None,
                "reached": False}
    finally:
        sock.close()


def ping(host, count=4, timeout=2):
    """Simple connectivity check using TCP connect to port 80/443."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"status": "error", "error": f"Cannot resolve: {host}"}

    results = []
    for port in [80, 443]:
        rtts = []
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            try:
                sock.connect((ip, port))
                elapsed = (time.time() - start) * 1000
                rtts.append(round(elapsed, 2))
                sock.close()
            except (socket.timeout, OSError):
                rtts.append(None)
            finally:
                sock.close()

        successful = [r for r in rtts if r is not None]
        if successful:
            results.append({
                "port": port,
                "sent": count,
                "received": len(successful),
                "lost": count - len(successful),
                "min_ms": round(min(successful), 2),
                "max_ms": round(max(successful), 2),
                "avg_ms": round(sum(successful) / len(successful), 2),
                "rtts": rtts,
            })

    if not results:
        return {"host": host, "ip": ip, "status": "unreachable"}

    best = min(results, key=lambda r: r["avg_ms"])
    return {
        "host": host,
        "ip": ip,
        "status": "reachable",
        "port": best["port"],
        "sent": best["sent"],
        "received": best["received"],
        "packet_loss": f"{(best['lost'] / best['sent']) * 100:.0f}%",
        "min_ms": best["min_ms"],
        "max_ms": best["max_ms"],
        "avg_ms": best["avg_ms"],
        "rtts": best["rtts"],
    }

