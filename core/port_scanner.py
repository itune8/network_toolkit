"""TCP port scanner with service detection."""

import socket
import time
import concurrent.futures

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def scan_port(host, port, timeout=1.5):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(host, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "response_ms": round(elapsed, 2),
            }
        return {"port": port, "state": "closed"}
    except socket.timeout:
        return {"port": port, "state": "filtered"}
    except Exception:
        return {"port": port, "state": "error"}


def grab_banner(host, port, timeout=2):
    """Attempt to grab service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if port in (80, 8080, 8000, 8443):
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else None
    except Exception:
        return None


def scan_ports(host, ports=None, max_workers=50, timeout=1.5, progress_callback=None):
    """Scan multiple ports concurrently."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results = []
    completed = 0
    total = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            results.append(result)
            completed += 1
            if progress_callback:
                progress_callback(completed / total)

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["state"] == "open"]
    filtered_ports = [r for r in results if r["state"] == "filtered"]

    return {
        "host": host,
        "total_scanned": total,
        "open": len(open_ports),
        "closed": total - len(open_ports) - len(filtered_ports),
        "filtered": len(filtered_ports),
        "results": results,
        "open_ports": open_ports,
    }
