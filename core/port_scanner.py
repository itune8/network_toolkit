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

WELL_KNOWN_PORTS = list(range(1, 1025))
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 27017,
    1433, 1521, 2049, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 5001,
    5060, 5061, 5222, 5269, 5432, 5984, 6379, 6667, 7001, 7002, 8000,
    8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8180, 8443, 8880, 8888, 9000, 9090, 9200, 9300, 10000, 10443,
    11211, 27017, 27018, 28017, 50000, 50070,
]


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


def resolve_host(host):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None

