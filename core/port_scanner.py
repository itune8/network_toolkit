"""TCP port scanner with service detection."""

import socket
import time

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
