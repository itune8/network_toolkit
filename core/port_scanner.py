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
            return {
                "port": port,
                "state": "open",
                "service": service,
                "response_ms": round(elapsed, 2),
            }
        return {"port": port, "state": "closed"}
    except socket.timeout:
        return {"port": port, "state": "filtered"}
    except Exception:
        return {"port": port, "state": "error"}
