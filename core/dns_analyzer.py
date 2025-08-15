"""DNS lookup and analysis module."""

import socket
import time
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def resolve_dns(domain, record_type="A", timeout=5):
    """Resolve DNS records for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        start = time.time()
        answers = resolver.resolve(domain, record_type)
        elapsed = (time.time() - start) * 1000

        records = []
        for rdata in answers:
            record = {"value": str(rdata), "ttl": answers.ttl}
            if record_type == "MX":
                record["priority"] = rdata.preference
            records.append(record)

        return {
            "domain": domain,
            "type": record_type,
            "records": records,
            "response_time_ms": round(elapsed, 2),
            "status": "success",
        }
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "type": record_type, "status": "error",
                "error": "Domain not found (NXDOMAIN)"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "type": record_type, "status": "error",
                "error": f"No {record_type} records found"}
    except dns.resolver.Timeout:
        return {"domain": domain, "type": record_type, "status": "error",
                "error": "DNS query timed out"}
    except Exception as e:
        return {"domain": domain, "type": record_type, "status": "error",
                "error": str(e)}


def full_dns_report(domain):
    """Get all available DNS records for a domain."""
    results = {}
    for rtype in RECORD_TYPES:
        result = resolve_dns(domain, rtype)
        if result["status"] == "success":
            results[rtype] = result
    return results


def reverse_lookup(ip):
    """Perform reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": hostname, "status": "success"}
    except socket.herror:
        return {"ip": ip, "status": "error", "error": "No PTR record found"}
    except Exception as e:
        return {"ip": ip, "status": "error", "error": str(e)}


def compare_dns_servers(domain, servers=None):
    """Compare DNS resolution across multiple DNS servers."""
    if servers is None:
        servers = {
            "Google": "8.8.8.8",
            "Cloudflare": "1.1.1.1",
            "Quad9": "9.9.9.9",
            "OpenDNS": "208.67.222.222",
        }

    results = {}
    for name, server_ip in servers.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server_ip]
            resolver.timeout = 5
            resolver.lifetime = 5

            start = time.time()
            answers = resolver.resolve(domain, "A")
            elapsed = (time.time() - start) * 1000

            results[name] = {
                "server": server_ip,
                "ips": [str(r) for r in answers],
                "response_time_ms": round(elapsed, 2),
                "status": "success",
            }
        except Exception as e:
            results[name] = {
                "server": server_ip,
                "status": "error",
                "error": str(e),
                "response_time_ms": None,
            }

    return results
