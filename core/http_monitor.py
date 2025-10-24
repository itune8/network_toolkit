"""HTTP endpoint monitoring and health checking."""

import time
import ssl
import socket
import requests
from urllib.parse import urlparse


def check_endpoint(url, timeout=10):
    """Check HTTP endpoint health and collect metrics."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "status": None,
        "status_code": None,
        "response_time_ms": None,
        "content_length": None,
        "headers": {},
        "redirects": [],
        "ssl": None,
        "error": None,
    }

    try:
        start = time.time()
        response = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "NetProbe/1.0"}
        )
        elapsed = (time.time() - start) * 1000

        result["status"] = "up"
        result["status_code"] = response.status_code
        result["response_time_ms"] = round(elapsed, 2)
        result["content_length"] = len(response.content)
        result["headers"] = dict(response.headers)

        if response.history:
            result["redirects"] = [
                {"url": r.url, "status_code": r.status_code}
                for r in response.history
            ]

    except requests.exceptions.ConnectionError:
        result["status"] = "down"
        result["error"] = "Connection refused or host unreachable"
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = f"Request timed out after {timeout}s"
    except requests.exceptions.SSLError as e:
        result["status"] = "ssl_error"
        result["error"] = f"SSL error: {str(e)[:100]}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:200]

        if url.startswith("https://"):
            result["ssl"] = check_ssl(urlparse(url).hostname)

    return result


def check_ssl(hostname, port=443):
    """Check SSL certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))

                return {
                    "valid": True,
                    "subject": subject.get("commonName", ""),
                    "issuer": issuer.get("organizationName", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "version": ssock.version(),
                    "serial": cert.get("serialNumber", ""),
                }
    except Exception as e:
        return {"valid": False, "error": str(e)[:200]}


def check_multiple_endpoints(urls, timeout=10):
    """Check multiple endpoints and return results."""
    results = []
    for url in urls:
        result = check_endpoint(url, timeout)
        results.append(result)
    return results


def get_response_headers_analysis(headers):
    """Analyze response headers for security best practices."""
    security_headers = {
        "Strict-Transport-Security": {
            "present": False,
            "description": "HSTS — forces HTTPS connections",
            "severity": "high",
        },
        "Content-Security-Policy": {
            "present": False,
            "description": "CSP — prevents XSS and injection attacks",
            "severity": "high",
        },
        "X-Content-Type-Options": {
            "present": False,
            "description": "Prevents MIME-type sniffing",
            "severity": "medium",
        },
        "X-Frame-Options": {
            "present": False,
            "description": "Prevents clickjacking via iframes",
            "severity": "medium",
        },
        "X-XSS-Protection": {
            "present": False,
            "description": "Legacy XSS filter (deprecated but still used)",
            "severity": "low",
        },
        "Referrer-Policy": {
            "present": False,
            "description": "Controls referrer information sent with requests",
            "severity": "low",
        },
        "Permissions-Policy": {
            "present": False,
            "description": "Controls browser feature access (camera, mic, etc.)",
            "severity": "medium",
        },
    }

    for header_name in security_headers:
        if header_name.lower() in {k.lower() for k in headers}:
            security_headers[header_name]["present"] = True
            matched_key = next(
                k for k in headers if k.lower() == header_name.lower()
            )
            security_headers[header_name]["value"] = headers[matched_key]

    present_count = sum(1 for h in security_headers.values() if h["present"])
    total = len(security_headers)
    score = round((present_count / total) * 100)

    return {"headers": security_headers, "score": score,
            "present": present_count, "total": total}
