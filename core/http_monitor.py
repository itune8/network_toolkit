"""HTTP endpoint monitoring and health checking."""

import time
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
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:200]

    return result
