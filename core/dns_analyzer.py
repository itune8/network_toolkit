"""DNS lookup and analysis module."""

import socket
import time
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
