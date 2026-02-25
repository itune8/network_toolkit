# NetProbe

Network Analysis & Monitoring Toolkit — a comprehensive suite of networking tools with an interactive web UI.

## Features

- **DNS Lookup & Analysis** — Resolve any DNS record type (A, AAAA, MX, NS, TXT, etc.), full domain reports, reverse lookups, and DNS server comparison across Google/Cloudflare/Quad9/OpenDNS
- **Port Scanner** — Multi-threaded TCP port scanner with service detection and banner grabbing. Supports common ports, top 100, or custom ranges
- **HTTP Endpoint Monitor** — Health checks with SSL certificate validation, response header analysis, redirect chain tracking, and security header scoring
- **Subnet Calculator** — CIDR calculator, IP analysis, subnet membership checks, and subnet splitting
- **Traceroute & Ping** — Network path tracing with hop-by-hop latency visualization and connectivity testing

## Tech Stack

- Python, Streamlit, Plotly, dnspython, Requests

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```
