"""NetProbe — Network Analysis & Monitoring Toolkit."""

import streamlit as st
import pandas as pd
import socket
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dns_analyzer import resolve_dns, full_dns_report, reverse_lookup, compare_dns_servers, RECORD_TYPES
from core.traceroute import traceroute, ping
from core.subnet_calc import calculate_subnet, get_ip_info, check_ip_in_subnet, split_subnet
from core.http_monitor import check_endpoint, get_response_headers_analysis
from core.port_scanner import scan_ports, resolve_host, COMMON_PORTS, TOP_100_PORTS
from utils.visualize import (
    plot_port_scan_results, plot_port_summary, plot_dns_comparison,
    plot_traceroute, plot_ping_results, plot_security_score,
)

st.set_page_config(
    page_title="NetProbe",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_header():
    st.markdown("""
    <div style='text-align: center; padding: 1rem 0;'>
        <h1 style='color: #2c3e50; margin-bottom: 0;'>NetProbe</h1>
        <p style='color: #7f8c8d; font-size: 1.2rem;'>
            Network Analysis & Monitoring Toolkit
        </p>
    </div>
    """, unsafe_allow_html=True)


def render_dns_tab():
    st.subheader("DNS Lookup & Analysis")

    col1, col2 = st.columns([2, 1])
    with col1:
        domain = st.text_input("Domain", "google.com", key="dns_domain")
    with col2:
        mode = st.selectbox("Mode", ["Single Record", "Full Report", "Compare DNS Servers", "Reverse Lookup"])

    if mode == "Single Record":
        record_type = st.selectbox("Record Type", RECORD_TYPES)
        if st.button("Lookup", type="primary", key="dns_lookup"):
            with st.spinner("Resolving..."):
                result = resolve_dns(domain, record_type)

            if result["status"] == "success":
                st.success(f"Resolved in {result['response_time_ms']}ms")
                for rec in result["records"]:
                    cols = st.columns([3, 1])
                    cols[0].code(rec["value"])
                    cols[1].caption(f"TTL: {rec['ttl']}s")
            else:
                st.error(result["error"])

    elif mode == "Full Report":
        if st.button("Get Full DNS Report", type="primary", key="dns_full"):
            with st.spinner("Querying all record types..."):
                report = full_dns_report(domain)

            if report:
                for rtype, result in report.items():
                    with st.expander(f"{rtype} Records ({len(result['records'])} found)", expanded=True):
                        for rec in result["records"]:
                            st.code(rec["value"])
            else:
                st.warning("No DNS records found for this domain.")

    elif mode == "Compare DNS Servers":
        if st.button("Compare DNS Servers", type="primary", key="dns_compare"):
            with st.spinner("Querying DNS servers..."):
                comparison = compare_dns_servers(domain)

            fig = plot_dns_comparison(comparison)
            st.plotly_chart(fig, use_container_width=True)

            for name, result in comparison.items():
                if result["status"] == "success":
                    st.success(f"**{name}** ({result['server']}): {result['response_time_ms']}ms → {', '.join(result['ips'])}")
                else:
                    st.error(f"**{name}** ({result['server']}): {result.get('error', 'Failed')}")

    elif mode == "Reverse Lookup":
        ip = st.text_input("IP Address", "8.8.8.8", key="dns_reverse_ip")
        if st.button("Reverse Lookup", type="primary", key="dns_reverse"):
            with st.spinner("Looking up..."):
                result = reverse_lookup(ip)
            if result["status"] == "success":
                st.success(f"**{ip}** → {result['hostname']}")
            else:
                st.error(result["error"])


def render_port_scanner_tab():
    st.subheader("Port Scanner")

    col1, col2 = st.columns([2, 1])
    with col1:
        host = st.text_input("Target Host", "scanme.nmap.org", key="port_host")
    with col2:
        scan_type = st.selectbox("Scan Type", [
            "Common Ports (20)", "Top 100 Ports", "Custom Range",
        ])

    if scan_type == "Custom Range":
        range_col1, range_col2 = st.columns(2)
        start_port = range_col1.number_input("Start Port", 1, 65535, 1)
        end_port = range_col2.number_input("End Port", 1, 65535, 1024)
        ports = list(range(start_port, end_port + 1))
    elif scan_type == "Top 100 Ports":
        ports = TOP_100_PORTS
    else:
        ports = list(COMMON_PORTS.keys())

    if st.button("Scan Ports", type="primary", key="port_scan"):
        resolved = resolve_host(host)
        if not resolved:
            st.error(f"Cannot resolve hostname: {host}")
            return

        st.info(f"Scanning **{host}** ({resolved}) — {len(ports)} ports...")
        progress = st.progress(0)

        with st.spinner("Scanning..."):
            results = scan_ports(host, ports, progress_callback=progress.progress)

        progress.empty()

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Scanned", results["total_scanned"])
        m2.metric("Open", results["open"], delta=None)
        m3.metric("Closed", results["closed"])
        m4.metric("Filtered", results["filtered"])

        if results["open_ports"]:
            st.markdown("### Open Ports")
            df = pd.DataFrame(results["open_ports"])
            st.dataframe(df[["port", "service", "state", "response_ms", "banner"]],
                         use_container_width=True)

            col_a, col_b = st.columns(2)
            with col_a:
                fig = plot_port_scan_results(results)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
            with col_b:
                fig = plot_port_summary(results)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No open ports found.")


def render_http_tab():
    st.subheader("HTTP Endpoint Monitor")

    url = st.text_input("URL", "https://google.com", key="http_url")

    if st.button("Check Endpoint", type="primary", key="http_check"):
        with st.spinner("Checking..."):
            result = check_endpoint(url)

        if result["status"] == "up":
            st.success(f"**Status:** UP — HTTP {result['status_code']} in {result['response_time_ms']}ms")
        elif result["status"] == "down":
            st.error(f"**Status:** DOWN — {result['error']}")
        else:
            st.warning(f"**Status:** {result['status'].upper()} — {result.get('error', '')}")

        if result["status"] == "up":
            m1, m2, m3 = st.columns(3)
            m1.metric("Response Time", f"{result['response_time_ms']}ms")
            m2.metric("Status Code", result['status_code'])
            m3.metric("Content Size", f"{result['content_length']:,} bytes")

            tab_ssl, tab_headers, tab_security = st.tabs([
                "SSL Certificate", "Response Headers", "Security Analysis",
            ])

            with tab_ssl:
                ssl_info = result.get("ssl")
                if ssl_info and ssl_info.get("valid"):
                    st.success("SSL certificate is valid")
                    info_df = pd.DataFrame([{
                        "Subject": ssl_info["subject"],
                        "Issuer": ssl_info["issuer"],
                        "Valid From": ssl_info["not_before"],
                        "Valid Until": ssl_info["not_after"],
                        "Protocol": ssl_info["version"],
                    }]).T
                    info_df.columns = ["Value"]
                    st.table(info_df)
                elif ssl_info:
                    st.error(f"SSL issue: {ssl_info.get('error', 'Unknown')}")
                else:
                    st.info("No SSL (HTTP connection)")

            with tab_headers:
                if result["headers"]:
                    header_df = pd.DataFrame(
                        list(result["headers"].items()),
                        columns=["Header", "Value"],
                    )
                    st.dataframe(header_df, use_container_width=True)

            with tab_security:
                if result["headers"]:
                    analysis = get_response_headers_analysis(result["headers"])
                    fig = plot_security_score(
                        analysis["score"], analysis["present"], analysis["total"],
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    for name, info in analysis["headers"].items():
                        if info["present"]:
                            st.success(f"**{name}** — {info['description']}")
                        else:
                            icon = "🔴" if info["severity"] == "high" else "🟡"
                            st.warning(f"{icon} **{name}** missing — {info['description']}")

            if result["redirects"]:
                with st.expander("Redirect Chain"):
                    for i, r in enumerate(result["redirects"]):
                        st.write(f"{i + 1}. `{r['status_code']}` → {r['url']}")


def render_subnet_tab():
    st.subheader("Subnet Calculator")

    mode = st.selectbox("Mode", ["Subnet Calculator", "IP Info", "IP in Subnet Check", "Subnet Splitter"])

    if mode == "Subnet Calculator":
        cidr = st.text_input("CIDR Notation", "192.168.1.0/24", key="subnet_cidr")
        if st.button("Calculate", type="primary", key="subnet_calc"):
            result = calculate_subnet(cidr)
            if result["status"] == "success":
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    | Property | Value |
                    |----------|-------|
                    | **Network** | `{result['network']}` |
                    | **Broadcast** | `{result['broadcast']}` |
                    | **Netmask** | `{result['netmask']}` |
                    | **Wildcard** | `{result['wildcard']}` |
                    | **CIDR** | `{result['cidr']}` |
                    """)
                with col2:
                    st.markdown(f"""
                    | Property | Value |
                    |----------|-------|
                    | **Total Hosts** | `{result['total_hosts']:,}` |
                    | **Usable Hosts** | `{result['usable_hosts']:,}` |
                    | **First Host** | `{result['first_host']}` |
                    | **Last Host** | `{result['last_host']}` |
                    | **Private** | `{result['is_private']}` |
                    """)
            else:
                st.error(result["error"])

    elif mode == "IP Info":
        ip = st.text_input("IP Address", "192.168.1.1", key="ip_info")
        if st.button("Analyze", type="primary", key="ip_analyze"):
            result = get_ip_info(ip)
            if result["status"] == "success":
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    | Property | Value |
                    |----------|-------|
                    | **IP** | `{result['ip']}` |
                    | **Version** | IPv{result['version']} |
                    | **Private** | {result['is_private']} |
                    | **Global** | {result['is_global']} |
                    | **Loopback** | {result['is_loopback']} |
                    | **Multicast** | {result['is_multicast']} |
                    """)
                with col2:
                    st.code(result["binary"], language=None)
                    st.caption("Binary representation")
                    st.code(result["reverse_pointer"], language=None)
                    st.caption("Reverse DNS pointer")
            else:
                st.error(result["error"])

    elif mode == "IP in Subnet Check":
        col1, col2 = st.columns(2)
        ip = col1.text_input("IP Address", "192.168.1.50", key="ip_check")
        cidr = col2.text_input("Subnet CIDR", "192.168.1.0/24", key="cidr_check")
        if st.button("Check", type="primary", key="ip_subnet_check"):
            result = check_ip_in_subnet(ip, cidr)
            if result["status"] == "success":
                if result["belongs"]:
                    st.success(f"`{ip}` belongs to subnet `{result['subnet']}`")
                else:
                    st.error(f"`{ip}` does NOT belong to subnet `{result['subnet']}`")
            else:
                st.error(result["error"])

    elif mode == "Subnet Splitter":
        col1, col2 = st.columns(2)
        cidr = col1.text_input("CIDR to Split", "10.0.0.0/16", key="split_cidr")
        new_prefix = col2.number_input("New Prefix Length", 1, 32, 24, key="split_prefix")
        if st.button("Split Subnet", type="primary", key="split_btn"):
            result = split_subnet(cidr, new_prefix)
            if result["status"] == "success":
                st.info(f"Split `{result['original']}` into **{result['num_subnets']}** /{new_prefix} subnets")
                df = pd.DataFrame(result["subnets"])
                st.dataframe(df, use_container_width=True, height=400)
            else:
                st.error(result["error"])


def render_traceroute_tab():
    st.subheader("Traceroute & Ping")

    col1, col2 = st.columns([2, 1])
    with col1:
        host = st.text_input("Target Host", "google.com", key="trace_host")
    with col2:
        mode = st.selectbox("Mode", ["Ping", "Traceroute"])

    if mode == "Ping":
        count = st.slider("Probe Count", 1, 10, 4, key="ping_count")
        if st.button("Ping", type="primary", key="ping_btn"):
            with st.spinner(f"Pinging {host}..."):
                result = ping(host, count=count)

            if result["status"] == "reachable":
                st.success(f"**{host}** ({result['ip']}) is reachable via port {result['port']}")

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Min RTT", f"{result['min_ms']}ms")
                m2.metric("Avg RTT", f"{result['avg_ms']}ms")
                m3.metric("Max RTT", f"{result['max_ms']}ms")
                m4.metric("Packet Loss", result['packet_loss'])

                fig = plot_ping_results(result)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.error(f"**{host}** is unreachable")

    elif mode == "Traceroute":
        max_hops = st.slider("Max Hops", 5, 30, 20, key="trace_hops")
        if st.button("Trace Route", type="primary", key="trace_btn"):
            with st.spinner(f"Tracing route to {host} (max {max_hops} hops)..."):
                result = traceroute(host, max_hops=max_hops)

            if result["status"] == "success":
                if result["reached"]:
                    st.success(f"Reached **{host}** in {result['total_hops']} hops")
                else:
                    st.warning(f"Did not reach destination within {max_hops} hops")

                hop_data = []
                for h in result["hops"]:
                    hop_data.append({
                        "Hop": h["ttl"],
                        "IP": h["ip"],
                        "Hostname": h["hostname"],
                        "RTT (ms)": h["rtt_ms"] if h["rtt_ms"] else "* (timeout)",
                    })
                st.dataframe(pd.DataFrame(hop_data), use_container_width=True)

                fig = plot_traceroute(result["hops"])
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.error(result.get("error", "Traceroute failed"))


def main():
    render_header()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔎 DNS Lookup",
        "🔓 Port Scanner",
        "🌐 HTTP Monitor",
        "📐 Subnet Calculator",
        "📡 Traceroute & Ping",
    ])

    with tab1:
        render_dns_tab()
    with tab2:
        render_port_scanner_tab()
    with tab3:
        render_http_tab()
    with tab4:
        render_subnet_tab()
    with tab5:
        render_traceroute_tab()

    st.divider()
    st.caption("NetProbe v1.0 | Network Analysis & Monitoring Toolkit")


if __name__ == "__main__":
    main()

