"""NetProbe — Network Analysis & Monitoring Toolkit."""

import streamlit as st
import pandas as pd
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dns_analyzer import resolve_dns, full_dns_report, reverse_lookup, compare_dns_servers, RECORD_TYPES

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
        st.subheader("Port Scanner")
    with tab3:
        st.subheader("HTTP Endpoint Monitor")
    with tab4:
        st.subheader("Subnet Calculator")
    with tab5:
        st.subheader("Traceroute & Ping")

    st.divider()
    st.caption("NetProbe v1.0 | Network Analysis & Monitoring Toolkit")


if __name__ == "__main__":
    main()
