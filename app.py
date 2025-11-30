"""NetProbe — Network Analysis & Monitoring Toolkit."""

import streamlit as st
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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


def main():
    render_header()
    st.info("Tools coming soon...")


if __name__ == "__main__":
    main()
