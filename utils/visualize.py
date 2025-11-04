"""Visualization utilities for NetProbe dashboard."""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


def plot_port_scan_results(results):
    """Visualize port scan results."""
    open_ports = results["open_ports"]
    if not open_ports:
        return None

    df = pd.DataFrame(open_ports)

    fig = go.Figure(go.Bar(
        x=[f"{r['port']} ({r['service']})" for r in open_ports],
        y=[r["response_ms"] for r in open_ports],
        marker_color="#e74c3c",
        text=[f"{r['response_ms']}ms" for r in open_ports],
        textposition="outside",
    ))
    fig.update_layout(
        xaxis_title="Port (Service)",
        yaxis_title="Response Time (ms)",
        margin=dict(t=30, b=30),
        height=350,
    )
    return fig


def plot_port_summary(results):
    """Pie chart of port states."""
    labels = ["Open", "Closed", "Filtered"]
    values = [results["open"], results["closed"], results["filtered"]]
    colors = ["#e74c3c", "#2ecc71", "#f39c12"]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        marker_colors=colors,
        hole=0.4,
        textinfo="label+value",
    ))
    fig.update_layout(
        margin=dict(t=30, b=30, l=30, r=30),
        height=300,
    )
    return fig


def plot_dns_comparison(comparison):
    """Bar chart comparing DNS server response times."""
    servers = list(comparison.keys())
    times = [
        comparison[s].get("response_time_ms", 0)
        for s in servers
    ]
    colors = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12"]

    fig = go.Figure(go.Bar(
        x=servers,
        y=times,
        marker_color=colors[:len(servers)],
        text=[f"{t:.1f}ms" if t else "N/A" for t in times],
        textposition="outside",
    ))
    fig.update_layout(
        xaxis_title="DNS Server",
        yaxis_title="Response Time (ms)",
        margin=dict(t=30, b=30),
        height=300,
    )
    return fig
