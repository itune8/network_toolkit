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
