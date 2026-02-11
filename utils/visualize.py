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


def plot_traceroute(hops):
    """Visualize traceroute path with latencies."""
    valid_hops = [h for h in hops if h["rtt_ms"] is not None]
    if not valid_hops:
        return None

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=list(range(1, len(hops) + 1)),
        y=[h["rtt_ms"] if h["rtt_ms"] else 0 for h in hops],
        mode="lines+markers",
        marker=dict(
            size=12,
            color=[h["rtt_ms"] if h["rtt_ms"] else 0 for h in hops],
            colorscale="RdYlGn_r",
            showscale=True,
            colorbar=dict(title="RTT (ms)"),
        ),
        text=[f"{h['hostname']}<br>{h['ip']}<br>{h['rtt_ms']}ms"
              if h["rtt_ms"] else f"Hop {h['ttl']}: * (timeout)"
              for h in hops],
        hoverinfo="text",
        line=dict(color="#3498db", width=2),
    ))

    fig.update_layout(
        xaxis_title="Hop Number",
        yaxis_title="Round Trip Time (ms)",
        margin=dict(t=30, b=30),
        height=350,
    )
    return fig


def plot_ping_results(ping_result):
    """Visualize ping RTT times."""
    rtts = ping_result.get("rtts", [])
    if not rtts:
        return None

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=list(range(1, len(rtts) + 1)),
        y=[r if r else 0 for r in rtts],
        mode="lines+markers",
        marker=dict(size=10, color="#3498db"),
        line=dict(color="#3498db", width=2),
    ))

    avg = ping_result.get("avg_ms", 0)
    fig.add_hline(y=avg, line_dash="dash", line_color="red",
                  annotation_text=f"Avg: {avg}ms")

    fig.update_layout(
        xaxis_title="Probe #",
        yaxis_title="RTT (ms)",
        margin=dict(t=30, b=30),
        height=250,
    )
    return fig


def plot_security_score(score, present, total):
    """Gauge chart for security header score."""
    color = "#2ecc71" if score >= 70 else "#f39c12" if score >= 40 else "#e74c3c"

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        title={"text": f"Security Headers ({present}/{total})"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 40], "color": "#fadbd8"},
                {"range": [40, 70], "color": "#fdebd0"},
                {"range": [70, 100], "color": "#d5f5e3"},
            ],
        },
    ))
    fig.update_layout(
        margin=dict(t=60, b=30),
        height=280,
    )
    return fig

