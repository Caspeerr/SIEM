import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template
import plotly.graph_objects as go
import plotly.io as pio

from db.database import Database
from core.log_viewer import discover_log_files, read_log_tail


def get_dashboard_log_files():
    configured_path = os.environ.get("SIEM_LOG_FILE")
    if configured_path:
        return discover_log_files([configured_path])
    return discover_log_files(["logs"])

app = Flask(__name__)
db = Database()


def build_severity_chart():
    counts = db.get_alert_counts_by_severity()
    if not counts:
        counts = {"No alerts yet": 1}
    fig = go.Figure(data=[go.Pie(labels=list(counts.keys()), values=list(counts.values()))])
    fig.update_layout(title="Alerts by Severity", margin=dict(t=40, b=10, l=10, r=10))
    return pio.to_json(fig)


def build_top_ips_chart():
    top_ips = db.get_top_offending_ips(limit=5)
    if not top_ips:
        top_ips = [("No data", 0)]
    ips, counts = zip(*top_ips)
    fig = go.Figure(data=[go.Bar(x=list(ips), y=list(counts))])
    fig.update_layout(title="Top Offending IPs (failed logins)", margin=dict(t=40, b=10, l=10, r=10))
    return pio.to_json(fig)


def build_timeline_chart():
    alerts = db.get_alerts(limit=200)
    if not alerts:
        fig = go.Figure()
        fig.update_layout(title="Alerts Over Time (no data yet)")
        return pio.to_json(fig)

    timestamps = [a.generated_at for a in alerts]
    severities = [a.severity for a in alerts]
    fig = go.Figure(data=[go.Scatter(
        x=timestamps, y=severities, mode="markers",
        marker=dict(size=10),
    )])
    fig.update_layout(title="Alerts Over Time", margin=dict(t=40, b=10, l=10, r=10))
    return pio.to_json(fig)


@app.route("/")
def dashboard():
    alerts = db.get_alerts(limit=50)
    log_files = get_dashboard_log_files()
    log_preview = []
    missing_log_message = None

    if log_files:
        for filepath in log_files[:5]:
            log_preview.append({
                "path": filepath,
                "lines": read_log_tail(filepath, lines=8),
            })
    else:
        configured_path = os.environ.get("SIEM_LOG_FILE")
        missing_log_message = (
            f"No readable log file found at {configured_path or 'the configured path'}. "
            "Please provide a valid .log file path."
        )

    return render_template(
        "dashboard.html",
        alerts=alerts,
        severity_chart=build_severity_chart(),
        top_ips_chart=build_top_ips_chart(),
        timeline_chart=build_timeline_chart(),
        log_files=log_files,
        log_preview=log_preview,
        missing_log_message=missing_log_message,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
