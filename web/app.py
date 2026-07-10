import sys
import os

# WHAT: Adds the project folder to Python's search path.
# WHY: Allows this file to import modules from other folders
# like 'db' and 'core' without import errors.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template
import plotly.graph_objects as go
import plotly.io as pio

from db.database import Database
from core.log_viewer import discover_log_files, read_log_tail


# WHAT: Finds the log files to display on the dashboard.
# WHY: Uses the log file set by the user if available,
# otherwise looks inside the default "logs" folder.
def get_dashboard_log_files():
    configured_path = os.environ.get("SIEM_LOG_FILE")
    if configured_path:
        return discover_log_files([configured_path])
    return discover_log_files(["logs"])


# WHAT: Creates the Flask web application.
# WHY: Flask runs the dashboard website.
app = Flask(__name__)

# WHAT: Creates a database object.
# WHY: Allows the dashboard to read alerts and log data.
db = Database()


# WHAT: Creates a pie chart showing alert severity.
# WHY: Gives a quick visual summary of how many LOW,
# MEDIUM, HIGH, and CRITICAL alerts were found.
def build_severity_chart():
    counts = db.get_alert_counts_by_severity()

    # WHAT: Shows a placeholder if no alerts exist.
    # WHY: Prevents the chart from being empty.
    if not counts:
        counts = {"No alerts yet": 1}

    fig = go.Figure(data=[
        go.Pie(
            labels=list(counts.keys()),
            values=list(counts.values())
        )
    ])

    fig.update_layout(
        title="Alerts by Severity",
        margin=dict(t=40, b=10, l=10, r=10)
    )

    # WHAT: Converts the chart into JSON.
    # WHY: The dashboard uses this JSON to display the chart.
    return pio.to_json(fig)


# WHAT: Creates a bar chart of the IPs with the most failed logins.
# WHY: Helps quickly identify the most suspicious IP addresses.
def build_top_ips_chart():
    top_ips = db.get_top_offending_ips(limit=5)

    # WHAT: Shows a placeholder if no data exists.
    # WHY: Prevents errors when there are no failed logins.
    if not top_ips:
        top_ips = [("No data", 0)]

    ips, counts = zip(*top_ips)

    fig = go.Figure(data=[
        go.Bar(
            x=list(ips),
            y=list(counts)
        )
    ])

    fig.update_layout(
        title="Top Offending IPs (failed logins)",
        margin=dict(t=40, b=10, l=10, r=10)
    )

    return pio.to_json(fig)


# WHAT: Creates a timeline of when alerts occurred.
# WHY: Lets the user see when suspicious activity happened.
def build_timeline_chart():
    alerts = db.get_alerts(limit=200)

    # WHAT: Shows an empty chart if there are no alerts.
    # WHY: Prevents the dashboard from crashing.
    if not alerts:
        fig = go.Figure()
        fig.update_layout(title="Alerts Over Time (no data yet)")
        return pio.to_json(fig)

    timestamps = [a.generated_at for a in alerts]
    severities = [a.severity for a in alerts]

    fig = go.Figure(data=[
        go.Scatter(
            x=timestamps,
            y=severities,
            mode="markers",
            marker=dict(size=10),
        )
    ])

    fig.update_layout(
        title="Alerts Over Time",
        margin=dict(t=40, b=10, l=10, r=10)
    )

    return pio.to_json(fig)


# WHAT: Creates the dashboard homepage.
# WHY: This function gathers all the data needed to display
# the dashboard in the browser.
@app.route("/")
def dashboard():

    # WHAT: Gets the latest alerts.
    # WHY: Displays recent security alerts on the dashboard.
    alerts = db.get_alerts(limit=50)

    # WHAT: Finds available log files.
    # WHY: Lets the dashboard show a preview of the logs.
    log_files = get_dashboard_log_files()

    log_preview = []
    missing_log_message = None

    if log_files:

        # WHAT: Reads a few lines from each log file.
        # WHY: Gives the user a quick preview without
        # loading the entire file.
        for filepath in log_files[:5]:
            log_preview.append({
                "path": filepath,
                "lines": read_log_tail(filepath, lines=8),
            })

    else:

        # WHAT: Creates an error message.
        # WHY: Informs the user if no log file could be found.
        configured_path = os.environ.get("SIEM_LOG_FILE")
        missing_log_message = (
            f"No readable log file found at {configured_path or 'the configured path'}. "
            "Please provide a valid .log file path."
        )

    # WHAT: Sends all data to the HTML dashboard.
    # WHY: The HTML page uses this data to display alerts,
    # charts, and log previews.
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


# WHAT: Starts the Flask web server.
# WHY: Runs the dashboard so it can be viewed in a web browser.
if __name__ == "__main__":
    app.run(debug=True, port=5000)