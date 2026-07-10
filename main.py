import argparse
import os

from rich.console import Console
from rich.table import Table

from core.parsers import AuthLogParser
from core.rules import BruteForceRule, RepeatedAuthFailureRule, UnauthorizedAccessRule
from core.engine import SIEMEngine
from core.log_viewer import collect_log_files
from db.database import Database

# WHAT: Creates a Rich console for colorful terminal output.
# WHY: Makes alerts and messages easier to read.
console = Console()

# WHAT: Default folder containing log files.
# WHY: Used if the user doesn't provide another log path.
DEFAULT_LOG_FILE = "logs"


# WHAT: Builds and returns the SIEM engine.
# WHY: This puts together the parser, detection rules,
# and database into one object that can analyze logs.
def build_engine() -> SIEMEngine:
    parser = AuthLogParser()

    rules = [
        BruteForceRule(threshold=10, window_seconds=60),
        RepeatedAuthFailureRule(threshold=4),
        UnauthorizedAccessRule(min_prior_failures=3),
    ]

    db = Database()

    return SIEMEngine(parser, rules, db)


# WHAT: Displays detected alerts in a table.
# WHY: Makes the results easy to read in the terminal.
def print_alerts(alerts):

    # WHAT: Checks if any alerts were found.
    # WHY: Displays a friendly message instead of an empty table.
    if not alerts:
        console.print("[yellow]No alerts triggered.[/yellow]")
        return

    table = Table(title=f"{len(alerts)} Alert(s) Triggered")

    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Description")
    table.add_column("Related", justify="right")

    # WHAT: Assigns a color to each severity level.
    # WHY: Makes important alerts stand out.
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green"
    }

    # WHAT: Adds each alert to the table.
    # WHY: Displays all detected alerts neatly.
    for alert in alerts:
        color = severity_colors.get(alert.severity, "white")

        table.add_row(
            f"[{color}]{alert.severity}[/{color}]",
            alert.rule_name,
            alert.description,
            str(len(alert.related_entries)),
        )

    console.print(table)


# WHAT: Performs one-time analysis of the log files.
# WHY: Reads the logs, runs all detection rules,
# and displays the detected alerts.
def run_batch(log_path: str):

    engine = build_engine()

    files = collect_log_files(log_path)

    # WHAT: Checks if any log files were found.
    # WHY: Prevents the program from trying to analyze
    # files that don't exist.
    if not files:
        console.print(
            f"[red]No log files found at {log_path}. "
            "Make sure the path exists and contains .log files.[/red]"
        )
        return

    console.print(
        f"[cyan]Parsing and analyzing {len(files)} log file(s)...[/cyan]"
    )

    alerts = engine.process_batch_files(files)

    print_alerts(alerts)

    console.print("[green]Results saved to siem.db[/green]")


# WHAT: Starts the web dashboard.
# WHY: Lets the user view alerts, charts,
# and log previews in a web browser.
def run_serve(log_file: str = "logs"):

    console.print(
        "[cyan]Starting dashboard at http://127.0.0.1:5000 ...[/cyan]"
    )

    os.environ["SIEM_LOG_FILE"] = log_file

    from web.app import app

    app.run(debug=True, port=5000)


# WHAT: Reads command-line options and runs the
# selected program mode.
# WHY: Lets the user choose between batch analysis
# and the web dashboard.
def main():

    parser = argparse.ArgumentParser(
        description="Basic SIEM system"
    )

    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run one-time batch analysis"
    )

    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the Flask + Plotly dashboard"
    )

    parser.add_argument(
        "--log-file",
        type=str,
        default=DEFAULT_LOG_FILE,
        help="Path to a .log file or logs directory to analyze",
    )

    args = parser.parse_args()

    # WHAT: Creates the log folder if it doesn't exist.
    # WHY: Prevents errors when the specified folder
    # has not been created yet.
    log_dir = os.path.dirname(args.log_file)

    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # WHAT: Runs the selected mode.
    # WHY: Only one mode should run at a time.
    if args.batch:
        run_batch(args.log_file)

    elif args.serve:
        run_serve(args.log_file)

    else:
        parser.print_help()


# WHAT: Starts the program.
# WHY: Calls the main function only when this file
# is run directly.
if __name__ == "__main__":
    main()