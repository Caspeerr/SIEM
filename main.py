import argparse
import os
import time

from rich.console import Console
from rich.table import Table

from core.parsers import AuthLogParser
from core.rules import BruteForceRule, RepeatedAuthFailureRule, UnauthorizedAccessRule
from core.engine import SIEMEngine
from core.log_viewer import collect_log_files
from db.database import Database

console = Console()
DEFAULT_LOG_FILE = "logs"


def build_engine() -> SIEMEngine:
    parser = AuthLogParser()
    rules = [
        BruteForceRule(threshold=10, window_seconds=60),
        RepeatedAuthFailureRule(threshold=4),
        UnauthorizedAccessRule(min_prior_failures=3),
    ]
    db = Database()
    return SIEMEngine(parser, rules, db)


def print_alerts(alerts):
    if not alerts:
        console.print("[yellow]No alerts triggered.[/yellow]")
        return

    table = Table(title=f"{len(alerts)} Alert(s) Triggered")
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Description")
    table.add_column("Related", justify="right")

    severity_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    for alert in alerts:
        color = severity_colors.get(alert.severity, "white")
        table.add_row(
            f"[{color}]{alert.severity}[/{color}]",
            alert.rule_name,
            alert.description,
            str(len(alert.related_entries)),
        )
    console.print(table)


def run_batch(log_path: str):
    engine = build_engine()
    files = collect_log_files(log_path)
    if not files:
        console.print(f"[red]No log files found at {log_path}. Make sure the path exists and contains .log files.[/red]")
        return

    console.print(f"[cyan]Parsing and analyzing {len(files)} log file(s)...[/cyan]")
    alerts = engine.process_batch_files(files)
    print_alerts(alerts)
    console.print("[green]Results saved to siem.db[/green]")


def run_watch(log_file: str):
    engine = build_engine()
    engine.start_monitoring(log_file)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor...[/yellow]")
        engine.stop_monitoring()


def run_serve(log_file: str = "logs"):
    console.print("[cyan]Starting dashboard at http://127.0.0.1:5000 ...[/cyan]")
    os.environ["SIEM_LOG_FILE"] = log_file
    from web.app import app
    app.run(debug=True, port=5000)


def main():
    parser = argparse.ArgumentParser(description="Basic SIEM system")
    parser.add_argument("--batch", action="store_true", help="Run one-time batch analysis")
    parser.add_argument("--watch", action="store_true", help="Monitor the log file or directory in real time")
    parser.add_argument("--serve", action="store_true", help="Launch the Flask + Plotly dashboard")
    parser.add_argument(
        "--log-file",
        type=str,
        default=DEFAULT_LOG_FILE,
        help="Path to a .log file or logs directory to analyze or monitor",
    )
    args = parser.parse_args()

    log_dir = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    if args.batch:
        run_batch(args.log_file)
    elif args.watch:
        run_watch(args.log_file)
    elif args.serve:
        run_serve(args.log_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
