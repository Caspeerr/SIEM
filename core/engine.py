import glob
import os
import time
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.log_entry import LogEntry
from core.parsers import LogParser
from core.alert import Alert


class _TailHandler(FileSystemEventHandler):
    def __init__(self, path: str, on_new_lines):
        self.path = path
        self.on_new_lines = on_new_lines
        self._positions: dict[str, int] = {}

        if os.path.isdir(path):
            for filepath in glob.glob(os.path.join(path, "*.log")):
                self._positions[os.path.abspath(filepath)] = self._current_size(filepath)
        else:
            self._positions[os.path.abspath(path)] = self._current_size(path)

    def _current_size(self, filepath: str) -> int:
        try:
            with open(filepath, "r") as f:
                f.seek(0, 2)
                return f.tell()
        except FileNotFoundError:
            return 0

    def _tail_file(self, filepath: str):
        if os.path.isdir(self.path) and not filepath.endswith(".log"):
            return

        abs_path = os.path.abspath(filepath)
        if abs_path not in self._positions:
            self._positions[abs_path] = self._current_size(abs_path)

        with open(abs_path, "r") as f:
            f.seek(self._positions[abs_path])
            new_lines = f.readlines()
            self._positions[abs_path] = f.tell()

        if new_lines:
            self.on_new_lines(new_lines)

    def _should_handle(self, event_path: str) -> bool:
        if event_path is None:
            return False
        if os.path.isdir(self.path):
            return event_path.endswith(".log")
        return os.path.abspath(event_path) == os.path.abspath(self.path)

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._should_handle(event.src_path):
            self._tail_file(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        if self._should_handle(event.src_path):
            self._tail_file(event.src_path)


class SIEMEngine:
    def __init__(self, parser: LogParser, rules: list, database):
        self.parser = parser
        self.rules = rules
        self.db = database
        self._observer = None
        self._all_entries: list[LogEntry] = []

    def process_batch(self, filepath: str) -> list[Alert]:
        entries = self.parser.parse_file(filepath)
        self.db.save_entries(entries)

        alerts = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(entries))

        self.db.save_alerts(alerts)
        return alerts

    def process_batch_files(self, filepaths: list[str]) -> list[Alert]:
        entries = []
        for filepath in filepaths:
            entries.extend(self.parser.parse_file(filepath))

        self.db.save_entries(entries)

        alerts = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(entries))

        self.db.save_alerts(alerts)
        return alerts

    def _handle_new_lines(self, lines: list[str]):
        new_entries = []
        for line in lines:
            entry = self.parser.parse_line(line.strip())
            if entry:
                new_entries.append(entry)

        if not new_entries:
            return

        self.db.save_entries(new_entries)
        self._all_entries.extend(new_entries)

        alerts = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(self._all_entries))

        new_alerts = [a for a in alerts if a.description not in self._seen_descriptions]
        for a in new_alerts:
            self._seen_descriptions.add(a.description)

        if new_alerts:
            self.db.save_alerts(new_alerts)
            for alert in new_alerts:
                print(f"[ALERT] {alert}")

    def start_monitoring(self, filepath: str):
        """Starts watching filepath or directory in a background thread. Non-blocking."""
        self._seen_descriptions = set()
        handler = _TailHandler(filepath, self._handle_new_lines)
        self._observer = Observer()
        watch_path = filepath if os.path.isdir(filepath) else os.path.dirname(filepath) or "."
        self._observer.schedule(handler, path=watch_path, recursive=False)
        self._observer.start()
        print(f"Monitoring {filepath} for new entries... (Ctrl+C to stop)")

    def stop_monitoring(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
