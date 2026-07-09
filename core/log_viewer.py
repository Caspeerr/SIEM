import os
from typing import Iterable


def collect_log_files(path: str) -> list[str]:
    """Return all .log files under a directory or a single .log file path."""
    if not path:
        return []

    if os.path.isfile(path):
        return [os.path.abspath(path)] if path.lower().endswith(".log") else []

    if not os.path.isdir(path):
        return []

    files: list[str] = []
    for root, _, filenames in os.walk(path):
        for filename in filenames:
            if filename.lower().endswith(".log"):
                files.append(os.path.abspath(os.path.join(root, filename)))

    return sorted(files)


def discover_log_files(candidate_paths: Iterable[str] | None = None) -> list[str]:
    """Collect log files from a single configured path or a list of explicit paths."""
    if candidate_paths:
        search_roots = list(candidate_paths)
    else:
        configured = os.environ.get("SIEM_LOG_FILE")
        if configured:
            return [os.path.abspath(configured)] if os.path.isfile(configured) else []
        search_roots = ["logs"]

    discovered: list[str] = []
    seen: set[str] = set()

    for root in search_roots:
        for filepath in collect_log_files(root):
            if filepath not in seen:
                seen.add(filepath)
                discovered.append(filepath)

    return sorted(discovered, key=lambda item: os.path.getmtime(item), reverse=True)


def read_log_tail(path: str, lines: int = 50) -> list[str]:
    """Read the last N non-empty lines from a log file."""
    if not path or not os.path.isfile(path):
        return []

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        all_lines = [line.rstrip("\n") for line in handle.readlines()]

    return [line for line in all_lines[-lines:] if line]
