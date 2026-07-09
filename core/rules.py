from abc import ABC, abstractmethod
from collections import defaultdict

from core.log_entry import LogEntry
from core.alert import Alert


class DetectionRule(ABC):
    @abstractmethod
    def evaluate(self, entries: list[LogEntry]) -> list[Alert]:
        raise NotImplementedError


class BruteForceRule(DetectionRule):
    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        failures_by_ip = defaultdict(list)

        for entry in entries:
            if not entry.success:
                failures_by_ip[entry.ip].append(entry)

        for ip, fails in failures_by_ip.items():
            fails.sort(key=lambda e: e.timestamp)
            for i in range(len(fails)):
                window = [
                    e for e in fails[i:]
                    if (e.timestamp - fails[i].timestamp).total_seconds() <= self.window_seconds
                ]
                if len(window) >= self.threshold:
                    alerts.append(Alert(
                        rule_name="BruteForceRule",
                        severity="HIGH",
                        description=(
                            f"{len(window)} failed logins from {ip} "
                            f"within {self.window_seconds}s (target user(s): "
                            f"{', '.join(sorted(set(e.user for e in window)))})"
                        ),
                        related_entries=window,
                    ))
                    break
        return alerts


class RepeatedAuthFailureRule(DetectionRule):
    def __init__(self, threshold: int = 4):
        self.threshold = threshold

    def evaluate(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        failures_by_user = defaultdict(list)

        for entry in entries:
            if not entry.success:
                failures_by_user[entry.user].append(entry)

        for user, fails in failures_by_user.items():
            distinct_ips = set(e.ip for e in fails)
            if len(distinct_ips) >= self.threshold:
                alerts.append(Alert(
                    rule_name="RepeatedAuthFailureRule",
                    severity="MEDIUM",
                    description=(
                        f"User '{user}' targeted from {len(distinct_ips)} "
                        f"distinct IPs ({len(fails)} failed attempts total)"
                    ),
                    related_entries=fails,
                ))
        return alerts


class UnauthorizedAccessRule(DetectionRule):
    def __init__(self, min_prior_failures: int = 3):
        self.min_prior_failures = min_prior_failures

    def evaluate(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        sorted_entries = sorted(entries, key=lambda e: e.timestamp)
        failures_by_ip = defaultdict(list)

        for entry in sorted_entries:
            if not entry.success:
                failures_by_ip[entry.ip].append(entry)
                continue

            prior_failures = failures_by_ip.get(entry.ip, [])
            if len(prior_failures) >= self.min_prior_failures:
                alerts.append(Alert(
                    rule_name="UnauthorizedAccessRule",
                    severity="CRITICAL",
                    description=(
                        f"Successful login for '{entry.user}' from {entry.ip} "
                        f"after {len(prior_failures)} prior failed attempts — "
                        f"possible compromised account"
                    ),
                    related_entries=prior_failures + [entry],
                ))
        return alerts
