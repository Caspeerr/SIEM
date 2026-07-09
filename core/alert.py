from dataclasses import dataclass, field
from datetime import datetime

from core.log_entry import LogEntry


@dataclass
class Alert:
    rule_name: str
    severity: str
    description: str
    related_entries: list[LogEntry] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)

    def __repr__(self):
        return f"[{self.severity}] {self.rule_name}: {self.description}"
