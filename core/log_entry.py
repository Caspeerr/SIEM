from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry:
    timestamp: datetime
    user: str
    ip: str
    success: bool
    raw_line: str

    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"<LogEntry {self.timestamp} {status} user={self.user} ip={self.ip}>"
