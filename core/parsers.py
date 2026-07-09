import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from core.log_entry import LogEntry


class LogParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        raise NotImplementedError

    def parse_file(self, filepath: str) -> list[LogEntry]:
        entries = []
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
        return entries


class AuthLogParser(LogParser):
    LINE_RE = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
        r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
        r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+\s+ssh2"
    )

    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = self.LINE_RE.match(line)
        if not match:
            return None

        data = match.groupdict()
        timestamp = datetime.strptime(
            f"{datetime.now().year} {data['month']} {data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S",
        )

        return LogEntry(
            timestamp=timestamp,
            user=data["user"],
            ip=data["ip"],
            success=(data["status"] == "Accepted"),
            raw_line=line,
        )
