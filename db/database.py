from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

from db.models import Base, LogEntryModel, AlertModel
from core.log_entry import LogEntry
from core.alert import Alert


class Database:
    def __init__(self, db_url: str = "sqlite:///siem.db"):
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_entries(self, entries: list[LogEntry]):
        if not entries:
            return
        session = self.Session()
        try:
            for e in entries:
                session.add(LogEntryModel(
                    timestamp=e.timestamp,
                    user=e.user,
                    ip=e.ip,
                    success=e.success,
                    raw_line=e.raw_line,
                ))
            session.commit()
        finally:
            session.close()

    def save_alerts(self, alerts: list[Alert]):
        if not alerts:
            return
        session = self.Session()
        try:
            for a in alerts:
                session.add(AlertModel(
                    rule_name=a.rule_name,
                    severity=a.severity,
                    description=a.description,
                    generated_at=a.generated_at,
                    related_count=len(a.related_entries),
                ))
            session.commit()
        finally:
            session.close()

    def get_alerts(self, limit: int = 100):
        session = self.Session()
        try:
            return (
                session.query(AlertModel)
                .order_by(desc(AlertModel.generated_at))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_entries(self, limit: int = 500):
        session = self.Session()
        try:
            return (
                session.query(LogEntryModel)
                .order_by(desc(LogEntryModel.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_alert_counts_by_severity(self):
        session = self.Session()
        try:
            rows = session.query(AlertModel.severity).all()
            counts = {}
            for (sev,) in rows:
                counts[sev] = counts.get(sev, 0) + 1
            return counts
        finally:
            session.close()

    def get_top_offending_ips(self, limit: int = 5):
        session = self.Session()
        try:
            rows = (
                session.query(LogEntryModel.ip)
                .filter(LogEntryModel.success == False)
                .all()
            )
            counts = {}
            for (ip,) in rows:
                counts[ip] = counts.get(ip, 0) + 1
            sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:limit]
        finally:
            session.close()
