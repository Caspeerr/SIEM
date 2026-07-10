from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

from db.models import Base, LogEntryModel, AlertModel
from core.log_entry import LogEntry
from core.alert import Alert


class Database:
    # WHAT: Creates the database connection and prepares sessions.
    # WHY: Every function needs a way to communicate with the database,
    # so we set it up once when the Database object is created.
    def __init__(self, db_url: str = "sqlite:///siem.db"):
        self.engine = create_engine(db_url)

        # WHAT: Creates the database tables if they don't already exist.
        # WHY: This means we don't have to manually create tables every time.
        Base.metadata.create_all(self.engine)

        # WHAT: Creates a session factory.
        # WHY: A session is how SQLAlchemy reads from and writes to the database.
        self.Session = sessionmaker(bind=self.engine)

    # WHAT: Saves parsed log entries into the database.
    # WHY: Keeping the logs in the database lets us search, analyze,
    # and display them later.
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

            # WHAT: Saves all new log entries.
            # WHY: Without commit(), nothing is actually written to the database.
            session.commit()

        finally:
            # WHAT: Closes the database session.
            # WHY: Frees resources and prevents connection leaks.
            session.close()

    # WHAT: Saves generated alerts into the database.
    # WHY: This keeps a permanent record of detected security incidents.
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

            # WHAT: Writes the alerts into the database.
            # WHY: Makes the alerts available for reports and dashboards.
            session.commit()

        finally:
            session.close()

    # WHAT: Retrieves the most recent alerts.
    # WHY: Lets the program display the latest detected threats first.
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

    # WHAT: Retrieves the most recent log entries.
    # WHY: Useful for reviewing recent activity.
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

    # WHAT: Counts how many alerts exist for each severity level.
    # WHY: Gives a quick overview of how many LOW, MEDIUM,
    # HIGH, or CRITICAL alerts have been detected.
    def get_alert_counts_by_severity(self):
        session = self.Session()

        try:
            rows = session.query(AlertModel.severity).all()

            counts = {}

            # WHAT: Counts each severity level.
            # WHY: SQL returns every severity separately, so we count
            # how many times each one appears.
            for (sev,) in rows:
                counts[sev] = counts.get(sev, 0) + 1

            return counts

        finally:
            session.close()

    # WHAT: Finds the IP addresses with the most failed login attempts.
    # WHY: Helps identify the most suspicious or active attackers.
    def get_top_offending_ips(self, limit: int = 5):
        session = self.Session()

        try:
            rows = (
                session.query(LogEntryModel.ip)

                # WHAT: Only selects failed logins.
                # WHY: Successful logins are not suspicious for this report.
                .filter(LogEntryModel.success == False)

                .all()
            )

            counts = {}

            # WHAT: Counts failures for each IP.
            # WHY: We want to know which IPs failed the most.
            for (ip,) in rows:
                counts[ip] = counts.get(ip, 0) + 1

            # WHAT: Sorts IPs from highest to lowest failure count.
            # WHY: This makes the worst offenders appear first.
            sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)

            # WHAT: Returns only the top IPs.
            # WHY: Showing every IP would be unnecessary; we only need
            # the most suspicious ones.
            return sorted_ips[:limit]

        finally:
            session.close()