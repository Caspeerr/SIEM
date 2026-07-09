from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class LogEntryModel(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    user = Column(String(100), nullable=False)
    ip = Column(String(50), nullable=False)
    success = Column(Boolean, nullable=False)
    raw_line = Column(Text, nullable=False)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    generated_at = Column(DateTime, default=datetime.now, nullable=False)
    related_count = Column(Integer, default=0)
