# Basic SIEM

A Python OOP-based Security Information and Event Management (SIEM) system.
Parses auth logs, detects suspicious activity (brute-force, repeated auth
failures, unauthorized access), stores results in SQLite, and visualizes
alerts on a Flask + Plotly dashboard.

## Structure

```
siem/
├── core/
│   ├── log_entry.py     # LogEntry data class
│   ├── parsers.py       # LogParser (ABC) + AuthLogParser
│   ├── rules.py         # DetectionRule (ABC) + BruteForceRule, RepeatedAuthFailureRule, UnauthorizedAccessRule
│   ├── alert.py         # Alert data class
│   └── engine.py        # SIEMEngine: batch processing + real-time monitoring
├── db/
│   ├── models.py         # SQLAlchemy models (LogEntryModel, AlertModel)
│   └── database.py       # Database wrapper class
├── web/
│   ├── app.py             # Flask dashboard
│   └── templates/
│       └── dashboard.html
├── logs/                  # put your downloaded log file(s) here
├── main.py                 # CLI entry point
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Parse and analyze a downloaded auth log
python main.py --batch --log-file logs/auth.log

# Monitor a downloaded auth log file in real time
python main.py --watch --log-file logs/auth.log

# Launch the dashboard
python main.py --serve
# then open http://127.0.0.1:5000
```

## Extending

- **New log format**: subclass `LogParser` in `core/parsers.py`, implement `parse_line()`.
- **New detection**: subclass `DetectionRule` in `core/rules.py`, implement `evaluate()`.
- Both plug straight into `SIEMEngine` — no changes needed elsewhere.
