import os
import tempfile
import unittest
from unittest.mock import patch

from core.log_viewer import collect_log_files, read_log_tail
from web.app import get_dashboard_log_files


class LogViewerTests(unittest.TestCase):
    def test_collects_log_files_from_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            first_log = os.path.join(tmp_dir, "auth.log")
            nested_dir = os.path.join(tmp_dir, "nested")
            os.makedirs(nested_dir, exist_ok=True)
            second_log = os.path.join(nested_dir, "system.log")

            with open(first_log, "w", encoding="utf-8") as handle:
                handle.write("first line\n")
            with open(second_log, "w", encoding="utf-8") as handle:
                handle.write("second line\n")

            files = collect_log_files(tmp_dir)

            self.assertEqual(files, [first_log, second_log])

    def test_read_log_tail_returns_last_lines(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = os.path.join(tmp_dir, "auth.log")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("line 1\nline 2\nline 3\n")

            lines = read_log_tail(log_path, lines=2)

            self.assertEqual(lines, ["line 2", "line 3"])

    def test_dashboard_uses_single_configured_log_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = os.path.join(tmp_dir, "auth.log")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("entry\n")

            with patch.dict(os.environ, {"SIEM_LOG_FILE": log_path}, clear=False):
                self.assertEqual(get_dashboard_log_files(), [log_path])


if __name__ == "__main__":
    unittest.main()
