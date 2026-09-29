"""
Integration tests for SentinelEngine, Storage, and Reporting.

Python Essentials Demonstrated:
- End-to-end integration testing
- File I/O verification with pathlib.Path
- Context manager execution
- Custom exception verification
"""

import tempfile
import unittest
from pathlib import Path

from sentinel.engine import SentinelEngine
from sentinel.exceptions import CorruptLogFormatError, LogFileNotFoundError
from sentinel.parsers import CombinedLogParser, JsonLogParser
from sentinel.reporter import ReportGenerator
from sentinel.storage import atomic_write_text


class TestEngineIntegration(unittest.TestCase):

    def setUp(self) -> None:
        self.sample_dir = Path(__file__).resolve().parent.parent / "sample_data"

    def test_analyze_clean_web_access_log(self) -> None:
        log_file = self.sample_dir / "web_access.log"
        engine = SentinelEngine(parser=CombinedLogParser())
        summary, incidents = engine.analyze_file(log_file)

        self.assertGreater(summary.total_requests, 10)
        self.assertEqual(summary.malformed_lines, 0)
        self.assertIn(200, summary.status_counts)
        # Web access log contains clean traffic
        self.assertEqual(len(incidents), 0)

    def test_analyze_security_incident_log(self) -> None:
        log_file = self.sample_dir / "security_incident.log"
        engine = SentinelEngine(parser=CombinedLogParser())
        summary, incidents = engine.analyze_file(log_file)

        self.assertGreater(len(incidents), 0)
        incident_types = [inc.rule_name for inc in incidents]
        self.assertIn("BruteForceDetector", incident_types)
        self.assertIn("SecurityThreatDetector", incident_types)

    def test_analyze_json_microservice_log(self) -> None:
        log_file = self.sample_dir / "microservice.json"
        engine = SentinelEngine(parser=JsonLogParser())
        summary, incidents = engine.analyze_file(log_file)

        self.assertGreater(summary.total_requests, 5)
        self.assertEqual(summary.malformed_lines, 0)
        self.assertTrue(any("Brute-Force" in inc.title for inc in incidents))

    def test_corrupt_log_format_error(self) -> None:
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as f:
            for _ in range(15):
                f.write("Total garbage corrupt unformatted system line\n")
            temp_path = Path(f.name)

        try:
            engine = SentinelEngine(parser=CombinedLogParser(), max_corrupt_ratio=0.5)
            with self.assertRaises(CorruptLogFormatError):
                engine.analyze_file(temp_path)
        finally:
            temp_path.unlink()

    def test_missing_file_raises_storage_error(self) -> None:
        engine = SentinelEngine()
        with self.assertRaises(LogFileNotFoundError):
            engine.analyze_file("non_existent_file_path_12345.log")

    def test_report_generation_formats(self) -> None:
        log_file = self.sample_dir / "security_incident.log"
        engine = SentinelEngine(parser=CombinedLogParser())
        summary, incidents = engine.analyze_file(log_file)

        # Terminal format
        term_out = ReportGenerator.render_terminal_dashboard(
            summary, incidents.sorted_by_severity(), "test.log", engine.last_execution_time
        )
        self.assertIn("LOGSENTINEL INCIDENT & SECURITY INVESTIGATION REPORT", term_out)

        # Markdown format
        md_out = ReportGenerator.render_markdown(
            summary, incidents.sorted_by_severity(), "test.log"
        )
        self.assertIn("# LogSentinel Security & Incident Diagnostic Report", md_out)
        self.assertIn("## Executive Traffic Summary", md_out)

        # JSON format
        json_out = ReportGenerator.render_json(
            summary, incidents.sorted_by_severity(), "test.log"
        )
        self.assertIn('"engine": "LogSentinel v1.0.0"', json_out)

    def test_atomic_write_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "sub" / "report.md"
            content = "# Sample Report Content"
            saved_path = atomic_write_text(target, content)

            self.assertTrue(saved_path.is_file())
            self.assertEqual(saved_path.read_text(encoding="utf-8"), content)


if __name__ == "__main__":
    unittest.main()
