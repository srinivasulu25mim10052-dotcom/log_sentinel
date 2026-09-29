"""
Unit tests for log format parsers.

Python Essentials Demonstrated:
- Testing regex parsing and exception handling
- Parameterized test scenarios
- Mocking and edge-case testing
"""

import unittest
from sentinel.exceptions import ParsingError
from sentinel.parsers import CombinedLogParser, JsonLogParser


class TestParsers(unittest.TestCase):

    def setUp(self) -> None:
        self.combined_parser = CombinedLogParser()
        self.json_parser = JsonLogParser()

    def test_parse_valid_combined_line(self) -> None:
        raw = '192.168.1.50 - - [29/Sep/2026:14:30:15 +0000] "GET /api/v1/users HTTP/1.1" 200 4812 "http://ref.com" "Mozilla/5.0" 0.045'
        entry = self.combined_parser.parse_line(raw, line_number=1)

        self.assertIsNotNone(entry)
        assert entry is not None  # type narrowing
        self.assertEqual(entry.ip, "192.168.1.50")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/api/v1/users")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.response_size, 4812)
        self.assertAlmostEqual(entry.response_time_ms, 45.0)
        self.assertEqual(entry.referer, "http://ref.com")

    def test_combined_empty_and_comment_lines(self) -> None:
        self.assertIsNone(self.combined_parser.parse_line(""))
        self.assertIsNone(self.combined_parser.parse_line("   "))
        self.assertIsNone(self.combined_parser.parse_line("# Comment line"))

    def test_combined_malformed_line_raises_parsing_error(self) -> None:
        raw_garbage = "Totally unformatted system crash text without any log structure"
        with self.assertRaises(ParsingError) as ctx:
            self.combined_parser.parse_line(raw_garbage, line_number=42)
        self.assertIn("line 42", str(ctx.exception))

    def test_parse_valid_json_line(self) -> None:
        raw = '{"ip": "10.0.0.1", "timestamp": "2026-09-29T10:00:00Z", "method": "POST", "path": "/login", "status": 401, "bytes": 128, "duration_ms": 15.2, "user_agent": "curl"}'
        entry = self.json_parser.parse_line(raw, line_number=1)

        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.ip, "10.0.0.1")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.path, "/login")
        self.assertEqual(entry.status_code, 401)
        self.assertEqual(entry.response_size, 128)
        self.assertAlmostEqual(entry.response_time_ms, 15.2)

    def test_json_malformed_syntax_raises_parsing_error(self) -> None:
        raw_bad_json = '{"ip": "10.0.0.1", "timestamp": UNQUOTED_VAL}'
        with self.assertRaises(ParsingError):
            self.json_parser.parse_line(raw_bad_json, line_number=10)


if __name__ == "__main__":
    unittest.main()
