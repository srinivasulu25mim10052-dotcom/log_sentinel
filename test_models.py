"""
Unit tests for domain models and data structures.

Python Essentials Demonstrated:
- unittest.TestCase subclassing
- Standard assertions (assertEqual, assertTrue, assertFalse, assertIn, assertRaises)
- Verification of dunder methods (__lt__, __len__, __iter__, __getitem__, __contains__, __add__)
"""

import unittest
from datetime import datetime
from sentinel.models import Incident, IncidentCollection, LogEntry, MetricSummary, Severity


class TestModels(unittest.TestCase):

    def test_severity_ordering(self) -> None:
        """Verify severity levels compare naturally using __lt__."""
        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.CRITICAL)
        self.assertFalse(Severity.CRITICAL < Severity.LOW)

    def test_log_entry_properties(self) -> None:
        """Test HTTP status categorization properties."""
        now = datetime.now()
        entry_200 = LogEntry(ip="1.1.1.1", timestamp=now, method="GET", path="/", status_code=200, response_size=100)
        entry_301 = LogEntry(ip="1.1.1.1", timestamp=now, method="GET", path="/", status_code=301, response_size=0)
        entry_404 = LogEntry(ip="1.1.1.1", timestamp=now, method="GET", path="/", status_code=404, response_size=50)
        entry_500 = LogEntry(ip="1.1.1.1", timestamp=now, method="GET", path="/", status_code=500, response_size=200)

        self.assertTrue(entry_200.is_success)
        self.assertFalse(entry_200.is_client_error)

        self.assertTrue(entry_301.is_redirect)
        self.assertTrue(entry_404.is_client_error)
        self.assertTrue(entry_500.is_server_error)

    def test_log_entry_sorting(self) -> None:
        """Test LogEntry natural ordering by timestamp."""
        t1 = datetime(2026, 9, 29, 10, 0, 0)
        t2 = datetime(2026, 9, 29, 10, 5, 0)
        e1 = LogEntry(ip="1.1.1.1", timestamp=t1, method="GET", path="/a", status_code=200, response_size=10)
        e2 = LogEntry(ip="2.2.2.2", timestamp=t2, method="GET", path="/b", status_code=200, response_size=20)

        self.assertTrue(e1 < e2)
        sorted_list = sorted([e2, e1])
        self.assertEqual(sorted_list, [e1, e2])

    def test_incident_collection_dunder_methods(self) -> None:
        """Test container emulation in IncidentCollection."""
        now = datetime.now()
        inc1 = Incident(
            id="INC-001",
            rule_name="TestRule",
            severity=Severity.HIGH,
            title="Incident One",
            description="Desc",
            timestamp=now,
        )
        inc2 = Incident(
            id="INC-002",
            rule_name="TestRule",
            severity=Severity.LOW,
            title="Incident Two",
            description="Desc",
            timestamp=now,
        )

        collection = IncidentCollection([inc1, inc2])

        # Test __len__
        self.assertEqual(len(collection), 2)

        # Test __getitem__ by index and ID
        self.assertEqual(collection[0], inc1)
        self.assertEqual(collection["INC-002"], inc2)
        with self.assertRaises(KeyError):
            _ = collection["NON-EXISTENT"]

        # Test __contains__
        self.assertIn("INC-001", collection)
        self.assertIn(inc2, collection)
        self.assertNotIn("INC-999", collection)

        # Test __iter__
        items = list(collection)
        self.assertEqual(items, [inc1, inc2])

    def test_metric_summary_math_and_addition(self) -> None:
        """Test MetricSummary calculations and __add__ operator overloading."""
        s1 = MetricSummary(
            total_requests=10,
            status_counts={200: 8, 500: 2},
            total_bytes=1000,
            response_times_ms=[10.0, 20.0, 30.0],
            malformed_lines=1,
        )
        s2 = MetricSummary(
            total_requests=10,
            status_counts={200: 9, 404: 1},
            total_bytes=2000,
            response_times_ms=[40.0, 50.0],
            malformed_lines=0,
        )

        # Test calculations
        self.assertEqual(s1.error_count, 2)
        self.assertAlmostEqual(s1.error_rate_percentage, 20.0)
        self.assertAlmostEqual(s1.avg_response_time_ms, 20.0)

        # Test operator overloading s1 + s2
        combined = s1 + s2
        self.assertEqual(combined.total_requests, 20)
        self.assertEqual(combined.total_bytes, 3000)
        self.assertEqual(combined.malformed_lines, 1)
        self.assertEqual(combined.status_counts[200], 17)
        self.assertEqual(combined.status_counts[500], 2)
        self.assertEqual(combined.status_counts[404], 1)
        self.assertEqual(len(combined.response_times_ms), 5)


if __name__ == "__main__":
    unittest.main()
