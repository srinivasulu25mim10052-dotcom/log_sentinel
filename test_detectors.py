"""
Unit tests for anomaly and security threat detectors.

Python Essentials Demonstrated:
- Stateful detector simulation
- Temporal window validation
- Exception asserting
- Pattern matching verification
"""

import unittest
from datetime import datetime, timedelta
from sentinel.detectors import (
    BruteForceDetector,
    ErrorSpikeDetector,
    PerformanceDetector,
    SecurityThreatDetector,
)
from sentinel.exceptions import InvalidThresholdError
from sentinel.models import LogEntry, Severity


class TestDetectors(unittest.TestCase):

    def test_brute_force_detector_triggers_incident(self) -> None:
        detector = BruteForceDetector(threshold_attempts=3, window_seconds=30)
        base_time = datetime(2026, 9, 29, 12, 0, 0)
        ip = "198.51.100.9"

        # Generate 3 failed login attempts within 10 seconds
        for i in range(3):
            entry = LogEntry(
                ip=ip,
                timestamp=base_time + timedelta(seconds=i * 3),
                method="POST",
                path="/api/login",
                status_code=401,
                response_size=50,
            )
            detector.process(entry)

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, Severity.HIGH)
        self.assertEqual(inc.source_ip, ip)
        self.assertIn("Brute-Force", inc.title)

    def test_brute_force_invalid_threshold_raises_error(self) -> None:
        with self.assertRaises(InvalidThresholdError):
            BruteForceDetector(threshold_attempts=1)

    def test_error_spike_detector(self) -> None:
        detector = ErrorSpikeDetector(min_requests_in_bucket=5, error_rate_threshold=0.40)
        t = datetime(2026, 9, 29, 15, 30, 10)

        # 3 successes and 3 failures in same minute = 50% error rate (> 40%)
        for i in range(3):
            detector.process(LogEntry(ip="1.1.1.1", timestamp=t, method="GET", path="/api", status_code=200, response_size=10))
        for i in range(3):
            detector.process(LogEntry(ip="1.1.1.1", timestamp=t, method="POST", path="/api/checkout", status_code=500, response_size=10))

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 1)
        self.assertIn("HTTP 5xx Server Outage Spike", incidents[0].title)

    def test_security_threat_detector_patterns(self) -> None:
        detector = SecurityThreatDetector()
        now = datetime.now()

        # Path traversal
        e1 = LogEntry(ip="10.0.0.1", timestamp=now, method="GET", path="/download?file=../../etc/passwd", status_code=403, response_size=10)
        # SQL injection
        e2 = LogEntry(ip="10.0.0.2", timestamp=now, method="GET", path="/search?q=1' UNION SELECT username,password FROM users--", status_code=500, response_size=10)
        # Malicious scanner User-Agent
        e3 = LogEntry(ip="10.0.0.3", timestamp=now, method="GET", path="/admin", status_code=404, response_size=10, user_agent="Nikto/2.1.6")

        detector.process(e1)
        detector.process(e2)
        detector.process(e3)

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 3)

        titles = [inc.title for inc in incidents]
        self.assertTrue(any("Directory Traversal" in t for t in titles))
        self.assertTrue(any("SQL Injection" in t for t in titles))
        self.assertTrue(any("Vulnerability Scanner" in t for t in titles))

    def test_performance_detector(self) -> None:
        detector = PerformanceDetector(sla_latency_ms=500.0, min_samples=3)
        now = datetime.now()

        # Slow endpoint with latencies: 600ms, 800ms, 700ms
        for lat in [600.0, 800.0, 700.0]:
            detector.process(
                LogEntry(ip="1.1.1.1", timestamp=now, method="GET", path="/api/heavy-calc", status_code=200, response_size=100, response_time_ms=lat)
            )

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].affected_path, "/api/heavy-calc")
        self.assertIn("Latency SLA", incidents[0].title)


if __name__ == "__main__":
    unittest.main()
