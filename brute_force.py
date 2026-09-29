"""
Brute-Force & Credential Stuffing Attack Detector.

Python Essentials Demonstrated:
- collections.deque for sliding time-window buffers
- collections.defaultdict for IP-to-attempt mapping
- datetime.timedelta for temporal threshold comparison
- Custom exception validation (InvalidThresholdError)
- List comprehensions and string formatting
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, List

from sentinel.exceptions import InvalidThresholdError
from sentinel.models import Incident, LogEntry, Severity
from .base import BaseDetector


class BruteForceDetector(BaseDetector):
    """
    Detects repeated failed authentication attempts (HTTP 401 Unauthorized / 403 Forbidden)
    originating from the same IP address within a configurable sliding time window.

    Real-World Scenario:
    Botnets repeatedly try passwords against /login or /api/auth endpoints.
    """

    def __init__(
        self,
        threshold_attempts: int = 5,
        window_seconds: int = 60,
        target_statuses: tuple = (401, 403),
    ) -> None:
        super().__init__("BruteForceDetector")
        if threshold_attempts <= 1:
            raise InvalidThresholdError(
                self.name, "threshold_attempts", threshold_attempts, "Must be greater than 1"
            )
        if window_seconds <= 0:
            raise InvalidThresholdError(
                self.name, "window_seconds", window_seconds, "Must be greater than 0"
            )

        self.threshold = threshold_attempts
        self.window = timedelta(seconds=window_seconds)
        self.target_statuses = target_statuses

        # Mapping of IP -> Deque of (timestamp, path, status_code)
        self._ip_failures: Dict[str, Deque[LogEntry]] = defaultdict(deque)
        # Track IPs that have already been flagged to avoid duplicate alert storms
        self._flagged_ips: set[str] = set()

    def process(self, entry: LogEntry) -> None:
        """
        Processes a log entry, maintaining a sliding window of recent auth failures.
        """
        # Only inspect failed authentication/authorization
        if entry.status_code not in self.target_statuses:
            return

        ip = entry.ip
        history = self._ip_failures[ip]
        history.append(entry)

        # Evict events that fall outside the sliding time window
        current_time = entry.timestamp
        cutoff = current_time - self.window
        while history and history[0].timestamp < cutoff:
            history.popleft()

        # Check if threshold is breached and IP has not yet been flagged
        if len(history) >= self.threshold and ip not in self._flagged_ips:
            self._flagged_ips.add(ip)
            evidence_samples = [
                f"{e.timestamp.strftime('%H:%M:%S')} - {e.method} {e.path} -> {e.status_code}"
                for e in list(history)[:8]
            ]

            incident = Incident(
                id=f"INC-BF-{len(self._incidents) + 1:03d}",
                rule_name=self.name,
                severity=Severity.HIGH,
                title=f"Brute-Force / Credential Stuffing Burst from {ip}",
                description=(
                    f"Detected {len(history)} failed auth requests ({self.target_statuses}) "
                    f"within {self.window.total_seconds():.0f}s from host {ip}."
                ),
                timestamp=current_time,
                source_ip=ip,
                affected_path=entry.path,
                evidence=evidence_samples,
                remediation=(
                    f"Add {ip} to temporary firewall/fail2ban ban list and enforce CAPTCHA "
                    f"or exponential rate limiting on {entry.path}."
                ),
            )
            self._incidents.append(incident)

    def finalize(self) -> List[Incident]:
        """Returns all detected brute-force incidents."""
        return list(self._incidents)

    def reset(self) -> None:
        super().reset()
        self._ip_failures.clear()
        self._flagged_ips.clear()
