"""
Outage & Error Spike Detector.

Python Essentials Demonstrated:
- collections.defaultdict for temporal bucketing (by minute/hour)
- Datetime manipulation (truncation to minute bins)
- Ratio and percentage calculations
- Pattern matching (match/case) for severity assignment
- Dictionary comprehensions
"""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

from sentinel.models import Incident, LogEntry, Severity
from .base import BaseDetector


class ErrorSpikeDetector(BaseDetector):
    """
    Detects sudden surges in HTTP 5xx server errors across rolling time buckets.

    Real-World Scenario:
    A database pool exhaustion or broken deploy starts returning 500/502/503 errors
    affecting legitimate users.
    """

    def __init__(
        self,
        min_requests_in_bucket: int = 5,
        error_rate_threshold: float = 0.25,  # 25% errors triggers alert
    ) -> None:
        super().__init__("ErrorSpikeDetector")
        self.min_requests = min_requests_in_bucket
        self.error_rate_threshold = error_rate_threshold

        # Bucket key: datetime truncated to minute -> [total_requests, server_errors]
        self._buckets: Dict[datetime, List[int]] = defaultdict(lambda: [0, 0])
        # Track path breakdown per minute bucket
        self._path_errors: Dict[datetime, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def process(self, entry: LogEntry) -> None:
        """
        Aggregates traffic into 1-minute time bins.
        """
        # Truncate to the nearest minute
        bucket_time = entry.timestamp.replace(second=0, microsecond=0)
        bucket = self._buckets[bucket_time]
        bucket[0] += 1  # Total requests

        if entry.is_server_error:
            bucket[1] += 1  # 5xx error
            self._path_errors[bucket_time][entry.path] += 1

    def finalize(self) -> List[Incident]:
        """
        Analyzes aggregated time buckets to identify intervals with abnormal error spikes.
        Demonstrates pattern matching for severity determination.
        """
        for bucket_time, (total, errors) in sorted(self._buckets.items()):
            if total < self.min_requests:
                continue

            error_rate = errors / total
            if error_rate >= self.error_rate_threshold:
                error_pct = error_rate * 100.0

                # Pattern matching (match/case) for severity classification
                match error_rate:
                    case r if r >= 0.50:
                        sev = Severity.CRITICAL
                    case r if r >= 0.30:
                        sev = Severity.HIGH
                    case _:
                        sev = Severity.MEDIUM

                top_affected_paths = sorted(
                    self._path_errors[bucket_time].items(),
                    key=lambda item: item[1],
                    reverse=True
                )[:3]

                path_summary = ", ".join(f"{p} ({cnt} errors)" for p, cnt in top_affected_paths) or "Various"

                incident = Incident(
                    id=f"INC-ERR-{len(self._incidents) + 1:03d}",
                    rule_name=self.name,
                    severity=sev,
                    title=f"HTTP 5xx Server Outage Spike ({error_pct:.1f}% error rate)",
                    description=(
                        f"At {bucket_time.strftime('%Y-%m-%d %H:%M')}, recorded {errors} server errors "
                        f"out of {total} requests ({error_pct:.1f}% failure rate)."
                    ),
                    timestamp=bucket_time,
                    affected_path=top_affected_paths[0][0] if top_affected_paths else "/",
                    evidence=[
                        f"Time Window: {bucket_time.strftime('%Y-%m-%d %H:%M:%S')} UTC",
                        f"Total Requests: {total}",
                        f"5xx Failures: {errors}",
                        f"Top Failing Endpoints: {path_summary}",
                    ],
                    remediation=(
                        "Inspect application backend logs, database connection pools, "
                        "and upstream microservice dependencies for outages."
                    ),
                )
                self._incidents.append(incident)

        return list(self._incidents)

    def reset(self) -> None:
        super().reset()
        self._buckets.clear()
        self._path_errors.clear()
