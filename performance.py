"""
Latency & Performance Bottleneck Detector.

Python Essentials Demonstrated:
- Built-in statistics module (statistics.mean, statistics.median, statistics.quantiles)
- collections.defaultdict with list values for endpoint latency grouping
- Higher-order functions with lambda sorting keys
- List comprehensions and formatting
"""

from collections import defaultdict
from datetime import datetime
import statistics
from typing import Dict, List

from sentinel.models import Incident, LogEntry, Severity
from .base import BaseDetector


class PerformanceDetector(BaseDetector):
    """
    Analyzes API response latencies per endpoint to identify severe performance degradations.

    Real-World Scenario:
    An unindexed SQL query or third-party API timeout causes /api/checkout or /search
    to exceed service-level objectives (SLAs).
    """

    def __init__(
        self,
        sla_latency_ms: float = 1000.0,  # 1.0 second SLA
        min_samples: int = 3,
    ) -> None:
        super().__init__("PerformanceDetector")
        self.sla_latency_ms = sla_latency_ms
        self.min_samples = min_samples

        # Path -> list of latency floats in ms
        self._endpoint_latencies: Dict[str, List[float]] = defaultdict(list)
        # Path -> latest observed timestamp
        self._endpoint_latest_ts: Dict[str, datetime] = {}

    def process(self, entry: LogEntry) -> None:
        """Collects response times for endpoints with non-zero durations."""
        if entry.response_time_ms > 0:
            self._endpoint_latencies[entry.path].append(entry.response_time_ms)
            self._endpoint_latest_ts[entry.path] = entry.timestamp

    def finalize(self) -> List[Incident]:
        """
        Calculates mean, median, and P95 latency per endpoint using the statistics module.
        """
        for path, latencies in self._endpoint_latencies.items():
            if len(latencies) < self.min_samples:
                continue

            avg_latency = statistics.mean(latencies)
            median_latency = statistics.median(latencies)
            max_latency = max(latencies)

            # Compute P90 / P95 percentile
            if len(latencies) >= 10:
                p90 = statistics.quantiles(latencies, n=10)[8]
            else:
                p90 = max_latency

            # Check if average or P90 breaches the SLA threshold
            if p90 >= self.sla_latency_ms or avg_latency >= self.sla_latency_ms:
                # Severity graduated based on severity of breach
                severity = Severity.HIGH if p90 > (self.sla_latency_ms * 2) else Severity.MEDIUM
                inc_time = self._endpoint_latest_ts.get(path, datetime.now())

                incident = Incident(
                    id=f"INC-PERF-{len(self._incidents) + 1:03d}",
                    rule_name=self.name,
                    severity=severity,
                    title=f"Latency SLA Degradation on {path}",
                    description=(
                        f"Endpoint '{path}' breached the {self.sla_latency_ms:.0f}ms SLA. "
                        f"P90 latency reached {p90:.1f}ms across {len(latencies)} requests."
                    ),
                    timestamp=inc_time,
                    affected_path=path,
                    evidence=[
                        f"Samples Analyzed: {len(latencies)} requests",
                        f"Average Latency: {avg_latency:.2f} ms",
                        f"Median Latency: {median_latency:.2f} ms",
                        f"P90 Latency: {p90:.2f} ms",
                        f"Peak Latency: {max_latency:.2f} ms",
                    ],
                    remediation=(
                        f"Profile endpoint handler for '{path}', inspect database query plans, "
                        "and implement Redis/Memcached response caching."
                    ),
                )
                self._incidents.append(incident)

        return list(self._incidents)

    def reset(self) -> None:
        super().reset()
        self._endpoint_latencies.clear()
        self._endpoint_latest_ts.clear()
