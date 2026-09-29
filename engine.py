"""
Core Orchestration Engine for LogSentinel.

Python Essentials Demonstrated:
- Composition and Strategy design patterns
- Generator consumption and streaming pipeline
- Exception handling and error tolerance thresholds
- Collections (collections.Counter, collections.defaultdict)
- Context managers (ExecutionTimer) and decorators (@timing, @audit_log)
- Polymorphism over registered parsers and detectors
"""

from collections import Counter
from pathlib import Path
from typing import List, Optional, Sequence, Union

from sentinel.context import ExecutionTimer
from sentinel.decorators import audit_log, timing
from sentinel.detectors import (
    BaseDetector,
    BruteForceDetector,
    ErrorSpikeDetector,
    PerformanceDetector,
    SecurityThreatDetector,
)
from sentinel.exceptions import CorruptLogFormatError, UnsupportedFormatError
from sentinel.models import Incident, IncidentCollection, LogEntry, MetricSummary
from sentinel.parsers import BaseLogParser, CombinedLogParser, JsonLogParser
from sentinel.storage import stream_log_lines


class SentinelEngine:
    """
    Main orchestration engine that processes log streams through configured
    parsers and anomaly detectors, returning aggregated metrics and incident collections.
    """

    def __init__(
        self,
        parser: Optional[BaseLogParser] = None,
        detectors: Optional[Sequence[BaseDetector]] = None,
        max_corrupt_ratio: float = 0.50,
    ) -> None:
        self.parser = parser or CombinedLogParser()
        self.detectors: List[BaseDetector] = (
            list(detectors)
            if detectors is not None
            else [
                BruteForceDetector(),
                ErrorSpikeDetector(),
                SecurityThreatDetector(),
                PerformanceDetector(),
            ]
        )
        self.max_corrupt_ratio = max_corrupt_ratio
        self.last_execution_time: float = 0.0

    def register_detector(self, detector: BaseDetector) -> None:
        """Dynamically attach a custom detection rule to the engine."""
        self.detectors.append(detector)

    @audit_log("Analyze Log File")
    def analyze_file(
        self,
        file_path: Union[str, Path],
    ) -> tuple[MetricSummary, IncidentCollection]:
        """
        Streams and analyzes a log file, returning (MetricSummary, IncidentCollection).

        Demonstrates:
        - Memory-efficient streaming generator
        - Line-by-line parsing and detector dispatch
        - Measuring run time with ExecutionTimer
        """
        path = Path(file_path)

        # Reset all detectors for a clean run
        for detector in self.detectors:
            detector.reset()

        total_lines = 0
        parsed_entries = 0
        malformed_lines = 0

        status_counter: Counter[int] = Counter()
        ip_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        total_bytes = 0
        latencies: List[float] = []

        with ExecutionTimer("Log Analysis") as timer:
            # Consume lazy generator line-by-line
            for line_no, raw_line in stream_log_lines(path):
                total_lines += 1
                try:
                    entry = self.parser.parse_line(raw_line, line_number=line_no)
                except Exception:
                    malformed_lines += 1
                    continue

                if entry is None:
                    continue  # Comment or whitespace

                parsed_entries += 1
                status_counter[entry.status_code] += 1
                ip_counter[entry.ip] += 1
                path_counter[entry.path] += 1
                total_bytes += entry.response_size
                if entry.response_time_ms > 0:
                    latencies.append(entry.response_time_ms)

                # Feed entry through all active polymorphic detectors
                for detector in self.detectors:
                    detector.process(entry)

        self.last_execution_time = timer.elapsed

        # Check corruption ratio guardrail
        if total_lines > 10 and (malformed_lines / total_lines) > self.max_corrupt_ratio:
            raise CorruptLogFormatError(
                f"Log file '{path.name}' had {malformed_lines}/{total_lines} unparseable lines "
                f"({(malformed_lines / total_lines) * 100:.1f}%), exceeding tolerance of {self.max_corrupt_ratio * 100:.0f}%. "
                f"Check that parser '{self.parser.format_name}' matches the file structure."
            )

        # Finalize incidents from all detectors
        incidents = IncidentCollection()
        for detector in self.detectors:
            for inc in detector.finalize():
                incidents.add(inc)

        summary = MetricSummary(
            total_requests=parsed_entries,
            status_counts=dict(status_counter),
            total_bytes=total_bytes,
            response_times_ms=latencies,
            malformed_lines=malformed_lines,
        )

        return summary, incidents

    @classmethod
    def get_parser_by_name(cls, name: str) -> BaseLogParser:
        """
        Factory method to instantiate a parser by keyword.
        Demonstrates match / case syntax.
        """
        match name.lower():
            case "combined" | "nginx" | "apache":
                return CombinedLogParser()
            case "json" | "microservice" | "cloud":
                return JsonLogParser()
            case _:
                raise UnsupportedFormatError(
                    f"Unknown parser format '{name}'. Supported formats: combined, json."
                )
