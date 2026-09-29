"""
Domain Models and Data Structures for LogSentinel.

Python Essentials Demonstrated:
- Enums (enum.Enum) with custom properties
- Dataclasses (@dataclass, field, default_factory)
- Encapsulation using @property getters
- Dunder (magic) methods:
    * __repr__, __str__ (string representation)
    * __eq__, __hash__ (equality and hashing)
    * __lt__ (rich comparison for natural sorting)
    * __add__ (operator overloading for metric aggregation)
    * __len__, __iter__, __getitem__, __contains__ (custom container emulation)
- Modern typing: Optional, Union, Sequence, TypeVar
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import statistics
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


def _normalize_dt(dt: datetime) -> datetime:
    """Helper to safely compare offset-naive and offset-aware datetimes."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class Severity(Enum):
    """
    Severity levels for detected incidents.

    Demonstrates:
    - Enum definition and ordering
    - Custom methods and properties on Enum members
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for sorting and comparison."""
        mapping = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return mapping[self]

    @property
    def ansi_color(self) -> str:
        """ANSI escape code for terminal color highlighting."""
        colors = {
            Severity.LOW: "\033[94m",       # Blue
            Severity.MEDIUM: "\033[93m",    # Yellow
            Severity.HIGH: "\033[91m",      # Red
            Severity.CRITICAL: "\033[1;91m" # Bold Red
        }
        return colors.get(self, "\033[0m")

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level < other.level


@dataclass
class LogEntry:
    """
    Represents a single parsed log transaction.

    Demonstrates:
    - @dataclass with typed attributes
    - @property getters for derived status categorization
    - Dunder methods __lt__ (sorting) and __str__
    """
    ip: str
    timestamp: datetime
    method: str
    path: str
    status_code: int
    response_size: int
    response_time_ms: float = 0.0
    user_agent: str = ""
    referer: str = "-"
    raw_line: str = ""

    @property
    def is_success(self) -> bool:
        """True if status code is in 2xx range."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """True if status code is in 3xx range."""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """True if status code is in 4xx range."""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """True if status code is in 5xx range."""
        return 500 <= self.status_code < 600

    def __lt__(self, other: "LogEntry") -> bool:
        """Natural sorting orders entries by timestamp."""
        if not isinstance(other, LogEntry):
            return NotImplemented
        return _normalize_dt(self.timestamp) < _normalize_dt(other.timestamp)

    def __str__(self) -> str:
        return f"{self.ip} [{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] \"{self.method} {self.path}\" {self.status_code}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry into serializable dictionary."""
        return {
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time_ms": self.response_time_ms,
            "user_agent": self.user_agent,
            "referer": self.referer,
        }


@dataclass
class Incident:
    """
    Represents an actionable security threat or operational incident.

    Demonstrates:
    - Severity ranking and sorting with __lt__
    - List formatting and serialization
    """
    id: str
    rule_name: str
    severity: Severity
    title: str
    description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    affected_path: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    remediation: str = "Review traffic and verify endpoint security controls."

    def __lt__(self, other: "Incident") -> bool:
        """Sort by severity descending, then by timestamp descending."""
        if not isinstance(other, Incident):
            return NotImplemented
        if self.severity != other.severity:
            return self.severity.level > other.severity.level  # higher severity first
        return _normalize_dt(self.timestamp) > _normalize_dt(other.timestamp)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "affected_path": self.affected_path,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class IncidentCollection:
    """
    Custom container for incidents demonstrating Python container emulation.

    Demonstrates:
    - __len__: len(collection)
    - __iter__: for incident in collection
    - __getitem__: collection[0] or collection["INC-001"]
    - __contains__: "INC-001" in collection or incident in collection
    """

    def __init__(self, items: Optional[Sequence[Incident]] = None) -> None:
        self._incidents: List[Incident] = list(items) if items else []
        self._id_index: Dict[str, Incident] = {inc.id: inc for inc in self._incidents}

    def add(self, incident: Incident) -> None:
        self._incidents.append(incident)
        self._id_index[incident.id] = incident

    def __len__(self) -> int:
        return len(self._incidents)

    def __iter__(self) -> Iterator[Incident]:
        return iter(self._incidents)

    def __getitem__(self, key: Any) -> Incident:
        if isinstance(key, int):
            return self._incidents[key]
        if isinstance(key, str):
            if key in self._id_index:
                return self._id_index[key]
            raise KeyError(f"Incident with ID '{key}' not found.")
        raise TypeError(f"Invalid key type: {type(key)}")

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, Incident):
            return item in self._incidents
        if isinstance(item, str):
            return item in self._id_index
        return False

    def sorted_by_severity(self) -> List[Incident]:
        """Returns incidents ordered by severity (highest first)."""
        return sorted(self._incidents)


@dataclass
class MetricSummary:
    """
    Traffic statistics and performance distribution metrics.

    Demonstrates:
    - Operator overloading with __add__ to merge summaries across time windows or files
    - Built-in statistics module (mean, median, quantiles)
    """
    total_requests: int = 0
    status_counts: Dict[int, int] = field(default_factory=dict)
    total_bytes: int = 0
    response_times_ms: List[float] = field(default_factory=list)
    malformed_lines: int = 0

    @property
    def error_count(self) -> int:
        """Count of 4xx and 5xx responses."""
        return sum(count for code, count in self.status_counts.items() if code >= 400)

    @property
    def error_rate_percentage(self) -> float:
        """Percentage of requests resulting in client or server errors."""
        if self.total_requests == 0:
            return 0.0
        return (self.error_count / self.total_requests) * 100.0

    @property
    def avg_response_time_ms(self) -> float:
        """Average latency in milliseconds using statistics.mean."""
        if not self.response_times_ms:
            return 0.0
        return statistics.mean(self.response_times_ms)

    @property
    def median_response_time_ms(self) -> float:
        """Median latency using statistics.median."""
        if not self.response_times_ms:
            return 0.0
        return statistics.median(self.response_times_ms)

    @property
    def p95_response_time_ms(self) -> float:
        """95th percentile latency using statistics.quantiles or sorted index."""
        if not self.response_times_ms:
            return 0.0
        if len(self.response_times_ms) < 4:
            return max(self.response_times_ms)
        # 100 quantiles gives exact percentiles
        quantiles = statistics.quantiles(self.response_times_ms, n=100)
        return quantiles[94]  # 95th percentile is index 94

    def __add__(self, other: "MetricSummary") -> "MetricSummary":
        """
        Merge two MetricSummary instances using the + operator.
        Demonstrates __add__ operator overloading.
        """
        if not isinstance(other, MetricSummary):
            return NotImplemented

        merged_counts = dict(self.status_counts)
        for code, count in other.status_counts.items():
            merged_counts[code] = merged_counts.get(code, 0) + count

        return MetricSummary(
            total_requests=self.total_requests + other.total_requests,
            status_counts=merged_counts,
            total_bytes=self.total_bytes + other.total_bytes,
            response_times_ms=self.response_times_ms + other.response_times_ms,
            malformed_lines=self.malformed_lines + other.malformed_lines,
        )
