"""
Structured JSON Log Parser.

Python Essentials Demonstrated:
- Standard library json module (json.loads)
- Defensive dictionary data extraction (.get() with default values)
- ISO 8601 datetime parsing (datetime.fromisoformat)
- Type coercion with error handling
- Custom exception chaining
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from sentinel.exceptions import ParsingError
from sentinel.models import LogEntry
from .base import BaseLogParser


class JsonLogParser(BaseLogParser):
    """
    Parser for structured JSON logs common in containerized and cloud-native microservices.

    Example Line:
    {"ip": "192.168.1.100", "timestamp": "2026-09-29T10:15:30Z", "method": "POST", "path": "/api/v1/auth", "status": 401, "bytes": 482, "duration_ms": 12.4, "user_agent": "curl/7.88.1"}
    """

    @property
    def format_name(self) -> str:
        return "Structured JSON Log"

    def parse_line(self, raw_line: str, line_number: int = 0) -> Optional[LogEntry]:
        """
        Parses a JSON-formatted log string into a LogEntry.
        """
        stripped = raw_line.strip()
        if not stripped:
            return None

        try:
            payload: Dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError as err:
            raise ParsingError(
                f"Invalid JSON syntax: {err.msg}",
                raw_line=stripped,
                line_number=line_number,
            ) from err

        # Field extraction with aliases to support varying cloud schemas
        ip = str(payload.get("ip") or payload.get("client_ip") or payload.get("remote_addr") or "127.0.0.1")
        method = str(payload.get("method") or payload.get("http_method") or "GET").upper()
        path = str(payload.get("path") or payload.get("uri") or payload.get("url") or "/")

        # Status code extraction
        status_val = payload.get("status") or payload.get("status_code") or payload.get("http_status") or 200
        try:
            status_code = int(status_val)
        except (ValueError, TypeError):
            status_code = 200

        # Timestamp parsing
        raw_ts = payload.get("timestamp") or payload.get("time") or payload.get("@timestamp")
        parsed_dt = self._parse_json_timestamp(raw_ts, line_number)

        # Bytes and duration
        bytes_val = int(payload.get("bytes") or payload.get("response_size") or 0)
        duration_ms = float(payload.get("duration_ms") or payload.get("response_time_ms") or 0.0)

        user_agent = str(payload.get("user_agent") or payload.get("agent") or "")
        referer = str(payload.get("referer") or payload.get("referrer") or "-")

        return LogEntry(
            ip=ip,
            timestamp=parsed_dt,
            method=method,
            path=path,
            status_code=status_code,
            response_size=bytes_val,
            response_time_ms=duration_ms,
            user_agent=user_agent,
            referer=referer,
            raw_line=stripped,
        )

    def _parse_json_timestamp(self, raw_ts: Any, line_number: int) -> datetime:
        """Parses ISO timestamp or numeric epoch into datetime."""
        if not raw_ts:
            return datetime.now()

        if isinstance(raw_ts, (int, float)):
            # Epoch timestamp
            return datetime.fromtimestamp(raw_ts)

        ts_str = str(raw_ts).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            pass

        # Fallback formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        raise ParsingError(f"Unrecognized JSON timestamp format: {raw_ts}", line_number=line_number)
