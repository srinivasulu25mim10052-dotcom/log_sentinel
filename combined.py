"""
Combined and Common Log Format (Nginx/Apache) Parser.

Python Essentials Demonstrated:
- Regular expressions with named capture groups (?P<name>...)
- re.compile with re.VERBOSE for documented, readable regex
- datetime.strptime for parsing Apache/Nginx log timestamps
- String splitting and unpacking
- Custom exception raising and chained exceptions (raise from)
"""

import re
from datetime import datetime
from typing import Optional

from sentinel.exceptions import ParsingError
from sentinel.models import LogEntry
from .base import BaseLogParser


class CombinedLogParser(BaseLogParser):
    """
    Parser for Nginx and Apache Combined Log Format.

    Standard Format Example:
    127.0.0.1 - frank [10/Oct/2026:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "https://ref.com" "Mozilla/5.0" 0.045
    """

    # Verbose compiled regex with named groups for maximum readability and efficiency
    COMBINED_LOG_REGEX = re.compile(
        r"""
        ^\s*
        (?P<ip>[\w\.\:]+)                          # Client IP address (IPv4 or IPv6)
        \s+
        (?P<ident>[\w\-]+)                         # RFC 1413 identity
        \s+
        (?P<authuser>[\w\-\@\.]+)                  # Authenticated user ID or '-'
        \s+
        \[(?P<timestamp>[^\]]+)\]                  # Timestamp enclosed in brackets
        \s+
        \"(?P<request>[^\"]*)\"                    # Request line in quotes (METHOD /path HTTP/x)
        \s+
        (?P<status>\d{3})                          # 3-digit HTTP status code
        \s+
        (?P<bytes>\d+|\-)                          # Response bytes or '-'
        (?:\s+\"(?P<referer>[^\"]*)\")?            # Optional Referer header in quotes
        (?:\s+\"(?P<user_agent>[^\"]*)\")?         # Optional User-Agent header in quotes
        (?:\s+(?P<duration>[\d\.]+))?              # Optional response duration in seconds/ms
        \s*$
        """,
        re.VERBOSE,
    )

    @property
    def format_name(self) -> str:
        return "Apache / Nginx Combined Log"

    def parse_line(self, raw_line: str, line_number: int = 0) -> Optional[LogEntry]:
        """
        Parses a single line in Combined Log Format into a LogEntry dataclass.
        """
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            return None  # Skip empty lines and comments

        match = self.COMBINED_LOG_REGEX.match(stripped)
        if not match:
            raise ParsingError(
                f"Line format did not match Apache/Nginx Combined specification",
                raw_line=stripped,
                line_number=line_number,
            )

        data = match.groupdict()

        # Parse request line: "METHOD /path PROTOCOL"
        request_parts = data["request"].split()
        if len(request_parts) >= 2:
            method = request_parts[0].upper()
            path = request_parts[1]
        elif len(request_parts) == 1:
            method = request_parts[0].upper()
            path = "/"
        else:
            method = "UNKNOWN"
            path = "/"

        # Parse timestamp: e.g. "10/Oct/2026:13:55:36 +0000"
        raw_ts = data["timestamp"]
        parsed_dt = self._parse_apache_datetime(raw_ts, line_number)

        # Parse numeric bytes and status
        status_code = int(data["status"])
        bytes_val = int(data["bytes"]) if data["bytes"] != "-" else 0

        # Parse duration (convert seconds to milliseconds if present)
        response_time_ms = 0.0
        if data.get("duration"):
            try:
                # If duration is already in seconds (e.g. 0.045), convert to ms
                val = float(data["duration"])
                response_time_ms = val * 1000.0 if val < 100.0 else val
            except ValueError:
                response_time_ms = 0.0

        return LogEntry(
            ip=data["ip"],
            timestamp=parsed_dt,
            method=method,
            path=path,
            status_code=status_code,
            response_size=bytes_val,
            response_time_ms=response_time_ms,
            user_agent=data.get("user_agent") or "",
            referer=data.get("referer") or "-",
            raw_line=stripped,
        )

    def _parse_apache_datetime(self, raw_ts: str, line_number: int) -> datetime:
        """
        Parses Apache formatted timestamp string into a datetime object.
        Demonstrates datetime.strptime with multiple format fallbacks.
        """
        formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(raw_ts, fmt)
            except ValueError:
                continue

        # If all standard formats fail, try stripping timezone offset
        try:
            ts_no_tz = raw_ts.split()[0]
            return datetime.strptime(ts_no_tz, "%d/%b/%Y:%H:%M:%S")
        except ValueError as err:
            raise ParsingError(
                f"Unable to parse timestamp '{raw_ts}' with known formats",
                line_number=line_number,
            ) from err
