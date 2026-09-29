"""
Custom Exception Hierarchy for LogSentinel.

Python Essentials Demonstrated:
- Object-Oriented Exception Hierarchy (inheriting from built-in Exception)
- Custom exception constructors (__init__) and attribute storage
- Formatted string representation for human-readable error messages
- Exception chaining capabilities (raise from)
"""

from typing import Optional


class LogSentinelError(Exception):
    """Base exception for all errors raised within the LogSentinel application."""

    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ParsingError(LogSentinelError):
    """Raised when a log line or file fails to parse."""

    def __init__(self, message: str, raw_line: Optional[str] = None, line_number: Optional[int] = None) -> None:
        super().__init__(message)
        self.raw_line = raw_line
        self.line_number = line_number

    def __str__(self) -> str:
        loc = f" at line {self.line_number}" if self.line_number is not None else ""
        return f"[ParsingError{loc}] {self.message}"


class CorruptLogFormatError(ParsingError):
    """Raised when the corrupted line ratio exceeds the acceptable threshold."""
    pass


class UnsupportedFormatError(ParsingError):
    """Raised when an unknown log format is specified."""
    pass


class DetectionRuleError(LogSentinelError):
    """Base class for errors originating from detection rules."""
    pass


class InvalidThresholdError(DetectionRuleError):
    """Raised when an invalid threshold parameter is provided to a detector."""

    def __init__(self, rule_name: str, parameter: str, value: object, reason: str) -> None:
        message = f"Invalid parameter '{parameter}={value}' for rule '{rule_name}': {reason}"
        super().__init__(message)
        self.rule_name = rule_name
        self.parameter = parameter
        self.value = value


class StorageError(LogSentinelError):
    """Base class for storage and file I/O operations."""
    pass


class LogFileNotFoundError(StorageError):
    """Raised when the requested log file does not exist."""
    pass


class ReportWriteError(StorageError):
    """Raised when an error occurs while writing an incident report."""
    pass
