"""
Abstract Base Parser Interface.

Python Essentials Demonstrated:
- Abstract Base Classes (abc.ABC) and abstract methods (@abstractmethod)
- Interface contract enforcement in Python
- Polymorphism: Allowing interchangeable parser strategies
- Type hinting with Optional and Union
"""

from abc import ABC, abstractmethod
from typing import Optional
from sentinel.models import LogEntry


class BaseLogParser(ABC):
    """
    Abstract Base Class defining the contract for all log format parsers.

    Demonstrates:
    - abc.ABC inheritance
    - @abstractmethod decorator preventing direct instantiation
    - Concrete helper methods shared across subclasses
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Human-readable name of the log format."""
        pass

    @abstractmethod
    def parse_line(self, raw_line: str, line_number: int = 0) -> Optional[LogEntry]:
        """
        Parse a single line of raw text into a structured LogEntry.

        Must return None or raise a ParsingError if the line is not valid.
        """
        pass

    def can_parse(self, sample_line: str) -> bool:
        """
        Heuristic probe to test if this parser can interpret a given sample line.
        """
        try:
            return self.parse_line(sample_line) is not None
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} format='{self.format_name}'>"
