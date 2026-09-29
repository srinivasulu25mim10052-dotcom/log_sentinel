"""
Abstract Base Detector Rule.

Python Essentials Demonstrated:
- Abstract Base Classes (abc.ABC, @abstractmethod)
- Polymorphic rule execution
- Property methods
- List handling and encapsulation
"""

from abc import ABC, abstractmethod
from typing import List
from sentinel.models import Incident, LogEntry


class BaseDetector(ABC):
    """
    Abstract interface for all detection rules in the LogSentinel engine.

    Demonstrates:
    - Life-cycle hooks: process() per log entry, finalize() at end of stream
    - Reset capability for multi-file or multi-run engines
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._incidents: List[Incident] = []

    @property
    def name(self) -> str:
        """Name of the detection rule."""
        return self._name

    @abstractmethod
    def process(self, entry: LogEntry) -> None:
        """
        Evaluate a single log entry against the detector's stateful or stateless rules.
        """
        pass

    @abstractmethod
    def finalize(self) -> List[Incident]:
        """
        Produce a list of finalized Incident objects after the entire log stream has ended.
        """
        pass

    def reset(self) -> None:
        """Reset internal detector state for a clean run."""
        self._incidents.clear()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name='{self._name}'>"
