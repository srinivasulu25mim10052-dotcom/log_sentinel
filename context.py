"""
Custom Context Managers for LogSentinel.

Python Essentials Demonstrated:
- Class-based context managers implementing __enter__ and __exit__
- Handling exceptions within __exit__ (suppression vs propagation)
- Generator-based context managers using contextlib.contextmanager
- Resource cleanup using try / finally blocks
"""

import time
import sys
from contextlib import contextmanager
from io import StringIO
from typing import Generator, Optional, Type


class ExecutionTimer:
    """
    Class-based context manager that measures wall-clock execution time of code blocks.

    Demonstrates:
    - __enter__: Initializes timer and returns self or timing handle.
    - __exit__: Computes elapsed time, captures exception info, and decides suppression.
    """

    def __init__(self, label: str = "Operation") -> None:
        self.label = label
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.elapsed: float = 0.0

    def __enter__(self) -> "ExecutionTimer":
        self.start_time = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object]
    ) -> bool:
        self.end_time = time.perf_counter()
        self.elapsed = self.end_time - self.start_time
        # Return False to allow any exceptions raised inside the block to propagate
        return False

    def __str__(self) -> str:
        return f"{self.label} completed in {self.elapsed * 1000:.2f} ms ({self.elapsed:.4f} s)"


@contextmanager
def capture_stdout() -> Generator[StringIO, None, None]:
    """
    Generator-based context manager to temporarily intercept sys.stdout.

    Demonstrates:
    - @contextlib.contextmanager decorator
    - 'yield' passing a resource to the 'with' block
    - 'try ... finally' guaranteeing restoration of original state
    """
    old_stdout = sys.stdout
    buffer = StringIO()
    try:
        sys.stdout = buffer
        yield buffer
    finally:
        sys.stdout = old_stdout
