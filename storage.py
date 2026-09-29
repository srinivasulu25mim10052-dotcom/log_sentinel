"""
File I/O, Streaming Generators & Atomic Persistence for LogSentinel.

Python Essentials Demonstrated:
- Generator functions with 'yield' for constant memory O(1) streaming
- Custom Iterator class implementing the iterator protocol (__iter__ and __next__)
- pathlib.Path for clean, cross-platform file system operations
- Safe atomic file persistence with os.replace
- Exception handling and custom storage exceptions
"""

import os
from pathlib import Path
from typing import Generator, Iterator, Optional, Tuple, Union

from sentinel.exceptions import LogFileNotFoundError, ReportWriteError


def stream_log_lines(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
) -> Generator[Tuple[int, str], None, None]:
    """
    Generator function that streams a log file line-by-line.

    Demonstrates:
    - 'yield' statement producing a lazy sequence of (line_number, line_text)
    - Memory efficiency: Never loads full gigabyte files into memory
    - pathlib.Path type flexibility
    - try / except wrapping file system errors
    """
    path = Path(file_path)
    if not path.is_file():
        raise LogFileNotFoundError(f"Log file not found: {path.resolve()}")

    try:
        with open(path, mode="r", encoding=encoding, errors="replace") as file_handle:
            for line_number, raw_line in enumerate(file_handle, start=1):
                yield line_number, raw_line
    except OSError as err:
        raise ReportWriteError(f"Operating system error reading file {path}: {err}") from err


class LogLineIterator:
    """
    Custom Iterator class implementing the formal Python iterator protocol.

    Demonstrates:
    - __iter__: Returns self
    - __next__: Yields next line or raises StopIteration
    - Resource management with close() and context manager support
    """

    def __init__(self, file_path: Union[str, Path], encoding: str = "utf-8") -> None:
        self.path = Path(file_path)
        if not self.path.is_file():
            raise LogFileNotFoundError(f"File does not exist: {self.path.resolve()}")
        self.encoding = encoding
        self._file = open(self.path, mode="r", encoding=self.encoding, errors="replace")
        self._line_number = 0

    def __iter__(self) -> "LogLineIterator":
        return self

    def __next__(self) -> Tuple[int, str]:
        line = self._file.readline()
        if not line:
            self.close()
            raise StopIteration
        self._line_number += 1
        return self._line_number, line

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()

    def __enter__(self) -> "LogLineIterator":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()


def atomic_write_text(file_path: Union[str, Path], content: str, encoding: str = "utf-8") -> Path:
    """
    Safely writes text to a destination path using atomic file replacement.

    Demonstrates:
    - Writing to temporary sibling file first
    - os.fsync to force kernel buffer flush to physical disk
    - os.replace for atomic overwrite
    - pathlib.Path directory creation (mkdir)
    """
    dest = Path(file_path)
    # Ensure destination directory exists
    dest.parent.mkdir(parents=True, exist_ok=True)

    temp_path = dest.with_suffix(f"{dest.suffix}.tmp.{os.getpid()}")
    try:
        with open(temp_path, mode="w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replacement: replaces destination cleanly
        os.replace(temp_path, dest)
        return dest
    except OSError as err:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise ReportWriteError(f"Failed to write report to {dest}: {err}") from err
