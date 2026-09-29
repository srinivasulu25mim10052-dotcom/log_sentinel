# Python Essentials: Comprehensive Concept Map & Reference Guide

This document maps every fundamental, intermediate, and advanced Python concept to its exact implementation in the **LogSentinel** codebase. It serves as an educational reference demonstrating best practices in native Python 3.

---

## Table of Contents

1. [Type Hinting & Static Typing](#1-type-hinting--static-typing)
2. [Data Structures & Containers](#2-data-structures--containers)
3. [Specialized Collections (`collections` module)](#3-specialized-collections-collections-module)
4. [Control Flow & Modern Pattern Matching](#4-control-flow--modern-pattern-matching)
5. [Iterators, Generators & Lazy Streaming](#5-iterators-generators--lazy-streaming)
6. [Functions, Closures & Decorators](#6-functions-closures--decorators)
7. [Object-Oriented Programming (OOP) & Dataclasses](#7-object-oriented-programming-oop--dataclasses)
8. [Dunder (Magic) Methods & Operator Overloading](#8-dunder-magic-methods--operator-overloading)
9. [Context Managers (`with` statement)](#9-context-managers-with-statement)
10. [Exception Handling & Chaining](#10-exception-handling--chaining)
11. [File I/O & Path Operations (`pathlib`)](#11-file-io--path-operations-pathlib)
12. [Standard Library Modules](#12-standard-library-modules)
13. [Unit Testing (`unittest` framework)](#13-unit-testing-unittest-framework)

---

## 1. Type Hinting & Static Typing
- **Concepts**: `Optional`, `Union`, `Sequence`, `Callable`, `TypeVar`, `cast`, modern union syntax (`A | B`), type narrowing.
- **Where to look**:
  - `sentinel/models.py`: Model attributes with explicit type hints (`Optional[str]`, `List[float]`, `Dict[int, int]`).
  - `sentinel/decorators.py`: `F = TypeVar("F", bound=Callable[..., Any])` used for generic decorator wrapping preserving function signatures.
  - `sentinel/parsers/base.py`: Return types `Optional[LogEntry]` signifying nullable parse results.

---

## 2. Data Structures & Containers
- **Concepts**:
  - **Lists**: Ordered collections, slicing, sorting (`latencies[:8]`, `list[collection]`).
  - **Tuples**: Immutable records (`Tuple[int, str]`, named pairs).
  - **Dictionaries**: Fast key-value lookups, `.get()` with default values, dictionary views.
  - **Sets**: Unordered unique collections, fast $O(1)$ membership testing (`in`), deduplication.
- **Where to look**:
  - `sentinel/detectors/threats.py`: `self._ip_threat_records[ip] = set()` to deduplicate alerts and prevent spamming.
  - `sentinel/detectors/brute_force.py`: `self._flagged_ips = set()` for tracking blocked hosts.
  - `sentinel/reporter.py`: Dictionary comprehensions to format status code breakdowns (`{code: count}`).

---

## 3. Specialized Collections (`collections` module)
- **Concepts**:
  - `collections.Counter`: Counting hashable items (e.g. status code occurrences, top IPs).
  - `collections.defaultdict`: Dictionaries with auto-initialized default values (`defaultdict(list)`, `defaultdict(deque)`).
  - `collections.deque`: Double-ended queues with $O(1)$ appends and `popleft()`.
- **Where to look**:
  - `sentinel/detectors/brute_force.py`: `defaultdict(deque)` implements an efficient sliding time window where old requests are evicted with `history.popleft()`.
  - `sentinel/detectors/error_spikes.py`: `defaultdict(lambda: [0, 0])` groups requests into 1-minute time buckets.
  - `sentinel/engine.py`: `status_counter: Counter[int] = Counter()` and `ip_counter: Counter[str] = Counter()`.

---

## 4. Control Flow & Modern Pattern Matching
- **Concepts**:
  - `match / case` (structural pattern matching introduced in Python 3.10).
  - `for ... else`: Loop construct where the `else` clause executes only if the loop completes without a `break`.
  - `while` loops for interactive shells.
- **Where to look**:
  - `sentinel/detectors/error_spikes.py`: `match error_rate:` with guard expressions (`case r if r >= 0.50:`) to assign incident severity.
  - `sentinel/detectors/threats.py`: `for threat in signatures: ... break else: pass` verifying signature evaluation.
  - `sentinel/engine.py`: `get_parser_by_name(cls, name)` uses `match name.lower(): case "combined" | "nginx":`.
  - `sentinel/cli.py`: Interactive command dispatching with `match choice:`.

---

## 5. Iterators, Generators & Lazy Streaming
- **Concepts**:
  - Generator functions with `yield`.
  - Constant $O(1)$ memory usage when processing gigabyte-scale files.
  - Formal Iterator protocol: classes with `__iter__` and `__next__`, raising `StopIteration`.
- **Where to look**:
  - `sentinel/storage.py`:
    - `stream_log_lines(file_path)`: Uses `yield line_number, raw_line` to stream lines lazily without reading the whole file into RAM.
    - `LogLineIterator`: Complete class-based iterator implementing `__iter__` and `__next__`.

---

## 6. Functions, Closures & Decorators
- **Concepts**:
  - Higher-order functions: Functions that accept or return other functions.
  - Closures: Functions retaining state from their enclosing scope.
  - `@functools.wraps`: Preserving function name, docstrings, and metadata.
  - Variadic arguments: `*args` and `**kwargs`.
  - Decorator factories: Decorators that accept configuration arguments.
- **Where to look**:
  - `sentinel/decorators.py`:
    - `@timing(label)`: Decorator measuring execution time via `time.perf_counter()`.
    - `@audit_log(action_name)`: Decorator logging start, finish, argument count, and exceptions.
    - `@safe_parse(fallback_value)`: Closure providing fault tolerance over brittle line transformations.

---

## 7. Object-Oriented Programming (OOP) & Dataclasses
- **Concepts**:
  - Abstract Base Classes (`abc.ABC`, `@abc.abstractmethod`).
  - Dataclasses (`@dataclass`, `field(default_factory=...)`).
  - Polymorphism and Strategy Pattern: Uniform interfaces across different parsers and detectors.
  - Encapsulation: Private/protected attributes (`_incidents`, `_name`), `@property` getters.
- **Where to look**:
  - `sentinel/parsers/base.py`: `BaseLogParser(ABC)` defines the abstract contract.
  - `sentinel/parsers/combined.py` & `json_parser.py`: Subclasses implementing concrete parsing strategies.
  - `sentinel/detectors/base.py`: `BaseDetector(ABC)` defines lifecycle methods `process()`, `finalize()`, `reset()`.
  - `sentinel/models.py`: `LogEntry` and `Incident` implemented as modern dataclasses with derived properties (`is_server_error`, `is_success`).

---

## 8. Dunder (Magic) Methods & Operator Overloading
- **Concepts**:
  - `__str__` vs `__repr__`: Human-friendly formatting vs developer inspection.
  - `__lt__`: Rich comparison enabling `sorted()`, `min()`, `max()`.
  - `__len__`, `__iter__`, `__getitem__`, `__contains__`: Container protocol emulation.
  - `__add__`: Operator overloading (`+`) to combine aggregate structures.
- **Where to look**:
  - `sentinel/models.py`:
    - `IncidentCollection`: Implements `__len__`, `__iter__`, `__getitem__` (supporting both index and string ID lookups), and `__contains__`.
    - `MetricSummary.__add__`: Merges two traffic summaries with `summary1 + summary2`.
    - `Severity.__lt__` and `LogEntry.__lt__`: Enables natural ordering with `sorted(entries)`.

---

## 9. Context Managers (`with` statement)
- **Concepts**:
  - Class-based context managers with `__enter__` and `__exit__`.
  - Generator-based context managers with `@contextlib.contextmanager`.
  - Deterministic resource cleanup with `try / finally`.
- **Where to look**:
  - `sentinel/context.py`:
    - `ExecutionTimer`: Class-based context manager tracking wall-clock time in high resolution.
    - `capture_stdout()`: Generator-based context manager using `contextlib.contextmanager` to safely intercept output.

---

## 10. Exception Handling & Chaining
- **Concepts**:
  - Custom exception hierarchies inheriting from `Exception`.
  - Explicit exception chaining (`raise ... from err`).
  - Safe error recovery (`try / except / else / finally`).
- **Where to look**:
  - `sentinel/exceptions.py`: Complete hierarchy (`LogSentinelError` -> `ParsingError`, `CorruptLogFormatError`, `InvalidThresholdError`, `StorageError`).
  - `sentinel/parsers/combined.py`: Demonstrates `raise ParsingError(...) from err` preserving the original traceback cause.
  - `sentinel/engine.py`: Captures malformed lines without crashing, and verifies corruption thresholds.

---

## 11. File I/O & Path Operations (`pathlib`)
- **Concepts**:
  - Cross-platform paths using `pathlib.Path`.
  - Explicit file encoding (`encoding="utf-8"`, `errors="replace"`).
  - Safe atomic file writes: Writing to temporary buffer, forcing disk flush with `os.fsync`, and replacing atomically with `os.replace`.
- **Where to look**:
  - `sentinel/storage.py`:
    - `stream_log_lines`: Path inspection (`is_file()`, `resolve()`) and clean file reading.
    - `atomic_write_text`: Atomic persistence preventing partial/corrupted files during power or process interruption.

---

## 12. Standard Library Modules
- **`re`**: Named capture groups (`(?P<ip>...)`), `re.VERBOSE` flag, case-insensitive threat pattern compilation.
  - *Location*: `sentinel/parsers/combined.py`, `sentinel/detectors/threats.py`.
- **`datetime`**: Parsing Apache dates (`strptime`), ISO 8601 formatting, `timedelta` arithmetic, timezone normalization.
  - *Location*: `sentinel/parsers/combined.py`, `sentinel/models.py`.
- **`statistics`**: Computing `mean()`, `median()`, and quantiles/percentiles (`quantiles(..., n=100)`).
  - *Location*: `sentinel/models.py`, `sentinel/detectors/performance.py`.
- **`argparse`**: Robust command-line parsing with subparsers (`scan`, `stats`, `threats`, `interactive`).
  - *Location*: `sentinel/cli.py`.
- **`json`**: Native serialization/deserialization with formatting (`indent=2`).
  - *Location*: `sentinel/parsers/json_parser.py`, `sentinel/reporter.py`.

---

## 13. Unit Testing (`unittest` framework)
- **Concepts**:
  - `unittest.TestCase` subclassing.
  - Fixtures with `setUp()` and `tearDown()`.
  - Assertions: `assertEqual`, `assertTrue`, `assertIn`, `assertRaises`, `assertAlmostEqual`.
  - Test discovery: `python -m unittest discover`.
- **Where to look**:
  - `tests/test_models.py`: Tests dunder methods, operators, and properties.
  - `tests/test_parsers.py`: Validates regex parsing and error handling.
  - `tests/test_detectors.py`: Simulates stateful attack bursts and thresholds.
  - `tests/test_engine.py`: Full end-to-end integration tests over real sample files.
