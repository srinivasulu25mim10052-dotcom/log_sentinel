"""
Custom Decorators for LogSentinel.

Python Essentials Demonstrated:
- Decorator design pattern with functools.wraps
- Variable-length argument packing (*args, **kwargs)
- Decorator factories (decorators that accept configuration arguments)
- Higher-order functions returning closures
- Exception handling inside wrapper closures
"""

import time
import functools
import logging
from typing import Any, Callable, Optional, TypeVar, cast

# Setup a module-level logger
logger = logging.getLogger("LogSentinel.Audit")

F = TypeVar("F", bound=Callable[..., Any])


def timing(label: Optional[str] = None) -> Callable[[F], F]:
    """
    Decorator factory that measures and prints/logs the execution time of a function.

    Demonstrates:
    - Decorator with optional arguments (factory returning actual decorator)
    - Closure capturing label and func
    - time.perf_counter for nanosecond-precision wall clock measurement
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            display_name = label or func.__name__
            t_start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                t_elapsed = time.perf_counter() - t_start
                # Store execution time on function if desired or log it
                wrapper.last_execution_time = t_elapsed  # type: ignore[attr-defined]

        # Initialize tracking attribute
        wrapper.last_execution_time = 0.0  # type: ignore[attr-defined]
        return cast(F, wrapper)
    return decorator


def audit_log(action_name: str) -> Callable[[F], F]:
    """
    Decorator factory that records an audit log entry whenever a critical engine function runs.

    Demonstrates:
    - Logging function arguments, outcome status, and execution metadata
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arg_count = len(args) + len(kwargs)
            logger.info("AUDIT: Executing action '%s' via %s (%d args)", action_name, func.__name__, arg_count)
            try:
                result = func(*args, **kwargs)
                logger.info("AUDIT: Action '%s' completed successfully", action_name)
                return result
            except Exception as exc:
                logger.warning("AUDIT: Action '%s' raised exception: %s", action_name, exc)
                raise
        return cast(F, wrapper)
    return decorator


def safe_parse(fallback_value: Any = None) -> Callable[[F], F]:
    """
    Decorator that suppresses parsing errors on individual log lines,
    returning a fallback value (e.g. None) instead of halting execution.

    Demonstrates:
    - Fault-tolerant data stream processing
    - try/except inside wrapper
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception:
                return fallback_value
        return cast(F, wrapper)
    return decorator
