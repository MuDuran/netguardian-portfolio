"""
Timing Utilities
Lightweight performance instrumentation for the application's hot paths.

Enabled by setting the NETGUARDIAN_PERF environment variable to 1. When
disabled, the decorator and context manager add a single boolean check and
no measurable overhead.

Usage:
    from utils.timing import timed, timed_block, perf_summary

    @timed("FirewallManager.get_rules")
    def get_rules(self): ...

    with timed_block("arp"):
        ...
"""

import functools
import logging
import sys
import threading
import time
from contextlib import contextmanager
from typing import Dict, List, Optional

import config

logger = logging.getLogger(__name__)

ENABLED = config.PERF_LOGGING

# label -> list of durations in milliseconds
_samples: Dict[str, List[float]] = {}
_samples_lock = threading.Lock()


def _record(label: str, elapsed_ms: float, extra: str = ""):
    """Record a timing sample and emit it to the log and stderr."""
    with _samples_lock:
        _samples.setdefault(label, []).append(elapsed_ms)

    suffix = f"  ({extra})" if extra else ""
    line = f"[PERF] {label:<45} {elapsed_ms:>9.1f} ms{suffix}"
    logger.info(line)
    # stderr so it shows up even when the app logger is not configured
    print(line, file=sys.stderr)


def timed(label: Optional[str] = None):
    """
    Decorator that times a function when instrumentation is enabled.

    Args:
        label: Name to report. Defaults to the qualified function name.
    """
    def decorator(func):
        name = label or getattr(func, "__qualname__", func.__name__)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not ENABLED:
                return func(*args, **kwargs)
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                _record(name, (time.perf_counter() - start) * 1000.0)

        return wrapper

    return decorator


@contextmanager
def timed_block(label: str, extra: str = ""):
    """Context manager that times a block of code."""
    if not ENABLED:
        yield
        return
    start = time.perf_counter()
    try:
        yield
    finally:
        _record(label, (time.perf_counter() - start) * 1000.0, extra)


class Stopwatch:
    """
    Manual stopwatch for measuring sub-phases inside one operation.

    Useful when a single call has several distinct costs worth splitting out,
    e.g. an ARP sweep followed by reverse-DNS resolution.
    """

    def __init__(self, label: str):
        self.label = label
        self._start = time.perf_counter()
        self._marks: List[tuple] = []
        self._last = self._start

    def mark(self, name: str):
        """Record a named split since the previous mark."""
        now = time.perf_counter()
        self._marks.append((name, (now - self._last) * 1000.0))
        self._last = now

    def done(self):
        """Emit the total plus every split."""
        if not ENABLED:
            return
        total = (time.perf_counter() - self._start) * 1000.0
        extra = " ".join(f"{n}={ms:.1f}" for n, ms in self._marks)
        _record(self.label, total, extra)


def perf_summary() -> str:
    """Build a human-readable summary of every sample collected so far."""
    with _samples_lock:
        if not _samples:
            return "No performance samples collected."
        lines = ["", "=" * 78, "PERFORMANCE SUMMARY", "=" * 78,
                 f"{'operation':<45}{'n':>5}{'avg ms':>12}{'max ms':>14}"]
        for label in sorted(_samples):
            values = _samples[label]
            lines.append(
                f"{label:<45}{len(values):>5}"
                f"{sum(values) / len(values):>12.1f}{max(values):>14.1f}"
            )
        lines.append("=" * 78)
        return "\n".join(lines)


def reset():
    """Clear all collected samples."""
    with _samples_lock:
        _samples.clear()
