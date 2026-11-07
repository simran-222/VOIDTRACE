"""VOIDTRACE performance measurement.

Records process memory (tracemalloc) and operation timings.
Timings are kept in memory and, when the database is ready, in SQLite.
"""

from __future__ import annotations

import functools
import inspect
import logging
import time
import tracemalloc
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

if not tracemalloc.is_tracing():
    tracemalloc.start()

_SAMPLES: deque[dict[str, Any]] = deque(maxlen=200)


@dataclass(frozen=True)
class PerformanceSnapshot:
    current_memory_kb: float
    peak_memory_kb: float
    timestamp_iso: str


def get_memory_metrics() -> PerformanceSnapshot:
    """Read current and peak memory allocations in kilobytes."""
    current, peak = tracemalloc.get_traced_memory()
    return PerformanceSnapshot(
        current_memory_kb=round(current / 1024.0, 2),
        peak_memory_kb=round(peak / 1024.0, 2),
        timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def record_timing(
    name: str,
    duration_ms: float,
    incident_id: Optional[str] = None,
    *,
    audit: bool = False,
) -> dict[str, Any]:
    """Record one operation timing. Database persistence is best-effort."""
    sample = {
        "name": name,
        "duration_ms": round(float(duration_ms), 3),
        "incident_id": incident_id,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    _SAMPLES.append(sample)
    try:
        from app.database import get_db_connection, record_audit_event

        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO performance_samples (name, duration_ms, incident_id, recorded_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (sample["name"], sample["duration_ms"], incident_id, sample["recorded_at"]),
                )
                if audit:
                    record_audit_event(
                        conn,
                        actor="SYSTEM",
                        action="PERFORMANCE_RECORDED",
                        details={"name": name, "duration_ms": sample["duration_ms"]},
                        incident_id=incident_id,
                    )
        finally:
            conn.close()
    except Exception:
        logger.debug("Performance sample kept in memory only.", exc_info=True)
    return sample


def recent_timings(limit: int = 30) -> list[dict[str, Any]]:
    """Return recent timings, preferring the database when it is available."""
    try:
        from app.database import get_db_connection

        conn = get_db_connection()
        try:
            cursor = conn.execute(
                """
                SELECT name, duration_ms, incident_id, recorded_at
                FROM performance_samples
                ORDER BY id DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
        if rows:
            rows.reverse()
            return rows
    except Exception:
        logger.debug("Performance table unavailable; using memory.", exc_info=True)
    return list(_SAMPLES)[-limit:]


def measure_execution_time(func: F) -> F:
    """Decorator that records wall-clock duration for a function."""

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        try:
            return await func(*args, **kwargs)
        finally:
            record_timing(func.__qualname__, (time.perf_counter() - start_time) * 1000.0)

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            record_timing(func.__qualname__, (time.perf_counter() - start_time) * 1000.0)

    if inspect.iscoroutinefunction(func):
        return async_wrapper  # type: ignore[return-value]
    return sync_wrapper  # type: ignore[return-value]
