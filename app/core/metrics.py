"""
CTIR — In-process metrics collector
Lightweight counters that accumulate across ingestion runs.
Exposed via GET /metrics for Prometheus-style scraping (text format).
No external dependency — pure Python.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import DefaultDict

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RunMetrics:
    """Metrics captured for a single ingestion run."""
    feed_name: str
    started_at: float = field(default_factory=time.time)
    records_fetched: int = 0
    records_valid: int = 0
    records_invalid: int = 0
    records_new: int = 0
    records_updated: int = 0
    records_dupes: int = 0
    latency_ms: int = 0
    success: bool = True


class MetricsCollector:
    """Thread-safe singleton for accumulating pipeline metrics."""

    _instance: "MetricsCollector | None" = None
    _lock: Lock = Lock()

    def __new__(cls) -> "MetricsCollector":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        self._counters: DefaultDict[str, int] = defaultdict(int)
        self._run_history: list[RunMetrics] = []
        self._max_history = 100

    def record_run(self, metrics: RunMetrics) -> None:
        with self._lock:
            self._counters["total_runs"] += 1
            self._counters["total_fetched"] += metrics.records_fetched
            self._counters["total_new"] += metrics.records_new
            self._counters["total_updated"] += metrics.records_updated
            self._counters["total_dupes"] += metrics.records_dupes
            self._counters["total_invalid"] += metrics.records_invalid
            if not metrics.success:
                self._counters["total_failures"] += 1

            self._run_history.append(metrics)
            if len(self._run_history) > self._max_history:
                self._run_history.pop(0)

        logger.debug("metrics_recorded", feed=metrics.feed_name, latency_ms=metrics.latency_ms)

    def get_counters(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def last_run(self) -> RunMetrics | None:
        with self._lock:
            return self._run_history[-1] if self._run_history else None

    def prometheus_text(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        lines: list[str] = []
        counters = self.get_counters()
        last = self.last_run()

        for name, value in counters.items():
            metric_name = f"ctir_{name}_total"
            lines.append(f"# HELP {metric_name} CTIR cumulative counter")
            lines.append(f"# TYPE {metric_name} counter")
            lines.append(f"{metric_name} {value}")

        if last:
            lines.append("# HELP ctir_last_run_latency_ms Last ingestion run latency")
            lines.append("# TYPE ctir_last_run_latency_ms gauge")
            lines.append(f"ctir_last_run_latency_ms {last.latency_ms}")

        return "\n".join(lines) + "\n"


# Singleton instance
metrics = MetricsCollector()