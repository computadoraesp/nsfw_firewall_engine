"""Prometheus metrics for the NSFW Firewall Engine (Sec. 31).

``prometheus_client`` is used when installed. When it is absent (slim images,
minimal CI) the module falls back to a small built-in registry that emits the
*same* metric names, labels and text-exposition format, so dashboards keep
working and ``GET /metrics`` never 500s.

Recording is deliberately best-effort: metrics must never break request
handling, so every failure is swallowed after being logged.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("nsfw_engine.core.metrics")

#: Latency buckets in seconds, tuned for the sub-100ms cascade.
LATENCY_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
)

# Metric names shared by both backends.
N_CLASSIFICATIONS = "nsfw_classifications_total"
N_ERRORS = "nsfw_errors_total"
N_CACHE_HITS = "nsfw_cache_hits_total"
N_CACHE_MISSES = "nsfw_cache_misses_total"
N_STAGE_LATENCY = "nsfw_stage_latency_seconds"
N_REQUEST_LATENCY = "nsfw_request_duration_seconds"
N_RISK_SCORE = "nsfw_risk_score"
N_MODELS_LOADED = "nsfw_models_loaded"
N_CACHE_ENTRIES = "nsfw_cache_entries"
# --- §31 metric names that were previously declared in a second, parallel
# registry (observability/metrics.py) that nothing imported. Two registries
# declaring the same metric name collide on Prometheus's default registry, so
# the duplicates are consolidated here - this module is the single source.
N_REQUESTS = "nsfw_requests_total"
N_INSPECTIONS = "nsfw_inspections_total"
N_ENFORCEMENT = "nsfw_enforcement_total"
N_MODEL_INFERENCE = "nsfw_model_inference_total"
N_PIPELINE_LATENCY = "nsfw_pipeline_latency_seconds"
N_QUEUE_DEPTH = "nsfw_queue_depth"
N_WORKER_ERRORS = "nsfw_worker_errors_total"
N_RATE_LIMITED = "nsfw_rate_limited_total"
N_RATE_LIMITERS = "nsfw_rate_limiters_total"
N_CPU_UTIL = "nsfw_cpu_utilization_ratio"
N_MEMORY_USAGE = "nsfw_memory_usage_bytes"
N_GPU_UTIL = "nsfw_gpu_utilization_ratio"
#: Wall-clock seconds between process start and the app being ready to serve.
#: A slow startup is invisible in every other metric - traffic just is not
#: arriving - so it needs its own series (§31).
N_STARTUP_TIME = "nsfw_startup_time_seconds"
#: Seconds a request waited between entering the process and the handler
#: starting. Distinct from request duration: this is queueing/scheduling delay,
#: which is what tells saturation apart from slow inference (§31).
N_QUEUE_LATENCY = "nsfw_queue_latency_seconds"
#: Requests that returned 5xx, by endpoint. Paired with ``N_REQUESTS`` this
#: yields the error rate; it is a counter rather than a gauge so a rate() over a
#: window is well-defined and resets cleanly with the process (§31).
N_REQUEST_ERRORS = "nsfw_request_errors_total"
#: Requests dead-lettered because the engine could not decide them, by reason
#: (§33). A rising rate here with flat request volume is the signature of a
#: failing dependency or a failing model - and those are precisely the requests
#: that policy will resolve to fail_action.
N_DEAD_LETTER = "nsfw_dead_letter_total"


def _label_key(labels: Dict[str, str], names: Iterable[str]) -> Tuple[str, ...]:
    return tuple(str(labels.get(name, "")) for name in names)


class _MiniRegistry:
    """Minimal counters / gauges / histograms in Prometheus text format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[str, Any]] = {}
        self._gauges: Dict[str, Dict[str, Any]] = {}
        self._histograms: Dict[str, Dict[str, Any]] = {}

    def counter(self, name: str, help_text: str, labels: Iterable[str] = ()) -> None:
        self._counters.setdefault(
            name, {"help": help_text, "labels": tuple(labels), "values": {}}
        )

    def gauge(self, name: str, help_text: str, labels: Iterable[str] = ()) -> None:
        self._gauges.setdefault(
            name, {"help": help_text, "labels": tuple(labels), "values": {}}
        )

    def histogram(
        self,
        name: str,
        help_text: str,
        labels: Iterable[str] = (),
        buckets: Tuple[float, ...] = LATENCY_BUCKETS,
    ) -> None:
        self._histograms.setdefault(
            name,
            {
                "help": help_text,
                "labels": tuple(labels),
                "buckets": tuple(buckets),
                "values": {},
            },
        )

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        with self._lock:
            spec = self._counters.get(name)
            if spec is None:
                return
            key = _label_key(labels, spec["labels"])
            spec["values"][key] = spec["values"].get(key, 0.0) + float(value)

    def set(self, name: str, value: float, **labels: str) -> None:
        with self._lock:
            spec = self._gauges.get(name)
            if spec is None:
                return
            spec["values"][_label_key(labels, spec["labels"])] = float(value)

    def observe(self, name: str, value: float, **labels: str) -> None:
        with self._lock:
            spec = self._histograms.get(name)
            if spec is None:
                return
            key = _label_key(labels, spec["labels"])
            series = spec["values"].setdefault(
                key, {"buckets": {}, "sum": 0.0, "count": 0}
            )
            for edge in spec["buckets"]:
                if value <= edge:
                    bkey = (key, edge)
                    series["buckets"][bkey] = series["buckets"].get(bkey, 0) + 1
            series["sum"] += float(value)
            series["count"] += 1

    @staticmethod
    def _labels(names: Tuple[str, ...], values: Tuple[str, ...], extra: str = "") -> str:
        pairs = [f'{n}="{v}"' for n, v in zip(names, values) if v != ""]
        if extra:
            pairs.append(extra)
        return "{" + ",".join(pairs) + "}" if pairs else ""

    def render(self) -> str:
        lines: List[str] = []
        with self._lock:
            for name, spec in self._counters.items():
                lines.append(f"# HELP {name} {spec['help']}")
                lines.append(f"# TYPE {name} counter")
                for key, value in sorted(spec["values"].items()):
                    lines.append(f"{name}{self._labels(spec['labels'], key)} {value}")
            for name, spec in self._gauges.items():
                lines.append(f"# HELP {name} {spec['help']}")
                lines.append(f"# TYPE {name} gauge")
                for key, value in sorted(spec["values"].items()):
                    lines.append(f"{name}{self._labels(spec['labels'], key)} {value}")
            for name, spec in self._histograms.items():
                lines.append(f"# HELP {name} {spec['help']}")
                lines.append(f"# TYPE {name} histogram")
                for key, series in sorted(spec["values"].items()):
                    for edge in spec["buckets"]:
                        extra = f'le="{edge}"'
                        lines.append(
                            f"{name}_bucket{self._labels(spec['labels'], key, extra)} "
                            f"{series['buckets'].get((key, edge), 0)}"
                        )
                    inf = self._labels(spec["labels"], key, 'le="+Inf"')
                    lines.append(f"{name}_bucket{inf} {series['count']}")
                    lines.append(
                        f"{name}_sum{self._labels(spec['labels'], key)} {series['sum']}"
                    )
                    lines.append(
                        f"{name}_count{self._labels(spec['labels'], key)} {series['count']}"
                    )
        return "\n".join(lines) + "\n"


class _PrometheusBackend:
    """Adapter around ``prometheus_client`` when the library is available."""

    def __init__(self) -> None:
        from prometheus_client import (  # type: ignore
            CollectorRegistry,
            Counter,
            Gauge,
            Histogram,
            generate_latest,
        )

        self._registry = CollectorRegistry()
        self._generate_latest = generate_latest

        def mk(cls, name, help_text, labels, **kw):
            return cls(name, help_text, list(labels), registry=self._registry, **kw)

        mk(Counter, N_CLASSIFICATIONS, "Classifications by verdict.", ("verdict", "action"))
        mk(Counter, N_ERRORS, "Errors by stage.", ("stage",))
        mk(Counter, N_CACHE_HITS, "Cache hits.", ())
        mk(Counter, N_CACHE_MISSES, "Cache misses.", ())
        mk(Counter, N_REQUESTS, "Requests by tenant and endpoint (§31).", ("tenant", "endpoint"))
        mk(Counter, N_INSPECTIONS, "Inspections by model and status (§31).", ("model", "status"))
        mk(Counter, N_ENFORCEMENT, "Enforcement actions (§31).", ("action",))
        mk(Counter, N_MODEL_INFERENCE, "Model inferences by model (§31).", ("model",))
        mk(Counter, N_WORKER_ERRORS, "Worker errors (§31).", ("worker",))
        mk(Counter, N_RATE_LIMITED, "Requests rejected by the rate limiter (§17).", ("tenant",))
        mk(Counter, N_RATE_LIMITERS, "Requests rejected by an open circuit (§33).", ("circuit",))
        mk(Gauge, N_MODELS_LOADED, "Loaded model count.", ())
        mk(Gauge, N_CACHE_ENTRIES, "Cache entry count.", ())
        mk(Gauge, N_QUEUE_DEPTH, "In-flight request depth (§31).", ())
        mk(Gauge, N_CPU_UTIL, "Process CPU utilization ratio (§31).", ())
        mk(Gauge, N_MEMORY_USAGE, "Process RSS in bytes (§31).", ())
        mk(Gauge, N_GPU_UTIL, "GPU utilization ratio (§31, 0 when no GPU).", ())
        mk(Histogram, N_STAGE_LATENCY, "Per-stage latency.", ("path",), buckets=LATENCY_BUCKETS)
        mk(
            Histogram,
            N_PIPELINE_LATENCY,
            "Full pipeline latency including policy (§31).",
            ("verdict",),
            buckets=LATENCY_BUCKETS,
        )
        mk(
            Histogram,
            N_REQUEST_LATENCY,
            "End-to-end latency.",
            ("verdict",),
            buckets=LATENCY_BUCKETS,
        )
        mk(Histogram, N_RISK_SCORE, "Risk score distribution.", ("verdict",))
        mk(Gauge, N_STARTUP_TIME, "Startup time (§31).", ())
        mk(Histogram, N_QUEUE_LATENCY, "Queue latency (§31).", ())
        mk(Counter, N_REQUEST_ERRORS, "5xx responses by endpoint (S31).", ("endpoint",))
        mk(Counter, N_DEAD_LETTER, "Dead-lettered requests (S33).", ("reason",))

    def render(self) -> str:
        return self._generate_latest(self._registry).decode("utf-8")


class _FallbackBackend:
    """API-compatible shim over :class:`_MiniRegistry`."""

    def __init__(self) -> None:
        self._reg = _MiniRegistry()
        self._reg.counter(N_CLASSIFICATIONS, "Classifications by verdict.", ("verdict", "action"))
        self._reg.counter(N_ERRORS, "Errors by stage.", ("stage",))
        self._reg.counter(N_CACHE_HITS, "Cache hits.", ())
        self._reg.counter(N_CACHE_MISSES, "Cache misses.", ())
        self._reg.counter(N_REQUESTS, "Requests by tenant and endpoint (§31).", ("tenant", "endpoint"))
        self._reg.counter(N_INSPECTIONS, "Inspections by model and status (§31).", ("model", "status"))
        self._reg.counter(N_ENFORCEMENT, "Enforcement actions (§31).", ("action",))
        self._reg.counter(N_MODEL_INFERENCE, "Model inferences by model (§31).", ("model",))
        self._reg.counter(N_WORKER_ERRORS, "Worker errors (§31).", ("worker",))
        self._reg.counter(N_RATE_LIMITED, "Requests rejected by the rate limiter (§17).", ("tenant",))
        self._reg.counter(N_RATE_LIMITERS, "Requests rejected by an open circuit (§33).", ("circuit",))
        self._reg.gauge(N_STARTUP_TIME, "Startup time (§31).", ())
        self._reg.histogram(N_QUEUE_LATENCY, "Queue latency (§31).", ())
        self._reg.counter(N_REQUEST_ERRORS, "5xx responses by endpoint (S31).", ("endpoint",))
        self._reg.counter(N_DEAD_LETTER, "Dead-lettered requests (S33).", ("reason",))
        self._reg.gauge(N_MODELS_LOADED, "Loaded model count.", ())
        self._reg.gauge(N_CACHE_ENTRIES, "Cache entry count.", ())
        self._reg.gauge(N_QUEUE_DEPTH, "In-flight request depth (§31).", ())
        self._reg.gauge(N_CPU_UTIL, "Process CPU utilization ratio (§31).", ())
        self._reg.gauge(N_MEMORY_USAGE, "Process RSS in bytes (§31).", ())
        self._reg.gauge(N_GPU_UTIL, "GPU utilization ratio (§31, 0 when no GPU).", ())
        self._reg.histogram(N_STAGE_LATENCY, "Per-stage latency.", ("path",))
        self._reg.histogram(N_PIPELINE_LATENCY, "Full pipeline latency including policy (§31).", ("verdict",))
        self._reg.histogram(N_REQUEST_LATENCY, "End-to-end latency.", ("verdict",))
        self._reg.histogram(N_RISK_SCORE, "Risk score distribution.", ("verdict",))

    def render(self) -> str:
        return self._reg.render()

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        self._reg.inc(name, value, **labels)

    def set(self, name: str, value: float, **labels: str) -> None:
        self._reg.set(name, value, **labels)

    def observe(self, name: str, value: float, **labels: str) -> None:
        self._reg.observe(name, value, **labels)
def _build_backend() -> Any:
    try:
        backend = _PrometheusBackend()
        logger.info("prometheus_client detected - using native metrics backend")
        return backend
    except Exception as exc:  # noqa: BLE001 - optional dependency
        logger.info("prometheus_client unavailable (%s) - using built-in backend", exc)
        return _FallbackBackend()


_BACKEND = _build_backend()
PROMETHEUS_NATIVE = isinstance(_BACKEND, _PrometheusBackend)


def render_latest() -> str:
    """Render current metrics in the Prometheus text exposition format."""
    try:
        return _BACKEND.render()
    except Exception as exc:  # noqa: BLE001 - metrics must not break a request
        logger.warning("failed to render metrics: %s", exc)
        return ""


def record_classification(
    verdict: str, action: str, latency_seconds: float, score: float = 0.0
) -> None:
    """Record one end-to-end classification."""
    try:
        _BACKEND.inc(N_CLASSIFICATIONS, 1.0, verdict=verdict, action=action)
        _BACKEND.observe(
            N_REQUEST_LATENCY, max(0.0, float(latency_seconds)), verdict=verdict
        )
        _BACKEND.observe(N_RISK_SCORE, max(0.0, min(1.0, float(score))), verdict=verdict)
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_classification failed: %s", exc)


def record_stage(path: str, latency_seconds: float) -> None:
    """Record the latency of a single cascade stage."""
    try:
        _BACKEND.observe(N_STAGE_LATENCY, max(0.0, float(latency_seconds)), path=path)
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_stage failed: %s", exc)


def record_error(stage: str = "unknown") -> None:
    try:
        _BACKEND.inc(N_ERRORS, 1.0, stage=stage)
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_error failed: %s", exc)


def record_cache(
    hits: Optional[int] = None, misses: Optional[int] = None, size: Optional[int] = None
) -> None:
    """Publish cache counters (absolute) and the entry-count gauge."""
    try:
        if hits is not None:
            _BACKEND.inc(N_CACHE_HITS, float(hits))
        if misses is not None:
            _BACKEND.inc(N_CACHE_MISSES, float(misses))
        if size is not None:
            _BACKEND.set(N_CACHE_ENTRIES, float(size))
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_cache failed: %s", exc)


def set_models_loaded(count: int) -> None:
    try:
        _BACKEND.set(N_MODELS_LOADED, float(count))
    except Exception as exc:  # noqa: BLE001
        logger.debug("set_models_loaded failed: %s", exc)


#: (wall-clock, cpu-time) of the previous sample, for the CPU utilisation ratio.
_LAST_CPU_SAMPLE = [time.time(), time.process_time()]


def record_request(tenant: str, endpoint: str) -> None:
    """Count one inbound request (§31 ``requests_total``)."""
    try:
        _BACKEND.inc(N_REQUESTS, 1.0, tenant=tenant or "-", endpoint=endpoint or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_request failed: %s", exc)


def record_inspection(model: str, status: str) -> None:
    """Count one inspection, split by model and cache status (§31)."""
    try:
        _BACKEND.inc(N_INSPECTIONS, 1.0, model=model or "-", status=status or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_inspection failed: %s", exc)


def record_enforcement(action: str) -> None:
    """Count one enforcement action: ALLOW/BLOCK/REVIEW/QUARANTINE (§31)."""
    try:
        _BACKEND.inc(N_ENFORCEMENT, 1.0, action=action or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_enforcement failed: %s", exc)


def set_startup_time(seconds: float) -> None:
    """Record how long the process took to become ready to serve (§31).

    Measured from interpreter start, not from the first request, so model
    loading is included. A deployment that loads slowly looks identical to one
    that receives no traffic unless this is exposed somewhere.
    """
    try:
        _BACKEND.set(N_STARTUP_TIME, max(0.0, float(seconds)))
    except Exception as exc:  # noqa: BLE001
        logger.debug("set_startup_time failed: %s", exc)


def record_queue_latency(seconds: float) -> None:
    """Record time a request spent queued before its handler began (§31).

    This is the signal that distinguishes "the engine is saturated" from "the
    model is slow". Request duration conflates the two; without this series an
    operator tuning concurrency has nothing to act on.
    """
    try:
        _BACKEND.observe(N_QUEUE_LATENCY, max(0.0, float(seconds)))
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_queue_latency failed: %s", exc)


def record_request_error(endpoint: str) -> None:
    """Count one 5xx response for *endpoint* (§31).

    Paired with :func:`record_request` this gives
    ``rate(nsfw_request_errors_total[5m]) / rate(nsfw_requests_total[5m])``.
    Only genuine server faults are counted - a 4xx is the client being told no,
    not the engine failing, and mixing them would make the ratio unreadable.
    """
    try:
        _BACKEND.inc(N_REQUEST_ERRORS, 1.0, endpoint=endpoint or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_request_error failed: %s", exc)


def record_dead_letter(reason: str) -> None:
    """Count one request dead-lettered because it could not be decided (§33).

    The ``reason`` label separates the failure modes an operator must respond
    to differently: ``circuit_open`` means a dependency is down, whereas
    ``classify_error`` means the engine itself is failing. A single undifferentiated
    counter would hide both behind one flat rate.
    """
    try:
        _BACKEND.inc(N_DEAD_LETTER, 1.0, reason=reason or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_dead_letter failed: %s", exc)


def record_model_inference(model: str) -> None:
    """Count one model inference (§31 ``model_inference_total``)."""
    try:
        _BACKEND.inc(N_MODEL_INFERENCE, 1.0, model=model or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_model_inference failed: %s", exc)


def record_pipeline_latency(latency_seconds: float, verdict: str) -> None:
    """Record full-pipeline latency, distinct from per-stage (§31)."""
    try:
        _BACKEND.observe(
            N_PIPELINE_LATENCY, max(0.0, float(latency_seconds)), verdict=verdict or "-"
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_pipeline_latency failed: %s", exc)


def record_rate_limited(tenant: str) -> None:
    """Count a request rejected by the rate limiter (§17, §31)."""
    try:
        _BACKEND.inc(N_RATE_LIMITED, 1.0, tenant=tenant or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_rate_limited failed: %s", exc)


def record_circuit_open(circuit: str) -> None:
    """Count a call rejected by an open circuit breaker (§33, §31)."""
    try:
        _BACKEND.inc(N_RATE_LIMITERS, 1.0, circuit=circuit or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_circuit_open failed: %s", exc)


def record_worker_error(worker: str) -> None:
    """Count a worker failure (§31 ``worker_errors``)."""
    try:
        _BACKEND.inc(N_WORKER_ERRORS, 1.0, worker=worker or "-")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_worker_error failed: %s", exc)


def set_queue_depth(depth: int) -> None:
    """Publish the in-flight request depth (§31 ``queue_depth``)."""
    try:
        _BACKEND.set(N_QUEUE_DEPTH, float(depth))
    except Exception as exc:  # noqa: BLE001
        logger.debug("set_queue_depth failed: %s", exc)


def record_process_resources() -> None:
    """Publish CPU and RSS gauges for the process (§31).

    Read from ``/proc`` on Linux and from ``resource`` elsewhere, so this adds no
    third-party dependency (``psutil``) to the request path. A failure here is
    non-fatal: the gauges simply keep their previous values.

    ``nsfw_gpu_utilization_ratio`` is deliberately *not* set here. There is no
    portable, dependency-free way to read GPU utilisation, and publishing a
    hardcoded ``0`` would look like a real measurement on a GPU node. A
    deployment with a GPU should set it from ``nvidia-smi`` via its own
    exporter instead.
    """
    try:
        rss = None
        try:
            with open("/proc/self/statm", "r", encoding="ascii") as handle:
                pages = int(handle.read().split()[1])
            rss = float(pages * os.sysconf("SC_PAGE_SIZE"))
        except Exception:  # noqa: BLE001 - not Linux, or /proc unavailable
            try:
                import resource

                rss = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024.0
            except Exception:  # noqa: BLE001
                rss = None
        if rss is not None:
            _BACKEND.set(N_MEMORY_USAGE, rss)

        # CPU: cumulative process time divided by wall time since the last call.
        now = time.time()
        cpu = time.process_time()
        elapsed = now - _LAST_CPU_SAMPLE[0]
        if elapsed > 0:
            ratio = max(0.0, min(1.0, (cpu - _LAST_CPU_SAMPLE[1]) / elapsed))
            _BACKEND.set(N_CPU_UTIL, ratio)
        _LAST_CPU_SAMPLE[0] = now
        _LAST_CPU_SAMPLE[1] = cpu
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_process_resources failed: %s", exc)


# ---------------------------------------------------------------------------
# Distributed tracing (observability.enable_tracing, §31)
# ---------------------------------------------------------------------------
#: True once OpenTelemetry has been initialised successfully.
TRACING_ACTIVE = False
_TRACER = None


def init_tracing(service_name: str = "nsfw-firewall-engine", enabled: bool = False) -> bool:
    """Initialise OpenTelemetry tracing when requested and available.

    Returns ``True`` only if tracing is really active. When disabled, the SDK is
    absent, or initialisation fails, this is a silent no-op: observability must
    never break request handling.
    """
    global TRACING_ACTIVE, _TRACER

    if not enabled:
        return False
    try:
        from opentelemetry import trace  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore

        provider = TracerProvider(
            resource=Resource.create({"service.name": service_name})
        )
        trace.set_tracer_provider(provider)
        _TRACER = trace.get_tracer(service_name)
        TRACING_ACTIVE = True
        logger.info("OpenTelemetry tracing initialised for %s", service_name)
    except Exception as exc:  # noqa: BLE001 - optional dependency
        logger.warning("tracing requested but unavailable (%s); continuing without it", exc)
        TRACING_ACTIVE = False
        _TRACER = None
    return TRACING_ACTIVE


def traced(name: str):
    """Decorator adding a span around a function when tracing is active."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            if not TRACING_ACTIVE or _TRACER is None:
                return func(*args, **kwargs)
            try:
                with _TRACER.start_as_current_span(name):
                    return func(*args, **kwargs)
            except Exception:  # noqa: BLE001 - never fail a call over telemetry
                return func(*args, **kwargs)

        wrapper.__name__ = getattr(func, "__name__", name)
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator


def tracing_status() -> dict:
    """Health-friendly tracing summary (never includes exporter internals)."""
    return {"enabled": bool(TRACING_ACTIVE), "backend": "opentelemetry" if TRACING_ACTIVE else "none"}


__all__ = [
    "PROMETHEUS_NATIVE",
    "LATENCY_BUCKETS",
    "TRACING_ACTIVE",
    "init_tracing",
    "render_latest",
    "record_cache",
    "record_classification",
    "record_error",
    "record_stage",
    "set_models_loaded",
    "traced",
    "tracing_status",
]