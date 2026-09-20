"""Low-cardinality Prometheus instrumentation for the FastAPI boundary."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "aegisgraph_http_requests_total",
    "HTTP requests handled by the fraud API.",
    ("method", "route", "status"),
)
HTTP_DURATION = Histogram(
    "aegisgraph_http_request_duration_seconds",
    "HTTP request latency by normalized route.",
    ("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
HTTP_IN_FLIGHT = Gauge(
    "aegisgraph_http_requests_in_flight",
    "HTTP requests currently being processed.",
)


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    return str(getattr(route, "path", "unmatched"))


async def observe_request(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Record request count and latency without using IDs as metric labels."""

    method = request.method
    started = time.perf_counter()
    status_code = 500
    HTTP_IN_FLIGHT.inc()
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        route = _route_label(request)
        HTTP_IN_FLIGHT.dec()
        HTTP_REQUESTS.labels(method=method, route=route, status=str(status_code)).inc()
        HTTP_DURATION.labels(method=method, route=route).observe(time.perf_counter() - started)


def metrics_response() -> Response:
    """Serialize the process registry in Prometheus exposition format."""

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
