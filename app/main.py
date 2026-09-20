"""FastAPI application factory and operational HTTP middleware."""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import ORJSONResponse

from app.api.deps import close_redis_client
from app.api.routes import alerts, auth, transactions
from app.core.config import Settings, get_settings
from app.db.base import database_healthcheck, dispose_database
from app.observability import metrics_response, observe_request


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Release shared infrastructure clients on clean shutdown."""

    yield
    await close_redis_client()
    await dispose_database()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application without opening external connections."""

    config = settings or get_settings()
    app = FastAPI(
        title=config.app_name,
        version=config.app_version,
        description="Real-time, explainable, privacy-preserving payment fraud detection.",
        docs_url="/docs" if not config.is_production else None,
        redoc_url="/redoc" if not config.is_production else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )
    app.state.settings = config
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.trusted_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=config.cors_allow_credentials,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
        expose_headers=["X-Correlation-ID", "X-Process-Time-Ms"],
    )

    @app.middleware("http")
    async def request_context(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
        started = time.perf_counter()
        request.state.correlation_id = correlation_id
        response = await observe_request(request, call_next)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Process-Time-Ms"] = f"{(time.perf_counter() - started) * 1000:.2f}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health/live", tags=["operations"])
    async def liveness() -> dict[str, str]:
        return {"status": "alive", "version": config.app_version}

    @app.get("/health/ready", tags=["operations"])
    async def readiness() -> ORJSONResponse:
        database_ready = await database_healthcheck(config)
        code = status.HTTP_200_OK if database_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        return ORJSONResponse(
            status_code=code,
            content={
                "status": "ready" if database_ready else "not_ready",
                "database": database_ready,
            },
        )

    app.add_api_route(
        config.metrics_path,
        metrics_response,
        methods=["GET"],
        include_in_schema=False,
    )
    app.include_router(auth.router, prefix=config.api_v1_prefix)
    app.include_router(transactions.router, prefix=config.api_v1_prefix)
    app.include_router(alerts.router, prefix=config.api_v1_prefix)
    return app


app = create_app()
