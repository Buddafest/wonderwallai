"""WonderwallAi hosted API server."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import get_settings
from server.db.engine import init_db, close_db
from server.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware
from server.instance_cache import warm_shared_model
from server.api import scan, admin, billing, canary, config, files, health, usage
from server.helpers import set_billing_service
from server.services.billing_service import BillingService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    warm_shared_model()
    billing_svc = BillingService()
    set_billing_service(billing_svc)
    logger.info("WonderwallAi server started")
    yield
    await close_db()
    logger.info("WonderwallAi server stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="WonderwallAi API",
        version="1.0.0",
        description="AI firewall for LLM applications",
        lifespan=lifespan,
    )
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(scan.router)
    app.include_router(admin.router)
    app.include_router(billing.router)
    app.include_router(canary.router)
    app.include_router(config.router)
    app.include_router(files.router)
    app.include_router(health.router)
    app.include_router(usage.router)
    return app


app = create_app()
