"""WonderwallAi hosted API server."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import get_settings
from server.db.engine import init_db, close_db
from server.middleware import SecurityHeadersMiddleware
from server.api import scan, admin, billing
from server.helpers import set_billing_service
from server.services.billing_service import BillingService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    # Initialize database (creates tables + runs migrations)
    await init_db()

    # Initialize Stripe billing service
    billing_svc = BillingService()
    set_billing_service(billing_svc)

    logger.info("WonderwallAi server started")
    yield

    # Shutdown
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

    # CORS
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Routers — no prefix here, each router defines its own prefix already
    app.include_router(scan.router)
    app.include_router(admin.router)
    app.include_router(billing.router)

    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    return app


app = create_app()
