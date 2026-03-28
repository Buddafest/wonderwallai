"""
================================================================================
GiLLBoT — FastAPI Application Entry Point
================================================================================
File:     server/main.py

HOW TO RUN
----------
    cd /Users/louisconstant/skintlabs/GiLLBoT
    pip install -r requirements.txt
    uvicorn server.main:app --reload --port 8000

    Swagger UI:  http://localhost:8000/docs
    Health:      http://localhost:8000/health
================================================================================
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("gillbot.main")

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
from server.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
CORS_ORIGINS = settings.cors_origin_list

if "*" in CORS_ORIGINS:
    logger.warning(
        "CORS_ORIGINS='*' detected — disabling allow_credentials for security. "
        "Set explicit origins in production."
    )
    _cors_credentials = False
else:
    _cors_credentials = True


# ============================================================================
# LIFESPAN — startup + graceful shutdown
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan handler — runs startup tasks, then yields, then shutdown."""

    # --- STARTUP: Database ---
    try:
        from server.db.engine import create_tables
        await create_tables()
        logger.info("Database tables created/verified.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)

    logger.info(
        f"GiLLBoT API started | env={settings.environment} | "
        f"stripe={'configured' if settings.stripe_configured else 'not_configured'} | "
        f"sendgrid={'configured' if settings.sendgrid_configured else 'not_configured'}"
    )

    yield

    # --- SHUTDOWN ---
    try:
        from server.db.engine import close_db
        await close_db()
    except Exception:
        pass

    logger.info("GiLLBoT API shutdown complete.")


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="GiLLBoT API",
    description=(
        "AI-powered outbound outreach automation. "
        "Manage campaigns, leads, and multi-channel sequences."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Mount API Routers
# ============================================================================

from server.api.auth import router as auth_router
app.include_router(auth_router, prefix="/v1/auth", tags=["Auth"])

from server.api.campaigns import router as campaigns_router
app.include_router(campaigns_router, prefix="/v1/campaigns", tags=["Campaigns"])

from server.api.leads import router as leads_router
app.include_router(leads_router, prefix="/v1/leads", tags=["Leads"])

from server.api.credentials import router as credentials_router
app.include_router(credentials_router, prefix="/v1/credentials", tags=["Credentials"])

from server.api.billing import router as billing_router
app.include_router(billing_router, prefix="/v1/billing", tags=["Billing"])

from server.api.webhooks import router as webhooks_router
app.include_router(webhooks_router, prefix="/v1/webhooks", tags=["Webhooks"])

from server.api.dashboard import router as dashboard_router
app.include_router(dashboard_router, prefix="/v1/dashboard", tags=["Dashboard"])

from server.api.unsubscribe import router as unsubscribe_router
app.include_router(unsubscribe_router, prefix="/v1/unsubscribe", tags=["Unsubscribe"])


# ============================================================================
# Core Endpoints
# ============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Health check — returns service status."""
    return {
        "status": "healthy",
        "product": "GiLLBoT",
        "version": "1.0.0",
        "environment": settings.environment,
        "services": {
            "database": "postgresql",
            "stripe": "configured" if settings.stripe_configured else "not_configured",
            "sendgrid": "configured" if settings.sendgrid_configured else "not_configured",
            "groq": "configured" if settings.groq_configured else "not_configured",
            "redis": "configured" if settings.redis_configured else "not_configured",
        },
    }


@app.get("/", tags=["System"])
async def root():
    """Root endpoint — product info."""
    return {
        "product": "GiLLBoT",
        "version": "1.0.0",
        "description": "AI-powered outbound outreach automation",
        "docs": "/docs",
        "health": "/health",
    }


# ============================================================================
# Global Exception Handler
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Please try again."},
    )


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    logger.info(
        f"Starting GiLLBoT API | environment={settings.environment} | port={settings.port}"
    )
    uvicorn.run(
        "server.main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.is_development,
        log_level="info",
    )
