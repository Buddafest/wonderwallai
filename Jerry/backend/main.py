"""
================================================================================
Jerry The Customer Service Bot — FastAPI Application Entry Point
================================================================================
File:     backend/main.py
Version:  4.0.0  (Session 13 — WonderwallAi SDK, production hardening)
Session:  5 (February 2026)
Author:   Built in collaboration with AI assistant

CHANGES IN v3.0.0
-------------------
- Added: Database initialization (SQLAlchemy async, SQLite/PostgreSQL)
- Added: Shopify OAuth routes (/shopify/install, /shopify/callback, /shopify/webhooks)
- Added: JWT authentication for WebSocket connections (query param ?token=xxx)
- Added: Centralized Settings (Pydantic BaseSettings) — replaces scattered os.getenv()
- Added: Widget token endpoint for chat widget auth
- Carried forward from v2.2.0: rate limiting, IP limits, CORS, graceful shutdown

HOW TO RUN
----------
    cd ~/sunsetbot/backend
    source venv/bin/activate
    python main.py

    Swagger UI:  http://localhost:8000/docs
    Health:      http://localhost:8000/health
    Chat test:   open test_chat.html in browser
================================================================================
"""

import asyncio
import os
import json
import logging
import time
import unicodedata
from collections import defaultdict
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Logging — structured observability (JSON in prod, console in dev)
# ---------------------------------------------------------------------------
from app.core.observability import (
    configure_logging, init_sentry, bind_context, clear_context,
    log_decision, log_llm_call, Timer,
)
from app.core.config import get_settings as _get_settings_early

_boot_settings = _get_settings_early()
configure_logging(
    service_name="jerry",
    environment=_boot_settings.environment,
    log_level=_boot_settings.log_level,
    log_format=_boot_settings.log_format,
)
logger = logging.getLogger("sunsetbot.main")

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
from app.core.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# CORS — validate before applying
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

# ---------------------------------------------------------------------------
# Rate limiting + connection tracking
# ---------------------------------------------------------------------------
RATE_LIMIT_MESSAGES_PER_MIN = settings.rate_limit_messages_per_min
MAX_CONNECTIONS_PER_IP = settings.max_connections_per_ip
MAX_WS_MESSAGE_BYTES = settings.max_ws_message_bytes

_message_timestamps: dict[str, list[float]] = defaultdict(list)
_connections_by_ip: dict[str, int] = defaultdict(int)

# ---------------------------------------------------------------------------
# Service instances (initialized at startup via lifespan)
# ---------------------------------------------------------------------------
conversation_engine = None
product_intelligence = None
billing_service = None
analytics_service = None
firewall_engine = None

# Active WebSocket connections: session_id → WebSocket
active_connections: dict[str, WebSocket] = {}
# Per-session locks to prevent race conditions during connect/disconnect
_session_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


# ============================================================================
# LIFESPAN — startup + graceful shutdown
# Must be defined BEFORE the FastAPI() constructor that references it.
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan handler (replaces deprecated @app.on_event)."""
    global conversation_engine, product_intelligence, billing_service, analytics_service, firewall_engine

    # --- STARTUP: Initialize Sentry ---
    init_sentry(settings.sentry_dsn, settings.environment, "jerry")

    # --- STARTUP: Initialize Database ---
    try:
        from app.db.engine import init_db
        await init_db()
        logger.info("Database initialized.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)

       # --- STARTUP: Initialize AI Services (correct order) ---
    try:
        from app.services.product_intelligence import ProductIntelligence
        product_intelligence = ProductIntelligence()
        logger.info("ProductIntelligence initialized.")
    except Exception as e:
        logger.error(f"ProductIntelligence failed: {e}", exc_info=True)
        product_intelligence = None

    try:
        from app.services.billing_service import ShopifyBillingService
        billing_service = ShopifyBillingService()
    except Exception as e:
        logger.error(f"ShopifyBillingService failed: {e}", exc_info=True)
        billing_service = None

    try:
        from app.services.analytics_service import AnalyticsService
        analytics_service = AnalyticsService(billing_service=billing_service)
        logger.info("AnalyticsService initialized.")
    except Exception as e:
        logger.error(f"AnalyticsService failed: {e}", exc_info=True)
        analytics_service = None

    try:
        from wonderwallai import Wonderwall
        from wonderwallai.patterns.topics import ECOMMERCE_TOPICS

        # Extra casual topics for real shoppers
        JERRY_EXTRA_TOPICS = [
            "Do you have any dresses shoes jackets pants shirts",
            "Show me something in blue red black white green",
            "I'm looking for something under 50 dollars",
            "What do you recommend for a gift birthday anniversary",
            "Do you have this in a different size or colour",
            "How much does this cost what is the price",
            "Is this item in stock available",
            "Can you help me find something",
            "I want to track my order where is my package",
            "What are your best sellers most popular items",
            "Do you have anything on sale or discounted",
            "I need something warm for winter cold weather",
            "What goes well with this outfit combination",
            "Tell me more about this product details features",
            "Do you deliver to my area my country my city",
        ]

        firewall_engine = Wonderwall(
            topics=ECOMMERCE_TOPICS + JERRY_EXTRA_TOPICS,
            similarity_threshold=0.20,
            embedding_model=product_intelligence.embedding_model if product_intelligence else None,
            sentinel_api_key=settings.groq_api_key if hasattr(settings, 'groq_api_key') else "",
            bot_description="a customer service chatbot that helps with shopping",
            canary_prefix="JERRY-CANARY-",
            block_message=(
                "I'm Jerry, your shopping assistant! I can help with products, "
                "orders, shipping, and returns. What can I help you with?"
            ),
            block_message_injection=(
                "I'm here to help with shopping! Could you rephrase your "
                "question about our products or orders?"
            ),
        )
        logger.info("WonderwallAi firewall initialized.")
    except Exception as e:
        logger.error(f"Wonderwall firewall failed: {e}", exc_info=True)
        firewall_engine = None

    # --- Finally create the engine and wire everything ---
    try:
        from app.services.conversation_engine import ConversationEngine
        conversation_engine = ConversationEngine()
        if analytics_service:
            conversation_engine.analytics = analytics_service
        if firewall_engine:
            conversation_engine.firewall_engine = firewall_engine
        if product_intelligence:
            conversation_engine._product_intelligence = product_intelligence
        logger.info("ConversationEngine initialized with WonderwallAi + Analytics.")
    except Exception as e:
        logger.error(f"ConversationEngine failed: {e}", exc_info=True)
        conversation_engine = None
        
    # Log integration status
    if settings.shopify_configured:
        logger.info("Shopify integration: CONFIGURED")
    else:
        logger.info("Shopify integration: NOT CONFIGURED (set SHOPIFY_API_KEY and SHOPIFY_API_SECRET)")

    yield

    # --- SHUTDOWN ---
    logger.info(f"Shutting down — closing {len(active_connections)} active connections...")
    for sid, ws in list(active_connections.items()):
        try:
            await ws.close(code=1001, reason="Server shutting down")
        except Exception:
            pass
    active_connections.clear()
    _message_timestamps.clear()
    _connections_by_ip.clear()

    # Close database connections
    try:
        from app.db.engine import close_db
        await close_db()
    except Exception:
        pass

    logger.info("Shutdown complete.")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Jerry The Customer Service Bot API",
    description=(
        "AI-powered e-commerce assistant backend for Shopify stores. "
        "Real-time chat via WebSocket, product search via vector embeddings, "
        "natural language responses via Llama 3.3 (Groq)."
    ),
    version="4.0.0",
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

# Security headers
from app.core.middleware import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Mount API Routers
# ---------------------------------------------------------------------------
from app.api.shopify import router as shopify_router
app.include_router(shopify_router)

from app.api.billing import router as billing_router
app.include_router(billing_router)

from app.api.dashboard import router as dashboard_router
app.include_router(dashboard_router)

from app.api.admin import router as admin_router
app.include_router(admin_router)

from app.api.tts import router as tts_router
app.include_router(tts_router)

# ---------------------------------------------------------------------------
# Serve static files (widget JS bundle)
# ---------------------------------------------------------------------------
import pathlib
_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ============================================================================
# WEBSOCKET ENDPOINT — Now with JWT authentication
# ============================================================================

@app.websocket("/ws/chat/{store_id}/{session_id}")
async def websocket_chat(
    websocket: WebSocket,
    store_id: str,
    session_id: str,
    token: str = Query(default=""),
):
    """
    Primary WebSocket endpoint for real-time AI chat.

    URL: ws://localhost:8000/ws/chat/{store_id}/{session_id}?token=xxx

    In production, the token parameter is REQUIRED — it's a JWT issued by
    /shopify/widget-token. In development mode, token is optional.
    """
    # --- JWT Authentication ---
    if settings.is_production:
        if not token:
            await websocket.close(code=4001, reason="Authentication required")
            return

        from app.core.security import verify_widget_token
        payload = verify_widget_token(token)

        if payload is None:
            await websocket.close(code=4001, reason="Invalid or expired token")
            return

        # Verify token matches the URL params
        if payload.get("store_id") != store_id:
            await websocket.close(code=4003, reason="Token store_id mismatch")
            return

        logger.info(f"JWT authenticated | store={store_id} | session={session_id}")

    elif token:
        # Development mode: validate token if provided, but don't require it
        from app.core.security import verify_widget_token
        payload = verify_widget_token(token)
        if payload:
            logger.info(f"JWT validated (dev mode) | store={store_id}")
        else:
            logger.warning(f"Invalid JWT in dev mode — allowing connection anyway")

    # --- Subscription gating (production only) ---
    if settings.is_production:
        try:
            from app.db.engine import get_db
            from app.db.models import Store
            from sqlalchemy import select as sa_select
            async with get_db() as db:
                result = await db.execute(
                    sa_select(Store).where(
                        Store.shopify_domain == f"{store_id}.myshopify.com"
                    )
                )
                store_record = result.scalar_one_or_none()
            if store_record:
                valid_statuses = {"active", "trialing", "none"}
                if getattr(store_record, "subscription_status", "none") not in valid_statuses:
                    await websocket.close(code=4003, reason="Subscription inactive")
                    return
            else:
                logger.warning(f"Store not found for subscription check: {store_id}")
        except Exception as e:
            logger.error(f"Subscription check failed: {e}")
            # Allow connection on check failure (graceful degradation)

    # --- Check service availability ---
    if conversation_engine is None:
        await websocket.close(code=1011, reason="Service unavailable")
        return

    # --- Connection-per-IP limiting ---
    client_ip = websocket.client.host if websocket.client else "unknown"
    if _connections_by_ip[client_ip] >= MAX_CONNECTIONS_PER_IP:
        logger.warning(f"Connection limit hit for IP {client_ip}")
        await websocket.close(code=4029, reason="Too many connections from your IP")
        return

    # --- Handle duplicate session: close old connection (with lock to prevent races) ---
    async with _session_locks[session_id]:
        if session_id in active_connections:
            old_ws = active_connections.pop(session_id)
            try:
                await old_ws.send_json({
                    "type": "error",
                    "error": "Connected from another device. This session will close.",
                })
                await old_ws.close(code=4009, reason="Session opened elsewhere")
            except Exception:
                pass  # Old connection might already be dead

        # --- Accept connection ---
        await websocket.accept()
        active_connections[session_id] = websocket
        _connections_by_ip[client_ip] += 1
    logger.info(f"WebSocket connected | session={session_id} | store={store_id} | ip={client_ip}")

    # --- Bind observability context (all subsequent logs auto-include these) ---
    bind_context(session_id=session_id, store_id=store_id, client_ip=client_ip)
    turn_number = 0

    # --- Load or create context ---
    context = await conversation_engine.get_or_create_context(session_id, store_id)

    # Inject canary token for egress filter (WonderwallAi SDK)
    if firewall_engine and not getattr(context, 'canary_token', None):
        context.canary_token = firewall_engine.generate_canary(session_id)
        context.canary_prompt_block = firewall_engine.get_canary_prompt(context.canary_token)

    # --- Send welcome message ---
    welcome = _build_welcome_message(store_id, session_id)
    await websocket.send_json(welcome)

    try:
        while True:
            raw = await websocket.receive_text()

            # --- Message size check ---
            if len(raw) > MAX_WS_MESSAGE_BYTES:
                await websocket.send_json({
                    "type": "error",
                    "error": "Message too large. Please keep it shorter.",
                })
                continue

            # --- Parse JSON ---
            try:
                payload = json.loads(raw)
                user_message = _sanitize_message(payload.get("message", ""))

                if not user_message:
                    await websocket.send_json({
                        "type": "error",
                        "error": "Message cannot be empty.",
                    })
                    continue

            except (json.JSONDecodeError, AttributeError):
                await websocket.send_json({
                    "type": "error",
                    "error": 'Invalid JSON. Send: {"message": "your text here"}',
                })
                continue

            # --- Rate limiting ---
            now = time.time()
            timestamps = _message_timestamps[session_id]
            timestamps.append(now)
            # Prune timestamps older than 60s
            _message_timestamps[session_id] = [ts for ts in timestamps if now - ts < 60]
            if len(_message_timestamps[session_id]) > RATE_LIMIT_MESSAGES_PER_MIN:
                await websocket.send_json({
                    "type": "error",
                    "error": "You're sending messages too quickly. Please wait a moment.",
                })
                continue

            # --- Increment turn counter + bind to context ---
            turn_number += 1
            bind_context(turn_number=turn_number)

            # --- FIREWALL: Inbound scan ---
            if firewall_engine is not None:
                try:
                    with Timer() as fw_in_t:
                        verdict = await firewall_engine.scan_inbound(user_message)
                    log_decision(
                        "firewall_inbound",
                        input_summary=user_message[:100],
                        chosen="blocked" if not verdict.allowed else "allowed",
                        reason=f"blocked_by={verdict.blocked_by}" if not verdict.allowed else "all_layers_passed",
                        latency_ms=fw_in_t.ms,
                        metadata={"violations": verdict.violations} if verdict.violations else None,
                    )
                    if not verdict.allowed:
                        await websocket.send_json({
                            "type": "message",
                            "text": verdict.message,
                            "intent": "firewall_block",
                            "products": [],
                            "escalated": False,
                            "session_id": session_id,
                        })
                        continue
                except Exception as e:
                    logger.error(f"Firewall inbound error (allowing): {e}")

            # --- Typing indicator ---
            await websocket.send_json({"type": "typing"})

            # --- Process message ---
            logger.info(
                f"Message received | session={session_id} | store={store_id} | "
                f"text='{user_message[:60]}'"
            )

            try:
                with Timer() as pipeline_t:
                    engine_response = await conversation_engine.process_message(
                        message=user_message,
                        context=context,
                    )
            except Exception as e:
                logger.error(f"ConversationEngine error: {e}", exc_info=True)
                await websocket.send_json({
                    "type": "error",
                    "error": "I'm having a moment — please try again!",
                })
                continue

            # --- FIREWALL: Outbound scan ---
            if firewall_engine is not None:
                try:
                    canary = getattr(context, 'canary_token', "") or ""
                    with Timer() as fw_out_t:
                        egress_verdict = await firewall_engine.scan_outbound(
                            engine_response.text, canary
                        )
                    fw_out_action = "allowed"
                    if egress_verdict.violations:
                        fw_out_action = "redacted"
                    log_decision(
                        "firewall_outbound",
                        chosen=fw_out_action,
                        latency_ms=fw_out_t.ms,
                        metadata={"violations": egress_verdict.violations} if egress_verdict.violations else None,
                    )
                    engine_response.text = egress_verdict.message
                except Exception as e:
                    logger.error(f"Firewall outbound error (allowing): {e}")

            # --- Send response ---
            response_payload = _serialize_engine_response(engine_response)
            await websocket.send_json(response_payload)

            log_decision(
                "message_pipeline",
                input_summary=user_message[:100],
                chosen=engine_response.intent,
                metadata={
                    "products_found": len(engine_response.products),
                    "escalated": engine_response.escalated,
                    "total_latency_ms": round(pipeline_t.ms, 2),
                },
            )

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected | session={session_id}")

    except Exception as e:
        logger.error(f"Unexpected WebSocket error | session={session_id}: {e}", exc_info=True)

    finally:
        active_connections.pop(session_id, None)
        _connections_by_ip[client_ip] = max(0, _connections_by_ip[client_ip] - 1)
        _message_timestamps.pop(session_id, None)
        if conversation_engine:
            await conversation_engine.end_session(session_id)
        logger.info(f"Session cleaned up | session={session_id} | turns={turn_number}")
        clear_context()


# ============================================================================
# REST ENDPOINTS
# ============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Health check — returns 200 even when degraded, with service status details."""
    engine_ready = conversation_engine is not None
    pi_ready = product_intelligence is not None
    all_ready = engine_ready and pi_ready

    return {
        "status": "healthy" if all_ready else "degraded",
        "environment": settings.environment,
        "version": "4.0.0",
        "services": {
            "conversation_engine": "ready" if engine_ready else "failed",
            "product_intelligence": (
                "mock" if (pi_ready and product_intelligence._mock_mode)
                else "pinecone" if pi_ready
                else "failed"
            ),
            "shopify": "configured" if settings.shopify_configured else "not_configured",
            "database": "sqlite" if "sqlite" in settings.database_url else "postgresql",
            "billing": "active" if (billing_service and billing_service.configured) else "disabled",
            "analytics": "active" if analytics_service else "disabled",
            "firewall": "active" if firewall_engine else "disabled",
            "active_sessions": len(active_connections),
        },
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "Jerry The Customer Service Bot API is running!",
        "version": "4.0.0",
        "docs": "/docs",
        "health": "/health",
        "chat": "ws://localhost:8000/ws/chat/{store_id}/{session_id}?token=xxx",
        "shopify_install": "/shopify/install?shop=your-store.myshopify.com",
    }


# ---------------------------------------------------------------------------
# Product Indexing
# ---------------------------------------------------------------------------

class IndexProductsRequest(BaseModel):
    store_id: str
    products: list[dict]


@app.post("/api/products/index", tags=["Products"])
async def index_products(request: IndexProductsRequest):
    """Index products into the vector database for semantic search."""
    if product_intelligence is None:
        raise HTTPException(status_code=503, detail="ProductIntelligence not available")

    from app.services.product_intelligence import CatalogProduct

    catalog_products = []
    for p in request.products:
        try:
            catalog_products.append(CatalogProduct(
                id=p["id"],
                title=p["title"],
                price=float(p.get("price", 0)),
                category=p.get("category", ""),
                description=p.get("description", ""),
                tags=p.get("tags", []),
                colors=p.get("colors", []),
                sizes=p.get("sizes", []),
                materials=p.get("materials", []),
                image_url=p.get("image_url"),
                url=p.get("url"),
                inventory=int(p.get("inventory", 99)),
                sales_velocity=float(p.get("sales_velocity", 0.5)),
            ))
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid product data: {e}")

    count = await product_intelligence.index_products(catalog_products, request.store_id)
    return {"indexed": count, "store_id": request.store_id}


@app.delete("/api/products/{product_id}", tags=["Products"])
async def delete_product(product_id: str, store_id: str):
    if product_intelligence is None:
        raise HTTPException(status_code=503, detail="ProductIntelligence not available")
    await product_intelligence.delete_product(product_id, store_id)
    return {"deleted": product_id}


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

@app.delete("/api/sessions/{session_id}", tags=["Sessions"])
async def delete_session(session_id: str):
    if conversation_engine is None:
        raise HTTPException(status_code=503, detail="ConversationEngine not available")
    await conversation_engine.end_session(session_id)
    return {"ended": session_id}


@app.get("/api/sessions/active", tags=["Sessions"])
async def get_active_sessions():
    return {
        "count": len(active_connections),
        "sessions": list(active_connections.keys()),
    }


# ============================================================================
# HELPERS
# ============================================================================

def _sanitize_message(text: str) -> str:
    """Sanitize user input: normalize Unicode, strip control chars, enforce length."""
    if not text:
        return ""
    # Normalize Unicode (prevents homoglyph attacks, e.g. Cyrillic 'а' vs Latin 'a')
    text = unicodedata.normalize("NFKC", text)
    # Remove control characters except newline/tab (keeps \n \t, strips \x00, ANSI escapes, etc.)
    text = "".join(
        c for c in text
        if unicodedata.category(c)[0] != "C" or c in "\n\t"
    )
    # Enforce max length (matches conversation engine's 2000 char limit)
    return text[:2000].strip()


def _build_welcome_message(store_id: str, session_id: str) -> dict:
    return {
        "type": "message",
        "text": (
            "Hey there! I'm your shopping assistant. "
            "I can help you find products, check sizing, answer questions "
            "about shipping and returns, or track your order. What can I help you with today?"
        ),
        "intent": "greeting",
        "products": [],
        "escalated": False,
        "session_id": session_id,
    }


def _serialize_engine_response(response) -> dict:
    return {
        "type": "message",
        "text": response.text,
        "intent": response.intent,
        "products": [
            {
                "id": p.id,
                "title": p.title,
                "price": round(p.price, 2),
                "image_url": p.image_url,
                "url": p.url,
                "inventory": p.inventory,
            }
            for p in (response.products or [])
        ],
        "escalated": response.escalated,
        "escalation_reason": response.escalation_reason,
        "entities": response.entities or {},
        "session_id": response.session_id,
    }


# ============================================================================
# GLOBAL EXCEPTION HANDLER (REST endpoints only — WS has its own)
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Please try again."},
    )


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    logger.info(f"Starting Jerry The Customer Service Bot API | environment={settings.environment} | port={settings.port}")

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.is_development,
        log_level="info",
    )
