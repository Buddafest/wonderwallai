"""
================================================================================
Jerry The Customer Service Bot — Shopify API Routes
================================================================================
File:     app/api/shopify.py
Version:  1.0.0
Session:  5 (February 2026)

PURPOSE
-------
Handles the Shopify OAuth install flow and webhooks.

ENDPOINTS
---------
GET  /shopify/install          — Starts OAuth: redirects store owner to Shopify consent screen
GET  /shopify/callback         — Shopify redirects here after consent; exchanges code for token
GET  /shopify/widget-token     — Returns a JWT for the chat widget (called by widget JS)
POST /shopify/webhooks         — Receives Shopify product/app webhooks

OAUTH FLOW
----------
1. Store owner clicks "Install" → hits /shopify/install?shop=xxx.myshopify.com
2. We redirect to Shopify OAuth consent page
3. Store owner approves → Shopify redirects to /shopify/callback?code=xxx&shop=xxx
4. We exchange the code for an access token, save it, trigger first product sync
5. Redirect store owner to a success page
================================================================================
"""

import logging
import secrets
import uuid
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse, HTMLResponse

from app.core.config import get_settings
from app.core.security import (
    create_widget_token,
    verify_admin_token,
    verify_shopify_hmac,
    verify_shopify_webhook,
)
from app.db.engine import get_db
from app.db.models import Store

from sqlalchemy import select

logger = logging.getLogger("sunsetbot.shopify")

router = APIRouter(prefix="/shopify", tags=["Shopify"])


# ============================================================================
# REDIS HELPERS — OAuth nonce storage
# ============================================================================

def _get_redis_client():
    """Return an async Redis client, or None if Redis is not configured."""
    settings = get_settings()
    if not settings.redis_configured:
        return None
    try:
        import redis.asyncio as aioredis
        return aioredis.from_url(settings.redis_url, decode_responses=False)
    except Exception as e:
        logger.warning(f"Failed to create Redis client: {e}")
        return None


async def _store_nonce(redis_client, nonce: str, shop: str) -> None:
    """Store OAuth nonce in Redis with 10-minute TTL."""
    await redis_client.setex(f"shopify_oauth_nonce:{nonce}", 600, shop)


async def _verify_and_consume_nonce(redis_client, nonce: str, shop: str) -> bool:
    """Verify nonce matches shop and delete it (one-time use)."""
    key = f"shopify_oauth_nonce:{nonce}"
    stored_shop = await redis_client.get(key)
    if stored_shop is None:
        return False
    # Compare (Redis may return bytes)
    stored = stored_shop.decode() if isinstance(stored_shop, bytes) else stored_shop
    if stored != shop:
        return False
    await redis_client.delete(key)
    return True


# ============================================================================
# INSTALL — Start OAuth
# ============================================================================

@router.get("/install")
async def shopify_install(shop: str = Query(..., description="e.g. my-store.myshopify.com")):
    """
    Step 1: Redirect the store owner to Shopify's OAuth consent page.

    Usage: GET /shopify/install?shop=my-store.myshopify.com
    """
    settings = get_settings()

    if not settings.shopify_configured:
        raise HTTPException(
            status_code=503,
            detail="Shopify integration not configured. Set SHOPIFY_API_KEY and SHOPIFY_API_SECRET in .env",
        )

    # Validate shop domain format
    if not shop.endswith(".myshopify.com"):
        raise HTTPException(status_code=400, detail="Invalid shop domain. Must end with .myshopify.com")

    # Generate nonce for CSRF protection and store in Redis
    nonce = secrets.token_urlsafe(32)
    redis_client = _get_redis_client()
    if redis_client is None:
        logger.warning("Redis not available — OAuth nonce will not be stored; callback will fail")
    else:
        try:
            await _store_nonce(redis_client, nonce, shop)
        except Exception as e:
            logger.error(f"Failed to store OAuth nonce in Redis: {e}")
            raise HTTPException(status_code=503, detail="OAuth state storage unavailable")

    # Build Shopify OAuth URL
    redirect_uri = f"{settings.app_url}/shopify/callback"
    params = {
        "client_id": settings.shopify_api_key,
        "scope": settings.shopify_scopes,
        "redirect_uri": redirect_uri,
        "state": nonce,
    }

    auth_url = f"https://{shop}/admin/oauth/authorize?{urlencode(params)}"
    logger.info(f"Starting OAuth install for shop: {shop}")

    return RedirectResponse(url=auth_url)


# ============================================================================
# CALLBACK — Exchange code for token
# ============================================================================

@router.get("/callback")
async def shopify_callback(request: Request):
    """
    Step 2: Shopify redirects here after the store owner approves.
    We verify the HMAC, exchange the code for an access token, and save the store.
    """
    settings = get_settings()

    # Read ALL query params directly from request (not manually listed)
    # This ensures HMAC verification includes every param Shopify sends
    query_params = dict(request.query_params)

    code = query_params.get("code", "")
    shop = query_params.get("shop", "")
    state = query_params.get("state", "")

    if not code or not shop or not state:
        raise HTTPException(status_code=400, detail="Missing required OAuth parameters")

    # --- Verify nonce (CSRF protection) ---
    redis_client = _get_redis_client()
    if redis_client is None:
        logger.warning("Redis not available — cannot verify OAuth nonce")
        raise HTTPException(status_code=503, detail="OAuth state verification unavailable")
    try:
        nonce_valid = await _verify_and_consume_nonce(redis_client, state, shop)
    except Exception as e:
        logger.error(f"Redis error during nonce verification: {e}")
        raise HTTPException(status_code=503, detail="OAuth state verification unavailable")
    if not nonce_valid:
        raise HTTPException(status_code=403, detail="Invalid or expired OAuth state")

    # --- Verify HMAC (proves request came from Shopify) ---
    if not verify_shopify_hmac(query_params):
        raise HTTPException(status_code=403, detail="HMAC verification failed")

    # --- Exchange authorization code for access token ---
    token_url = f"https://{shop}/admin/oauth/access_token"
    token_payload = {
        "client_id": settings.shopify_api_key,
        "client_secret": settings.shopify_api_secret,
        "code": code,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(token_url, json=token_payload)
            resp.raise_for_status()
            token_data = resp.json()
        except httpx.HTTPError as e:
            logger.error(f"Token exchange failed for {shop}: {e}")
            raise HTTPException(status_code=502, detail="Failed to exchange authorization code")

    access_token = token_data.get("access_token")
    granted_scopes = token_data.get("scope", "")

    if not access_token:
        logger.error(f"No access_token in response for {shop}: {token_data}")
        raise HTTPException(status_code=502, detail="No access token received from Shopify")

    # --- Fetch shop info ---
    shop_info = await _fetch_shop_info(shop, access_token, settings.shopify_api_version)

    # --- Save or update store in database ---
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == shop)
        )
        store = result.scalar_one_or_none()

        if store:
            # Re-install: update token and reactivate
            store.access_token = access_token
            store.scopes = granted_scopes
            store.is_active = True
            store.uninstalled_at = None
            if shop_info:
                store.name = shop_info.get("name", store.name)
                store.email = shop_info.get("email", store.email)
                store.shop_owner = shop_info.get("shop_owner", store.shop_owner)
                store.currency = shop_info.get("currency", store.currency)
                store.timezone = shop_info.get("iana_timezone", store.timezone)
                store.plan_name = shop_info.get("plan_name", store.plan_name)
            logger.info(f"Store re-installed: {shop}")
        else:
            # New install
            store = Store(
                shopify_domain=shop,
                access_token=access_token,
                scopes=granted_scopes,
                name=shop_info.get("name", shop) if shop_info else shop,
                email=shop_info.get("email") if shop_info else None,
                shop_owner=shop_info.get("shop_owner") if shop_info else None,
                currency=shop_info.get("currency", "USD") if shop_info else "USD",
                timezone=shop_info.get("iana_timezone") if shop_info else None,
                plan_name=shop_info.get("plan_name") if shop_info else None,
            )
            db.add(store)
            logger.info(f"New store installed: {shop}")

        # Flush to get the store ID
        await db.flush()
        store_id = store.id
        store_domain = store.shopify_domain

    # --- Trigger background product sync ---
    # Import here to avoid circular dependency at module level
    try:
        from app.services.shopify_sync import sync_store_products
        import asyncio
        asyncio.create_task(sync_store_products(store_domain))
        logger.info(f"Product sync triggered for {store_domain}")
    except ImportError:
        logger.warning("shopify_sync not available — skipping initial product sync")

    # --- Redirect to Shopify billing (plan selection) ---
    # After install, take merchant straight to billing approval via Shopify's native UI.
    # Default to "base" plan — merchant can upgrade later from the dashboard.
    billing_url = f"{settings.app_url}/billing/shopify/subscribe?shop={store_domain}&plan=base"
    logger.info(f"Redirecting {store_domain} to Shopify billing approval")
    return RedirectResponse(url=billing_url)


# ============================================================================
# WIDGET TOKEN — Called by the chat widget JS
# ============================================================================

@router.get("/widget-token")
async def get_widget_token(
    shop: str = Query(..., description="Store's myshopify.com domain"),
):
    """
    Generate a JWT token for the chat widget to authenticate WebSocket connections.

    Called by the embeddable widget JS on page load. The token contains the
    store_id and a unique session_id, valid for 24 hours.
    """
    # Verify the store exists and is active
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(
                Store.shopify_domain == shop,
                Store.is_active == True,
            )
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found or inactive")

    # Generate unique session ID
    session_id = f"ws-{uuid.uuid4().hex[:16]}"

    token = create_widget_token(
        store_id=store.store_id_for_pinecone,
        session_id=session_id,
    )

    return {
        "token": token,
        "session_id": session_id,
        "store_id": store.store_id_for_pinecone,
        "store_name": store.name,
        "widget_color": store.widget_color,
        "welcome_message": store.welcome_message,
        "chat_language": getattr(store, "chat_language", "en-US") or "en-US",
        "tts_enabled": get_settings().openai_configured,
    }


# ============================================================================
# WEBHOOKS — Product changes & app lifecycle
# ============================================================================

@router.post("/webhooks")
async def shopify_webhooks(request: Request):
    """
    Receive webhooks from Shopify for product changes and app lifecycle events.

    Shopify sends:
    - products/create, products/update, products/delete
    - app/uninstalled
    """
    # --- Verify webhook HMAC ---
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(body, hmac_header):
        logger.warning("Webhook HMAC verification failed")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # --- Parse webhook ---
    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    topic = request.headers.get("X-Shopify-Topic", "unknown")
    shop_domain = request.headers.get("X-Shopify-Shop-Domain", "unknown")

    logger.info(f"Webhook received | topic={topic} | shop={shop_domain}")

    # --- Handle by topic ---
    if topic == "app/uninstalled":
        await _handle_app_uninstalled(shop_domain)
    elif topic in ("products/create", "products/update"):
        await _handle_product_upsert(shop_domain, payload)
    elif topic == "products/delete":
        await _handle_product_delete(shop_domain, payload)
    elif topic == "refunds/create":
        await _handle_refund_created(shop_domain, payload)
    elif topic == "orders/create":
        await _handle_order_created(shop_domain, payload)
    elif topic == "app_subscriptions/activate":
        subscription_id = payload.get("app_subscription", {}).get("admin_graphql_api_id")
        if subscription_id:
            async with get_db() as db:
                result = await db.execute(
                    select(Store).where(Store.shopify_domain == shop_domain)
                )
                store = result.scalar_one_or_none()
                if store:
                    store.subscription_status = "active"
                    store.shopify_subscription_id = subscription_id
                    logger.info(f"Shopify subscription activated for {shop_domain}: {subscription_id}")
                else:
                    logger.warning(f"app_subscriptions/activate: store not found for {shop_domain}")
    elif topic == "app_subscriptions/cancelled":
        async with get_db() as db:
            result = await db.execute(
                select(Store).where(Store.shopify_domain == shop_domain)
            )
            store = result.scalar_one_or_none()
            if store:
                store.subscription_status = "cancelled"
                logger.info(f"Shopify subscription cancelled for {shop_domain}")
            else:
                logger.warning(f"app_subscriptions/cancelled: store not found for {shop_domain}")
    elif topic == "app_subscriptions/approaching_capped_amount":
        logger.warning(f"Shopify subscription approaching cap for {shop_domain}")
    else:
        logger.info(f"Unhandled webhook topic: {topic}")

    return Response(status_code=200)


# ============================================================================
# GDPR MANDATORY WEBHOOKS — Required for Shopify App Store
# ============================================================================

@router.post("/gdpr/customers-data-request")
async def gdpr_customers_data_request(request: Request):
    """
    Shopify GDPR: Customer data request.
    A store owner requests data Jerry holds about a specific customer.
    Jerry only stores anonymous chat sessions (no PII), so we acknowledge the request.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    import json
    payload = json.loads(body)
    shop_domain = payload.get("shop_domain", "unknown")
    logger.info(f"GDPR customers/data_request from {shop_domain} — Jerry stores no customer PII")

    return Response(status_code=200)


@router.post("/gdpr/customers-redact")
async def gdpr_customers_redact(request: Request):
    """
    Shopify GDPR: Customer data erasure request.
    A customer requests deletion of their data. Jerry stores no customer PII
    (only anonymous session IDs), so we acknowledge the request.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    import json
    payload = json.loads(body)
    shop_domain = payload.get("shop_domain", "unknown")
    logger.info(f"GDPR customers/redact from {shop_domain} — Jerry stores no customer PII")

    return Response(status_code=200)


@router.post("/gdpr/shop-redact")
async def gdpr_shop_redact(request: Request):
    """
    Shopify GDPR: Shop data erasure request.
    48 hours after a store uninstalls, Shopify requests deletion of all store data.
    We delete the store record and all associated chat sessions, resolutions, and sales.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    import json
    payload = json.loads(body)
    shop_domain = payload.get("shop_domain", "unknown")

    logger.info(f"GDPR shop/redact for {shop_domain} — deleting all store data")

    try:
        from app.db.models import ChatSession, SupportResolution, AttributedSale, ChatInteraction
        from sqlalchemy import delete

        async with get_db() as db:
            result = await db.execute(
                select(Store).where(Store.shopify_domain == shop_domain)
            )
            store = result.scalar_one_or_none()

            if store:
                # Delete all related records (cascade should handle this, but be explicit)
                await db.execute(
                    delete(ChatInteraction).where(
                        ChatInteraction.session_id.in_(
                            select(ChatSession.id).where(ChatSession.merchant_id == store.id)
                        )
                    )
                )
                await db.execute(delete(SupportResolution).where(SupportResolution.merchant_id == store.id))
                await db.execute(delete(AttributedSale).where(AttributedSale.merchant_id == store.id))
                await db.execute(delete(ChatSession).where(ChatSession.merchant_id == store.id))
                await db.delete(store)
                logger.info(f"All data deleted for {shop_domain}")
            else:
                logger.info(f"No store found for {shop_domain} — nothing to delete")

    except Exception as e:
        logger.error(f"GDPR shop/redact failed for {shop_domain}: {e}", exc_info=True)

    return Response(status_code=200)


# ============================================================================
# STORE INFO ENDPOINT — For admin/debug
# ============================================================================

@router.get("/stores", dependencies=[Depends(verify_admin_token)])
async def list_stores():
    """List all installed stores (admin endpoint — add auth in production!)."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.is_active == True)
        )
        stores = result.scalars().all()

    return {
        "count": len(stores),
        "stores": [
            {
                "id": s.id,
                "domain": s.shopify_domain,
                "name": s.name,
                "plan": s.sunsetbot_plan,
                "products": s.products_count,
                "synced_at": s.products_synced_at.isoformat() if s.products_synced_at else None,
                "installed_at": s.installed_at.isoformat() if s.installed_at else None,
            }
            for s in stores
        ],
    }


# ============================================================================
# RESYNC — Manual product sync trigger (admin/dev)
# ============================================================================

@router.post("/resync", dependencies=[Depends(verify_admin_token)])
async def resync_store(
    shop: str = Query(..., description="Store's myshopify.com domain"),
):
    """
    Manually trigger a full product sync for a store.

    Admin/dev endpoint — useful for testing, recovery, or re-indexing
    after code changes. In production, add proper admin auth.
    """
    import asyncio

    # Verify store exists and is active
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(
                Store.shopify_domain == shop,
                Store.is_active == True,
            )
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail=f"Store not found or inactive: {shop}")

    # Trigger sync in background
    try:
        from app.services.shopify_sync import sync_store_products
        asyncio.create_task(sync_store_products(shop))
        logger.info(f"Manual resync triggered for {shop}")
    except ImportError:
        raise HTTPException(status_code=503, detail="shopify_sync service not available")

    return {
        "status": "sync_started",
        "shop": shop,
        "message": "Product sync started in background. Check server logs for progress.",
    }


# ============================================================================
# HELPERS
# ============================================================================

async def _fetch_shop_info(
    shop: str, access_token: str, api_version: str
) -> dict:
    """Fetch store details from Shopify Shop API."""
    url = f"https://{shop}/admin/api/{api_version}/shop.json"
    headers = {"X-Shopify-Access-Token": access_token}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("shop", {})
    except Exception as e:
        logger.error(f"Failed to fetch shop info for {shop}: {e}")
        return {}


async def _handle_app_uninstalled(shop_domain: str) -> None:
    """Mark store as inactive when the app is uninstalled."""
    from datetime import datetime

    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == shop_domain)
        )
        store = result.scalar_one_or_none()
        if store:
            store.is_active = False
            store.uninstalled_at = datetime.now()
            logger.info(f"Store uninstalled: {shop_domain}")


async def _handle_product_upsert(shop_domain: str, payload: dict) -> None:
    """Handle product create/update webhook."""
    try:
        from app.services.shopify_sync import ShopifySyncService
        sync = ShopifySyncService()
        await sync.handle_product_webhook(shop_domain, "upsert", payload)
    except ImportError:
        logger.warning("shopify_sync not available — ignoring product webhook")
    except Exception as e:
        logger.error(f"Product webhook handler failed: {e}", exc_info=True)


async def _handle_product_delete(shop_domain: str, payload: dict) -> None:
    """Handle product delete webhook."""
    try:
        from app.services.shopify_sync import ShopifySyncService
        sync = ShopifySyncService()
        await sync.handle_product_webhook(shop_domain, "delete", payload)
    except ImportError:
        logger.warning("shopify_sync not available — ignoring product webhook")
    except Exception as e:
        logger.error(f"Product delete webhook failed: {e}", exc_info=True)


async def _handle_refund_created(shop_domain: str, payload: dict) -> None:
    """
    Handle refunds/create webhook — parse the refund and log a confirmation.

    Uses OrderService.parse_refund_webhook() to extract order ID, transaction
    status/amount/currency, and refunded product titles from the payload.

    Future enhancement: push real-time notification to the customer's
    active WebSocket session if they're still connected.
    """
    try:
        from app.services.order_service import OrderService
        update_message = OrderService.parse_refund_webhook(payload)
        order_id = payload.get("order_id", "unknown")
        logger.info(
            f"Refund webhook processed | shop={shop_domain} | "
            f"order_id={order_id} | message={update_message}"
        )
    except Exception as e:
        logger.error(f"Refund webhook handler failed: {e}", exc_info=True)


async def _handle_order_created(shop_domain: str, payload: dict) -> None:
    """
    Handle orders/create webhook for sale attribution.
    Only attributes the sale to Jerry if there was a chat session
    in the last 24 hours (attribution window).
    """
    order_id = str(payload.get("id", ""))
    order_total = float(payload.get("total_price", 0))

    if not order_id or order_total <= 0:
        return

    try:
        # Check for recent chat session (24-hour attribution window)
        from app.db.engine import get_db
        from app.db.models import Store, ChatSession
        from sqlalchemy import select, and_
        from datetime import datetime, timedelta, timezone

        async with get_db() as db:
            result = await db.execute(
                select(Store).where(Store.shopify_domain == shop_domain)
            )
            store = result.scalar_one_or_none()
            if not store:
                logger.warning(f"Order webhook: store not found for {shop_domain}")
                return

            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            session_result = await db.execute(
                select(ChatSession).where(
                    and_(
                        ChatSession.merchant_id == store.id,
                        ChatSession.created_at >= cutoff,
                    )
                ).limit(1)
            )
            recent_session = session_result.scalar_one_or_none()

        if not recent_session:
            logger.info(f"Order {order_id} not attributed — no chat session in last 24h for {shop_domain}")
            return

        from main import analytics_service
        if analytics_service:
            await analytics_service.record_attributed_sale(
                shop_domain=shop_domain,
                shopify_order_id=order_id,
                order_value=order_total,
            )
            logger.info(f"Order {order_id} attributed to Jerry — ${order_total} for {shop_domain}")
    except Exception as e:
        logger.error(f"Order attribution failed: {e}", exc_info=True)
