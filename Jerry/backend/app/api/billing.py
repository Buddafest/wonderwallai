"""
Jerry The Customer Service Bot — Billing API Routes
Handles Stripe subscription management and webhook processing.
"""

import logging

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.db.engine import get_db
from app.db.models import Store
from sqlalchemy import select

logger = logging.getLogger("jerry.billing.api")

router = APIRouter(prefix="/billing", tags=["Billing"])


class CreateSubscriptionRequest(BaseModel):
    shop_domain: str
    plan: str = "base"  # "base", "growth", or "elite"


@router.post("/create-subscription")
async def create_subscription(req: CreateSubscriptionRequest):
    """Create a Stripe subscription for a merchant."""
    # Import billing service from app state
    from main import billing_service

    if not billing_service or not billing_service.configured:
        raise HTTPException(status_code=503, detail="Billing not configured")

    # Find store
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == req.shop_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    # Create Stripe customer if needed
    if not store.stripe_customer_id:
        customer_id = await billing_service.create_customer(store)
        if not customer_id:
            raise HTTPException(status_code=500, detail="Failed to create Stripe customer")
        async with get_db() as db:
            result = await db.execute(
                select(Store).where(Store.id == store.id)
            )
            store = result.scalar_one()
            store.stripe_customer_id = customer_id
    else:
        customer_id = store.stripe_customer_id

    # Create subscription
    sub_result = await billing_service.create_subscription(customer_id, req.plan)
    if not sub_result:
        raise HTTPException(status_code=500, detail="Failed to create subscription")

    # Save subscription ID to store
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.id == store.id)
        )
        store = result.scalar_one()
        store.stripe_subscription_id = sub_result["subscription_id"]
        store.jerry_plan = req.plan
        store.subscription_status = sub_result.get("status", "incomplete")

    return {
        "status": "subscription_created",
        "subscription_id": sub_result["subscription_id"],
        "client_secret": sub_result.get("client_secret"),
        "plan": req.plan,
    }


@router.get("/checkout")
async def checkout(plan: str = "base"):
    """Create a Stripe Checkout Session and redirect to Stripe-hosted payment page."""
    try:
        import stripe as stripe_mod
    except ImportError:
        raise HTTPException(status_code=503, detail="Stripe not available")

    from app.services.billing_service import PLAN_CONFIG
    import os

    api_key = os.getenv("STRIPE_SECRET_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Billing not configured")

    stripe_mod.api_key = api_key

    config = PLAN_CONFIG.get(plan)
    if not config:
        valid_plans = ", ".join(PLAN_CONFIG.keys())
        raise HTTPException(status_code=400, detail=f"Invalid plan '{plan}'. Valid plans: {valid_plans}.")

    try:
        session = stripe_mod.checkout.Session.create(
            mode="subscription",
            line_items=[
                {"price": config["flat_price_id"], "quantity": 1},
                {"price": config["metered_price_id"]},
            ],
            success_url="https://jerry.skintlabs.ai/?checkout=success",
            cancel_url="https://jerry.skintlabs.ai/#pricing",
            allow_promotion_codes=True,
        )
        return RedirectResponse(session.url, status_code=303)
    except Exception as e:
        logger.error(f"Failed to create checkout session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create checkout session")


@router.post("/webhooks")
async def stripe_webhooks(request: Request):
    """Process Stripe webhook events — updates store subscription status in DB."""
    from main import billing_service

    if not billing_service or not billing_service.configured:
        return Response(status_code=200)

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    event = await billing_service.handle_webhook_event(payload, sig_header)
    if not event:
        raise HTTPException(status_code=400, detail="Invalid webhook")

    event_type = event["type"]
    obj = event["data"]["object"]

    try:
        if event_type == "invoice.paid":
            customer_id = obj.get("customer")
            if customer_id:
                store = await _find_store_by_stripe_customer(customer_id)
                if store:
                    async with get_db() as db:
                        result = await db.execute(select(Store).where(Store.id == store.id))
                        s = result.scalar_one()
                        s.subscription_status = "active"
                        s.current_month_usage = 0
                        # Reset billing cycle from invoice period
                        lines = obj.get("lines", {}).get("data", [])
                        if lines:
                            period_end = lines[0].get("period", {}).get("end")
                            if period_end:
                                from datetime import datetime, timezone
                                s.billing_cycle_reset = datetime.fromtimestamp(period_end, tz=timezone.utc)
                    logger.info(f"invoice.paid: store={store.shopify_domain} → active, usage reset")
                else:
                    logger.warning(f"invoice.paid: no store for customer {customer_id}")

        elif event_type == "invoice.payment_failed":
            customer_id = obj.get("customer")
            if customer_id:
                store = await _find_store_by_stripe_customer(customer_id)
                if store:
                    async with get_db() as db:
                        result = await db.execute(select(Store).where(Store.id == store.id))
                        s = result.scalar_one()
                        s.subscription_status = "past_due"
                    logger.warning(f"invoice.payment_failed: store={store.shopify_domain} → past_due")

        elif event_type == "customer.subscription.updated":
            sub_id = obj.get("id")
            stripe_status = obj.get("status", "unknown")
            if sub_id:
                store = await _find_store_by_subscription(sub_id)
                if store:
                    async with get_db() as db:
                        result = await db.execute(select(Store).where(Store.id == store.id))
                        s = result.scalar_one()
                        s.subscription_status = stripe_status
                    logger.info(f"subscription.updated: store={store.shopify_domain} → {stripe_status}")

        elif event_type == "customer.subscription.deleted":
            sub_id = obj.get("id")
            if sub_id:
                store = await _find_store_by_subscription(sub_id)
                if store:
                    async with get_db() as db:
                        result = await db.execute(select(Store).where(Store.id == store.id))
                        s = result.scalar_one()
                        s.subscription_status = "canceled"
                    logger.info(f"subscription.deleted: store={store.shopify_domain} → canceled")

        else:
            logger.info(f"Unhandled Stripe event: {event_type}")

    except Exception as e:
        logger.error(f"Webhook handler error for {event_type}: {e}", exc_info=True)

    return Response(status_code=200)


async def _find_store_by_stripe_customer(customer_id: str):
    """Look up a store by its Stripe customer ID."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.stripe_customer_id == customer_id)
        )
        return result.scalar_one_or_none()


async def _find_store_by_subscription(subscription_id: str):
    """Look up a store by its Stripe subscription ID."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.stripe_subscription_id == subscription_id)
        )
        return result.scalar_one_or_none()


@router.get("/shopify/subscribe")
async def shopify_subscribe(
    shop: str,
    plan: str = "base",
):
    """Initiate Shopify App Subscription — redirects merchant to Shopify billing approval page."""
    from app.services.billing_service import ShopifyBillingService
    from app.core.config import get_settings
    settings = get_settings()

    if plan not in ("base", "growth", "elite"):
        raise HTTPException(status_code=400, detail="Invalid plan. Choose: base, growth, elite")

    # Look up the store
    async with get_db() as db:
        result = await db.execute(select(Store).where(Store.shopify_domain == shop))
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    return_url = f"{settings.app_url}/billing/shopify/callback?shop={shop}&plan={plan}"

    shopify_billing = ShopifyBillingService()
    sub_result = await shopify_billing.create_subscription(
        shop_domain=shop,
        access_token=store.access_token,
        plan=plan,
        return_url=return_url,
    )

    # Store the pending subscription ID
    async with get_db() as db:
        result = await db.execute(select(Store).where(Store.shopify_domain == shop))
        store = result.scalar_one()
        store.shopify_subscription_id = sub_result["subscription_id"]
        store.jerry_plan = plan

    # Redirect merchant to Shopify billing approval
    return RedirectResponse(url=sub_result["confirmation_url"])


@router.get("/shopify/callback")
async def shopify_billing_callback(
    shop: str,
    plan: str,
    charge_id: str = None,
):
    """Handle return from Shopify billing approval page."""
    from app.core.config import get_settings
    settings = get_settings()

    async with get_db() as db:
        result = await db.execute(select(Store).where(Store.shopify_domain == shop))
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    if charge_id:
        # Merchant approved — start 7-day trial immediately so the app is usable at once.
        # The Shopify app_subscriptions/activate webhook will later confirm and set to "active".
        async with get_db() as db:
            result = await db.execute(select(Store).where(Store.shopify_domain == shop))
            store = result.scalar_one()
            store.subscription_status = "trialing"
            store.jerry_plan = plan
            # Persist the numeric charge_id as a temporary reference until
            # the webhook overwrites it with the full GID (gid://shopify/AppSubscription/…)
            if not store.shopify_subscription_id:
                store.shopify_subscription_id = str(charge_id)
        logger.info(f"Shopify billing approved for {shop}, plan={plan}, charge_id={charge_id} → trialing")
        # Redirect to Jerry dashboard
        return RedirectResponse(url=f"{settings.app_url}/static/dashboard.html?store={shop}&billing=approved")
    else:
        # Merchant declined
        async with get_db() as db:
            result = await db.execute(select(Store).where(Store.shopify_domain == shop))
            store = result.scalar_one()
            store.subscription_status = "cancelled"
        logger.warning(f"Shopify billing declined for {shop}")
        return RedirectResponse(url=f"{settings.app_url}/static/dashboard.html?store={shop}&billing=declined")


@router.get("/usage/{store_domain}")
async def get_usage(store_domain: str):
    """Get current billing cycle usage for a store."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    return {
        "store": store.shopify_domain,
        "plan": store.jerry_plan,
        "usage": store.current_month_usage,
        "limit": store.monthly_interaction_limit,
        "billing_cycle_reset": store.billing_cycle_reset.isoformat() if store.billing_cycle_reset else None,
    }
