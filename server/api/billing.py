"""Billing endpoints — subscription info, plan upgrades, Stripe webhooks."""

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select

from server.auth import get_current_api_key
from server.config import get_settings
from server.db.engine import get_db
from server.db.models import ApiKey, UsageRecord
from server.helpers import _billing_service
from server.rate_limiter import PLAN_LIMITS
from server.schemas.requests import UpgradePlanRequest
from server.schemas.responses import BillingSubscriptionResponse
from server.services.billing_service import PLAN_CONFIG

logger = logging.getLogger("wonderwallai.server.billing")

router = APIRouter(prefix="/v1/billing", tags=["Billing"])


@router.get("/checkout")
async def checkout(plan: str = "starter"):
    """Create a Stripe Checkout Session and redirect to Stripe-hosted payment page.

    Used by the landing page pricing buttons. No auth required — Stripe handles
    everything on their hosted page.

    Query params:
        plan: starter | pro | business
    """
    try:
        import stripe as stripe_mod
    except ImportError:
        raise HTTPException(status_code=503, detail="Stripe not available")

    api_key = os.getenv("STRIPE_SECRET_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")

    stripe_mod.api_key = api_key

    config = PLAN_CONFIG.get(plan)
    if not config or plan == "free":
        raise HTTPException(status_code=400, detail=f"Invalid plan: {plan}")

    flat_price = config.get("flat_price_id")
    overage_price = config.get("overage_price_id")
    if not flat_price:
        raise HTTPException(status_code=503, detail=f"Price not configured for plan: {plan}")

    line_items = [{"price": flat_price, "quantity": 1}]
    if overage_price:
        line_items.append({"price": overage_price})

    # Auto-apply early bird coupon if promotion is still active
    checkout_kwargs = {
        "mode": "subscription",
        "line_items": line_items,
        "success_url": "https://wonderwallai.skintlabs.ai/?checkout=success",
        "cancel_url": "https://wonderwallai.skintlabs.ai/#pricing",
    }

    settings = get_settings()
    if settings.early_bird_coupon_id:
        checkout_kwargs["discounts"] = [{"coupon": settings.early_bird_coupon_id}]
        logger.info(f"Applied early bird coupon: {settings.early_bird_coupon_id}")
    else:
        checkout_kwargs["allow_promotion_codes"] = True

    try:
        session = stripe_mod.checkout.Session.create(**checkout_kwargs)
        return RedirectResponse(session.url, status_code=303)
    except Exception as e:
        logger.error(f"Failed to create Checkout Session: {e}")
        raise HTTPException(status_code=502, detail="Failed to create checkout session")


@router.get("/subscription", response_model=BillingSubscriptionResponse)
async def get_subscription(api_key: ApiKey = Depends(get_current_api_key)):
    """Get current subscription details, usage, and overage for this billing period."""
    plan = api_key.plan or "free"
    config = PLAN_CONFIG.get(plan, PLAN_CONFIG["free"])
    included_scans = config["included_scans"]

    # Count scans this calendar month
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    try:
        async with get_db() as db:
            result = await db.execute(
                select(func.count(UsageRecord.id)).where(
                    UsageRecord.api_key_id == api_key.id,
                    UsageRecord.timestamp >= month_start,
                )
            )
            scans_used = result.scalar() or 0
    except Exception as e:
        logger.warning(f"Failed to count usage records: {e}")
        scans_used = 0

    overage = max(0, scans_used - included_scans)

    return BillingSubscriptionResponse(
        plan=plan,
        billing_status=api_key.billing_status or "none",
        included_scans=included_scans,
        scans_used=scans_used,
        overage_scans=overage,
        rate_limit=api_key.rate_limit,
        stripe_customer_id=api_key.stripe_customer_id,
        stripe_subscription_id=api_key.stripe_subscription_id,
    )


@router.post("/upgrade")
async def upgrade_plan(
    req: UpgradePlanRequest,
    api_key: ApiKey = Depends(get_current_api_key),
):
    """Upgrade or change subscription plan."""
    if not _billing_service or not _billing_service.configured:
        raise HTTPException(status_code=503, detail="Billing service not configured")

    if api_key.plan == req.new_plan:
        raise HTTPException(status_code=400, detail=f"Already on {req.new_plan} plan")

    subscription_id = api_key.stripe_subscription_id

    # If coming from free tier, create customer + subscription
    if api_key.plan == "free" or not subscription_id:
        customer_id = api_key.stripe_customer_id
        if not customer_id:
            customer_id = await _billing_service.create_customer(
                name=api_key.name, email=api_key.owner_email, api_key_id=api_key.id
            )
            if not customer_id:
                raise HTTPException(status_code=502, detail="Failed to create Stripe customer")

        # Check early bird eligibility
        coupon_id = None
        if await _billing_service.is_early_bird_available():
            coupon_id = get_settings().early_bird_coupon_id

        sub_result = await _billing_service.create_subscription(
            customer_id=customer_id, plan=req.new_plan, coupon_id=coupon_id
        )
        # Race condition fallback: if coupon was rejected, retry without it
        if not sub_result and coupon_id:
            logger.info("Early bird coupon rejected — retrying at full price")
            coupon_id = None
            sub_result = await _billing_service.create_subscription(
                customer_id=customer_id, plan=req.new_plan
            )
        if not sub_result:
            raise HTTPException(status_code=502, detail="Failed to create subscription")

        # Update DB
        new_rate_limit = PLAN_LIMITS.get(req.new_plan, PLAN_LIMITS["free"])
        async with get_db() as db:
            result = await db.execute(
                select(ApiKey).where(ApiKey.id == api_key.id)
            )
            key = result.scalar_one()
            key.plan = req.new_plan
            key.rate_limit = new_rate_limit
            key.stripe_customer_id = customer_id
            key.stripe_subscription_id = sub_result["subscription_id"]
            key.billing_status = "active"
            if coupon_id:
                key.has_early_bird = True

        return {
            "plan": req.new_plan,
            "subscription_id": sub_result["subscription_id"],
            "client_secret": sub_result.get("client_secret"),
            "status": sub_result["status"],
            "early_bird": bool(coupon_id),
        }

    # Existing subscription — change plan
    result = await _billing_service.update_subscription_plan(
        subscription_id=subscription_id, new_plan=req.new_plan
    )
    if not result:
        raise HTTPException(status_code=502, detail="Failed to update subscription")

    # Update DB
    new_rate_limit = PLAN_LIMITS.get(req.new_plan, PLAN_LIMITS["free"])
    async with get_db() as db:
        db_result = await db.execute(
            select(ApiKey).where(ApiKey.id == api_key.id)
        )
        key = db_result.scalar_one()
        key.plan = req.new_plan
        key.rate_limit = new_rate_limit

    return result


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events (no auth — verified by Stripe signature)."""
    if not _billing_service or not _billing_service.configured:
        raise HTTPException(status_code=503, detail="Billing not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    event = await _billing_service.handle_webhook_event(payload, sig_header)
    if not event:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event_type = event["type"]

    # --- Handle specific events ---
    if event_type == "invoice.paid":
        # Subscription payment succeeded — ensure billing_status = active
        subscription_id = event["data"]["object"].get("subscription")
        if subscription_id:
            async with get_db() as db:
                result = await db.execute(
                    select(ApiKey).where(
                        ApiKey.stripe_subscription_id == subscription_id
                    )
                )
                key = result.scalar_one_or_none()
                if key:
                    key.billing_status = "active"
                    logger.info(
                        f"Invoice paid for {key.key_prefix}... — billing active"
                    )

    elif event_type == "invoice.payment_failed":
        subscription_id = event["data"]["object"].get("subscription")
        if subscription_id:
            async with get_db() as db:
                result = await db.execute(
                    select(ApiKey).where(
                        ApiKey.stripe_subscription_id == subscription_id
                    )
                )
                key = result.scalar_one_or_none()
                if key:
                    key.billing_status = "past_due"
                    logger.warning(
                        f"Payment failed for {key.key_prefix}... — billing past_due"
                    )

    elif event_type == "customer.subscription.deleted":
        subscription_id = event["data"]["object"].get("id")
        if not subscription_id:
            logger.warning(f"Webhook {event_type}: no subscription ID in event")
            return {"status": "ok"}
        async with get_db() as db:
            result = await db.execute(
                select(ApiKey).where(
                    ApiKey.stripe_subscription_id == subscription_id
                )
            )
            key = result.scalar_one_or_none()
            if key:
                key.plan = "free"
                key.rate_limit = PLAN_LIMITS["free"]
                key.billing_status = "cancelled"
                key.stripe_subscription_id = None
                logger.info(
                    f"Subscription cancelled for {key.key_prefix}... — downgraded to free"
                )

    return {"status": "ok"}


@router.get("/early-bird")
async def early_bird_status():
    """Public endpoint (no auth): returns early bird promotion status for the landing page."""
    settings = get_settings()

    if not settings.early_bird_coupon_id:
        return {
            "active": False,
            "total_spots": 0,
            "remaining_spots": 0,
            "discount_percent": 0,
        }

    if not _billing_service:
        # Billing not initialised yet — return defaults
        return {
            "active": True,
            "total_spots": settings.early_bird_max_redemptions,
            "remaining_spots": settings.early_bird_max_redemptions,
            "discount_percent": 50,
        }

    count = await _billing_service.get_early_bird_count()
    remaining = max(0, settings.early_bird_max_redemptions - count)

    return {
        "active": remaining > 0,
        "total_spots": settings.early_bird_max_redemptions,
        "remaining_spots": remaining,
        "discount_percent": 50,
    }
