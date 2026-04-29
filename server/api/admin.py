"""Admin endpoints — create and manage API keys."""

import hmac
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from server.auth import hash_api_key
from server.config import get_settings
from server.db.engine import get_db
from server.db.models import ApiKey
from server.rate_limiter import PLAN_LIMITS

logger = logging.getLogger("wonderwallai.server.admin")

router = APIRouter(prefix="/admin", tags=["Admin"])

ADMIN_HEADER = "X-Admin-API-Key"


async def _verify_admin(request: Request) -> None:
    """Verify the admin API key from request headers (timing-safe)."""
    settings = get_settings()
    api_key = request.headers.get(ADMIN_HEADER, "")
    if not hmac.compare_digest(api_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="Invalid admin API key")


# --- Request/Response Models ---


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    owner_email: str = Field(..., min_length=3, max_length=255)
    plan: str = Field(default="free")


class CreateKeyResponse(BaseModel):
    api_key: str  # Raw key — shown ONCE, never stored
    key_prefix: str
    name: str
    plan: str
    rate_limit: int
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    client_secret: Optional[str] = None  # For frontend payment confirmation
    has_early_bird: bool = False


class KeyInfo(BaseModel):
    key_prefix: str
    name: str
    owner_email: str
    plan: str
    rate_limit: int
    is_active: bool
    created_at: str
    last_used_at: Optional[str] = None


# --- Endpoints ---


@router.post("/keys", response_model=CreateKeyResponse)
async def create_api_key(req: CreateKeyRequest, request: Request):
    """Create a new customer API key. Returns the raw key once."""
    await _verify_admin(request)

    # Generate raw key: ww_live_<32 hex chars>
    raw_key = f"ww_live_{secrets.token_hex(16)}"
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:16]
    rate_limit = PLAN_LIMITS.get(req.plan, PLAN_LIMITS["free"])

    # Create DB row first so we have the api_key.id
    async with get_db() as db:
        api_key_row = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=req.name,
            owner_email=req.owner_email,
            plan=req.plan,
            rate_limit=rate_limit,
            is_active=True,
        )
        db.add(api_key_row)
        await db.flush()  # Get auto-incremented ID

        # --- Stripe billing for paid plans ---
        stripe_customer_id = None
        stripe_subscription_id = None
        client_secret = None

        has_early_bird = False

        if req.plan != "free":
            from server.helpers import _billing_service

            if _billing_service and _billing_service.configured:
                stripe_customer_id = await _billing_service.create_customer(
                    name=req.name, email=req.owner_email, api_key_id=api_key_row.id
                )
                if stripe_customer_id:
                    # Check early bird eligibility
                    coupon_id = None
                    if await _billing_service.is_early_bird_available():
                        settings = get_settings()
                        coupon_id = settings.early_bird_coupon_id

                    sub_result = await _billing_service.create_subscription(
                        customer_id=stripe_customer_id, plan=req.plan, coupon_id=coupon_id
                    )
                    # Race condition fallback: retry without coupon
                    if not sub_result and coupon_id:
                        logger.info("Early bird coupon rejected — retrying at full price")
                        coupon_id = None
                        sub_result = await _billing_service.create_subscription(
                            customer_id=stripe_customer_id, plan=req.plan
                        )
                    if sub_result:
                        stripe_subscription_id = sub_result["subscription_id"]
                        client_secret = sub_result.get("client_secret")
                        if coupon_id:
                            has_early_bird = True

                api_key_row.stripe_customer_id = stripe_customer_id
                api_key_row.stripe_subscription_id = stripe_subscription_id
                api_key_row.billing_status = "active" if stripe_subscription_id else "none"
                api_key_row.has_early_bird = has_early_bird

    logger.info(f"Created API key {key_prefix}... for {req.owner_email} ({req.plan})")

    return CreateKeyResponse(
        api_key=raw_key,
        key_prefix=key_prefix,
        name=req.name,
        plan=req.plan,
        rate_limit=rate_limit,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
        client_secret=client_secret,
        has_early_bird=has_early_bird,
    )


@router.get("/keys", response_model=list[KeyInfo])
async def list_api_keys(request: Request):
    """List all API keys (admin only)."""
    await _verify_admin(request)

    async with get_db() as db:
        result = await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
        keys = result.scalars().all()

    return [
        KeyInfo(
            key_prefix=k.key_prefix,
            name=k.name,
            owner_email=k.owner_email,
            plan=k.plan,
            rate_limit=k.rate_limit,
            is_active=k.is_active,
            created_at=k.created_at.isoformat() if k.created_at else "",
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        )
        for k in keys
    ]


@router.patch("/keys/{key_prefix}/deactivate")
async def deactivate_api_key(key_prefix: str, request: Request):
    """Deactivate a compromised or cancelled API key."""
    await _verify_admin(request)

    async with get_db() as db:
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_prefix == key_prefix)
        )
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(status_code=404, detail="API key not found")
        key.is_active = False
        logger.info(f"Deactivated API key {key_prefix}")

    return {"deactivated": key_prefix, "is_active": False}


@router.patch("/keys/{key_prefix}/reactivate")
async def reactivate_api_key(key_prefix: str, request: Request):
    """Reactivate a previously deactivated API key."""
    await _verify_admin(request)

    async with get_db() as db:
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_prefix == key_prefix)
        )
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(status_code=404, detail="API key not found")
        key.is_active = True
        logger.info(f"Reactivated API key {key_prefix}")

    return {"reactivated": key_prefix, "is_active": True}


class SetPlanRequest(BaseModel):
    plan: str = Field(..., min_length=1, max_length=32)


@router.patch("/keys/{key_prefix}/plan")
async def set_api_key_plan(key_prefix: str, req: SetPlanRequest, request: Request):
    """Set the plan tier on an existing key without touching Stripe.

    Useful for demo accounts, comps, manual overrides, and internal testing.
    Updates rate_limit to match the new plan. Stripe customer and subscription
    fields are left untouched, so this does not create or modify a real
    subscription.
    """
    await _verify_admin(request)

    if req.plan not in PLAN_LIMITS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan. Allowed: {sorted(PLAN_LIMITS.keys())}",
        )

    async with get_db() as db:
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_prefix == key_prefix)
        )
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(status_code=404, detail="API key not found")

        previous_plan = key.plan
        key.plan = req.plan
        key.rate_limit = PLAN_LIMITS[req.plan]
        logger.info(
            f"Plan override on {key_prefix}: {previous_plan} -> {req.plan}"
        )

    return {
        "key_prefix": key_prefix,
        "plan": req.plan,
        "rate_limit": PLAN_LIMITS[req.plan],
        "previous_plan": previous_plan,
    }
