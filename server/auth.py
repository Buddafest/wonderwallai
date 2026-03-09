"""API key authentication — Bearer token → DB lookup + Usage Reporting."""

import hashlib
import logging
import stripe
from fastapi import HTTPException, Security, BackgroundTasks
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, update
from sqlalchemy import func as sql_func

from server.config import get_settings
from server.db.engine import get_db
from server.db.models import ApiKey

logger = logging.getLogger("wonderwallai.server.auth")
_bearer_scheme = HTTPBearer()

def hash_api_key(raw_key: str) -> str:
    """SHA-256 hash of the raw API key for secure storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()

def report_ai_usage_sync(subscription_id: str):
    """
    Standard function to report usage to Stripe. 
    FastAPI will run this in the background to prevent latency.
    """
    settings = get_settings()
    stripe.api_key = settings.stripe_secret_key
    try:
        # 1. Get the subscription to find the specific Overage item ID
        subscription = stripe.Subscription.retrieve(subscription_id)
        for item in subscription['items']['data']:
            if item.price.id == settings.stripe_pro_overage_price_id:
                # 2. Record the usage 'hit'
                stripe.SubscriptionItem.create_usage_record(
                    item.id,
                    quantity=1,
                    timestamp="now",
                    action="increment"
                )
                logger.info(f"Overage reported for sub: {subscription_id}")
                return
    except Exception as e:
        logger.error(f"Stripe usage reporting failed: {e}")

async def get_current_api_key(
    background_tasks: BackgroundTasks, # Added to handle background reporting
    credentials: HTTPAuthorizationCredentials = Security(_bearer_scheme),
) -> ApiKey:
    """FastAPI dependency: validate token, check billing, and report usage."""
    key_hash = hash_api_key(credentials.credentials)

    async with get_db() as db:
        result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
        api_key = result.scalar_one_or_none()

        # 1. Validation
        if not api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        if not api_key.is_active:
            raise HTTPException(status_code=403, detail="API key deactivated")

        # 2. Billing Gate (Blocked if status is 'none', 'past_due', or 'canceled')
        if not getattr(api_key, "has_early_bird", False):
            status = getattr(api_key, "billing_status", "none")
            if status not in ["active", "trialing"]:
                raise HTTPException(
                    status_code=402, 
                    detail=f"Payment required. Your subscription is currently: {status}"
                )

        # 3. Update 'Last Used' timestamp in our DB
        await db.execute(
            update(ApiKey)
            .where(ApiKey.id == api_key.id)
            .values(last_used_at=sql_func.now())
        )

        # 4. Usage Reporting (Handled in background so AI feels fast)
        if api_key.stripe_subscription_id and not getattr(api_key, "has_early_bird", False):
            background_tasks.add_task(report_ai_usage_sync, api_key.stripe_subscription_id)

    return api_key
Se
