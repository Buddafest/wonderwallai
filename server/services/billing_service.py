"""
WonderwallAi — Stripe Billing Service
Handles subscription creation, metered overage reporting, and plan upgrades.
Currency: USD. Uses Stripe Python SDK (sync calls wrapped in run_in_executor).
"""

import asyncio
import logging
from typing import Optional

from server.config import get_settings

logger = logging.getLogger("wonderwallai.server.billing")

try:
    import stripe

    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("stripe package not installed — billing disabled")


# ---------------------------------------------------------------------------
# Plan configuration
# ---------------------------------------------------------------------------
# Each paid tier has:
#   flat_price_id     → recurring monthly charge
#   overage_price_id  → metered per-scan charge above included limit
#   included_scans    → scans included in the flat fee
#   rate_limit        → requests per minute

PLAN_CONFIG = {
    "free": {
        "flat_price_id": None,
        "overage_price_id": None,
        "included_scans": 1_000,
        "rate_limit": 10,
    },
    "starter": {
        "flat_price_id": None,   # Loaded from env at init
        "overage_price_id": None,
        "included_scans": 50_000,
        "rate_limit": 60,
    },
    "pro": {
        "flat_price_id": None,
        "overage_price_id": None,
        "included_scans": 500_000,
        "rate_limit": 200,
    },
    "business": {
        "flat_price_id": None,
        "overage_price_id": None,
        "included_scans": 2_000_000,
        "rate_limit": 500,
    },
    "enterprise": {
        "flat_price_id": None,
        "overage_price_id": None,
        "included_scans": 999_999_999,  # Effectively unlimited
        "rate_limit": 1000,
    },
}


class BillingService:
    """Manages Stripe subscriptions and metered overage billing for WonderwallAi."""

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.stripe_secret_key
        self.webhook_secret = settings.stripe_webhook_secret
        self.configured = bool(self.api_key) and STRIPE_AVAILABLE

        if self.configured:
            stripe.api_key = self.api_key
            # Load price IDs from env into PLAN_CONFIG
            PLAN_CONFIG["starter"]["flat_price_id"] = settings.stripe_starter_flat_price_id or None
            PLAN_CONFIG["starter"]["overage_price_id"] = (
                settings.stripe_starter_overage_price_id or None
            )
            PLAN_CONFIG["pro"]["flat_price_id"] = settings.stripe_pro_flat_price_id or None
            PLAN_CONFIG["pro"]["overage_price_id"] = (
                settings.stripe_pro_overage_price_id or None
            )
            PLAN_CONFIG["business"]["flat_price_id"] = (
                settings.stripe_business_flat_price_id or None
            )
            PLAN_CONFIG["business"]["overage_price_id"] = (
                settings.stripe_business_overage_price_id or None
            )
            logger.info("BillingService initialized (Stripe connected)")
        else:
            logger.warning("BillingService: Stripe not configured — billing disabled")

    # ------------------------------------------------------------------
    # Customer management
    # ------------------------------------------------------------------

    async def create_customer(
        self, name: str, email: str, api_key_id: int
    ) -> Optional[str]:
        """Create a Stripe customer. Returns customer ID or None."""
        if not self.configured:
            logger.warning("Stripe not configured — skipping customer creation")
            return None

        loop = asyncio.get_running_loop()
        try:
            customer = await loop.run_in_executor(
                None,
                lambda: stripe.Customer.create(
                    email=email,
                    name=name,
                    metadata={
                        "api_key_id": str(api_key_id),
                        "service": "wonderwallai",
                    },
                ),
            )
            logger.info(f"Stripe customer created: {customer.id} for key {api_key_id}")
            return customer.id
        except Exception as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            return None

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    async def create_subscription(
        self, customer_id: str, plan: str, coupon_id: Optional[str] = None
    ) -> Optional[dict]:
        """
        Create a subscription with flat fee + metered overage price.
        Optionally applies a coupon (e.g. early bird discount).
        Returns dict with subscription_id, client_secret, status — or None.
        """
        if not self.configured:
            return None

        config = PLAN_CONFIG.get(plan)
        if not config or plan == "free":
            logger.error(f"Cannot create subscription for plan: {plan}")
            return None

        flat_price = config["flat_price_id"]
        overage_price = config["overage_price_id"]

        if not flat_price:
            logger.error(f"No flat_price_id configured for plan: {plan}")
            return None

        items = [{"price": flat_price}]
        if overage_price:
            items.append({"price": overage_price})

        create_kwargs = {
            "customer": customer_id,
            "items": items,
            "payment_behavior": "default_incomplete",
            "expand": ["latest_invoice.payment_intent"],
        }
        if coupon_id:
            create_kwargs["coupon"] = coupon_id

        loop = asyncio.get_running_loop()
        try:
            subscription = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.create(**create_kwargs),
            )
            logger.info(f"Subscription created: {subscription.id} (plan={plan})")

            client_secret = None
            if (
                subscription.latest_invoice
                and subscription.latest_invoice.payment_intent
            ):
                client_secret = (
                    subscription.latest_invoice.payment_intent.client_secret
                )

            return {
                "subscription_id": subscription.id,
                "client_secret": client_secret,
                "status": subscription.status,
            }
        except Exception as e:
            logger.error(f"Failed to create subscription: {e}")
            return None

    async def update_subscription_plan(
        self, subscription_id: str, new_plan: str
    ) -> Optional[dict]:
        """
        Change subscription to a different plan. Replaces price items.
        Returns updated subscription info or None.
        """
        if not self.configured or not subscription_id:
            return None

        config = PLAN_CONFIG.get(new_plan)
        if not config or new_plan == "free":
            logger.error(f"Cannot upgrade to plan: {new_plan}")
            return None

        loop = asyncio.get_running_loop()
        try:
            # Retrieve current subscription to get existing items
            sub = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.retrieve(subscription_id),
            )

            # Build update: remove old items, add new ones
            items = []
            for item in sub["items"]["data"]:
                items.append({"id": item["id"], "deleted": True})

            if config["flat_price_id"]:
                items.append({"price": config["flat_price_id"]})
            if config["overage_price_id"]:
                items.append({"price": config["overage_price_id"]})

            updated = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.modify(
                    subscription_id,
                    items=items,
                    proration_behavior="create_prorations",
                ),
            )
            logger.info(
                f"Subscription {subscription_id} upgraded to {new_plan}"
            )
            return {
                "subscription_id": updated.id,
                "status": updated.status,
                "plan": new_plan,
            }
        except Exception as e:
            logger.error(f"Failed to update subscription: {e}")
            return None

    # ------------------------------------------------------------------
    # Metered overage reporting
    # ------------------------------------------------------------------

    async def report_overage(
        self, subscription_id: str, plan: str, count: int = 1
    ) -> bool:
        """
        Report overage scans to Stripe metered billing.
        Called as fire-and-forget when a customer exceeds included scans.
        """
        if not self.configured or not subscription_id:
            return False

        config = PLAN_CONFIG.get(plan, PLAN_CONFIG["starter"])
        overage_price_id = config.get("overage_price_id")
        if not overage_price_id:
            return False

        loop = asyncio.get_running_loop()
        try:
            sub = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.retrieve(subscription_id),
            )

            overage_item = None
            for item in sub["items"]["data"]:
                if item["price"]["id"] == overage_price_id:
                    overage_item = item
                    break

            if not overage_item:
                logger.warning(
                    f"Overage price item not found in subscription {subscription_id}"
                )
                return False

            await loop.run_in_executor(
                None,
                lambda: stripe.SubscriptionItem.create_usage_record(
                    overage_item["id"],
                    quantity=count,
                    action="increment",
                ),
            )
            logger.info(
                f"Reported {count} overage scan(s) for sub={subscription_id}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to report overage: {e}")
            return False

    # ------------------------------------------------------------------
    # Webhook handling
    # ------------------------------------------------------------------

    async def handle_webhook_event(
        self, payload: bytes, sig_header: str
    ) -> Optional[dict]:
        """
        Verify and return a Stripe webhook event.
        Returns the event dict or None if verification fails.
        """
        if not self.configured:
            return None

        try:
            event = stripe.Webhook.construct_event(
                payload,
                sig_header,
                self.webhook_secret,
            )
        except Exception as e:
            logger.warning(f"Stripe webhook verification failed: {e}")
            return None

        logger.info(f"Stripe webhook: {event['type']}")
        return event

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_plan_config(self, plan: str) -> dict:
        """Return plan config dict (included_scans, rate_limit, etc.)."""
        return PLAN_CONFIG.get(plan, PLAN_CONFIG["free"])

    def get_included_scans(self, plan: str) -> int:
        """Return the number of scans included in a plan."""
        return self.get_plan_config(plan).get("included_scans", 1_000)

    # ------------------------------------------------------------------
    # Early bird promotion
    # ------------------------------------------------------------------

    async def get_early_bird_count(self) -> int:
        """Count how many API keys have redeemed the early bird discount."""
        from sqlalchemy import func, select

        from server.db.engine import get_db
        from server.db.models import ApiKey

        try:
            async with get_db() as db:
                result = await db.execute(
                    select(func.count(ApiKey.id)).where(
                        ApiKey.has_early_bird == True  # noqa: E712
                    )
                )
                return result.scalar() or 0
        except Exception as e:
            logger.warning(f"Failed to count early bird redemptions: {e}")
            return 0

    async def is_early_bird_available(self) -> bool:
        """Check if early bird promotion slots remain."""
        settings = get_settings()
        if not settings.early_bird_coupon_id:
            return False
        count = await self.get_early_bird_count()
        return count < settings.early_bird_max_redemptions
