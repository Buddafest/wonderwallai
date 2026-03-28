"""
GiLLBoT — Billing Service
Manages Stripe subscriptions for GiLLBoT users.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("gillbot.billing")

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("stripe package not installed — billing disabled")


class BillingService:
    """Manages Stripe subscriptions and billing events for GiLLBoT users."""

    def __init__(self):
        from server.config import get_settings
        settings = get_settings()
        self.api_key = settings.stripe_secret_key
        self.webhook_secret = settings.stripe_webhook_secret
        self.configured = bool(self.api_key) and STRIPE_AVAILABLE

        if self.configured:
            stripe.api_key = self.api_key
            logger.info("BillingService initialized (Stripe connected)")
        else:
            logger.warning("BillingService: Stripe not configured — billing disabled")

    async def create_customer(self, user) -> Optional[str]:
        """Create a Stripe customer for a user. Returns customer ID or None."""
        if not self.configured:
            return None

        loop = asyncio.get_running_loop()
        try:
            customer = await loop.run_in_executor(
                None,
                lambda: stripe.Customer.create(
                    email=user.email,
                    name=user.full_name or user.email,
                    metadata={"user_id": str(user.id)},
                ),
            )
            logger.info(f"Stripe customer created: {customer.id} for {user.email}")
            return customer.id
        except Exception as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            return None

    async def create_checkout_session(
        self,
        customer_id: str,
        price_id: str,
        success_url: str,
        cancel_url: str,
    ) -> Optional[str]:
        """
        Create a Stripe Checkout Session for a subscription.

        Returns:
            Checkout session URL or None on failure.
        """
        if not self.configured:
            return None

        loop = asyncio.get_running_loop()
        try:
            session = await loop.run_in_executor(
                None,
                lambda: stripe.checkout.Session.create(
                    customer=customer_id,
                    mode="subscription",
                    line_items=[{"price": price_id, "quantity": 1}],
                    success_url=success_url,
                    cancel_url=cancel_url,
                ),
            )
            return session.url
        except Exception as e:
            logger.error(f"Failed to create checkout session: {e}")
            return None

    async def handle_webhook_event(
        self, payload: bytes, sig_header: str
    ) -> Optional[dict]:
        """
        Verify and parse a Stripe webhook event.

        Returns:
            Event dict or None if verification fails.
        """
        if not self.configured:
            return None

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
        except stripe.error.SignatureVerificationError:
            logger.warning("Stripe webhook signature verification failed")
            return None
        except Exception as e:
            logger.error(f"Stripe webhook error: {e}")
            return None

        logger.info(f"Stripe webhook received: {event['type']}")
        return event
