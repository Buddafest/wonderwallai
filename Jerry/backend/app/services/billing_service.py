"""
Jerry The Customer Service Bot — Stripe Billing Service
Handles subscription creation and metered usage reporting.
Currency: USD. Uses Stripe Python SDK (sync calls wrapped in run_in_executor).
"""

import asyncio
import logging
import os

from typing import Optional

logger = logging.getLogger("jerry.billing")

# Only import stripe at module level — it may not be installed yet
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("stripe package not installed — billing disabled")


PLAN_CONFIG = {
    # Base: $49/mo USD flat + $0.25/resolution
    "base": {
        "flat_price_id": os.getenv("STRIPE_BASE_FLAT_PRICE_ID", "price_placeholder_base_flat"),
        "metered_price_id": os.getenv("STRIPE_BASE_METERED_PRICE_ID", "price_placeholder_base_metered"),
        "per_resolution_usd": 25,           # $0.25
    },
    # Growth: $149/mo USD flat + $0.25/resolution
    "growth": {
        "flat_price_id": os.getenv("STRIPE_GROWTH_FLAT_PRICE_ID", "price_placeholder_growth_flat"),
        "metered_price_id": os.getenv("STRIPE_GROWTH_METERED_PRICE_ID", "price_placeholder_growth_metered"),
        "per_resolution_usd": 25,           # $0.25
    },
    # Elite: $499/mo USD flat + $0.25/resolution
    "elite": {
        "flat_price_id": os.getenv("STRIPE_ELITE_FLAT_PRICE_ID", "price_placeholder_elite_flat"),
        "metered_price_id": os.getenv("STRIPE_ELITE_METERED_PRICE_ID", "price_placeholder_elite_metered"),
        "per_resolution_usd": 25,           # $0.25
    },
}


class BillingService:
    """Manages Stripe subscriptions and metered usage for Jerry merchants."""

    def __init__(self):
        self.api_key = os.getenv("STRIPE_SECRET_KEY", "")
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
        self.configured = bool(self.api_key) and STRIPE_AVAILABLE

        if self.configured:
            stripe.api_key = self.api_key
            logger.info("BillingService initialized (Stripe connected)")
        else:
            logger.warning("BillingService: Stripe not configured — billing disabled")

    async def create_customer(self, store) -> Optional[str]:
        """Create a Stripe customer for a store. Returns customer ID or None."""
        if not self.configured:
            logger.warning("Stripe not configured — skipping customer creation")
            return None

        loop = asyncio.get_running_loop()
        try:
            customer = await loop.run_in_executor(
                None,
                lambda: stripe.Customer.create(
                    email=store.email or "",
                    name=store.name or store.shopify_domain,
                    metadata={
                        "shopify_domain": store.shopify_domain,
                        "store_id": str(store.id),
                    },
                ),
            )
            logger.info(f"Stripe customer created: {customer.id} for {store.shopify_domain}")
            return customer.id
        except Exception as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            return None

    async def create_subscription(self, customer_id: str, plan: str) -> Optional[dict]:
        """
        Create a hybrid subscription with flat fee + 2 metered price components.
        Returns subscription dict or None.
        """
        if not self.configured:
            return None

        config = PLAN_CONFIG.get(plan)
        if not config:
            logger.error(f"Unknown plan: {plan}")
            return None

        loop = asyncio.get_running_loop()
        try:
            subscription = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.create(
                    customer=customer_id,
                    items=[
                        {"price": config["flat_price_id"]},
                        {"price": config["metered_price_id"]},
                    ],
                    currency="usd",
                    payment_behavior="default_incomplete",
                    expand=["latest_invoice.payment_intent"],
                ),
            )
            logger.info(f"Subscription created: {subscription.id} (plan={plan})")
            return {
                "subscription_id": subscription.id,
                "client_secret": subscription.latest_invoice.payment_intent.client_secret
                if subscription.latest_invoice and subscription.latest_invoice.payment_intent
                else None,
                "status": subscription.status,
            }
        except Exception as e:
            logger.error(f"Failed to create subscription: {e}")
            return None

    async def report_resolution(self, subscription_id: str, plan: str, count: int = 1) -> bool:
        """Push resolution usage to Stripe metered billing."""
        if not self.configured or not subscription_id:
            return False

        config = PLAN_CONFIG.get(plan, PLAN_CONFIG["base"])
        loop = asyncio.get_running_loop()

        try:
            # Find the resolution subscription item
            sub = await loop.run_in_executor(
                None,
                lambda: stripe.Subscription.retrieve(subscription_id),
            )
            res_item = None
            for item in sub["items"]["data"]:
                if item["price"]["id"] == config["metered_price_id"]:
                    res_item = item
                    break

            if not res_item:
                logger.warning(f"Resolution price item not found in subscription {subscription_id}")
                return False

            await loop.run_in_executor(
                None,
                lambda: stripe.SubscriptionItem.create_usage_record(
                    res_item["id"],
                    quantity=count,
                    action="increment",
                ),
            )
            logger.info(f"Reported {count} resolution(s) to Stripe for sub={subscription_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to report resolution usage: {e}")
            return False

    async def report_revenue_share(self, subscription_id: str, plan: str, order_value_cents: int) -> bool:
        """Revenue share billing has been removed. This is a no-op for backward compatibility."""
        logger.debug("report_revenue_share called but revenue share billing is disabled")
        return True

    async def handle_webhook_event(self, payload: bytes, sig_header: str) -> Optional[dict]:
        """
        Verify and process a Stripe webhook event.
        Returns the event dict or None if verification fails.
        """
        if not self.configured:
            return None

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret,
            )
        except stripe.error.SignatureVerificationError:
            logger.warning("Stripe webhook signature verification failed")
            return None
        except Exception as e:
            logger.error(f"Stripe webhook error: {e}")
            return None

        logger.info(f"Stripe webhook: {event['type']}")
        return event


class ShopifyBillingService:
    """Manages Shopify App Subscriptions for App Store billing."""

    PLAN_CONFIG = {
        "base": {
            "name": "Jerry Base",
            "price": "49.00",
            "currency": "USD",
            "interval": "EVERY_30_DAYS",
            "trial_days": 7,
        },
        "growth": {
            "name": "Jerry Growth",
            "price": "149.00",
            "currency": "USD",
            "interval": "EVERY_30_DAYS",
            "trial_days": 7,
        },
        "elite": {
            "name": "Jerry Elite",
            "price": "499.00",
            "currency": "USD",
            "interval": "EVERY_30_DAYS",
            "trial_days": 7,
        },
    }

    async def create_subscription(
        self,
        shop_domain: str,
        access_token: str,
        plan: str,
        return_url: str,
    ) -> dict:
        """
        Create a Shopify AppSubscription and return the confirmationUrl.
        The merchant must be redirected to confirmationUrl to approve billing.
        """
        plan_config = self.PLAN_CONFIG.get(plan)
        if not plan_config:
            raise ValueError(f"Unknown plan: {plan}")

        mutation = """
        mutation AppSubscriptionCreate($name: String!, $returnUrl: URL!, $lineItems: [AppSubscriptionLineItemInput!]!, $trialDays: Int) {
          appSubscriptionCreate(name: $name, returnUrl: $returnUrl, lineItems: $lineItems, trialDays: $trialDays) {
            appSubscription {
              id
              status
            }
            confirmationUrl
            userErrors {
              field
              message
            }
          }
        }
        """

        variables = {
            "name": plan_config["name"],
            "returnUrl": return_url,
            "trialDays": plan_config["trial_days"],
            "lineItems": [
                {
                    "plan": {
                        "appRecurringPricingDetails": {
                            "price": {
                                "amount": plan_config["price"],
                                "currencyCode": plan_config["currency"],
                            },
                            "interval": plan_config["interval"],
                        }
                    }
                }
            ],
        }

        import httpx
        url = f"https://{shop_domain}/admin/api/2024-10/graphql.json"
        headers = {
            "X-Shopify-Access-Token": access_token,
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json={"query": mutation, "variables": variables},
                headers=headers,
            )
            response.raise_for_status()

        data = response.json()
        result = data.get("data", {}).get("appSubscriptionCreate", {})

        user_errors = result.get("userErrors", [])
        if user_errors:
            raise ValueError(f"Shopify billing error: {user_errors}")

        return {
            "subscription_id": result["appSubscription"]["id"],
            "confirmation_url": result["confirmationUrl"],
            "status": result["appSubscription"]["status"],
        }

    async def cancel_subscription(
        self,
        shop_domain: str,
        access_token: str,
        subscription_id: str,
    ) -> bool:
        """Cancel a Shopify AppSubscription."""
        mutation = """
        mutation AppSubscriptionCancel($id: ID!) {
          appSubscriptionCancel(id: $id) {
            appSubscription { id status }
            userErrors { field message }
          }
        }
        """
        import httpx
        url = f"https://{shop_domain}/admin/api/2024-10/graphql.json"
        headers = {
            "X-Shopify-Access-Token": access_token,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json={"query": mutation, "variables": {"id": subscription_id}},
                headers=headers,
            )
            response.raise_for_status()

        data = response.json()
        result = data.get("data", {}).get("appSubscriptionCancel", {})
        user_errors = result.get("userErrors", [])
        if user_errors:
            logger.error(f"Cancel subscription errors: {user_errors}")
            return False
        return True

    async def get_subscription_status(
        self,
        shop_domain: str,
        access_token: str,
        subscription_id: str,
    ) -> str:
        """Get the current status of a Shopify AppSubscription. Returns ACTIVE, PENDING, CANCELLED, DECLINED, EXPIRED, FROZEN."""
        query = """
        query AppSubscription($id: ID!) {
          node(id: $id) {
            ... on AppSubscription {
              id
              status
            }
          }
        }
        """
        import httpx
        url = f"https://{shop_domain}/admin/api/2024-10/graphql.json"
        headers = {
            "X-Shopify-Access-Token": access_token,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json={"query": query, "variables": {"id": subscription_id}},
                headers=headers,
            )
            response.raise_for_status()
        data = response.json()
        return data.get("data", {}).get("node", {}).get("status", "UNKNOWN")
