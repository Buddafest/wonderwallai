
"""Stripe Webhook Handler — Updates DB based on payment events."""

import logging
import stripe
from fastapi import APIRouter, Header, Request, HTTPException
from sqlalchemy import update

from server.config import get_settings
from server.db.engine import get_db
from server.db.models import ApiKey

logger = logging.getLogger("wonderwallai.server.webhooks")
router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

@router.post("/stripe")
async def stripe_webhook(request: Request, x_stripe_signature: str = Header(None)):
    settings = get_settings()
    stripe.api_key = settings.stripe_secret_key
    webhook_secret = settings.stripe_webhook_secret

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, x_stripe_signature, webhook_secret
        )
    except Exception as e:
        logger.error(f"Webhook signature verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data_object = event["data"]["object"]

    async with get_db() as db:
        # 1. Handle Successful Payments / New Subscriptions
        if event_type in ["checkout.session.completed", "customer.subscription.created", "customer.subscription.updated"]:
            stripe_cust_id = data_object.get("customer")
            stripe_sub_id = data_object.get("id") if "subscription" not in event_type else data_object.get("subscription")
            
            # For checkout.session.completed, we need to map the 'client_reference_id' 
            # (which should be your internal API Key ID) to the Stripe Customer.
            api_key_id = data_object.get("client_reference_id")
            
            status = data_object.get("status")
            if event_type == "checkout.session.completed":
                status = "active" # Force active on successful checkout

            if api_key_id:
                await db.execute(
                    update(ApiKey)
                    .where(ApiKey.id == api_key_id)
                    .values(
                        stripe_customer_id=stripe_cust_id,
                        stripe_subscription_id=stripe_sub_id,
                        billing_status=status
                    )
                )
                logger.info(f"Updated Key {api_key_id}: Status {status}")

        # 2. Handle Payment Failures or Cancellations
        elif event_type in ["invoice.payment_failed", "customer.subscription.deleted"]:
            stripe_sub_id = data_object.get("id") if event_type == "customer.subscription.deleted" else data_object.get("subscription")
            
            await db.execute(
                update(ApiKey)
                .where(ApiKey.stripe_subscription_id == stripe_sub_id)
                .values(billing_status="canceled" if event_type == "customer.subscription.deleted" else "past_due")
            )
            logger.warning(f"Subscription {stripe_sub_id} failed or deleted.")

    return {"status": "success"}
