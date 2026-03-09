import stripe
from server.config import get_settings

def create_checkout_session(api_key_id: str, customer_email: str):
    settings = get_settings()
    stripe.api_key = settings.stripe_secret_key

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[
            {
                # Your Flat Fee Price ID
                'price': settings.stripe_pro_flat_price_id,
                'quantity': 1,
            },
        ],
        mode='subscription',
        # This is the CRITICAL part for the webhook
        client_reference_id=api_key_id,
        customer_email=customer_email,
        success_url="https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://yourdomain.com/cancel",
        # Adding the overage price as a metered item if needed
        # Stripe handles this differently depending on your product setup
    )
    return session.url
Sent
Write to


import stripe
from fastapi import APIRouter, Depends
from server.config import get_settings
from server.auth import get_current_api_key
from server.db.models import ApiKey

router = APIRouter(prefix="/api/billing", tags=["billing"])

def create_checkout_session(api_key_id: str, customer_email: str):
    settings = get_settings()
    stripe.api_key = settings.stripe_secret_key

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[
            {
                'price': settings.stripe_pro_flat_price_id,
                'quantity': 1,
            },
        ],
        mode='subscription',
        client_reference_id=api_key_id,
        customer_email=customer_email,
        # Update these URLs to your actual frontend domain
        success_url="https://wonderwall.ai/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://wonderwall.ai/cancel",
    )
    return session.url

@router.post("/create-checkout")
async def start_checkout(
    user_key: ApiKey = Depends(get_current_api_key)
):
    # This calls the function above and returns the link
    checkout_url = create_checkout_session(
        api_key_id=str(user_key.id), 
        customer_email=user_key.email
    )
    return {"url": checkout_url}
