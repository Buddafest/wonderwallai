import stripe
from fastapi import APIRouter, Depends
from server.config import get_settings
from server.auth import get_current_api_key
from server.db.models import ApiKey

router = APIRouter(prefix="/api/billing", tags=["billing"])

def create_checkout_session(api_key_id: str, customer_email: str):
    """Generates a Stripe Checkout URL for the Pro subscription."""
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
        # Update these to your actual Railway or custom domain
        success_url="https://wonderwall.ai/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://wonderwall.ai/cancel",
    )
    return session.url

@router.post("/create-checkout")
async def start_checkout(
    user_key: ApiKey = Depends(get_current_api_key)
):
    """FastAPI endpoint to start the billing process."""
    # Check if 'email' exists on your model; if it's named differently, 
    # change user_key.email to match your model's field name.
    email = getattr(user_key, "email", None) 
    
    checkout_url = create_checkout_session(
        api_key_id=str(user_key.id), 
        customer_email=email
    )
    return {"url": checkout_url}
