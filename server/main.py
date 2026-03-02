"""
WonderwallAi — API Server
FastAPI server exposing the firewall SDK + Stripe billing.
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

import stripe
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from wonderwallai.client import Wonderwall
from wonderwallai.config import WonderwallConfig

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.server")

# ---------------------------------------------------------------------------
# Stripe setup
# ---------------------------------------------------------------------------
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

PRICE_IDS = {
    "starter":  os.environ.get("STRIPE_PRICE_STARTER", ""),
    "pro":      os.environ.get("STRIPE_PRICE_PRO", ""),
    "business": os.environ.get("STRIPE_PRICE_BUSINESS", ""),
}

PLAN_LIMITS = {
    "free":     {"scans_per_month": 1_000,       "rate_per_min": 10},
    "starter":  {"scans_per_month": 50_000,      "rate_per_min": 60},
    "pro":      {"scans_per_month": 500_000,     "rate_per_min": 200},
    "business": {"scans_per_month": 2_000_000,   "rate_per_min": 500},
}

EARLY_BIRD_COUPON = "EARLY_BIRD_50"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://wonderwallai.com")

# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------
firewall: Optional[Wonderwall] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global firewall
    firewall = Wonderwall(
        sentinel_api_key=os.environ.get("GROQ_API_KEY", ""),
        bot_description="an AI firewall protecting LLM applications",
        fail_open=True,
    )
    logger.info("Wonderwall firewall initialized")
    yield


app = FastAPI(
    title="WonderwallAi API",
    description="AI firewall for LLM applications",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def get_api_key(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    return authorization.removeprefix("Bearer ").strip()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanInboundRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

class ScanOutboundRequest(BaseModel):
    text: str
    canary_token: Optional[str] = ""

class CheckoutRequest(BaseModel):
    plan: str  # starter | pro | business
    email: Optional[str] = None
    apply_early_bird: bool = True

class CanaryRequest(BaseModel):
    session_id: str


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "firewall": "ready" if firewall else "initializing"}


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/scan/inbound")
async def scan_inbound(body: ScanInboundRequest, api_key: str = Depends(get_api_key)):
    if not firewall:
        raise HTTPException(status_code=503, detail="Firewall not ready")
    verdict = await firewall.scan_inbound(body.message)
    return {
        "allowed":    verdict.allowed,
        "action":     verdict.action,
        "message":    verdict.message,
        "blocked_by": verdict.blocked_by,
        "violations": verdict.violations,
        "scores":     verdict.scores,
    }


@app.post("/v1/scan/outbound")
async def scan_outbound(body: ScanOutboundRequest, api_key: str = Depends(get_api_key)):
    if not firewall:
        raise HTTPException(status_code=503, detail="Firewall not ready")
    verdict = await firewall.scan_outbound(body.text, body.canary_token or "")
    return {
        "allowed":    verdict.allowed,
        "action":     verdict.action,
        "message":    verdict.message,
        "blocked_by": verdict.blocked_by,
        "violations": verdict.violations,
    }


@app.post("/v1/canary/generate")
async def generate_canary(body: CanaryRequest, api_key: str = Depends(get_api_key)):
    if not firewall:
        raise HTTPException(status_code=503, detail="Firewall not ready")
    token = firewall.generate_canary(body.session_id)
    prompt = firewall.get_canary_prompt(token)
    return {"canary_token": token, "system_prompt_addition": prompt}


# ---------------------------------------------------------------------------
# Stripe endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/billing/checkout")
async def create_checkout(body: CheckoutRequest):
    plan = body.plan.lower()
    if plan not in PRICE_IDS:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {plan}. Choose starter, pro, or business.")

    price_id = PRICE_IDS[plan]
    if not price_id:
        raise HTTPException(status_code=500, detail=f"Price ID for {plan} not configured")

    params = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": f"{FRONTEND_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url":  f"{FRONTEND_URL}/pricing",
        "allow_promotion_codes": True,
    }

    if body.email:
        params["customer_email"] = body.email

    # Auto-apply early bird coupon if requested
    if body.apply_early_bird and EARLY_BIRD_COUPON:
        try:
            params["discounts"] = [{"coupon": EARLY_BIRD_COUPON}]
            # Can't combine discounts with allow_promotion_codes
            params.pop("allow_promotion_codes", None)
        except Exception:
            pass

    try:
        session = stripe.checkout.Session.create(**params)
        return {"checkout_url": session.url, "session_id": session.id}
    except stripe.StripeError as e:
        logger.error(f"Stripe error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/billing/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        customer_id = data.get("customer")
        subscription_id = data.get("subscription")
        customer_email = data.get("customer_details", {}).get("email")
        logger.info(f"New subscription: customer={customer_email} sub={subscription_id}")
        # TODO: store in your DB, provision API key, send welcome email

    elif event_type == "customer.subscription.deleted":
        subscription_id = data.get("id")
        logger.info(f"Subscription cancelled: {subscription_id}")
        # TODO: revoke API key, send offboarding email

    elif event_type == "invoice.payment_failed":
        customer_email = data.get("customer_email")
        logger.warning(f"Payment failed for: {customer_email}")
        # TODO: notify customer

    return {"received": True}


@app.get("/v1/billing/plans")
async def get_plans():
    """Return plan info for the pricing page."""
    return {
        "early_bird": {
            "active": True,
            "coupon": EARLY_BIRD_COUPON,
            "discount": "50% off forever",
            "spots_remaining": None,  # wire up from Stripe if needed
        },
        "plans": [
            {
                "id": "free",
                "name": "Free",
                "price_monthly": 0,
                "early_bird_price": 0,
                **PLAN_LIMITS["free"],
            },
            {
                "id": "starter",
                "name": "Starter",
                "price_monthly": 29,
                "early_bird_price": 14.50,
                **PLAN_LIMITS["starter"],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price_monthly": 99,
                "early_bird_price": 49.50,
                **PLAN_LIMITS["pro"],
            },
            {
                "id": "business",
                "name": "Business",
                "price_monthly": 299,
                "early_bird_price": 149.50,
                **PLAN_LIMITS["business"],
            },
        ],
    }
