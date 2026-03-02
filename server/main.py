import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
import stripe
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from wonderwallai.client import Wonderwall

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.server")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
PRICE_IDS = {
    "starter": os.environ.get("STRIPE_PRICE_STARTER", ""),
    "pro": os.environ.get("STRIPE_PRICE_PRO", ""),
    "business": os.environ.get("STRIPE_PRICE_BUSINESS", ""),
}
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://wonderwallai-production.up.railway.app")
firewall = None

@asynccontextmanager
async def lifespan(app):
    global firewall
    firewall = Wonderwall(sentinel_api_key=os.environ.get("GROQ_API_KEY", ""), fail_open=True)
    yield

app = FastAPI(title="WonderwallAi API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_api_key(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    return authorization.removeprefix("Bearer ").strip()

class ScanInboundRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

class ScanOutboundRequest(BaseModel):
    text: str
    canary_token: Optional[str] = ""

class CheckoutRequest(BaseModel):
    plan: str
    email: Optional[str] = None
    apply_early_bird: bool = True

class CanaryRequest(BaseModel):
    session_id: str

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/v1/scan/inbound")
async def scan_inbound(body: ScanInboundRequest, api_key: str = Depends(get_api_key)):
    verdict = await firewall.scan_inbound(body.message)
    return {"allowed": verdict.allowed, "action": verdict.action, "message": verdict.message, "blocked_by": verdict.blocked_by, "violations": verdict.violations, "scores": verdict.scores}

@app.post("/v1/scan/outbound")
async def scan_outbound(body: ScanOutboundRequest, api_key: str = Depends(get_api_key)):
    verdict = await firewall.scan_outbound(body.text, body.canary_token or "")
    return {"allowed": verdict.allowed, "action": verdict.action, "message": verdict.message, "violations": verdict.violations}

@app.post("/v1/canary/generate")
async def generate_canary(body: CanaryRequest, api_key: str = Depends(get_api_key)):
    token = firewall.generate_canary(body.session_id)
    return {"canary_token": token, "system_prompt_addition": firewall.get_canary_prompt(token)}

@app.post("/v1/billing/checkout")
async def create_checkout(body: CheckoutRequest):
    plan = body.plan.lower()
    if plan not in PRICE_IDS:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {plan}")
    price_id = PRICE_IDS[plan]
    if not price_id:
        raise HTTPException(status_code=500, detail=f"Price ID for {plan} not configured")
    params = {"mode": "subscription", "line_items": [{"price": price_id, "quantity": 1}], "success_url": f"{FRONTEND_URL}/success?session_id={{CHECKOUT_SESSION_ID}}", "cancel_url": f"{FRONTEND_URL}/pricing"}
    if body.email:
        params["customer_email"] = body.email
    if body.apply_early_bird:
        params["discounts"] = [{"coupon": "EARLY_BIRD_50"}]
    else:
        params["allow_promotion_codes"] = True
    try:
        session = stripe.checkout.Session.create(**params)
        return {"checkout_url": session.url, "session_id": session.id}
    except stripe.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/v1/billing/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    logger.info(f"Stripe event: {event['type']}")
    return {"received": True}

@app.get("/v1/billing/plans")
async def get_plans():
    return {"plans": [{"id": "free", "name": "Free", "price": 0}, {"id": "starter", "name": "Starter", "price": 29, "early_bird": 14.50}, {"id": "pro", "name": "Pro", "price": 99, "early_bird": 49.50}, {"id": "business", "name": "Business", "price": 299, "early_bird": 149.50}]}
