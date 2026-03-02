"""WonderwallAi hosted API server."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import get_settings
from server.db.engine import init_db, close_db
from server.middleware import RateLimitMiddleware
from server.api import scan, admin, billing
from server.helpers import set_billing_service
from server.services.billing_service import BillingService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings = get_settings()

    # Initialize database (creates tables + runs migrations)
    await init_db()

    # Initialize Stripe billing service
    billing_svc = BillingService()
    set_billing_service(billing_svc)

    logger.info("WonderwallAi server started")
    yield

    # Shutdown
    await close_db()
    logger.info("WonderwallAi server stopped")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="WonderwallAi API",
        version="1.0.0",
        description="AI firewall for LLM applications",
        lifespan=lifespan,
    )

    # CORS
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Routers
    app.include_router(scan.router, prefix="/v1/scan", tags=["scan"])
    app.include_router(admin.router, prefix="/v1/admin", tags=["admin"])
    app.include_router(billing.router, prefix="/v1/billing", tags=["billing"])

    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    return app


app = create_app()@app.post("/v1/scan/outbound")
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
