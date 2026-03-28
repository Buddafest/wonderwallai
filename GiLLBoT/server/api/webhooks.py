"""
GiLLBoT — Webhooks API Router
Handles incoming webhooks from Stripe and SendGrid.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/stripe")
async def stripe_webhook(request: Request):
    """Receive and process Stripe webhook events. (stub)"""
    return {"received": True}


@router.post("/sendgrid")
async def sendgrid_webhook(request: Request):
    """Receive and process SendGrid event webhooks (opens, clicks, bounces). (stub)"""
    return {"received": True}
