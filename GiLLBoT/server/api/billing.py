"""
GiLLBoT — Billing API Router
Stripe subscription management (create checkout, portal, cancel).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from server.auth import get_current_user
from server.db.models import User

router = APIRouter()


@router.get("/status")
async def billing_status(current_user: User = Depends(get_current_user)):
    """Return current billing plan and status for the authenticated user. (stub)"""
    return {
        "plan": current_user.plan,
        "billing_status": current_user.billing_status,
        "monthly_lead_limit": current_user.monthly_lead_limit,
        "leads_enrolled_this_month": current_user.leads_enrolled_this_month,
    }
