"""
GiLLBoT — Dashboard API Router
Aggregate stats for the user's dashboard overview.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from server.auth import get_current_user
from server.db.models import User

router = APIRouter()


@router.get("")
async def dashboard_overview(current_user: User = Depends(get_current_user)):
    """Return top-level dashboard statistics for the authenticated user. (stub)"""
    return {
        "user_id": str(current_user.id),
        "plan": current_user.plan,
        "leads_enrolled_this_month": current_user.leads_enrolled_this_month,
        "monthly_lead_limit": current_user.monthly_lead_limit,
        "active_campaigns": 0,
        "total_sent": 0,
        "total_opened": 0,
        "total_clicked": 0,
        "total_replied": 0,
    }
