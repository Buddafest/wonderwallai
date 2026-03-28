"""
GiLLBoT — Campaigns API Router
CRUD for outreach campaigns and sequence steps.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from server.auth import get_current_user
from server.db.models import User

router = APIRouter()


@router.get("")
async def list_campaigns(current_user: User = Depends(get_current_user)):
    """List all campaigns for the current user. (stub)"""
    return {"campaigns": [], "user_id": str(current_user.id)}
