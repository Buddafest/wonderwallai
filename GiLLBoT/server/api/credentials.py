"""
GiLLBoT — Channel Credentials API Router
Manage encrypted outreach channel credentials (email, SMS, LinkedIn, etc.).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from server.auth import get_current_user
from server.db.models import User

router = APIRouter()


@router.get("")
async def list_credentials(current_user: User = Depends(get_current_user)):
    """List channel credentials for the current user. (stub)"""
    return {"credentials": [], "user_id": str(current_user.id)}
