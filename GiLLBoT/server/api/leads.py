"""
GiLLBoT — Leads API Router
CRUD for leads, lead lists, and CSV import.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from server.auth import get_current_user
from server.db.models import User

router = APIRouter()


@router.get("")
async def list_leads(current_user: User = Depends(get_current_user)):
    """List all leads for the current user. (stub)"""
    return {"leads": [], "user_id": str(current_user.id)}
