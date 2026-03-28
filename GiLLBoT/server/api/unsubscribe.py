"""
GiLLBoT — Unsubscribe API Router
Public unsubscribe endpoint linked from outbound emails.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("", response_class=HTMLResponse)
async def unsubscribe(
    email: str = Query(..., description="Email address to unsubscribe"),
    token: str = Query(..., description="HMAC verification token"),
    user_id: str = Query(default="", description="Optional sender user ID for scoped unsubscribe"),
):
    """
    Public one-click unsubscribe endpoint.
    Verifies the token and records the unsubscribe. (stub)
    """
    return HTMLResponse(
        content="<html><body><h2>You have been unsubscribed.</h2></body></html>",
        status_code=200,
    )
