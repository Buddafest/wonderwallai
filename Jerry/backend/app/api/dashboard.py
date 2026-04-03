"""
Jerry The Customer Service Bot — Store Dashboard API
Provides merchant-facing stats and chat history.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func

from app.db.engine import get_db
from app.db.models import Store, ChatSession, SupportResolution, AttributedSale

logger = logging.getLogger("jerry.dashboard")

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/{store_domain}/stats")
async def get_dashboard_stats(store_domain: str):
    """Get store dashboard stats for the current billing period."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    # Count conversations, resolutions, and attributed revenue
    async with get_db() as db:
        conversations = (await db.execute(
            select(func.count(ChatSession.id)).where(ChatSession.merchant_id == store.id)
        )).scalar() or 0

        resolutions = (await db.execute(
            select(func.count(SupportResolution.id)).where(SupportResolution.merchant_id == store.id)
        )).scalar() or 0

        revenue_result = await db.execute(
            select(func.sum(AttributedSale.order_value)).where(AttributedSale.merchant_id == store.id)
        )
        attributed_revenue = revenue_result.scalar() or 0.0

    return {
        "store": store.shopify_domain,
        "name": store.name,
        "plan": store.jerry_plan,
        "subscription_status": getattr(store, "subscription_status", "none"),
        "usage": {
            "current": store.current_month_usage,
            "limit": store.monthly_interaction_limit,
            "billing_cycle_reset": store.billing_cycle_reset.isoformat() if store.billing_cycle_reset else None,
        },
        "totals": {
            "conversations": conversations,
            "resolutions": resolutions,
            "attributed_revenue": round(float(attributed_revenue), 2),
        },
    }


@router.get("/{store_domain}/recent-chats")
async def get_recent_chats(store_domain: str, limit: int = Query(default=20, le=100)):
    """Get recent chat sessions for a store."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    async with get_db() as db:
        result = await db.execute(
            select(ChatSession)
            .where(ChatSession.merchant_id == store.id)
            .order_by(ChatSession.created_at.desc())
            .limit(limit)
        )
        sessions = result.scalars().all()

    return {
        "store": store.shopify_domain,
        "chats": [
            {
                "id": s.id,
                "session_token": s.session_token,
                "resolved": s.resolved,
                "human_intervention": s.human_intervention,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in sessions
        ],
    }


SUPPORTED_LANGUAGES = {
    "en-US", "es-ES", "fr-FR", "de-DE", "it-IT", "pt-BR", "hi-IN", "th-TH",
}


class UpdateSettingsRequest(BaseModel):
    chat_language: str = Field(..., max_length=10)


@router.get("/{store_domain}/settings")
async def get_settings(store_domain: str):
    """Get store settings."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    return {
        "chat_language": getattr(store, "chat_language", "en-US") or "en-US",
    }


@router.post("/{store_domain}/settings")
async def update_settings(store_domain: str, req: UpdateSettingsRequest):
    """Update store settings."""
    if req.chat_language not in SUPPORTED_LANGUAGES:
        raise HTTPException(status_code=400, detail=f"Unsupported language. Choose from: {', '.join(sorted(SUPPORTED_LANGUAGES))}")

    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()
        if not store:
            raise HTTPException(status_code=404, detail="Store not found")
        store.chat_language = req.chat_language

    return {"status": "updated", "chat_language": req.chat_language}
