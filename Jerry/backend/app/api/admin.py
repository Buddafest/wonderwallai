"""
Jerry The Customer Service Bot — Admin Panel API
Protected by X-Admin-API-Key header. For the product owner to monitor all stores.
"""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func

from app.db.engine import get_db
from app.db.models import Store, ChatSession, SupportResolution, AttributedSale
from app.core.security import verify_admin_token

logger = logging.getLogger("jerry.admin")

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/stores", dependencies=[Depends(verify_admin_token)])
async def list_all_stores():
    """List all installed stores with subscription and usage info."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).order_by(Store.installed_at.desc())
        )
        stores = result.scalars().all()

    return {
        "count": len(stores),
        "stores": [
            {
                "id": s.id,
                "domain": s.shopify_domain,
                "name": s.name,
                "plan": s.jerry_plan,
                "subscription_status": getattr(s, "subscription_status", "none"),
                "usage": s.current_month_usage,
                "limit": s.monthly_interaction_limit,
                "is_active": s.is_active,
                "installed_at": s.installed_at.isoformat() if s.installed_at else None,
            }
            for s in stores
        ],
    }


@router.get("/stats", dependencies=[Depends(verify_admin_token)])
async def get_global_stats():
    """Get global platform stats — total stores, MRR, conversations."""
    async with get_db() as db:
        total_stores = (await db.execute(
            select(func.count(Store.id))
        )).scalar() or 0

        active_stores = (await db.execute(
            select(func.count(Store.id)).where(Store.is_active == True)
        )).scalar() or 0

        total_conversations = (await db.execute(
            select(func.count(ChatSession.id))
        )).scalar() or 0

        total_resolutions = (await db.execute(
            select(func.count(SupportResolution.id))
        )).scalar() or 0

        total_revenue = (await db.execute(
            select(func.sum(AttributedSale.order_value))
        )).scalar() or 0.0

    return {
        "stores": {"total": total_stores, "active": active_stores},
        "conversations": total_conversations,
        "resolutions": total_resolutions,
        "attributed_revenue": round(float(total_revenue), 2),
    }


@router.get("/stores/{store_domain}/conversations", dependencies=[Depends(verify_admin_token)])
async def get_store_conversations(store_domain: str, limit: int = Query(default=50, le=200)):
    """Get recent conversations for a specific store."""
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(Store.shopify_domain == store_domain)
        )
        store = result.scalar_one_or_none()

    if not store:
        return {"error": "Store not found"}

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
        "conversations": [
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
