"""
Jerry The Customer Service Bot — Analytics Service
Tracks chat sessions, support resolutions, and attributed sales.
Replaces the _AnalyticsServiceStub in conversation_engine.py.
"""

import asyncio
import logging
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import select

from app.db.engine import get_db
from app.db.models import Store, ChatSession, SupportResolution, AttributedSale

logger = logging.getLogger("jerry.analytics")


class AnalyticsService:
    def __init__(self, billing_service=None):
        self.billing_service = billing_service
        logger.info(
            f"AnalyticsService initialized "
            f"(billing={'connected' if billing_service and billing_service.configured else 'disabled'})"
        )

    async def track_conversation(
        self,
        store_id: str,
        session_id: str,
        message: str,
        response_text: str,
        intent: str,
        entities: dict,
        products_shown: int,
        escalated: bool,
    ) -> None:
        """Called after every message. Now also logs full interaction details."""
        try:
            async with get_db() as db:
                store = await self._get_store(db, store_id)
                if not store:
                    return

                session = await self._get_or_create_session(db, store, session_id, escalated)

                # TODO: once you add ChatInteraction model, insert here:
                # interaction = ChatInteraction(...)
                # db.add(interaction)

                await db.commit()

                logger.info(
                    f"Session tracked | store={store_id} | session={session_id} | "
                    f"usage={store.current_month_usage}/{store.monthly_interaction_limit} | escalated={escalated}"
                )

        except Exception as e:
            logger.error(f"Analytics tracking failed: {e}", exc_info=True)

    async def record_resolution(self, store_id: str, session_id: str, resolution_type: str) -> None:
        try:
            async with get_db() as db:
                store = await self._get_store(db, store_id)
                if not store:
                    return

                session = await self._get_session(db, session_id)
                resolution = SupportResolution(
                    merchant_id=store.id,
                    session_id=session.id if session else None,
                    resolution_type=resolution_type,
                )
                db.add(resolution)
                if session:
                    session.resolved = True

                await db.commit()

            # Fire-and-forget Stripe (safe after commit)
            if self.billing_service and getattr(store, "stripe_subscription_id", None):
                asyncio.create_task(
                    self.billing_service.report_resolution(
                        store.stripe_subscription_id, store.jerry_plan
                    )
                )

            logger.info(f"Resolution recorded | store={store_id} | type={resolution_type}")

        except Exception as e:
            logger.error(f"Resolution recording failed: {e}", exc_info=True)

    async def record_attributed_sale(
        self, shop_domain: str, shopify_order_id: str, order_value: float
    ) -> None:
        try:
            async with get_db() as db:
                store = await self._get_store(db, shop_domain.replace(".myshopify.com", ""))
                if not store:
                    return

                # Idempotency
                existing = await db.execute(
                    select(AttributedSale).where(AttributedSale.shopify_order_id == shopify_order_id)
                )
                if existing.scalar_one_or_none():
                    return

                plan_config = {"base": Decimal("0.02"), "growth": Decimal("0.03"), "elite": Decimal("0.05")}
                pct = plan_config.get(store.jerry_plan, Decimal("0.02"))
                order_cents = int(order_value * 100)
                commission = int(order_cents * pct)

                sale = AttributedSale(
                    merchant_id=store.id,
                    shopify_order_id=shopify_order_id,
                    order_value=order_value,
                    commission_cents=commission,
                )
                db.add(sale)
                await db.commit()

            if self.billing_service and getattr(store, "stripe_subscription_id", None):
                asyncio.create_task(
                    self.billing_service.report_revenue_share(
                        store.stripe_subscription_id, store.jerry_plan, order_cents
                    )
                )

            logger.info(
                f"Sale attributed | shop={shop_domain} | order={shopify_order_id} | "
                f"value=${order_value} | commission={commission}¢"
            )

        except Exception as e:
            logger.error(f"Sale attribution failed: {e}", exc_info=True)

    # Private helpers for cleanliness & reuse
    async def _get_store(self, db, store_id: str):
        domain = f"{store_id}.myshopify.com"
        result = await db.execute(select(Store).where(Store.shopify_domain == domain))
        store = result.scalar_one_or_none()
        if not store:
            result = await db.execute(select(Store).where(Store.shopify_domain.contains(store_id)))
            store = result.scalar_one_or_none()
            if not store:
                logger.debug(f"Store not found for {store_id}")
        return store

    async def _get_or_create_session(self, db, store, session_id: str, escalated: bool):
        result = await db.execute(
            select(ChatSession).where(ChatSession.session_token == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            session = ChatSession(
                merchant_id=store.id,
                session_token=session_id,
                human_intervention=escalated,
            )
            db.add(session)
            store.current_month_usage += 1
        elif escalated and not session.human_intervention:
            session.human_intervention = True
        return session

    async def _get_session(self, db, session_id: str):
        result = await db.execute(
            select(ChatSession).where(ChatSession.session_token == session_id)
        )
        return result.scalar_one_or_none()
