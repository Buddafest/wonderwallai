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
from app.db.models import Store, ChatSession, SupportResolution, AttributedSale, ChatInteraction

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
        turn_number: int = 0,
        latency_ms: Optional[float] = None,
        firewall_verdict: Optional[str] = None,
    ) -> None:
        """Called after every message. Persists full interaction details for auditability."""
        try:
            async with get_db() as db:
                store = await self._get_store(db, store_id)
                if not store:
                    return

                session = await self._get_or_create_session(db, store, session_id, escalated)
                await db.flush()  # Ensure session.id is available

                # Persist full interaction — the audit trail
                interaction = ChatInteraction(
                    session_id=session.id,
                    message=message[:500],           # truncate for privacy/storage
                    response_text=response_text[:500] if response_text else None,
                    intent=intent,
                    entities=entities,
                    products_shown=products_shown,
                    escalated=escalated,
                    turn_number=turn_number,
                    latency_ms=latency_ms,
                    firewall_verdict=firewall_verdict,
                )
                db.add(interaction)

                await db.commit()

                logger.info(
                    f"Session tracked | store={store_id} | session={session_id} | "
                    f"turn={turn_number} | intent={intent} | "
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

            # Fire-and-forget Shopify usage billing (safe after commit)
            if (
                self.billing_service
                and getattr(store, "shopify_subscription_id", None)
                and getattr(store, "subscription_status", "none") in ("active", "trialing")
            ):
                asyncio.create_task(
                    self._report_shopify_usage(store, resolution_type)
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

            logger.info(
                f"Sale attributed | shop={shop_domain} | order={shopify_order_id} | "
                f"value=${order_value} | commission={commission}¢"
            )

        except Exception as e:
            logger.error(f"Sale attribution failed: {e}", exc_info=True)

    async def _report_shopify_usage(self, store, resolution_type: str) -> None:
        """Report a $0.25 usage charge to Shopify for a resolved interaction."""
        try:
            usage_line_item_id = await self.billing_service.get_usage_line_item_id(
                shop_domain=store.shopify_domain,
                access_token=store.access_token,
            )
            if not usage_line_item_id:
                logger.warning(f"No usage line item found for {store.shopify_domain} — skipping usage billing")
                return

            await self.billing_service.report_resolution(
                shop_domain=store.shopify_domain,
                access_token=store.access_token,
                subscription_line_item_id=usage_line_item_id,
                description=f"AI resolution: {resolution_type}",
            )
        except Exception as e:
            logger.error(f"Shopify usage billing failed for {store.shopify_domain}: {e}")

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
