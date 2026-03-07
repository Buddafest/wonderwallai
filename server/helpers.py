"""Shared helpers used across API endpoints."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import func, select

from server.db.engine import get_db
from server.db.models import ApiKey, FirewallConfig, UsageRecord
from server.instance_cache import compute_config_hash, get_or_create_instance
from wonderwallai import Wonderwall

logger = logging.getLogger("wonderwallai.server.helpers")

# Lazy reference to the billing service — set by main.py lifespan
_billing_service = None


def set_billing_service(svc) -> None:
    """Called from main.py lifespan to inject the BillingService instance."""
    global _billing_service
    _billing_service = svc


async def get_wonderwall_for_key(api_key: ApiKey) -> Wonderwall:
    """Load the FirewallConfig for an API key and return a cached Wonderwall instance."""
    async with get_db() as db:
        result = await db.execute(
            select(FirewallConfig).where(FirewallConfig.api_key_id == api_key.id)
        )
        config = result.scalar_one_or_none()

    if not config:
        # Use default config if none set
        default_dict = {
            "topics": [],
            "similarity_threshold": 0.35,
            "sentinel_enabled": True,
            "sentinel_model": "llama-3.1-8b-instant",
            "bot_description": "an AI assistant",
            "canary_prefix": "WONDERWALL-",
            "fail_open": True,
            "block_message": "I can only help with topics I'm designed for. Could you rephrase?",
            "block_message_injection": "Could you rephrase your question?",
            "allowed_mime_types": None,
        }
        config_hash = compute_config_hash(default_dict)
        return get_or_create_instance(config_hash, default_dict)

    config_dict = {
        "topics": config.topics or [],
        "similarity_threshold": config.similarity_threshold,
        "sentinel_enabled": config.sentinel_enabled,
        "sentinel_model": config.sentinel_model,
        "bot_description": config.bot_description,
        "canary_prefix": config.canary_prefix,
        "fail_open": config.fail_open,
        "block_message": config.block_message,
        "block_message_injection": config.block_message_injection,
        "allowed_mime_types": config.allowed_mime_types,
    }

    return get_or_create_instance(config.config_hash, config_dict)


async def record_usage(
    api_key_id: int,
    endpoint: str,
    latency_ms: float,
    was_blocked: bool = False,
    blocked_by: Optional[str] = None,
) -> None:
    """Write a usage record for billing/analytics."""
    try:
        async with get_db() as db:
            db.add(
                UsageRecord(
                    api_key_id=api_key_id,
                    endpoint=endpoint,
                    latency_ms=latency_ms,
                    was_blocked=was_blocked,
                    blocked_by=blocked_by,
                )
            )
    except Exception as e:
        # Never let usage tracking break a scan request
        logger.error(f"Failed to record usage: {e}")


async def check_scan_limit(api_key: ApiKey) -> None:
    """
    Enforce monthly scan limits per plan.
    - Free tier: hard 429 at 1,000 scans.
    - Paid tiers: report overage to Stripe metered billing (fire-and-forget).
    """
    from server.services.billing_service import PLAN_CONFIG

    plan = api_key.plan or "free"
    config = PLAN_CONFIG.get(plan, PLAN_CONFIG["free"])
    included_scans = config["included_scans"]

    # Count scans this calendar month
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    try:
        async with get_db() as db:
            result = await db.execute(
                select(func.count(UsageRecord.id)).where(
                    UsageRecord.api_key_id == api_key.id,
                    UsageRecord.timestamp >= month_start,
                )
            )
            scan_count = result.scalar() or 0
    except Exception as e:
        logger.error(f"Failed to count scans for limit check: {e}")
        return  # Fail open — don't block if we can't count

    if plan == "free" and scan_count >= included_scans:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Free tier scan limit reached ({included_scans:,} scans/month). "
                "Upgrade to Starter ($29/mo) for 50,000 scans."
            ),
        )

    # Paid tiers: report overage as fire-and-forget
    if plan != "free" and scan_count > included_scans and _billing_service:
        subscription_id = api_key.stripe_subscription_id
        if subscription_id:
            task = asyncio.create_task(
                _billing_service.report_overage(subscription_id, plan, count=1)
            )
            task.add_done_callback(
                lambda t: logger.error(f"Overage report failed: {t.exception()}")
                if t.exception() else None
            )
