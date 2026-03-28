"""
GiLLBoT — Sequence Scheduler
Polls the database for campaign_leads with next_send_at <= now()
and enqueues sequence step execution tasks.

This runs as a cron job within the arq worker.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from arq import ArqRedis
from sqlalchemy import select

logger = logging.getLogger("gillbot.scheduler")


async def poll_and_enqueue_pending_sends(ctx: dict) -> int:
    """
    Cron task: find all CampaignLeads due for their next send and enqueue them.

    Returns:
        Number of tasks enqueued.
    """
    from server.db.engine import get_db
    from server.db.models import CampaignLead

    redis: ArqRedis = ctx.get("redis")
    if not redis:
        logger.error("No redis connection in context")
        return 0

    now = datetime.now(timezone.utc)
    enqueued = 0

    async with get_db() as db:
        result = await db.execute(
            select(CampaignLead).where(
                CampaignLead.next_send_at <= now,
                CampaignLead.status.in_(["pending", "in_progress"]),
            )
        )
        due_leads = result.scalars().all()

    for campaign_lead in due_leads:
        await redis.enqueue_job(
            "run_sequence_step",
            str(campaign_lead.id),
        )
        enqueued += 1

    if enqueued:
        logger.info(f"Scheduler: enqueued {enqueued} sequence step(s)")

    return enqueued
