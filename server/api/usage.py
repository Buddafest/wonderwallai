"""Usage stats endpoint."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from server.auth import get_current_api_key
from server.db.engine import get_db
from server.db.models import ApiKey, UsageRecord
from server.schemas.responses import UsageResponse

router = APIRouter(prefix="/v1/usage", tags=["Usage"])


@router.get("/", response_model=UsageResponse)
async def get_usage(api_key: ApiKey = Depends(get_current_api_key)):
    """Get usage stats for the current billing period (calendar month)."""
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    # Last day of current month
    if now.month == 12:
        period_end = period_start.replace(year=now.year + 1, month=1) - timedelta(
            seconds=1
        )
    else:
        period_end = period_start.replace(month=now.month + 1) - timedelta(seconds=1)

    async with get_db() as db:
        # Total requests
        total_q = await db.execute(
            select(func.count(UsageRecord.id)).where(
                UsageRecord.api_key_id == api_key.id,
                UsageRecord.timestamp >= period_start,
            )
        )
        total_requests = total_q.scalar() or 0

        # Requests by endpoint
        by_endpoint_q = await db.execute(
            select(UsageRecord.endpoint, func.count(UsageRecord.id))
            .where(
                UsageRecord.api_key_id == api_key.id,
                UsageRecord.timestamp >= period_start,
            )
            .group_by(UsageRecord.endpoint)
        )
        requests_by_endpoint = {row[0]: row[1] for row in by_endpoint_q.all()}

        # Blocked count
        blocked_q = await db.execute(
            select(func.count(UsageRecord.id)).where(
                UsageRecord.api_key_id == api_key.id,
                UsageRecord.timestamp >= period_start,
                UsageRecord.was_blocked == True,
            )
        )
        blocked_count = blocked_q.scalar() or 0

        # Average latency
        avg_q = await db.execute(
            select(func.avg(UsageRecord.latency_ms)).where(
                UsageRecord.api_key_id == api_key.id,
                UsageRecord.timestamp >= period_start,
            )
        )
        avg_latency = avg_q.scalar() or 0.0

    return UsageResponse(
        api_key_prefix=api_key.key_prefix,
        plan=api_key.plan,
        period_start=period_start.date().isoformat(),
        period_end=period_end.date().isoformat(),
        total_requests=total_requests,
        requests_by_endpoint=requests_by_endpoint,
        blocked_count=blocked_count,
        avg_latency_ms=round(avg_latency, 2),
    )
