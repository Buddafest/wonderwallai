"""Scan endpoints — the core product."""

import time
import unicodedata

from fastapi import APIRouter, Depends

from server.auth import get_current_api_key
from server.db.models import ApiKey
from server.helpers import check_scan_limit, get_wonderwall_for_key, record_usage
from server.rate_limiter import check_rate_limit
from server.schemas.requests import ScanInboundRequest, ScanOutboundRequest
from server.schemas.responses import VerdictResponse

router = APIRouter(prefix="/v1/scan", tags=["Scan"])


def _sanitize_input(text: str) -> str:
    """Normalize Unicode and strip control characters (from Jerry's hardening)."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(
        c for c in text if unicodedata.category(c)[0] != "C" or c in "\n\t"
    )
    return text.strip()


@router.post("/inbound", response_model=VerdictResponse)
async def scan_inbound(
    req: ScanInboundRequest,
    api_key: ApiKey = Depends(get_current_api_key),
):
    """Scan a user message before it reaches the LLM.

    Pipeline: SemanticRouter (fast) → SentinelScan (LLM-based).
    """
    check_rate_limit(api_key.id, api_key.rate_limit)
    await check_scan_limit(api_key)
    start = time.perf_counter()

    instance = await get_wonderwall_for_key(api_key)
    sanitized = _sanitize_input(req.message)
    verdict = await instance.scan_inbound(sanitized)

    latency = (time.perf_counter() - start) * 1000

    await record_usage(
        api_key.id,
        "scan_inbound",
        latency,
        was_blocked=not verdict.allowed,
        blocked_by=verdict.blocked_by,
    )

    return VerdictResponse(
        allowed=verdict.allowed,
        action=verdict.action,
        blocked_by=verdict.blocked_by,
        message=verdict.message,
        violations=verdict.violations,
        scores=verdict.scores,
        latency_ms=round(latency, 2),
    )


@router.post("/outbound", response_model=VerdictResponse)
async def scan_outbound(
    req: ScanOutboundRequest,
    api_key: ApiKey = Depends(get_current_api_key),
):
    """Scan an LLM response before it reaches the user.

    Checks for canary token leaks (hard block), API key leaks (redact),
    and PII (redact).
    """
    check_rate_limit(api_key.id, api_key.rate_limit)
    await check_scan_limit(api_key)
    start = time.perf_counter()

    instance = await get_wonderwall_for_key(api_key)
    sanitized = _sanitize_input(req.text)
    verdict = await instance.scan_outbound(sanitized, req.canary_token)

    latency = (time.perf_counter() - start) * 1000

    await record_usage(
        api_key.id,
        "scan_outbound",
        latency,
        was_blocked=not verdict.allowed,
        blocked_by=verdict.blocked_by,
    )

    return VerdictResponse(
        allowed=verdict.allowed,
        action=verdict.action,
        blocked_by=verdict.blocked_by,
        message=verdict.message,
        violations=verdict.violations,
        scores=verdict.scores,
        latency_ms=round(latency, 2),
    )
