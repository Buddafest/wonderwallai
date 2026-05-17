"""
WonderwallAi — Public Demo Scanner API

Unauthenticated endpoints powering the live scanner on the
WonderwallAi landing page. Rate-limited per client IP to prevent abuse.

Routes:
    POST /v1/demo/scan-prompt   Static analysis of a pasted system prompt
    POST /v1/demo/scan-url      Live black-box scan of a target chatbot URL

Both endpoints return the same JSON shape so the frontend can render
identical results UI from either entry point.
"""

import logging
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select

from server.db.engine import get_db
from server.db.models import SharedScan
from server.services.prober import probe_system_prompt, probe_url

logger = logging.getLogger("wonderwallai.demo")

router = APIRouter(prefix="/v1/demo", tags=["Demo"])


# ============================================================
# IP-based rate limiter (sliding window, in-process)
#
# Free demo usage is capped per IP per hour to keep abuse manageable.
# This is intentionally separate from the API-key rate limiter used
# for authenticated /v1/scan/* endpoints.
# ============================================================

_ip_timestamps: dict[str, list[float]] = defaultdict(list)

# Per-endpoint hourly caps for unauthenticated callers
DEMO_LIMITS = {
    "scan-prompt": 5,   # 5 prompt scans per hour per IP
    "scan-url": 3,      # 3 live URL scans per hour per IP
}
WINDOW_SECONDS = 3600


def _client_ip(request: Request) -> str:
    """Extract the client IP, honouring Cloudflare/proxy headers."""
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _check_demo_limit(request: Request, endpoint: str) -> None:
    """Raise 429 if this IP has exceeded the demo cap for this endpoint."""
    ip = _client_ip(request)
    limit = DEMO_LIMITS.get(endpoint, 3)
    now = time.time()
    cutoff = now - WINDOW_SECONDS
    key = f"{ip}:{endpoint}"

    # Prune expired entries
    _ip_timestamps[key] = [t for t in _ip_timestamps[key] if t > cutoff]

    if len(_ip_timestamps[key]) >= limit:
        raise HTTPException(
            status_code=429,
            detail=(
                f"You've used your {limit} free {endpoint.replace('-', ' ')}s "
                "for this hour. Upgrade to Starter for 5 scans/day, or Pro "
                "for continuous monitoring + AI-generated fixes."
            ),
            headers={"Retry-After": str(WINDOW_SECONDS)},
        )

    _ip_timestamps[key].append(now)


# ============================================================
# Share-link store (SQLite-backed, 7-day TTL)
#
# Each completed scan is given a short opaque id and persisted so it
# can be retrieved by GET /v1/demo/scan/{id} after Railway restarts.
# Expired rows are pruned lazily on read.
# ============================================================

_SHARE_TTL_DAYS = 7


def _new_share_id() -> str:
    return secrets.token_urlsafe(8)[:10]


async def _store_scan(result_dict: dict) -> str:
    sid = _new_share_id()
    target = (result_dict.get("target") or "")[:2048]
    score = int(result_dict.get("score") or 0)
    async with get_db() as db:
        # Resolve rare collision by retrying a fresh id
        for _ in range(3):
            existing = await db.execute(select(SharedScan.id).where(SharedScan.id == sid))
            if existing.first() is None:
                break
            sid = _new_share_id()
        db.add(SharedScan(id=sid, payload=result_dict, target=target, score=score))
    return sid


async def _load_scan(share_id: str) -> Optional[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=_SHARE_TTL_DAYS)
    async with get_db() as db:
        # Lazy prune of expired rows (cheap, runs at most once per request)
        await db.execute(delete(SharedScan).where(SharedScan.created_at < cutoff))
        row = await db.execute(select(SharedScan).where(SharedScan.id == share_id))
        scan = row.scalar_one_or_none()
        if scan is None:
            return None
        return scan.payload


# ============================================================
# Request models
# ============================================================

class EndpointShape(BaseModel):
    """Optional advanced options for non-standard chatbot endpoints."""
    method: str = "POST"
    path: str = "/api/chat"
    body_template: dict = Field(default_factory=lambda: {"message": "{{message}}"})
    headers: Optional[dict] = None


class ScanPromptRequest(BaseModel):
    system_prompt: str = Field(..., min_length=1, max_length=10_000)

    @field_validator("system_prompt")
    @classmethod
    def strip_text(cls, v: str) -> str:
        return v.strip()


class ScanUrlRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    endpoint_shape: Optional[EndpointShape] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# ============================================================
# Endpoints
# ============================================================

@router.post("/scan-prompt")
async def scan_prompt(req: ScanPromptRequest, request: Request):
    """
    Static-analyse a system prompt and return predicted vulnerabilities.

    No external calls. Instant. Rate-limited to 5 per hour per IP.
    """
    _check_demo_limit(request, "scan-prompt")
    logger.info(
        f"demo scan-prompt | ip={_client_ip(request)} | len={len(req.system_prompt)}"
    )
    result = probe_system_prompt(req.system_prompt)
    payload = result.to_dict()
    payload["scan_id"] = await _store_scan(payload)
    return payload


@router.post("/scan-url")
async def scan_url(req: ScanUrlRequest, request: Request):
    """
    Run the v1 attack library against a live chatbot URL.

    Sends ~20 attack payloads concurrently, evaluates each response,
    and returns a vulnerability score plus per-attack findings.
    Rate-limited to 3 per hour per IP.
    """
    _check_demo_limit(request, "scan-url")
    ip = _client_ip(request)
    logger.info(f"demo scan-url | ip={ip} | target={req.url}")

    shape = req.endpoint_shape.model_dump() if req.endpoint_shape else None
    try:
        result = await probe_url(req.url, endpoint_shape=shape)
    except Exception as e:
        logger.exception(f"prober failed for {req.url}: {e}")
        raise HTTPException(
            status_code=500,
            detail="The scanner hit an unexpected error. Please try again or use the prompt tab instead.",
        )
    payload = result.to_dict()
    payload["scan_id"] = await _store_scan(payload)
    return payload


@router.get("/scan/{share_id}")
async def get_shared_scan(share_id: str):
    """
    Retrieve a previously-stored scan by share id. Public, no auth.

    Returned payload is the same shape as scan-prompt/scan-url responses.
    The frontend treats anonymous viewers as locked past the free findings
    limit regardless of who originally ran the scan.
    """
    if not share_id or len(share_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid share id.")
    payload = await _load_scan(share_id)
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="That scan link has expired or doesn't exist. Run a fresh scan to get a new link.",
        )
    return payload
