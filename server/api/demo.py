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
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

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
    return result.to_dict()


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
    return result.to_dict()
