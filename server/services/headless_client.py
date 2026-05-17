"""
Client for the wonderwallai-headless Railway service.

Called by the main prober when the cheap HTTP probe can't find a chat
endpoint. The headless service uses Playwright + Chromium to find and
interact with widgets like Intercom, Crisp, Drift, Tidio, Tawk.to, plus
a generic input fallback.

Configured via env:
    HEADLESS_SERVICE_URL    e.g. https://wonderwallai-headless-production.up.railway.app
    HEADLESS_INTERNAL_TOKEN shared secret for the X-Internal-Token header
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger("wonderwallai.headless_client")

HEADLESS_TIMEOUT = httpx.Timeout(180.0, connect=10.0)


def _service_url() -> Optional[str]:
    return os.getenv("HEADLESS_SERVICE_URL", "").rstrip("/") or None


def _token() -> str:
    return os.getenv("HEADLESS_INTERNAL_TOKEN", "")


def headless_enabled() -> bool:
    return bool(_service_url() and _token())


async def probe_widget(target_url: str, attacks: list[dict]) -> Optional[dict]:
    """
    Send the URL + attack payloads to the headless service. Returns the
    raw response dict (with `chat_found`, `widget_vendor`, `outcomes`),
    or None if the headless service is unavailable / errored.

    The caller is responsible for evaluating each outcome's
    `response_excerpt` against its success_detector.
    """
    base = _service_url()
    if not base:
        logger.info("Headless service not configured; skipping widget probe.")
        return None

    payload = {
        "url": target_url,
        "attacks": [
            {"id": a["id"], "title": a["title"], "payload": a["payload"]}
            for a in attacks
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=HEADLESS_TIMEOUT) as client:
            resp = await client.post(
                f"{base}/probe-widget",
                json=payload,
                headers={"X-Internal-Token": _token()},
            )
        if resp.status_code != 200:
            logger.warning(f"Headless service returned {resp.status_code}: {resp.text[:300]}")
            return None
        return resp.json()
    except Exception as e:
        logger.warning(f"Headless probe failed: {type(e).__name__}: {e}")
        return None
