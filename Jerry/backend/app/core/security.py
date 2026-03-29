"""
================================================================================
Jerry The Customer Service Bot — Security Utilities
================================================================================
File:     app/core/security.py
Version:  1.0.0
Session:  5 (February 2026)

PURPOSE
-------
JWT token creation and validation for:
1. Widget authentication — chat widget gets a short-lived token to connect WebSocket
2. Shopify HMAC verification — validates that OAuth callbacks really come from Shopify

USAGE
-----
    from app.core.security import create_widget_token, verify_widget_token

    token = create_widget_token(store_id="my-store", session_id="sess-123")
    payload = verify_widget_token(token)  # Returns dict or None
================================================================================
"""

import hashlib
import hmac
import logging
import time
from typing import Optional
from urllib.parse import urlencode

import jwt

from app.core.config import get_settings

logger = logging.getLogger("sunsetbot.security")


# ---------------------------------------------------------------------------
# JWT — Widget Tokens
# ---------------------------------------------------------------------------

def create_widget_token(
    store_id: str,
    session_id: str,
    extra_claims: Optional[dict] = None,
) -> str:
    """
    Create a JWT for the chat widget to authenticate WebSocket connections.

    Payload:
        - store_id: Which store this widget belongs to
        - session_id: Unique session identifier
        - iat: Issued at timestamp
        - exp: Expiration timestamp (24h by default)

    Returns:
        Encoded JWT string
    """
    settings = get_settings()
    now = int(time.time())

    payload = {
        "store_id": store_id,
        "session_id": session_id,
        "iat": now,
        "exp": now + (settings.jwt_expiry_hours * 3600),
    }

    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token


def verify_widget_token(token: str) -> Optional[dict]:
    """
    Verify and decode a widget JWT.

    Returns:
        Decoded payload dict if valid, None if invalid/expired.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Widget token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid widget token: {e}")
        return None


# ---------------------------------------------------------------------------
# Shopify HMAC Verification
# ---------------------------------------------------------------------------

def verify_shopify_hmac(query_params: dict) -> bool:
    """
    Verify that an OAuth callback request actually came from Shopify.

    Shopify signs the query string with the app's API secret using HMAC-SHA256.
    Format: sort params alphabetically, join as key=value&key=value (no URL encoding).

    Args:
        query_params: Dict of ALL query parameters from the callback URL

    Returns:
        True if HMAC is valid, False otherwise
    """
    settings = get_settings()

    if not settings.shopify_api_secret:
        logger.error("SHOPIFY_API_SECRET not configured — cannot verify HMAC")
        return False

    received_hmac = query_params.get("hmac", "")
    if not received_hmac:
        logger.warning("No HMAC in query params")
        return False

    # Remove 'hmac' from params, sort alphabetically by key
    params_to_sign = {k: v for k, v in sorted(query_params.items()) if k != "hmac"}

    # Shopify format: key=value joined with & (NO url-encoding of values)
    message = "&".join(f"{k}={v}" for k, v in params_to_sign.items())

    logger.info(f"HMAC verification — params: {list(params_to_sign.keys())}")

    computed_hmac = hmac.new(
        settings.shopify_api_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    is_valid = hmac.compare_digest(computed_hmac, received_hmac)

    if not is_valid:
        logger.warning(
            f"Shopify HMAC mismatch — received: {received_hmac[:16]}... "
            f"computed: {computed_hmac[:16]}..."
        )

    return is_valid


def verify_shopify_webhook(data: bytes, hmac_header: str) -> bool:
    """
    Verify that a webhook request actually came from Shopify.

    Shopify sends the HMAC in the X-Shopify-Hmac-Sha256 header.

    Args:
        data: Raw request body bytes
        hmac_header: Value of X-Shopify-Hmac-Sha256 header

    Returns:
        True if HMAC is valid
    """
    import base64

    settings = get_settings()

    if not settings.shopify_api_secret:
        logger.error("SHOPIFY_API_SECRET not configured — cannot verify webhook")
        return False

    computed = hmac.new(
        settings.shopify_api_secret.encode("utf-8"),
        data,
        hashlib.sha256,
    ).digest()

    computed_b64 = base64.b64encode(computed).decode("utf-8")

    return hmac.compare_digest(computed_b64, hmac_header)


# ---------------------------------------------------------------------------
# Admin API Key — protects internal endpoints
# ---------------------------------------------------------------------------

from fastapi import HTTPException, Request

ADMIN_API_KEY_HEADER = "X-Admin-API-Key"


async def verify_admin_token(request: Request) -> bool:
    """
    Verify admin API key from request header.
    Use as a FastAPI dependency: dependencies=[Depends(verify_admin_token)]
    """
    settings = get_settings()
    api_key = request.headers.get(ADMIN_API_KEY_HEADER, "")

    if not api_key or api_key != settings.admin_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")

    return True
