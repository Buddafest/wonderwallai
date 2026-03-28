"""
GiLLBoT — Unsubscribe Service
Generates and verifies unsubscribe tokens, records unsubscribes.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

logger = logging.getLogger("gillbot.unsubscribe")


class UnsubscribeService:
    """Handles unsubscribe token generation, verification, and recording."""

    def __init__(self):
        from server.config import get_settings
        settings = get_settings()
        self.secret = settings.unsubscribe_secret
        self.app_url = settings.app_url

    def generate_token(self, email: str, user_id: Optional[str] = None) -> str:
        """
        Generate an HMAC-based unsubscribe token for a given email.

        Args:
            email: The recipient email address.
            user_id: Optional sender user ID for scoped unsubscribes.

        Returns:
            Hex HMAC token string.
        """
        message = f"{email}:{user_id or ''}"
        return hmac.new(
            self.secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_token(
        self, email: str, token: str, user_id: Optional[str] = None
    ) -> bool:
        """Verify that an unsubscribe token is valid for a given email."""
        expected = self.generate_token(email, user_id)
        return hmac.compare_digest(expected, token)

    def build_unsubscribe_url(
        self, email: str, user_id: Optional[str] = None
    ) -> str:
        """Build the full one-click unsubscribe URL to embed in emails."""
        token = self.generate_token(email, user_id)
        params = f"email={email}&token={token}"
        if user_id:
            params += f"&user_id={user_id}"
        return f"{self.app_url}/v1/unsubscribe?{params}"
