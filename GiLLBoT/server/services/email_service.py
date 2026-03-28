"""
GiLLBoT — Email Service
Sends transactional and outreach emails via SendGrid.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("gillbot.email")


class EmailService:
    """
    Sends outreach emails via SendGrid.
    Handles open/click tracking and unsubscribe headers.
    """

    def __init__(self):
        from server.config import get_settings
        settings = get_settings()
        self.api_key = settings.sendgrid_api_key
        self.configured = bool(self.api_key)

        if self.configured:
            try:
                import sendgrid
                self.client = sendgrid.SendGridAPIClient(api_key=self.api_key)
                logger.info("EmailService initialized (SendGrid connected)")
            except ImportError:
                logger.warning("sendgrid package not installed — email sending disabled")
                self.client = None
                self.configured = False
        else:
            self.client = None
            logger.warning("EmailService: SENDGRID_API_KEY not set — email sending disabled")

    async def send_email(
        self,
        to_email: str,
        from_email: str,
        from_name: str,
        subject: str,
        html_body: str,
        reply_to: Optional[str] = None,
        unsubscribe_url: Optional[str] = None,
        message_id_header: Optional[str] = None,
    ) -> Optional[str]:
        """
        Send a single outreach email.

        Returns:
            SendGrid message ID on success, None on failure.
        """
        # TODO: implement SendGrid API call
        logger.info(f"EmailService.send_email called (stub) to={to_email}")
        return None
