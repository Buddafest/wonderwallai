"""
GiLLBoT — Send Email Task
Worker task for sending a single outreach email via SendGrid.
Separated from sequence_runner to allow retries at the channel level.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("gillbot.send_email")


async def send_email_task(
    ctx: dict,
    execution_id: str,
    to_email: str,
    from_email: str,
    from_name: str,
    subject: str,
    html_body: str,
    reply_to: Optional[str] = None,
    unsubscribe_url: Optional[str] = None,
) -> dict:
    """
    ARQ task: send a single outreach email and update SequenceExecution status.

    Args:
        ctx: ARQ context dict.
        execution_id: UUID string of the SequenceExecution record.
        to_email: Recipient email address.
        from_email: Sender email address.
        from_name: Sender display name.
        subject: Email subject line.
        html_body: HTML email body.
        reply_to: Optional reply-to address.
        unsubscribe_url: Optional one-click unsubscribe URL.

    Returns:
        Result dict with status and provider message ID.
    """
    logger.info(f"send_email_task: execution_id={execution_id} to={to_email}")

    # TODO: implement via EmailService
    # 1. Call email_service.send_email(...)
    # 2. Update SequenceExecution.status = "sent" and sent_at = now()
    # 3. Store provider_message_id for webhook tracking

    return {
        "status": "stub",
        "execution_id": execution_id,
        "to_email": to_email,
        "message": "send_email_task not yet implemented",
    }
