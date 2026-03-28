"""
GiLLBoT — AI Service
Generates personalized outreach copy using Groq/LLM.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("gillbot.ai")


class AIService:
    """
    Generates AI-personalized email subjects and bodies for sequence steps.
    Uses Groq (Llama 3.3) for fast inference.
    """

    def __init__(self):
        from server.config import get_settings
        settings = get_settings()
        self.api_key = settings.groq_api_key
        self.model = settings.groq_model
        self.configured = bool(self.api_key)

        if self.configured:
            try:
                from groq import AsyncGroq
                self.client = AsyncGroq(api_key=self.api_key)
                logger.info("AIService initialized (Groq connected)")
            except ImportError:
                logger.warning("groq package not installed — AI personalization disabled")
                self.client = None
                self.configured = False
        else:
            self.client = None
            logger.warning("AIService: GROQ_API_KEY not set — AI personalization disabled")

    async def personalize_message(
        self,
        template: str,
        lead_context: dict,
        campaign_context: str,
        subject_template: Optional[str] = None,
    ) -> dict[str, str]:
        """
        Personalize a message template for a specific lead.

        Args:
            template: The body template with optional {{placeholders}}
            lead_context: Dict of lead fields (first_name, company, title, etc.)
            campaign_context: The user's pitch/context prompt
            subject_template: Optional subject line template

        Returns:
            Dict with "subject" and "body" keys containing personalized content.
        """
        # TODO: implement Groq API call with personalization prompt
        return {
            "subject": subject_template or "",
            "body": template,
        }
