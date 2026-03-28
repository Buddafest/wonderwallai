"""
GiLLBoT — Response Schemas (Pydantic)
Serialized API response shapes for all endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    """Response for POST /v1/auth/login"""
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Serialized user — returned on register and GET /v1/auth/me"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: Optional[str]
    plan: str
    monthly_lead_limit: int
    leads_enrolled_this_month: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

class CampaignResponse(BaseModel):
    """Serialized campaign"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    status: str
    from_name: str
    from_email: str
    reply_to_email: Optional[str]
    context_prompt: Optional[str]
    created_at: datetime
    updated_at: datetime


class SequenceStepResponse(BaseModel):
    """Serialized sequence step"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    campaign_id: uuid.UUID
    step_number: int
    channel: str
    delay_days: int
    subject_template: Optional[str]
    body_template: str
    ai_personalize: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Leads
# ---------------------------------------------------------------------------

class LeadResponse(BaseModel):
    """Serialized lead"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    email: Optional[str]
    phone: Optional[str]
    linkedin_url: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    company: Optional[str]
    title: Optional[str]
    website: Optional[str]
    custom_fields: Optional[dict[str, Any]]
    source: str
    enriched_at: Optional[datetime]
    created_at: datetime


class LeadListResponse(BaseModel):
    """Serialized lead list with member count"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    created_at: datetime
    lead_count: int = 0


# ---------------------------------------------------------------------------
# Campaign Stats
# ---------------------------------------------------------------------------

class CampaignStatsResponse(BaseModel):
    """Aggregate stats for a campaign"""
    campaign_id: uuid.UUID
    total_enrolled: int = 0
    sent: int = 0
    opened: int = 0
    clicked: int = 0
    replied: int = 0
    bounced: int = 0

    @property
    def open_rate(self) -> float:
        return round(self.opened / self.sent, 4) if self.sent > 0 else 0.0

    @property
    def click_rate(self) -> float:
        return round(self.clicked / self.sent, 4) if self.sent > 0 else 0.0

    @property
    def reply_rate(self) -> float:
        return round(self.replied / self.sent, 4) if self.sent > 0 else 0.0
