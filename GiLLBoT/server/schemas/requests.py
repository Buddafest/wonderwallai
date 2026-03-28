"""
GiLLBoT — Request Schemas (Pydantic)
Validated request bodies for all API endpoints.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    """Request body for POST /v1/auth/register"""
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: Optional[str] = Field(default=None, max_length=255)


class UserLogin(BaseModel):
    """Request body for POST /v1/auth/login (JSON variant — form handled by OAuth2)"""
    email: EmailStr
    password: str


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

class CampaignCreate(BaseModel):
    """Request body for POST /v1/campaigns"""
    name: str = Field(min_length=1, max_length=255)
    from_name: str = Field(min_length=1, max_length=255)
    from_email: EmailStr
    reply_to_email: Optional[EmailStr] = None
    context_prompt: Optional[str] = Field(
        default=None,
        description="User's pitch/context for AI personalization",
    )


class CampaignUpdate(BaseModel):
    """Request body for PATCH /v1/campaigns/{id} — all fields optional"""
    name: Optional[str] = Field(default=None, max_length=255)
    status: Optional[str] = Field(
        default=None,
        pattern="^(draft|active|paused|completed|archived)$",
    )
    from_name: Optional[str] = Field(default=None, max_length=255)
    from_email: Optional[EmailStr] = None
    reply_to_email: Optional[EmailStr] = None
    context_prompt: Optional[str] = None


# ---------------------------------------------------------------------------
# Sequence Steps
# ---------------------------------------------------------------------------

class SequenceStepCreate(BaseModel):
    """Request body for POST /v1/campaigns/{id}/steps"""
    step_number: int = Field(ge=1)
    channel: str = Field(
        default="email",
        pattern="^(email|sms|linkedin|slack|discord)$",
    )
    delay_days: int = Field(default=0, ge=0)
    subject_template: Optional[str] = Field(default=None, max_length=500)
    body_template: str = Field(min_length=1)
    ai_personalize: bool = True


# ---------------------------------------------------------------------------
# Leads
# ---------------------------------------------------------------------------

class LeadCreate(BaseModel):
    """Request body for POST /v1/leads"""
    email: Optional[str] = None
    phone: Optional[str] = Field(default=None, max_length=50)
    linkedin_url: Optional[str] = Field(default=None, max_length=500)
    first_name: Optional[str] = Field(default=None, max_length=255)
    last_name: Optional[str] = Field(default=None, max_length=255)
    company: Optional[str] = Field(default=None, max_length=255)
    title: Optional[str] = Field(default=None, max_length=255)
    website: Optional[str] = Field(default=None, max_length=500)
    custom_fields: Optional[dict[str, Any]] = None


class LeadListCreate(BaseModel):
    """Request body for POST /v1/leads/lists"""
    name: str = Field(min_length=1, max_length=255)
