"""
================================================================================
GiLLBoT — Database Models
================================================================================
File:     server/db/models.py

PURPOSE
-------
SQLAlchemy ORM models for GiLLBoT's persistent data layer.
All models use UUID primary keys and PostgreSQL-native types (JSONB, asyncpg).
================================================================================
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as pgUUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Base class for all models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


# ---------------------------------------------------------------------------
# User — one row per registered GiLLBoT user
# ---------------------------------------------------------------------------

class User(Base):
    """Represents a GiLLBoT user account with billing state."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        sa.String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)

    # --- Billing ---
    plan: Mapped[str] = mapped_column(
        sa.String(50), default="free",
        comment="free | starter | pro | business",
    )
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        sa.String(255), nullable=True
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(
        sa.String(255), nullable=True
    )
    billing_status: Mapped[str] = mapped_column(
        sa.String(50), default="none",
        comment="none | active | past_due | cancelled",
    )
    monthly_lead_limit: Mapped[int] = mapped_column(sa.Integer, default=50)
    leads_enrolled_this_month: Mapped[int] = mapped_column(sa.Integer, default=0)
    billing_cycle_reset: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} plan={self.plan}>"


# ---------------------------------------------------------------------------
# Campaign — outbound outreach campaign
# ---------------------------------------------------------------------------

class Campaign(Base):
    """Represents an outbound outreach campaign owned by a user."""

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(50), default="draft",
        comment="draft | active | paused | completed | archived",
    )

    # --- Sender identity ---
    from_name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    from_email: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    reply_to_email: Mapped[Optional[str]] = mapped_column(
        sa.String(255), nullable=True
    )

    # --- AI context ---
    context_prompt: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True,
        comment="User's pitch/context for AI personalization",
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<Campaign id={self.id} name={self.name} status={self.status}>"


# ---------------------------------------------------------------------------
# SequenceStep — individual step in a campaign sequence
# ---------------------------------------------------------------------------

class SequenceStep(Base):
    """A single step within a campaign's outreach sequence."""

    __tablename__ = "sequence_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    step_number: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    channel: Mapped[str] = mapped_column(
        sa.String(50), default="email",
        comment="email | sms | linkedin | slack | discord",
    )
    delay_days: Mapped[int] = mapped_column(sa.Integer, default=0)
    subject_template: Mapped[Optional[str]] = mapped_column(
        sa.String(500), nullable=True
    )
    body_template: Mapped[str] = mapped_column(sa.Text, nullable=False)
    ai_personalize: Mapped[bool] = mapped_column(sa.Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<SequenceStep id={self.id} step={self.step_number} channel={self.channel}>"


# ---------------------------------------------------------------------------
# Lead — a prospect to be contacted
# ---------------------------------------------------------------------------

class Lead(Base):
    """A prospect contact owned by a user."""

    __tablename__ = "leads"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    email: Mapped[Optional[str]] = mapped_column(
        sa.String(255), nullable=True, index=True
    )
    phone: Mapped[Optional[str]] = mapped_column(sa.String(50), nullable=True)
    linkedin_url: Mapped[Optional[str]] = mapped_column(
        sa.String(500), nullable=True
    )
    first_name: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    company: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(sa.String(500), nullable=True)
    custom_fields: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    enriched_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )
    source: Mapped[str] = mapped_column(
        sa.String(50), default="manual",
        comment="csv | hubspot | salesforce | pipedrive | manual",
    )

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<Lead id={self.id} email={self.email} company={self.company}>"


# ---------------------------------------------------------------------------
# LeadList — named collection of leads
# ---------------------------------------------------------------------------

class LeadList(Base):
    """A named list of leads for organizing and targeting campaigns."""

    __tablename__ = "lead_lists"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(sa.String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<LeadList id={self.id} name={self.name}>"


# ---------------------------------------------------------------------------
# LeadListMember — join table between LeadList and Lead
# ---------------------------------------------------------------------------

class LeadListMember(Base):
    """Association between a lead list and individual leads."""

    __tablename__ = "lead_list_members"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    lead_list_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("lead_lists.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    lead_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("leads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        sa.UniqueConstraint("lead_list_id", "lead_id", name="uq_lead_list_member"),
    )

    def __repr__(self) -> str:
        return f"<LeadListMember list={self.lead_list_id} lead={self.lead_id}>"


# ---------------------------------------------------------------------------
# CampaignLead — enrollment of a lead in a campaign
# ---------------------------------------------------------------------------

class CampaignLead(Base):
    """Tracks a lead's enrollment and progress through a campaign sequence."""

    __tablename__ = "campaign_leads"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    lead_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("leads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        sa.String(50), default="pending",
        comment="pending | in_progress | completed | unsubscribed | bounced | replied | opted_out",
    )
    current_step: Mapped[int] = mapped_column(sa.Integer, default=0)
    enrolled_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )
    next_send_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime, nullable=True, index=True,
        comment="THE scheduling field — worker polls this to find pending sends",
    )

    __table_args__ = (
        sa.UniqueConstraint("campaign_id", "lead_id", name="uq_campaign_lead"),
    )

    def __repr__(self) -> str:
        return (
            f"<CampaignLead id={self.id} campaign={self.campaign_id} "
            f"lead={self.lead_id} status={self.status}>"
        )


# ---------------------------------------------------------------------------
# SequenceExecution — individual send record for each step × lead
# ---------------------------------------------------------------------------

class SequenceExecution(Base):
    """Records the execution of a sequence step for a specific lead."""

    __tablename__ = "sequence_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_lead_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("campaign_leads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("sequence_steps.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    channel: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(50), default="pending",
        comment="pending | sent | failed | opened | clicked | replied | bounced",
    )

    # --- Generated content ---
    generated_subject: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    generated_body: Mapped[str] = mapped_column(sa.Text, nullable=False)

    # --- Tracking timestamps ---
    sent_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    opened_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    clicked_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    replied_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)

    # --- Provider ---
    provider_message_id: Mapped[Optional[str]] = mapped_column(
        sa.String(255), nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<SequenceExecution id={self.id} channel={self.channel} status={self.status}>"


# ---------------------------------------------------------------------------
# ChannelCredential — encrypted outreach channel credentials per user
# ---------------------------------------------------------------------------

class ChannelCredential(Base):
    """Stores Fernet-encrypted credentials for outreach channels (email, SMS, etc.)."""

    __tablename__ = "channel_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    channel: Mapped[str] = mapped_column(
        sa.String(50), nullable=False,
        comment="email | sms | linkedin | slack | discord",
    )
    credentials_encrypted: Mapped[str] = mapped_column(
        sa.Text, nullable=False,
        comment="Fernet-encrypted JSON blob containing channel credentials",
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )

    __table_args__ = (
        sa.UniqueConstraint("user_id", "channel", name="uq_user_channel_credential"),
    )

    def __repr__(self) -> str:
        return f"<ChannelCredential id={self.id} user={self.user_id} channel={self.channel}>"


# ---------------------------------------------------------------------------
# Unsubscribe — global and per-user unsubscribe records
# ---------------------------------------------------------------------------

class Unsubscribe(Base):
    """
    Tracks unsubscribed email addresses.
    user_id=None means globally unsubscribed from all Prospect senders.
    """

    __tablename__ = "unsubscribes"

    id: Mapped[uuid.UUID] = mapped_column(
        pgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        sa.String(255), nullable=False, index=True
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        pgUUID(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="NULL = globally unsubscribed from all senders on this platform",
    )

    unsubscribed_at: Mapped[datetime] = mapped_column(
        sa.DateTime, server_default=sa.func.now(), nullable=False
    )
    reason: Mapped[str] = mapped_column(
        sa.String(50), default="user_request",
        comment="user_request | bounced | spam_complaint",
    )

    def __repr__(self) -> str:
        return f"<Unsubscribe email={self.email} user_id={self.user_id} reason={self.reason}>"
