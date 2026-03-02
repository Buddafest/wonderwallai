"""Database models for the WonderwallAi API server."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    """One row per customer API key. Raw key is never stored — only SHA-256 hash."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    rate_limit: Mapped[int] = mapped_column(Integer, default=100)
    plan: Mapped[str] = mapped_column(String(32), default="free")
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    billing_status: Mapped[str] = mapped_column(String(32), default="none")
    has_early_bird: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class FirewallConfig(Base):
    """Per-key firewall configuration. One API key has one active config."""

    __tablename__ = "firewall_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    api_key_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("api_keys.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    topics: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    similarity_threshold: Mapped[float] = mapped_column(Float, default=0.35)
    sentinel_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sentinel_model: Mapped[str] = mapped_column(
        String(64), default="llama-3.1-8b-instant"
    )
    bot_description: Mapped[str] = mapped_column(
        String(512), default="an AI assistant"
    )
    canary_prefix: Mapped[str] = mapped_column(String(32), default="WONDERWALL-")
    fail_open: Mapped[bool] = mapped_column(Boolean, default=True)
    block_message: Mapped[str] = mapped_column(
        Text,
        default="I can only help with topics I'm designed for. Could you rephrase?",
    )
    block_message_injection: Mapped[str] = mapped_column(
        Text, default="Could you rephrase your question?"
    )
    allowed_mime_types: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class UsageRecord(Base):
    """Per-request usage tracking for metered billing."""

    __tablename__ = "usage_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    api_key_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("api_keys.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint: Mapped[str] = mapped_column(String(64), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    was_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True
    )
