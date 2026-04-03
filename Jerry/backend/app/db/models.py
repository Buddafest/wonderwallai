"""
================================================================================
Jerry The Customer Service Bot — Database Models
================================================================================
File:     app/db/models.py
Version:  1.0.0
Session:  5 (February 2026)

PURPOSE
-------
SQLAlchemy ORM models for Jerry The Customer Service Bot's persistent data layer.
Currently stores Shopify store info and OAuth tokens.
Uses async SQLAlchemy with SQLite (dev) or PostgreSQL (production).
================================================================================
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Float,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# ---------------------------------------------------------------------------
# Base class for all models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


# ---------------------------------------------------------------------------
# Store model — one row per installed Shopify store
# ---------------------------------------------------------------------------

class Store(Base):
    """
    Represents a Shopify store that has installed Jerry The Customer Service Bot.

    Created during OAuth callback, updated on product sync and billing events.
    The access_token is the Shopify Admin API token — treat it like a password.
    """

    __tablename__ = "stores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # --- Shopify identity ---
    shopify_domain: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True,
        comment="e.g. my-cool-store.myshopify.com",
    )
    shopify_store_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
        comment="Shopify's numeric store ID (from Shop API response)",
    )
    access_token: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Shopify Admin API access token — NEVER expose in logs or API responses",
    )
    scopes: Mapped[str] = mapped_column(
        Text, nullable=False, default="read_products,read_orders",
        comment="Comma-separated OAuth scopes granted by the store owner",
    )

    # --- Store info (fetched from Shopify Shop API after install) ---
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    shop_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    currency: Mapped[str] = mapped_column(String(10), default="USD")
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    plan_name: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
        comment="Shopify plan (basic, shopify, advanced, plus)",
    )

    # --- Jerry The Customer Service Bot config ---
    sunsetbot_plan: Mapped[str] = mapped_column(
        String(32), default="trial",
        comment="Jerry The Customer Service Bot billing plan: trial | starter | pro",
    )
    widget_color: Mapped[str] = mapped_column(
        String(7), default="#FF6B35",
        comment="Primary widget color hex code",
    )
    welcome_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
        comment="Custom welcome message (overrides default)",
    )
    chat_language: Mapped[str] = mapped_column(
        String(10), default="en-US",
        comment="Language for voice input/output (e.g. en-US, es-ES)",
    )

    # --- Billing ---
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Stripe Customer ID (cus_xxx) — legacy, kept for migration",
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Stripe Subscription ID (sub_xxx) — legacy, kept for migration",
    )
    shopify_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Shopify AppSubscription GID (gid://shopify/AppSubscription/xxx)",
    )
    shopify_plan: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True,
        comment="Shopify billing plan: base | growth | elite",
    )
    jerry_plan: Mapped[str] = mapped_column(
        String(32), default="base",
        comment="Billing plan: base | growth | elite",
    )
    monthly_interaction_limit: Mapped[int] = mapped_column(
        Integer, default=500,
        comment="Max chat sessions per billing cycle (0 = unlimited)",
    )
    current_month_usage: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Sessions used this billing cycle",
    )
    billing_cycle_reset: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True,
        comment="When current_month_usage resets",
    )
    subscription_status: Mapped[str] = mapped_column(
        String(32), default="none",
        comment="Status: none | trialing | active | past_due | canceled | incomplete",
    )

    # --- Sync state ---
    products_count: Mapped[int] = mapped_column(Integer, default=0)
    products_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True,
        comment="Last successful full product sync timestamp",
    )
    webhook_registered: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Status ---
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, index=True,
        comment="False = uninstalled or suspended",
    )
    installed_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False,
    )
    uninstalled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True,
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Store id={self.id} domain={self.shopify_domain} active={self.is_active}>"

    @property
    def store_id_for_pinecone(self) -> str:
        """Namespace used in Pinecone for this store's products."""
        return self.shopify_domain.replace(".myshopify.com", "")


# ---------------------------------------------------------------------------
# ChatSession — tracks each chat session for usage billing
# ---------------------------------------------------------------------------

class ChatSession(Base):
    """Tracks each chat session for usage billing."""
    __tablename__ = "chat_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    merchant_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("stores.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    human_intervention: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# SupportResolution — tracks resolved support interactions for metered billing
# ---------------------------------------------------------------------------

class SupportResolution(Base):
    """Tracks resolved support interactions for metered billing."""
    __tablename__ = "support_resolutions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    merchant_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("stores.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    session_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("chat_sessions.id"), nullable=True,
    )
    resolution_type: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="product_recommendation | order_tracked | return_initiated | refund_processed | general_support",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# AttributedSale — tracks orders attributed to Jerry for revenue share billing
# ---------------------------------------------------------------------------

class AttributedSale(Base):
    """Tracks orders attributed to Jerry for revenue share billing."""
    __tablename__ = "attributed_sales"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    merchant_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("stores.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    shopify_order_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    order_value: Mapped[float] = mapped_column(
        Float, nullable=False,
        comment="Order total in store currency",
    )
    commission_cents: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Pre-calculated commission in USD cents for Stripe metered billing",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

# ---------------------------------------------------------------------------
# ChatInteraction — Stores every individual message for full analytics and debugging
# ---------------------------------------------------------------------------

class ChatInteraction(Base):
    """Stores every individual message for full analytics and debugging."""
    __tablename__ = "chat_interactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    response_text: Mapped[str] = mapped_column(Text, nullable=True)
    intent: Mapped[str] = mapped_column(String(50), nullable=True)
    entities: Mapped[dict] = mapped_column(JSON, nullable=True)
    products_shown: Mapped[int] = mapped_column(Integer, default=0)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # --- Observability fields (added for intent logging) ---
    turn_number: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Turn number within the conversation session",
    )
    latency_ms: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True,
        comment="End-to-end pipeline latency for this message in milliseconds",
    )
    firewall_verdict: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True,
        comment="Firewall outcome: allowed | blocked_inbound | blocked_outbound | redacted",
    )


