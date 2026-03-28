"""
================================================================================
GiLLBoT — Application Settings
================================================================================
File:     server/config.py

PURPOSE
-------
Centralized application settings using Pydantic BaseSettings.
All env vars are validated at startup with sensible defaults for development.
In production, set these via Railway dashboard or .env file.
================================================================================
"""

from functools import lru_cache
from typing import Any
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator


class Settings(BaseSettings):
    """
    Application settings — loaded from environment variables / .env file.
    Use get_settings() to access the singleton instance.
    """

    # --- Environment ---
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://user:password@localhost:5432/gillbot",
        alias="DATABASE_URL",
    )

    # --- Redis ---
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # --- JWT / Auth ---
    jwt_secret_key: str = Field(
        default="local-dev-secret-key-change-in-production-abc123xyz",
        alias="JWT_SECRET_KEY",
    )
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=1440, alias="JWT_EXPIRE_MINUTES")

    # --- Encryption (Fernet key for channel credentials) ---
    encryption_key: str = Field(default="", alias="ENCRYPTION_KEY")

    # --- AI / LLM ---
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")

    # --- Email (SendGrid) ---
    sendgrid_api_key: str = Field(default="", alias="SENDGRID_API_KEY")
    sendgrid_webhook_verify_key: str = Field(default="", alias="SENDGRID_WEBHOOK_VERIFY_KEY")

    # --- Billing (Stripe) ---
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")
    stripe_starter_price_id: str = Field(
        default="price_placeholder_starter", alias="STRIPE_STARTER_PRICE_ID"
    )
    stripe_pro_price_id: str = Field(
        default="price_placeholder_pro", alias="STRIPE_PRO_PRICE_ID"
    )
    stripe_business_price_id: str = Field(
        default="price_placeholder_business", alias="STRIPE_BUSINESS_PRICE_ID"
    )

    # --- App ---
    app_url: str = Field(default="http://localhost:8000", alias="APP_URL")
    unsubscribe_secret: str = Field(
        default="local-dev-unsubscribe-secret-change-me",
        alias="UNSUBSCRIBE_SECRET",
    )

    # --- CORS ---
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
        alias="CORS_ORIGINS",
    )

    # --- Port ---
    port: int = Field(default=8000, alias="PORT")

    # --- Validators ---
    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Fail hard if production is missing real secrets."""
        if self.environment == "production":
            weak_jwt = {"", "local-dev-secret-key-change-in-production-abc123xyz"}
            if self.jwt_secret_key in weak_jwt:
                raise ValueError(
                    "JWT_SECRET_KEY must be set to a strong, unique value in production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            if len(self.jwt_secret_key) < 32:
                raise ValueError("JWT_SECRET_KEY must be at least 32 characters in production.")
        return self

    # --- Computed helpers ---
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def stripe_configured(self) -> bool:
        return bool(self.stripe_secret_key)

    @property
    def sendgrid_configured(self) -> bool:
        return bool(self.sendgrid_api_key)

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key)

    @property
    def redis_configured(self) -> bool:
        return bool(self.redis_url)

    @property
    def plan_configs(self) -> dict[str, dict]:
        """
        Plan configuration for GiLLBoT billing tiers.

        STARTER:  $49/mo  — 500 leads/month,    3 active campaigns
        PRO:      $149/mo — 2000 leads/month,   unlimited campaigns
        BUSINESS: $499/mo — 10000 leads/month,  unlimited campaigns
        """
        return {
            "starter": {
                "price_id": self.stripe_starter_price_id,
                "price_usd": 49,
                "monthly_lead_limit": 500,
                "max_active_campaigns": 3,
                "label": "Starter",
            },
            "pro": {
                "price_id": self.stripe_pro_price_id,
                "price_usd": 149,
                "monthly_lead_limit": 2000,
                "max_active_campaigns": None,  # unlimited
                "label": "Pro",
            },
            "business": {
                "price_id": self.stripe_business_price_id,
                "price_usd": 499,
                "monthly_lead_limit": 10000,
                "max_active_campaigns": None,  # unlimited
                "label": "Business",
            },
        }

    def get_plan_config(self, plan: str) -> dict[str, Any]:
        """Return config for a specific plan, or free-tier defaults."""
        return self.plan_configs.get(plan, {
            "price_id": None,
            "price_usd": 0,
            "monthly_lead_limit": 50,
            "max_active_campaigns": 1,
            "label": "Free",
        })

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings singleton. Call once at startup."""
    return Settings()
