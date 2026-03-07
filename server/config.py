"""Server configuration — Pydantic BaseSettings with env var loading."""

from functools import lru_cache
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class ServerSettings(BaseSettings):
    """All server settings loaded from environment variables with sensible defaults."""

    # --- Server ---
    environment: str = Field(default="development", alias="ENVIRONMENT")
    port: int = Field(default=8080, alias="PORT")
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")

    # --- Database ---
    database_url: str = Field(
        default="sqlite+aiosqlite:///./wonderwall_server.db",
        alias="DATABASE_URL",
    )

    # --- Groq (shared sentinel key for hosted scans) ---
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")

    # --- Rate Limiting ---
    default_rate_limit: int = Field(default=100, alias="DEFAULT_RATE_LIMIT")

    # --- Admin ---
    admin_api_key: str = Field(default="dev-admin-key", alias="ADMIN_API_KEY")

    # --- Stripe Billing ---
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")

    # --- Stripe Price IDs (set in Stripe Dashboard, load from env) ---
    stripe_starter_flat_price_id: str = Field(default="", alias="STRIPE_STARTER_FLAT_PRICE_ID")
    stripe_starter_overage_price_id: str = Field(default="", alias="STRIPE_STARTER_OVERAGE_PRICE_ID")
    stripe_pro_flat_price_id: str = Field(default="", alias="STRIPE_PRO_FLAT_PRICE_ID")
    stripe_pro_overage_price_id: str = Field(default="", alias="STRIPE_PRO_OVERAGE_PRICE_ID")
    stripe_business_flat_price_id: str = Field(default="", alias="STRIPE_BUSINESS_FLAT_PRICE_ID")
    stripe_business_overage_price_id: str = Field(default="", alias="STRIPE_BUSINESS_OVERAGE_PRICE_ID")

    # --- Early Bird Promotion ---
    early_bird_coupon_id: str = Field(default="", alias="EARLY_BIRD_COUPON_ID")
    early_bird_max_redemptions: int = Field(default=300, alias="EARLY_BIRD_MAX_REDEMPTIONS")

    # --- Production validation ---
    @model_validator(mode="after")
    def validate_production(self) -> "ServerSettings":
        if self.environment == "production":
            if self.admin_api_key in ("", "dev-admin-key"):
                raise ValueError("ADMIN_API_KEY must be set in production")
            if not self.stripe_secret_key:
                import logging
                logging.getLogger("wonderwallai.server").warning(
                    "STRIPE_SECRET_KEY not set in production — billing will be disabled"
                )
        return self

    @property
    def is_development(self) -> bool:
        return self.environment != "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> ServerSettings:
    return ServerSettings()
