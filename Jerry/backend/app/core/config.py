"""
================================================================================
Jerry The Customer Service Bot — Application Settings
================================================================================
File:     app/core/config.py
Version:  1.0.0
Session:  5 (February 2026)

PURPOSE
-------
Centralized application settings using Pydantic BaseSettings.
All env vars are validated at startup with sensible defaults for development.
In production, set these via Railway dashboard or .env file.
================================================================================
"""

from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator


class Settings(BaseSettings):
    """
    Application settings — loaded from environment variables / .env file.
    Use get_settings() to access the singleton instance.
    """

    # --- Environment ---
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=False)

    # --- Server ---
    port: int = Field(default=8000, alias="PORT")
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
        alias="CORS_ORIGINS",
    )

    # --- Security ---
    secret_key: str = Field(
        default="local-dev-secret-key-change-in-production-abc123",
        alias="SECRET_KEY",
    )
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24  # Widget tokens expire after 24h

    # --- AI / LLM ---
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")

    # --- Pinecone ---
    pinecone_api_key: str = Field(default="", alias="PINECONE_API_KEY")
    pinecone_index_name: str = Field(default="sunsetbot-products", alias="PINECONE_INDEX_NAME")

    # --- Shopify ---
    shopify_api_key: str = Field(default="", alias="SHOPIFY_API_KEY")
    shopify_api_secret: str = Field(default="", alias="SHOPIFY_API_SECRET")
    shopify_scopes: str = Field(
        default="read_products,write_products,read_orders,write_orders,read_customers,write_customers",
        alias="SHOPIFY_SCOPES",
    )
    shopify_api_version: str = Field(default="2024-10", alias="SHOPIFY_API_VERSION")

    # --- Database ---
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sunsetbot.db",
        alias="DATABASE_URL",
    )

    # --- Redis ---
    redis_url: str = Field(default="", alias="REDIS_URL")

    # --- Stripe ---
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")

    # --- OpenAI (TTS) ---
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_tts_model: str = Field(default="tts-1", alias="OPENAI_TTS_MODEL")
    openai_tts_voice: str = Field(default="onyx", alias="OPENAI_TTS_VOICE")

    # --- Admin ---
    admin_api_key: str = Field(default="dev-admin-key-change-me", alias="ADMIN_API_KEY")

    # --- Rate Limits ---
    rate_limit_messages_per_min: int = 30
    max_connections_per_ip: int = 10
    max_ws_message_bytes: int = 8192  # 8 KB

    # --- App URL (for OAuth callbacks — set to ngrok URL in dev) ---
    app_url_override: str = Field(default="", alias="APP_URL")

    # --- Sentry ---
    sentry_dsn: str = Field(default="", alias="SENTRY_DSN")

    # --- Observability ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="auto", alias="LOG_FORMAT")  # "json", "console", or "auto" (json in prod)

    # --- Validators ---
    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Fail hard if production is missing a real SECRET_KEY."""
        if self.environment == "production":
            weak_defaults = {"", "local-dev-secret-key-change-in-production-abc123"}
            if self.secret_key in weak_defaults:
                raise ValueError(
                    "SECRET_KEY must be set to a strong, unique value in production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            if len(self.secret_key) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters in production.")
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
    def shopify_configured(self) -> bool:
        return bool(self.shopify_api_key and self.shopify_api_secret)

    @property
    def redis_configured(self) -> bool:
        return bool(self.redis_url)

    @property
    def stripe_configured(self) -> bool:
        return bool(self.stripe_secret_key)

    @property
    def openai_configured(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def app_url(self) -> str:
        """Base URL for OAuth callbacks. In dev, use ngrok or localhost."""
        # APP_URL override takes priority (set this to your ngrok URL in dev)
        if self.app_url_override:
            return self.app_url_override.rstrip("/")
        if self.is_production:
            # Railway sets RAILWAY_PUBLIC_DOMAIN automatically
            import os
            domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
            return f"https://{domain}"
        return f"http://localhost:{self.port}"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings singleton. Call once at startup."""
    return Settings()
