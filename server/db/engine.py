"""Async SQLAlchemy engine - SQLite for dev, PostgreSQL for production."""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from server.config import get_settings
from server.db.models import Base

logger = logging.getLogger("wonderwallai.server.db")

_engine = None
_session_factory = None


def _get_database_url() -> str:
    url = get_settings().database_url
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def init_db() -> None:
    global _engine, _session_factory
    url = _get_database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    _engine = create_async_engine(url, connect_args=connect_args, echo=False)
    _session_factory = async_sessionmaker(
        _engine, class_=AsyncSession, expire_on_commit=False
    )
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _migrate_add_missing_columns()
    logger.info(f"Database initialized ({url.split('://')[0]})")


async def _migrate_add_missing_columns() -> None:
    from sqlalchemy import text
    migrations = [
        ("api_keys", "stripe_customer_id", "VARCHAR(255)"),
        ("api_keys", "stripe_subscription_id", "VARCHAR(255)"),
        ("api_keys", "billing_status", "VARCHAR(32) DEFAULT 'none'"),
        ("api_keys", "has_early_bird", "BOOLEAN DEFAULT FALSE"),
    ]
    async with _engine.begin() as conn:
        for table, column, col_type in migrations:
            try:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
                logger.info(f"Migration: added {table}.{column}")
            except Exception as e:
                err = str(e).lower()
                if "duplicate column" in err or "already exists" in err:
                    pass
                else:
                    logger.warning(f"Migration skip {table}.{column}: {e}")


async def close_db() -> None:
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database connection closed")


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if _session_factory is None:
        raise RuntimeError("Database not initialized - call init_db() first")
    session = _session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
