"""
================================================================================
GiLLBoT — JWT Authentication & Password Utilities
================================================================================
File:     server/auth.py

PURPOSE
-------
JWT token creation and validation for GiLLBoT user authentication.
Provides FastAPI dependencies for protecting routes.

USAGE
-----
    from server.auth import get_current_user, create_access_token

    # Create token on login:
    token = create_access_token({"sub": str(user.id)})

    # Protect a route:
    async def my_route(user: User = Depends(get_current_user)):
        ...
================================================================================
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.db.engine import get_db_dependency

logger = logging.getLogger("gillbot.auth")

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return _pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# OAuth2 scheme — token extracted from Authorization: Bearer <token>
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------

def create_access_token(data: dict) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Payload dict. Should include "sub" (user ID as string).

    Returns:
        Encoded JWT string.
    """
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_expire_minutes
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})

    token = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token


def verify_token(token: str) -> dict:
    """
    Verify and decode a JWT access token.

    Args:
        token: Encoded JWT string.

    Returns:
        Decoded payload dict.

    Raises:
        HTTPException 401 if the token is invalid or expired.
    """
    settings = get_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise credentials_exception


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db_dependency),
):
    """
    FastAPI dependency that extracts and validates the current user from a JWT.

    Returns:
        User ORM object for the authenticated user.

    Raises:
        HTTPException 401 if token is invalid or user not found.
    """
    # Import here to avoid circular imports
    from server.db.models import User

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = verify_token(token)
    user_id_str: Optional[str] = payload.get("sub")
    if user_id_str is None:
        logger.warning("JWT payload missing 'sub' claim")
        raise credentials_exception

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        logger.warning(f"Invalid UUID in JWT sub: {user_id_str}")
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        logger.warning(f"User not found for JWT sub: {user_id}")
        raise credentials_exception

    return user
