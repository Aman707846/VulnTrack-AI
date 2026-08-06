from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import JWT_ACCESS_TOKEN_EXPIRES_MINUTES, JWT_REFRESH_TOKEN_EXPIRES_DAYS
from backend.app.core.security import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from backend.app.models.auth_session import RefreshToken
from backend.app.models.role import RoleCode
from backend.app.models.user import User


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _generate_token_id() -> str:
    return secrets.token_hex(16)


@dataclass(slots=True)
class SessionTokenPair:
    access_token: str
    refresh_token: str
    session_id: str
    refresh_token_id: str

    @property
    def access_token_expires_in(self) -> int:
        return JWT_ACCESS_TOKEN_EXPIRES_MINUTES * 60

    @property
    def refresh_token_expires_in(self) -> int:
        return JWT_REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60


def _serialize_user_claims(user: User, *, session_id: str, token_type: str, token_id: str) -> dict[str, object]:
    return {
        "sub": str(user.id),
        "email": user.email,
        "organization_id": user.organization_id,
        "role": user.role.code if user.role else RoleCode.USER.value,
        "sid": session_id,
        "jti": token_id,
        "token_type": token_type,
    }


def _load_user(db: Session, user_id: int) -> User | None:
    return db.scalar(
        select(User)
        .options(selectinload(User.organization), selectinload(User.role))
        .where(User.id == user_id)
    )


def _store_refresh_token(
    db: Session,
    *,
    user_id: int,
    session_id: str,
    token_id: str,
    expires_at: datetime,
    parent_token_id: str | None = None,
) -> RefreshToken:
    refresh_token = RefreshToken(
        user_id=user_id,
        session_id=session_id,
        token_id=token_id,
        parent_token_id=parent_token_id,
        expires_at=expires_at,
    )
    db.add(refresh_token)
    return refresh_token


def _issue_session_tokens(
    db: Session,
    user: User,
    *,
    session_id: str | None = None,
    parent_token_id: str | None = None,
) -> SessionTokenPair:
    normalized_session_id = session_id or _generate_token_id()
    access_token_id = _generate_token_id()
    refresh_token_id = _generate_token_id()

    access_token = create_access_token(
        _serialize_user_claims(
            user,
            session_id=normalized_session_id,
            token_type=ACCESS_TOKEN_TYPE,
            token_id=access_token_id,
        )
    )
    refresh_token = create_refresh_token(
        _serialize_user_claims(
            user,
            session_id=normalized_session_id,
            token_type=REFRESH_TOKEN_TYPE,
            token_id=refresh_token_id,
        )
    )
    refresh_payload = decode_refresh_token(refresh_token)
    refresh_expires_at = datetime.fromtimestamp(int(refresh_payload["exp"]), tz=timezone.utc)
    _store_refresh_token(
        db,
        user_id=user.id,
        session_id=normalized_session_id,
        token_id=refresh_token_id,
        expires_at=refresh_expires_at,
        parent_token_id=parent_token_id,
    )
    db.commit()
    return SessionTokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        session_id=normalized_session_id,
        refresh_token_id=refresh_token_id,
    )


def issue_session_tokens(db: Session, user: User) -> SessionTokenPair:
    return _issue_session_tokens(db, user)


def _find_refresh_token(db: Session, token_id: str) -> RefreshToken | None:
    return db.scalar(select(RefreshToken).where(RefreshToken.token_id == token_id))


def _revoke_session_family(db: Session, session_id: str) -> None:
    active_rows = list(db.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all())
    now = utc_now()
    for row in active_rows:
        if row.revoked_at is None:
            row.revoked_at = now
    db.commit()


def validate_session_is_active(db: Session, session_id: str) -> bool:
    now = utc_now()
    rows = db.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
    for row in rows:
        expires_at = _as_utc(row.expires_at)
        if row.revoked_at is None and expires_at is not None and expires_at > now:
            return True
    return False


def refresh_session(db: Session, refresh_token_value: str) -> tuple[User, SessionTokenPair]:
    payload = decode_refresh_token(refresh_token_value)
    if payload.get("token_type") != REFRESH_TOKEN_TYPE:
        raise ValueError("Invalid refresh token.")

    token_id = str(payload.get("jti") or "")
    session_id = str(payload.get("sid") or "")
    if not token_id or not session_id:
        raise ValueError("Refresh token is missing session metadata.")

    token_row = _find_refresh_token(db, token_id)
    if token_row is None:
        raise ValueError("Refresh token is not recognized.")

    now = utc_now()
    expires_at = _as_utc(token_row.expires_at)
    if expires_at is not None and expires_at <= now:
        _revoke_session_family(db, token_row.session_id)
        raise ValueError("Refresh token has expired.")

    if token_row.revoked_at is not None:
        _revoke_session_family(db, token_row.session_id)
        raise ValueError("Refresh token has already been used.")

    user = _load_user(db, token_row.user_id)
    if user is None or user.role is None or user.organization is None:
        raise ValueError("Session user is unavailable.")

    token_row.revoked_at = now
    next_pair = _issue_session_tokens(db, user, session_id=token_row.session_id, parent_token_id=token_row.token_id)
    token_row.replaced_by_token_id = next_pair.refresh_token_id
    token_row.last_used_at = now
    db.commit()
    refreshed_user = _load_user(db, user.id)
    if refreshed_user is None:
        raise ValueError("Session user is unavailable.")
    return refreshed_user, next_pair


def revoke_session(db: Session, token_value: str) -> None:
    try:
        payload = decode_access_token(token_value)
    except ValueError:
        payload = decode_refresh_token(token_value)

    session_id = str(payload.get("sid") or "")
    if not session_id:
        raise ValueError("Token is missing session metadata.")

    _revoke_session_family(db, session_id)
