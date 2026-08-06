from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.security import decode_access_token
from backend.app.db.session import get_db
from backend.app.models.role import RoleCode
from backend.app.models.user import User
from backend.app.services.auth_session_service import validate_session_is_active


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is missing subject.")

    try:
        normalized_user_id = int(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject.") from exc

    user = db.scalar(
        select(User)
        .options(selectinload(User.organization), selectinload(User.role))
        .where(User.id == normalized_user_id)
    )
    if user is None or user.role is None or user.organization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User session is invalid.")

    token_role = str(payload.get("role") or "")
    token_organization_id = payload.get("organization_id")
    if token_role and token_role != user.role.code:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token role no longer matches.")

    if token_organization_id is not None:
        try:
            normalized_organization_id = int(token_organization_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token organization.") from exc
        if normalized_organization_id != user.organization_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token organization no longer matches.")

    session_id = str(payload.get("sid") or "")
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is missing session metadata.")

    if not validate_session_is_active(db, session_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has expired or been revoked.")

    return user


def require_roles(*allowed_roles: str | RoleCode) -> Callable[[User], User]:
    normalized_allowed_roles = {
        role.value if isinstance(role, RoleCode) else str(role)
        for role in allowed_roles
    }

    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role.code == RoleCode.SUPER_ADMIN.value:
            return current_user

        if current_user.role.code not in normalized_allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return current_user

    return dependency


def require_same_organization(current_user: User, organization_id: int) -> None:
    if current_user.role.code == RoleCode.SUPER_ADMIN.value:
        return

    if current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this organization.",
        )


def can_manage_roles(current_user: User) -> bool:
    return current_user.role.code in {
        RoleCode.SUPER_ADMIN.value,
        RoleCode.ORGANIZATION_OWNER.value,
    }
