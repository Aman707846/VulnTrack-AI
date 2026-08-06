from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.authorization import get_current_user
from backend.app.core.security import hash_password, verify_password
from backend.app.db.session import get_db
from backend.app.models.role import Role, RoleCode
from backend.app.models.user import User
from backend.app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RefreshResponse,
    RegisterRequest,
    UserResponse,
)
from backend.app.services.organization_service import resolve_user_organization
from backend.app.services.rbac_service import get_default_role_for_registration, get_user, seed_default_roles
from backend.app.services.auth_session_service import issue_session_tokens, refresh_session, revoke_session


refresh_bearer_scheme = HTTPBearer(auto_error=False)


router = APIRouter(prefix="/auth", tags=["auth"])


def normalize_email(email: str) -> str:
    return email.strip().lower()


def has_super_admin_account(db: Session) -> bool:
    return (
        db.scalar(
            select(User.id)
            .join(Role, Role.id == User.role_id)
            .where(Role.code == RoleCode.SUPER_ADMIN.value)
            .limit(1)
        )
        is not None
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> User:
    email = normalize_email(payload.email)
    existing_user = db.scalar(select(User).where(User.email == email))
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists.",
        )

    seed_default_roles(db)
    requested_role_code = payload.role_code.value if payload.role_code else None
    if requested_role_code == RoleCode.SUPER_ADMIN.value and has_super_admin_account(db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A super admin account already exists.",
        )

    role = None
    if requested_role_code:
        role = db.scalar(select(Role).where(Role.code == requested_role_code))
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Selected role is unavailable.",
            )

    organization_name = payload.organization_name.strip() if payload.organization_name else None
    is_super_admin_registration = requested_role_code == RoleCode.SUPER_ADMIN.value
    if is_super_admin_registration and not organization_name:
        organization_name = "Platform Administration"

    organization_description = payload.organization_name.strip() if payload.organization_name else None
    if payload.industry or payload.company_size:
        details: list[str] = []
        if payload.industry:
            details.append(f"Industry: {payload.industry.strip()}")
        if payload.company_size:
            details.append(f"Company size: {payload.company_size.strip()}")
        organization_description = " | ".join(details) if details else organization_description
    elif is_super_admin_registration:
        organization_description = "Platform-wide governance workspace for system operators."

    is_owner_registration = requested_role_code == RoleCode.ORGANIZATION_OWNER.value
    try:
        organization = resolve_user_organization(
            db,
            organization_id=payload.organization_id,
            organization_name=organization_name,
            user_email=email,
            description=organization_description if (is_owner_registration or is_super_admin_registration) else None,
            industry=payload.industry if is_owner_registration else None,
            company_size=payload.company_size if is_owner_registration else None,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if role is None:
        role = get_default_role_for_registration(db, organization.id)

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        organization_id=organization.id,
        role_id=role.id,
        department=payload.department.strip() if payload.department else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    fresh_user = get_user(db, user.id)
    return fresh_user or user


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    email = normalize_email(payload.email)
    user = db.scalar(
        select(User)
        .options(selectinload(User.organization), selectinload(User.role))
        .where(User.email == email)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found. Create an account first.",
        )

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password.",
        )

    tokens = issue_session_tokens(db, user)

    return LoginResponse(
        message="Login successful.",
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=RefreshResponse)
def rotate_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(refresh_bearer_scheme),
    db: Session = Depends(get_db),
) -> RefreshResponse:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh credentials were not provided.",
        )

    try:
        user, tokens = refresh_session(db, credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return RefreshResponse(
        message="Session refreshed.",
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(refresh_bearer_scheme),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    if credentials is not None and credentials.credentials:
        try:
            revoke_session(db, credentials.credentials)
        except ValueError:
            pass

    return LogoutResponse(message="Logout successful.")


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
