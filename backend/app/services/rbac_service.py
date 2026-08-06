from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.organization import Organization
from backend.app.models.role import Role, RoleCode
from backend.app.models.user import User


DEFAULT_ROLE_DEFINITIONS = [
    {
        "code": RoleCode.SUPER_ADMIN.value,
        "name": "Super Admin",
        "description": "Platform-level access across all tenants and role assignments.",
    },
    {
        "code": RoleCode.ORGANIZATION_OWNER.value,
        "name": "Organization Owner",
        "description": "Full administrative control over a single organization.",
    },
    {
        "code": RoleCode.MANAGER.value,
        "name": "Manager",
        "description": "Operational access for coordinating users and reviewing security activity.",
    },
    {
        "code": RoleCode.ANALYST.value,
        "name": "Analyst",
        "description": "Read and investigate telemetry with limited administrative access.",
    },
    {
        "code": RoleCode.USER.value,
        "name": "User",
        "description": "Baseline access for standard members of an organization.",
    },
]


def seed_default_roles(db: Session) -> None:
    existing_codes = {row[0] for row in db.execute(select(Role.code)).all()}
    created = False
    for definition in DEFAULT_ROLE_DEFINITIONS:
        if definition["code"] in existing_codes:
            continue
        db.add(Role(**definition))
        created = True
    if created:
        db.commit()


def list_roles(db: Session) -> list[Role]:
    seed_default_roles(db)
    return list(db.scalars(select(Role).order_by(Role.id.asc())).all())


def get_role(db: Session, role_id: int) -> Role | None:
    return db.get(Role, role_id)


def get_role_by_code(db: Session, code: str | RoleCode) -> Role | None:
    normalized_code = code.value if isinstance(code, RoleCode) else str(code)
    return db.scalar(select(Role).where(Role.code == normalized_code))


def get_default_role_for_registration(db: Session, organization_id: int) -> Role:
    seed_default_roles(db)
    member_count = db.scalar(select(func.count(User.id)).where(User.organization_id == organization_id)) or 0
    preferred_code = RoleCode.ORGANIZATION_OWNER if member_count == 0 else RoleCode.USER
    role = get_role_by_code(db, preferred_code)
    if role is None:
        raise LookupError("Default role is unavailable.")
    return role


def list_users(
    db: Session,
    *,
    organization_id: int | None = None,
) -> list[User]:
    seed_default_roles(db)
    query = (
        select(User)
        .options(selectinload(User.organization), selectinload(User.role))
        .order_by(User.created_at.asc(), User.id.asc())
    )
    if organization_id is not None:
        query = query.where(User.organization_id == organization_id)
    return list(db.scalars(query).all())


def get_user(db: Session, user_id: int) -> User | None:
    return db.scalar(
        select(User)
        .options(selectinload(User.organization), selectinload(User.role))
        .where(User.id == user_id)
    )


def assign_user_role(db: Session, user_id: int, role_id: int) -> User:
    seed_default_roles(db)
    user = get_user(db, user_id)
    if user is None:
        raise LookupError("User not found.")

    role = get_role(db, role_id)
    if role is None:
        raise LookupError("Role not found.")

    current_role_code = user.role.code if user.role else None
    if current_role_code == RoleCode.ORGANIZATION_OWNER.value and role.code != RoleCode.ORGANIZATION_OWNER.value:
        owner_count = db.scalar(
            select(func.count(User.id)).join(Role).where(
                User.organization_id == user.organization_id,
                Role.code == RoleCode.ORGANIZATION_OWNER.value,
            )
        ) or 0
        if owner_count <= 1:
            raise ValueError("Organization must retain at least one owner.")

    user.role_id = role.id
    db.commit()
    db.refresh(user)
    return get_user(db, user.id) or user


def backfill_users_with_roles(db: Session) -> None:
    seed_default_roles(db)
    owner_role = get_role_by_code(db, RoleCode.ORGANIZATION_OWNER)
    user_role = get_role_by_code(db, RoleCode.USER)
    if owner_role is None or user_role is None:
        raise LookupError("Default roles are unavailable.")

    organizations = list(db.scalars(select(Organization).order_by(Organization.created_at.asc(), Organization.id.asc())).all())
    for organization in organizations:
        ordered_users = list(
            db.scalars(
                select(User)
                .where(User.organization_id == organization.id)
                .order_by(User.created_at.asc(), User.id.asc())
            ).all()
        )
        if not ordered_users:
            continue

        for index, user in enumerate(ordered_users):
            if user.role_id:
                continue
            user.role_id = owner_role.id if index == 0 else user_role.id

    remaining_users = list(
        db.scalars(select(User).where(User.role_id.is_(None)).order_by(User.created_at.asc(), User.id.asc())).all()
    )
    for user in remaining_users:
        user.role_id = user_role.id

    db.commit()
