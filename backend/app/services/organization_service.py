from __future__ import annotations

import re
import unicodedata

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.schemas.organization import OrganizationCreate, OrganizationUpdate


DEFAULT_ORGANIZATION_NAME = "Default Organization"


def normalize_organization_name(value: str) -> str:
    return " ".join(value.split()).strip()


def slugify_organization_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value).strip("-")
    return slug or "organization"


def get_organization(db: Session, organization_id: int) -> Organization | None:
    return db.get(Organization, organization_id)


def get_organization_by_slug(db: Session, slug: str) -> Organization | None:
    normalized_slug = slugify_organization_name(slug)
    return db.scalar(select(Organization).where(Organization.slug == normalized_slug))


def _ensure_unique_slug(db: Session, base_slug: str, *, exclude_id: int | None = None) -> str:
    candidate = base_slug
    suffix = 2
    query = select(Organization.id).where(Organization.slug == candidate)
    if exclude_id is not None:
        query = query.where(Organization.id != exclude_id)
    while db.scalar(query) is not None:
        candidate = f"{base_slug}-{suffix}"
        suffix += 1
        query = select(Organization.id).where(Organization.slug == candidate)
        if exclude_id is not None:
            query = query.where(Organization.id != exclude_id)
    return candidate


def _build_organization_payload(db: Session, organization: Organization) -> dict[str, object]:
    member_count = db.scalar(
        select(func.count(User.id)).where(User.organization_id == organization.id)
    ) or 0
    return {
        "id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "industry": organization.industry,
        "company_size": organization.company_size,
        "description": organization.description,
        "status": organization.status,
        "member_count": int(member_count),
        "created_at": organization.created_at,
        "updated_at": organization.updated_at,
    }


def list_organizations(db: Session) -> list[dict[str, object]]:
    rows = db.execute(
        select(Organization, func.count(User.id).label("member_count"))
        .outerjoin(User, User.organization_id == Organization.id)
        .group_by(Organization.id)
        .order_by(Organization.created_at.asc(), Organization.id.asc())
    ).all()

    organizations: list[dict[str, object]] = []
    for organization, member_count in rows:
        organizations.append(
            {
                "id": organization.id,
                "name": organization.name,
                "slug": organization.slug,
                "industry": organization.industry,
                "company_size": organization.company_size,
                "description": organization.description,
                "status": organization.status,
                "member_count": int(member_count or 0),
                "created_at": organization.created_at,
                "updated_at": organization.updated_at,
            }
        )
    return organizations


def create_organization(db: Session, payload: OrganizationCreate) -> Organization:
    name = normalize_organization_name(payload.name)
    if not name:
        raise ValueError("Organization name is required.")

    base_slug = slugify_organization_name(payload.slug or name)
    organization = Organization(
        name=name,
        slug=_ensure_unique_slug(db, base_slug),
        industry=payload.industry.strip() if payload.industry else None,
        company_size=payload.company_size.strip() if payload.company_size else None,
        description=payload.description.strip() if payload.description else None,
        status="active",
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    return organization


def get_or_create_organization_by_name(
    db: Session,
    name: str,
    description: str | None = None,
    industry: str | None = None,
    company_size: str | None = None,
) -> Organization:
    normalized_name = normalize_organization_name(name)
    if not normalized_name:
        raise ValueError("Organization name is required.")

    normalized_slug = slugify_organization_name(normalized_name)
    organization = db.scalar(select(Organization).where(Organization.slug == normalized_slug))
    if organization is not None:
        return organization

    organization = Organization(
        name=normalized_name,
        slug=_ensure_unique_slug(db, normalized_slug),
        industry=industry.strip() if industry else None,
        company_size=company_size.strip() if company_size else None,
        description=description.strip() if description else None,
        status="active",
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    return organization


def resolve_user_organization(
    db: Session,
    *,
    organization_id: int | None = None,
    organization_name: str | None = None,
    user_email: str | None = None,
    description: str | None = None,
    industry: str | None = None,
    company_size: str | None = None,
) -> Organization:
    if organization_id is not None:
        organization = get_organization(db, organization_id)
        if organization is None:
            raise LookupError("Organization not found.")
        return organization

    if organization_name and organization_name.strip():
        return get_or_create_organization_by_name(
            db,
            organization_name,
            description=description,
            industry=industry,
            company_size=company_size,
        )

    fallback_name = DEFAULT_ORGANIZATION_NAME
    if user_email:
        local_part = user_email.split("@", maxsplit=1)[0].strip()
        if local_part:
            fallback_name = f"{local_part.title()} Workspace"

    return get_or_create_organization_by_name(
        db,
        fallback_name,
        description=description,
        industry=industry,
        company_size=company_size,
    )


def update_organization(db: Session, organization_id: int, payload: OrganizationUpdate) -> Organization:
    organization = get_organization(db, organization_id)
    if organization is None:
        raise LookupError("Organization not found.")

    if payload.name is not None:
        name = normalize_organization_name(payload.name)
        if not name:
            raise ValueError("Organization name is required.")
        organization.name = name
        organization.slug = _ensure_unique_slug(db, slugify_organization_name(name), exclude_id=organization.id)

    if payload.industry is not None:
        organization.industry = payload.industry.strip() or None

    if payload.company_size is not None:
        organization.company_size = payload.company_size.strip() or None

    if payload.description is not None:
        organization.description = payload.description.strip() or None

    if payload.status is not None:
        organization.status = payload.status.strip().lower()

    db.commit()
    db.refresh(organization)
    return organization


def delete_organization(db: Session, organization_id: int) -> dict[str, object]:
    organization = get_organization(db, organization_id)
    if organization is None:
        raise LookupError("Organization not found.")

    member_count = db.scalar(select(func.count(User.id)).where(User.organization_id == organization.id)) or 0
    if member_count:
        raise ValueError("Organization still has members.")

    payload = _build_organization_payload(db, organization)
    db.delete(organization)
    db.commit()
    return payload
