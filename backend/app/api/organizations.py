from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.authorization import get_current_user, require_same_organization
from backend.app.db.session import get_db
from backend.app.models.role import RoleCode
from backend.app.models.user import User
from backend.app.schemas.organization import OrganizationCreate, OrganizationResponse, OrganizationUpdate
from backend.app.services.organization_service import (
    _build_organization_payload,
    create_organization,
    delete_organization,
    get_organization,
    list_organizations,
    update_organization,
)


router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationResponse])
def read_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, object]]:
    organizations = list_organizations(db)
    if current_user.role.code == RoleCode.SUPER_ADMIN.value:
        return organizations

    return [organization for organization in organizations if organization["id"] == current_user.organization_id]


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization_endpoint(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only super admins can create organizations.")

    try:
        organization = create_organization(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "industry": organization.industry,
        "company_size": organization.company_size,
        "description": organization.description,
        "status": organization.status,
        "member_count": 0,
        "created_at": organization.created_at,
        "updated_at": organization.updated_at,
    }


@router.get("/{organization_id}", response_model=OrganizationResponse)
def read_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    organization = get_organization(db, organization_id)
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        require_same_organization(current_user, organization_id)

    return _build_organization_payload(db, organization)


@router.patch("/{organization_id}", response_model=OrganizationResponse)
def update_organization_endpoint(
    organization_id: int,
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    if current_user.role.code not in {RoleCode.SUPER_ADMIN.value, RoleCode.ORGANIZATION_OWNER.value}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to update organizations.",
        )

    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        require_same_organization(current_user, organization_id)

    try:
        organization = update_organization(db, organization_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return _build_organization_payload(db, organization)


@router.delete("/{organization_id}", response_model=OrganizationResponse)
def delete_organization_endpoint(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    if current_user.role.code not in {RoleCode.SUPER_ADMIN.value, RoleCode.ORGANIZATION_OWNER.value}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete organizations.",
        )

    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        require_same_organization(current_user, organization_id)

    try:
        return delete_organization(db, organization_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
