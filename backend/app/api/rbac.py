from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.authorization import can_manage_roles, get_current_user, require_roles, require_same_organization
from backend.app.db.session import get_db
from backend.app.models.role import RoleCode
from backend.app.models.user import User
from backend.app.schemas.role import RoleAssignmentRequest, RoleResponse, UserManagementResponse
from backend.app.services.rbac_service import assign_user_role, get_role, get_user, list_roles, list_users


router = APIRouter(prefix="/rbac", tags=["rbac"])


@router.get("/roles", response_model=list[RoleResponse])
def read_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RoleResponse]:
    _ = current_user
    return [RoleResponse.model_validate(role) for role in list_roles(db)]


@router.get("/users", response_model=list[UserManagementResponse])
def read_users(
    organization_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(RoleCode.SUPER_ADMIN, RoleCode.ORGANIZATION_OWNER, RoleCode.MANAGER)),
) -> list[UserManagementResponse]:
    target_organization_id = organization_id

    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        if target_organization_id is not None and target_organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view users in this organization.",
            )
        target_organization_id = current_user.organization_id

    users = list_users(db, organization_id=target_organization_id)
    return [UserManagementResponse.model_validate(user) for user in users]


@router.patch("/users/{user_id}/role", response_model=UserManagementResponse)
def update_user_role(
    user_id: int,
    payload: RoleAssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserManagementResponse:
    if not can_manage_roles(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to assign roles.",
        )

    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role from this screen.",
        )

    target_user = get_user(db, user_id)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if current_user.role.code != RoleCode.SUPER_ADMIN.value:
        require_same_organization(current_user, target_user.organization_id)

    role = get_role(db, payload.role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    if current_user.role.code != RoleCode.SUPER_ADMIN.value and role.code == RoleCode.SUPER_ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can assign the super admin role.",
        )

    try:
        updated_user = assign_user_role(db, user_id, payload.role_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return UserManagementResponse.model_validate(updated_user)
