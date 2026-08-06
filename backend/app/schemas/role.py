from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.organization import OrganizationSummaryResponse


class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class RoleAssignmentRequest(BaseModel):
    role_id: int = Field(gt=0)


class UserManagementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    organization_id: int
    organization: OrganizationSummaryResponse
    role_id: int
    role: RoleResponse
    department: str | None = None
    created_at: datetime
