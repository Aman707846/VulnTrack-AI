from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.role import RoleCode
from backend.app.schemas.organization import OrganizationSummaryResponse
from backend.app.schemas.role import RoleResponse


class RegisterRequest(BaseModel):
    email: str
    password: str
    role_code: RoleCode | None = None
    organization_id: int | None = None
    organization_name: str | None = None
    industry: str | None = Field(default=None, max_length=255)
    company_size: str | None = Field(default=None, max_length=64)
    department: str | None = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    role_id: int
    email: str
    department: str | None = None
    created_at: datetime
    organization: OrganizationSummaryResponse
    role: RoleResponse


class LoginResponse(BaseModel):
    message: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class RefreshResponse(LoginResponse):
    message: str = "Session refreshed."


class LogoutResponse(BaseModel):
    message: str
