from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    industry: str | None = Field(default=None, max_length=255)
    company_size: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=4096)
    slug: str | None = Field(default=None, min_length=2, max_length=255)


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    industry: str | None = Field(default=None, max_length=255)
    company_size: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=4096)
    status: str | None = Field(default=None, min_length=2, max_length=32)


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    industry: str | None = None
    company_size: str | None = None
    description: str | None = None
    status: str
    member_count: int = 0
    created_at: datetime
    updated_at: datetime


class OrganizationSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    industry: str | None = None
    company_size: str | None = None
    description: str | None = None
    status: str
    created_at: datetime
    updated_at: datetime
