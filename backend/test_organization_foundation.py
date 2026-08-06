import os
import sys
import unittest
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.api.auth import register  # noqa: E402
from backend.app.api.organizations import (  # noqa: E402
    create_organization_endpoint,
    delete_organization_endpoint,
    read_organizations,
    update_organization_endpoint,
)
from backend.app.core.security import hash_password  # noqa: E402
from backend.app.db.base import Base  # noqa: E402
from backend.app.db.schema import ensure_schema  # noqa: E402
from backend.app.models.role import RoleCode  # noqa: E402
from backend.app.models.user import User  # noqa: E402
from backend.app.schemas.auth import RegisterRequest  # noqa: E402
from backend.app.schemas.organization import OrganizationCreate, OrganizationUpdate  # noqa: E402
from backend.app.services.rbac_service import get_role_by_code, get_user, seed_default_roles  # noqa: E402


class OrganizationFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.SessionLocal()
        seed_default_roles(self.db)

        self.owner = register(
            RegisterRequest(
                email="owner@example.com",
                password="StrongPass123!",
                organization_name="Northwind Security",
                role_code=RoleCode.ORGANIZATION_OWNER,
                industry="Cybersecurity",
                company_size="51-200 employees",
            ),
            self.db,
        )
        self.member = register(
            RegisterRequest(
                email="member@example.com",
                password="StrongPass123!",
                organization_name="Northwind Security",
                role_code=RoleCode.USER,
            ),
            self.db,
        )
        self.super_admin = self._make_user("admin@example.com", RoleCode.SUPER_ADMIN.value)
        self.manager = self._make_user("manager@example.com", RoleCode.MANAGER.value)

    def tearDown(self) -> None:
        self.db.close()

    def _make_user(self, email: str, role_code: str) -> User:
        role = get_role_by_code(self.db, role_code)
        assert role is not None

        user = User(
            email=email,
            password_hash=hash_password("StrongPass123!"),
            organization_id=self.owner.organization_id,
            role_id=role.id,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return get_user(self.db, user.id) or user

    def test_register_links_user_to_organization_and_role(self) -> None:
        self.assertEqual(self.owner.email, "owner@example.com")
        self.assertEqual(self.owner.organization.name, "Northwind Security")
        self.assertEqual(self.owner.organization.slug, "northwind-security")
        self.assertEqual(self.owner.organization.industry, "Cybersecurity")
        self.assertEqual(self.owner.organization.company_size, "51-200 employees")
        self.assertEqual(self.owner.organization_id, self.owner.organization.id)
        self.assertEqual(self.owner.role.code, RoleCode.ORGANIZATION_OWNER.value)

        self.assertEqual(self.member.role.code, RoleCode.USER.value)
        self.assertEqual(self.member.organization_id, self.owner.organization_id)

    def test_ensure_schema_keeps_fresh_database_clean(self) -> None:
        ensure_schema(self.engine)
        inspector = inspect(self.engine)

        self.assertIn("organizations", inspector.get_table_names())
        self.assertIn("roles", inspector.get_table_names())
        self.assertIn("organization_id", {column["name"] for column in inspector.get_columns("users")})
        self.assertIn("role_id", {column["name"] for column in inspector.get_columns("users")})
        self.assertEqual(self.db.execute(text("SELECT COUNT(*) FROM organizations")).scalar_one(), 1)
        self.assertEqual(self.db.execute(text("SELECT COUNT(*) FROM roles")).scalar_one(), 5)

    def test_organization_crud_supports_update_and_delete(self) -> None:
        create_response = create_organization_endpoint(
            OrganizationCreate(
                name="Blue Team",
                description="Security operations tenant",
            ),
            self.db,
            current_user=self.super_admin,
        )

        organization = create_response
        self.assertEqual(organization["member_count"], 0)

        list_response = read_organizations(self.db, current_user=self.super_admin)
        self.assertGreaterEqual(len(list_response), 2)

        update_response = update_organization_endpoint(
            organization["id"],
            OrganizationUpdate(
                name="Blue Team Ops",
                status="suspended",
            ),
            self.db,
            current_user=self.super_admin,
        )

        updated = update_response
        self.assertEqual(updated["name"], "Blue Team Ops")
        self.assertEqual(updated["status"], "suspended")
        self.assertTrue(updated["slug"].startswith("blue-team-ops"))

        delete_response = delete_organization_endpoint(updated["id"], self.db, current_user=self.super_admin)
        self.assertEqual(delete_response["name"], "Blue Team Ops")

    def test_non_admin_cannot_modify_organizations(self) -> None:
        with self.assertRaises(HTTPException) as context:
            create_organization_endpoint(
                OrganizationCreate(name="Denied Org", description="Should not be allowed"),
                self.db,
                current_user=self.owner,
            )
        self.assertEqual(context.exception.status_code, 403)

        with self.assertRaises(HTTPException) as context:
            update_organization_endpoint(
                self.owner.organization_id,
                OrganizationUpdate(name="Renamed"),
                self.db,
                current_user=self.manager,
            )
        self.assertEqual(context.exception.status_code, 403)

        with self.assertRaises(HTTPException) as context:
            delete_organization_endpoint(
                self.owner.organization_id,
                self.db,
                current_user=self.member,
            )
        self.assertEqual(context.exception.status_code, 403)

    def test_delete_organization_with_members_is_blocked(self) -> None:
        create_response = create_organization_endpoint(
            OrganizationCreate(
                name="Red Team",
                description="Shared tenant",
            ),
            self.db,
            current_user=self.super_admin,
        )
        organization = create_response

        register(
            RegisterRequest(
                email="red-member@example.com",
                password="StrongPass123!",
                organization_id=organization["id"],
            ),
            self.db,
        )

        with self.assertRaises(HTTPException) as context:
            delete_organization_endpoint(organization["id"], self.db, current_user=self.super_admin)

        self.assertEqual(context.exception.status_code, 409)
        self.assertIn("members", context.exception.detail.lower())


if __name__ == "__main__":
    unittest.main()
