import os
import sys
import unittest
from pathlib import Path

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.api.auth import login, register  # noqa: E402
from backend.app.api.rbac import read_users, update_user_role  # noqa: E402
from backend.app.core.authorization import get_current_user  # noqa: E402
from backend.app.core.security import decode_access_token, hash_password  # noqa: E402
from backend.app.db.base import Base  # noqa: E402
from backend.app.models.role import RoleCode  # noqa: E402
from backend.app.models.user import User  # noqa: E402
from backend.app.schemas.auth import LoginRequest, RegisterRequest  # noqa: E402
from backend.app.schemas.role import RoleAssignmentRequest  # noqa: E402
from backend.app.services.rbac_service import get_role_by_code, get_user, seed_default_roles  # noqa: E402


class RBACFoundationTests(unittest.TestCase):
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
        self.manager = register(
            RegisterRequest(
                email="manager@example.com",
                password="StrongPass123!",
                organization_name="Northwind Security",
                role_code=RoleCode.MANAGER,
                department="Security Operations",
            ),
            self.db,
        )

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

    def test_login_includes_token_and_role_claim(self) -> None:
        login_response = login(
            LoginRequest(
                email="owner@example.com",
                password="StrongPass123!",
            ),
            self.db,
        )

        claims = decode_access_token(login_response.access_token)
        self.assertEqual(claims["role"], RoleCode.ORGANIZATION_OWNER.value)
        self.assertEqual(int(claims["organization_id"]), self.owner.organization_id)
        self.assertEqual(int(claims["sub"]), self.owner.id)
        self.assertEqual(login_response.user.role.code, RoleCode.ORGANIZATION_OWNER.value)
        self.assertEqual(login_response.user.organization_id, self.owner.organization_id)

    def test_current_user_dependency_uses_jwt_claims(self) -> None:
        login_response = login(
            LoginRequest(
                email="member@example.com",
                password="StrongPass123!",
            ),
            self.db,
        )

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.access_token)
        current_user = get_current_user(credentials, self.db)

        self.assertEqual(current_user.email, self.member.email)
        self.assertEqual(current_user.role.code, RoleCode.USER.value)
        self.assertEqual(current_user.organization_id, self.member.organization_id)

    def test_registration_can_assign_manager_role_and_department(self) -> None:
        self.assertEqual(self.manager.role.code, RoleCode.MANAGER.value)
        self.assertEqual(self.manager.department, "Security Operations")
        self.assertEqual(self.manager.organization_id, self.owner.organization_id)

    def test_owner_can_manage_users_but_manager_cannot(self) -> None:
        manager_role = get_role_by_code(self.db, RoleCode.MANAGER.value)
        assert manager_role is not None

        updated_user = update_user_role(
            self.member.id,
            RoleAssignmentRequest(role_id=manager_role.id),
            self.db,
            current_user=self.owner,
        )
        self.assertEqual(updated_user.role.code, RoleCode.MANAGER.value)

        with self.assertRaises(HTTPException) as context:
            update_user_role(
                self.owner.id,
                RoleAssignmentRequest(role_id=manager_role.id),
                self.db,
                current_user=self.manager,
            )
        self.assertEqual(context.exception.status_code, 403)

    def test_read_users_is_scoped_to_organization(self) -> None:
        users = read_users(organization_id=None, db=self.db, current_user=self.owner)
        self.assertGreaterEqual(len(users), 2)
        self.assertTrue(all(user.organization_id == self.owner.organization_id for user in users))

        with self.assertRaises(HTTPException) as context:
            read_users(organization_id=self.owner.organization_id + 999, db=self.db, current_user=self.owner)
        self.assertEqual(context.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
