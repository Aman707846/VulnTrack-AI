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

from backend.app.api.auth import login, logout, register, rotate_session  # noqa: E402
from backend.app.core.authorization import get_current_user  # noqa: E402
from backend.app.core.security import decode_refresh_token  # noqa: E402
from backend.app.db.base import Base  # noqa: E402
from backend.app.models.role import RoleCode  # noqa: E402
from backend.app.schemas.auth import LoginRequest, RegisterRequest  # noqa: E402
from backend.app.services.rbac_service import seed_default_roles  # noqa: E402


class AuthSessionFlowTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.db.close()

    def test_login_issues_refresh_token_and_session_claims(self) -> None:
        login_response = login(
            LoginRequest(
                email="owner@example.com",
                password="StrongPass123!",
            ),
            self.db,
        )

        refresh_claims = decode_refresh_token(login_response.refresh_token)
        self.assertEqual(refresh_claims["token_type"], "refresh")
        self.assertEqual(refresh_claims["role"], RoleCode.ORGANIZATION_OWNER.value)
        self.assertEqual(int(refresh_claims["sub"]), self.owner.id)
        self.assertEqual(int(refresh_claims["organization_id"]), self.owner.organization_id)

        current_user = get_current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.access_token),
            self.db,
        )
        self.assertEqual(current_user.email, self.owner.email)

    def test_refresh_rotates_and_replay_revokes_session(self) -> None:
        login_response = login(
            LoginRequest(
                email="owner@example.com",
                password="StrongPass123!",
            ),
            self.db,
        )

        rotated_response = rotate_session(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.refresh_token),
            self.db,
        )

        self.assertNotEqual(rotated_response.refresh_token, login_response.refresh_token)
        self.assertEqual(rotated_response.user.email, self.owner.email)

        current_user = get_current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.access_token),
            self.db,
        )
        self.assertEqual(current_user.email, self.owner.email)

        with self.assertRaises(HTTPException) as context:
            rotate_session(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.refresh_token),
                self.db,
            )
        self.assertEqual(context.exception.status_code, 401)

        with self.assertRaises(HTTPException) as logout_context:
            get_current_user(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.access_token),
                self.db,
            )
        self.assertEqual(logout_context.exception.status_code, 401)

    def test_logout_revokes_session(self) -> None:
        login_response = login(
            LoginRequest(
                email="owner@example.com",
                password="StrongPass123!",
            ),
            self.db,
        )

        logout(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.refresh_token),
            self.db,
        )

        with self.assertRaises(HTTPException) as context:
            get_current_user(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=login_response.access_token),
                self.db,
            )
        self.assertEqual(context.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
