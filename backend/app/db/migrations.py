from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from backend.app.models.organization import Organization
from backend.app.models.role import Role
from backend.app.services.organization_service import DEFAULT_ORGANIZATION_NAME, get_or_create_organization_by_name
from backend.app.services.rbac_service import backfill_users_with_roles, seed_default_roles


def apply_organization_foundation_migration(engine: Engine) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    if "organizations" not in table_names:
        Organization.__table__.create(bind=engine, checkfirst=True)

    if "users" not in table_names:
        return

    organization_columns = set()
    if "organizations" in table_names:
        organization_columns = {column["name"] for column in inspector.get_columns("organizations")}
        if "industry" not in organization_columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE organizations ADD COLUMN industry VARCHAR(255)"))
        if "company_size" not in organization_columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE organizations ADD COLUMN company_size VARCHAR(64)"))

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "organization_id" not in user_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN organization_id INTEGER"))
    if "department" not in user_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN department VARCHAR(255)"))

    _ensure_default_legacy_organization(engine)
    _backfill_users_without_organization(engine)
    if engine.dialect.name == "postgresql":
        _ensure_postgresql_user_organization_constraints(engine, user_columns)
    _ensure_user_organization_index(engine)


def _ensure_default_legacy_organization(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        user_count = db.scalar(text("SELECT COUNT(*) FROM users")) or 0
        if not user_count:
            return

        if db.scalar(text("SELECT 1 FROM organizations LIMIT 1")) is not None:
            return
        get_or_create_organization_by_name(db, DEFAULT_ORGANIZATION_NAME)


def _backfill_users_without_organization(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        pending_users = db.scalar(text("SELECT COUNT(*) FROM users WHERE organization_id IS NULL")) or 0
        if not pending_users:
            return

        fallback_organization = get_or_create_organization_by_name(db, DEFAULT_ORGANIZATION_NAME)
        db.execute(
            text("UPDATE users SET organization_id = :organization_id WHERE organization_id IS NULL"),
            {"organization_id": fallback_organization.id},
        )
        db.commit()


def _ensure_user_organization_index(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_users_organization_id ON users (organization_id)"))


def _ensure_postgresql_user_organization_constraints(engine: Engine, user_columns: set[str]) -> None:
    if "organization_id" in user_columns:
        return

    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE users ADD CONSTRAINT fk_users_organization_id "
                "FOREIGN KEY (organization_id) REFERENCES organizations(id)"
            )
        )
        connection.execute(text("ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL"))


def apply_rbac_foundation_migration(engine: Engine) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    if "roles" not in table_names:
        Role.__table__.create(bind=engine, checkfirst=True)

    _seed_default_roles(engine)

    if "users" not in table_names:
        return

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "role_id" not in user_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN role_id INTEGER"))

    _backfill_users_without_role(engine)
    if engine.dialect.name == "postgresql":
        _ensure_postgresql_user_role_constraints(engine, user_columns)
    _ensure_user_role_index(engine)


def _seed_default_roles(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        seed_default_roles(db)


def _backfill_users_without_role(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        backfill_users_with_roles(db)


def _ensure_user_role_index(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_users_role_id ON users (role_id)"))


def _ensure_postgresql_user_role_constraints(engine: Engine, user_columns: set[str]) -> None:
    if "role_id" in user_columns:
        return

    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE users ADD CONSTRAINT fk_users_role_id "
                "FOREIGN KEY (role_id) REFERENCES roles(id)"
            )
        )
        connection.execute(text("ALTER TABLE users ALTER COLUMN role_id SET NOT NULL"))
