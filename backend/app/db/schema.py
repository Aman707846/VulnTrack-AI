from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.base import Base
from backend.app.db.migrations import apply_organization_foundation_migration, apply_rbac_foundation_migration
from backend.app.models.malware_intelligence import TrustedVendor
from backend.app.repositories.malware_intelligence import DEFAULT_TRUSTED_VENDORS
from backend.app.repositories.threat_intelligence import DEFAULT_ATTACK_TECHNIQUES
from backend.app.models.threat_intelligence import AttackTechnique


def ensure_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)
    apply_organization_foundation_migration(engine)
    apply_rbac_foundation_migration(engine)
    _ensure_postgresql_enum_labels(engine)
    _ensure_scan_status_enum(engine)
    _ensure_scan_results_sha256_column(engine)
    _ensure_scan_results_explanation_column(engine)
    _seed_default_trusted_vendors(engine)
    _seed_default_attack_techniques(engine)


def _ensure_postgresql_enum_labels(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return

    _synchronize_postgresql_enum_labels(
        engine,
        "scantargettype",
        {
            "FILE": "file",
            "URL": "url",
        },
    )
    _synchronize_postgresql_enum_labels(
        engine,
        "scanstatus",
        {
            "PENDING": "pending",
            "PROCESSING": "processing",
            "COMPLETED": "completed",
            "FAILED": "failed",
        },
    )


def _synchronize_postgresql_enum_labels(
    engine: Engine,
    enum_name: str,
    value_map: dict[str, str],
) -> None:
    with engine.begin() as connection:
        existing_values = {
            row[0]
            for row in connection.execute(
                text(
                    """
                    SELECT e.enumlabel
                    FROM pg_type t
                    JOIN pg_enum e ON t.oid = e.enumtypid
                    WHERE t.typname = :enum_name
                    """
                ),
                {"enum_name": enum_name},
            )
        }
        if not existing_values:
            return

        for old_value, new_value in value_map.items():
            if old_value in existing_values and new_value not in existing_values:
                connection.execute(
                    text(f"ALTER TYPE {enum_name} RENAME VALUE '{old_value}' TO '{new_value}'")
                )
                existing_values.remove(old_value)
                existing_values.add(new_value)


def _ensure_scan_status_enum(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'processing'"
            )
        )


def _ensure_scan_results_sha256_column(engine: Engine) -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        if "scan_results" not in inspector.get_table_names():
            return

        existing_columns = {column["name"] for column in inspector.get_columns("scan_results")}
        if "sha256" not in existing_columns:
            connection.execute(text("ALTER TABLE scan_results ADD COLUMN sha256 VARCHAR(64)"))

        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_scan_results_sha256 ON scan_results (sha256)")
        )


def _ensure_scan_results_explanation_column(engine: Engine) -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        if "scan_results" not in inspector.get_table_names():
            return

        existing_columns = {column["name"] for column in inspector.get_columns("scan_results")}
        if "explanation" not in existing_columns:
            connection.execute(text("ALTER TABLE scan_results ADD COLUMN explanation TEXT"))


def _seed_default_trusted_vendors(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        existing_names = {row[0] for row in db.query(TrustedVendor.normalized_vendor_name).all()}
        created = False
        for vendor in DEFAULT_TRUSTED_VENDORS:
            if vendor["normalized_vendor_name"] in existing_names:
                continue
            db.add(TrustedVendor(**vendor))
            created = True
        if created:
            db.commit()


def _seed_default_attack_techniques(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db:
        existing_ids = {row[0] for row in db.query(AttackTechnique.technique_id).all()}
        created = False
        for technique in DEFAULT_ATTACK_TECHNIQUES:
            if technique["technique_id"] in existing_ids:
                continue
            db.add(AttackTechnique(**technique))
            created = True
        if created:
            db.commit()
