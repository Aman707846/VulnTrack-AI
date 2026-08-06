import sys
from pathlib import Path

from sqlalchemy import text

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from backend.app.db.base import Base
from backend.app.db.schema import ensure_schema
from backend.app.db.session import engine


def main() -> int:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        ensure_schema(engine)

        print("Database connection successful.")
        print("Tables created or already present:")
        for table_name in sorted(Base.metadata.tables.keys()):
            print(f"- {table_name}")
        return 0
    except Exception as exc:
        print(f"Database setup failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
