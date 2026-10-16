import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOCAL_SQLITE_PATH = PROJECT_ROOT / "backend" / "vulntrack.db"
DEFAULT_DATABASE_URL = f"sqlite:///{LOCAL_SQLITE_PATH.as_posix()}"

for env_path in (
    PROJECT_ROOT / ".env",
    PROJECT_ROOT / "backend" / ".env",
    PROJECT_ROOT / "frontend" / ".env.local",
):
    load_dotenv(env_path, override=False)


def _normalize_database_url(database_url: str | None) -> str:
    normalized = (database_url or "").strip()
    if not normalized:
        return DEFAULT_DATABASE_URL
    if normalized.startswith("postgresql://"):
        return normalized.replace("postgresql://", "postgresql+psycopg://", 1)
    if normalized in ("sqlite://", "sqlite:///:memory:", "sqlite://:memory:"):
        return normalized
    if normalized.startswith("sqlite:///"):
        clean = normalized.replace("sqlite:///", "", 1)
        if clean == ":memory:":
            return normalized
        if not clean.startswith("/") and (len(clean) < 2 or clean[1] != ":"):
            abs_path = (PROJECT_ROOT / clean).resolve()
            return f"sqlite:///{abs_path.as_posix()}"
    return normalized


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL"))
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "vulntrack-dev-jwt-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "15"))
JWT_REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "365"))
