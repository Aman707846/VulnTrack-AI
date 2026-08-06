import os
from dotenv import load_dotenv

load_dotenv()


def _normalize_database_url(database_url: str | None) -> str | None:
    if database_url and database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL"))
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "vulntrack-dev-jwt-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "15"))
JWT_REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "365"))
