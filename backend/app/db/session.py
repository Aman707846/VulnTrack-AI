# backend/app/db/session.py
import logging
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import DATABASE_URL, DEFAULT_DATABASE_URL

logger = logging.getLogger("backend.db")


def _build_engine(url: str):
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


def _init_engine(primary_url: str):
    engine = _build_engine(primary_url)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine
    except Exception as exc:
        if primary_url != DEFAULT_DATABASE_URL:
            logger.warning(
                "Unable to connect to primary database (%s): %s. Falling back to local SQLite database: %s",
                primary_url.split("@")[-1] if "@" in primary_url else primary_url,
                exc,
                DEFAULT_DATABASE_URL,
            )
            fallback_engine = _build_engine(DEFAULT_DATABASE_URL)
            return fallback_engine
        raise


engine = _init_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

