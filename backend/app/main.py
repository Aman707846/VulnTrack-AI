import sys
import socket
import logging
from contextlib import asynccontextmanager
from pathlib import Path

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes import router
from backend.app.core.logging import setup_logging
from backend.app.db.schema import ensure_schema
from backend.app.db.session import SessionLocal, engine
from backend.app.services.threat_intelligence import ThreatIntelSyncService


setup_logging()
logger = logging.getLogger("backend.startup")
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8001
threat_intel_service = ThreatIntelSyncService()
threat_intel_scheduler = None


def _port_is_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        ensure_schema(engine)
        global threat_intel_scheduler
        threat_intel_scheduler = threat_intel_service.start_scheduler(SessionLocal)
    except Exception:
        logger.exception("Backend startup failed")
        raise

    logger.info("Backend started on http://%s:%s", BACKEND_HOST, BACKEND_PORT)
    try:
        yield
    finally:
        if threat_intel_scheduler is not None:
            threat_intel_scheduler.stop()


app = FastAPI(title="VulnTrack AI", lifespan=lifespan)
ensure_schema(engine)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    if _port_is_in_use(BACKEND_HOST, BACKEND_PORT):
        raise SystemExit(
            f"Port {BACKEND_PORT} on {BACKEND_HOST} is already in use. "
            "Stop the existing backend process or start only one launcher."
        )

    uvicorn.run(
        "backend.app.main:app",
        host=BACKEND_HOST,
        port=BACKEND_PORT,
        reload=True,
    )
