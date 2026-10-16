import sys
from pathlib import Path

# Ensure project root and backend are in sys.path before importing backend modules
_project_root = Path(__file__).resolve().parents[1]
_backend_path = _project_root / "backend"

for _path_str in (str(_project_root), str(_backend_path)):
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)

from backend.app.main import app, lifespan, ensure_schema, SessionLocal, engine

__all__ = ["app", "lifespan", "ensure_schema", "SessionLocal", "engine"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8001, reload=True)
