import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parents[1]
_backend_path = _project_root / "backend"

if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
if str(_backend_path) not in sys.path:
    sys.path.insert(0, str(_backend_path))
