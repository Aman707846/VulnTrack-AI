from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from backend.app.models import (  # noqa: E402,F401
    malware_intelligence,
    organization,
    role,
    scan,
    scan_result,
    threat_intelligence,
    user,
    vulnerability,
)
