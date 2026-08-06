from fastapi import APIRouter, Depends

from backend.app.api.auth import router as auth_router
from backend.app.api.ai_intelligence import router as ai_router
from backend.app.api.organizations import router as organizations_router
from backend.app.api.rbac import router as rbac_router
from backend.app.api.malware_intelligence import router as malware_router
from backend.app.api.threat_intelligence import router as threat_router
from backend.app.api.scans import router as scans_router
from backend.app.core.authorization import get_current_user


router = APIRouter()


@router.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


router.include_router(auth_router)
router.include_router(organizations_router)
router.include_router(rbac_router)
router.include_router(scans_router, dependencies=[Depends(get_current_user)])
router.include_router(malware_router, dependencies=[Depends(get_current_user)])
router.include_router(threat_router, dependencies=[Depends(get_current_user)])
router.include_router(ai_router, dependencies=[Depends(get_current_user)])
