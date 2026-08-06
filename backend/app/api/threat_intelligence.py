from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.malware_intelligence import FileHash
from backend.app.schemas.threat_intelligence import (
    MitreCoverageResponse,
    ThreatAnalysisResponse,
    ThreatIntelAssetRequest,
    ThreatAssetResponse,
    ThreatCorrelationRequest,
    ThreatCorrelationResponse,
    ThreatCveResponse,
    ThreatIndicatorIngestRequest,
    ThreatIndicatorResponse,
    ThreatIndicatorSummaryResponse,
    ThreatIntelDashboardResponse,
    ThreatIntelSyncRequest,
    ThreatSyncRunResponse,
    ThreatTechniqueResponse,
)
from backend.app.services.threat_intelligence import ThreatIntelSyncService
from backend.app.repositories.threat_intelligence import ThreatIntelligenceRepository


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["threat-intelligence"])

repository = ThreatIntelligenceRepository()
service = ThreatIntelSyncService(repository=repository)


@router.post(
    "/threat-intel/sync",
    response_model=dict[str, object],
    summary="Synchronize NVD CVEs and MITRE ATT&CK techniques",
)
def sync_threat_intel(payload: ThreatIntelSyncRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return service.sync_all(db, request=payload.model_dump())
    except Exception as exc:
        logger.exception("Threat intel sync failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.get(
    "/dashboard/threat-intelligence",
    response_model=ThreatIntelDashboardResponse,
    summary="Return the threat intelligence dashboard payload",
)
def get_threat_dashboard(db: Session = Depends(get_db)) -> ThreatIntelDashboardResponse:
    payload = service.build_dashboard(db)
    return ThreatIntelDashboardResponse.model_validate(payload)


@router.get(
    "/threat-intel/cves",
    response_model=list[ThreatCveResponse],
    summary="List threat intelligence CVEs",
)
def list_cves(
    severity: str | None = Query(default=None),
    critical_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ThreatCveResponse]:
    cves = repository.list_cves(db, severity=severity, critical_only=critical_only, limit=limit)
    return [ThreatCveResponse.model_validate(record) for record in cves]


@router.get(
    "/threat-intel/cves/{cve_id}",
    response_model=ThreatCveResponse,
    summary="Get a CVE intelligence record",
)
def get_cve(cve_id: str = Path(..., min_length=4), db: Session = Depends(get_db)) -> ThreatCveResponse:
    record = repository.get_cve(db, cve_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found.")
    return ThreatCveResponse.model_validate(record)


@router.get(
    "/threat-intel/attack-techniques",
    response_model=list[ThreatTechniqueResponse],
    summary="List ATT&CK technique coverage",
)
def list_attack_techniques(db: Session = Depends(get_db)) -> list[ThreatTechniqueResponse]:
    records = repository.list_attack_techniques(db)
    return [ThreatTechniqueResponse.model_validate(record) for record in records]


@router.post(
    "/threat-intel/assets",
    response_model=ThreatAssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a threat asset",
)
def upsert_asset(payload: ThreatIntelAssetRequest, db: Session = Depends(get_db)) -> ThreatAssetResponse:
    from backend.app.models.threat_intelligence import ThreatAsset

    asset = ThreatAsset(
        asset_name=payload.asset_name,
        asset_type=payload.asset_type,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        environment=payload.environment,
        criticality=payload.criticality,
        owner=payload.owner,
        business_unit=payload.business_unit,
        software_inventory=payload.software_inventory,
        tags=payload.tags,
        notes=payload.notes,
        last_seen_at=None,
    )
    stored = repository.upsert_asset(db, asset)
    db.commit()
    db.refresh(stored)
    return ThreatAssetResponse.model_validate(stored)


@router.get(
    "/threat-intel/assets",
    response_model=list[ThreatAssetResponse],
    summary="List threat assets",
)
def list_assets(db: Session = Depends(get_db)) -> list[ThreatAssetResponse]:
    return [ThreatAssetResponse.model_validate(asset) for asset in repository.list_assets(db)]


@router.get(
    "/threat-intel/assets/{asset_id}",
    response_model=ThreatAssetResponse,
    summary="Get a threat asset",
)
def get_asset(asset_id: int = Path(..., ge=1), db: Session = Depends(get_db)) -> ThreatAssetResponse:
    asset = repository.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return ThreatAssetResponse.model_validate(asset)


@router.post(
    "/threat-intel/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a threat indicator",
)
def ingest_indicator(payload: ThreatIndicatorIngestRequest, db: Session = Depends(get_db)) -> ThreatIndicatorResponse:
    indicator = service.ingest_indicator(
        db,
        indicator_type=payload.indicator_type,
        indicator_value=payload.indicator_value,
        source=payload.source,
        reputation_score=payload.reputation_score,
        reputation_level=payload.reputation_level,
        confidence=payload.confidence,
        severity=payload.severity,
        labels=payload.labels,
        expires_at=payload.expires_at,
        first_seen_at=payload.first_seen_at,
        last_seen_at=payload.last_seen_at,
        raw_payload=payload.raw_payload,
    )
    return ThreatIndicatorResponse.model_validate(indicator)


@router.get(
    "/threat-intel/indicators",
    response_model=list[ThreatIndicatorResponse],
    summary="List threat indicators",
)
def list_indicators(db: Session = Depends(get_db)) -> list[ThreatIndicatorResponse]:
    return [ThreatIndicatorResponse.model_validate(indicator) for indicator in repository.list_indicators(db)]


@router.post(
    "/threat-intel/correlate",
    response_model=ThreatAnalysisResponse,
    summary="Correlate CVEs, indicators, malware, and assets",
)
def correlate(payload: ThreatCorrelationRequest, db: Session = Depends(get_db)) -> ThreatAnalysisResponse:
    analysis = service.correlate(
        db,
        asset_id=payload.asset_id,
        cve_ids=payload.cve_ids,
        indicator_ids=payload.indicator_ids,
        file_hash_ids=payload.file_hash_ids,
        indicator_values=payload.indicator_values,
        notes=payload.notes,
    )
    return ThreatAnalysisResponse.model_validate(analysis.__dict__)


@router.get(
    "/threat-intel/correlations",
    response_model=list[ThreatCorrelationResponse],
    summary="List threat correlations",
)
def list_correlations(db: Session = Depends(get_db)) -> list[ThreatCorrelationResponse]:
    return [ThreatCorrelationResponse.model_validate(record) for record in repository.list_correlations(db)]


@router.get(
    "/threat-intel/correlations/{correlation_id}",
    response_model=ThreatCorrelationResponse,
    summary="Get a threat correlation record",
)
def get_correlation(correlation_id: int = Path(..., ge=1), db: Session = Depends(get_db)) -> ThreatCorrelationResponse:
    record = repository.get_correlation(db, correlation_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation not found.")
    return ThreatCorrelationResponse.model_validate(record)


@router.get(
    "/threat-intel/sync-runs",
    response_model=list[ThreatSyncRunResponse],
    summary="List threat sync runs",
)
def list_sync_runs(db: Session = Depends(get_db)) -> list[ThreatSyncRunResponse]:
    return [ThreatSyncRunResponse.model_validate(run) for run in repository.list_sync_runs(db)]
