from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.ai_security_intelligence import (
    AICopilotRequest,
    AICopilotResponse,
    AIDashboardResponse,
    AIIncidentSummaryRequest,
    AIIncidentSummaryResponse,
    AIReportRequest,
    AIReportResponse,
    AIRiskScoreRequest,
    AIRiskScoreResponse,
    AIThreatCorrelationRequest,
    AIThreatCorrelationResponse,
    AIVulnerabilityAnalysisRequest,
    AIVulnerabilityAnalysisResponse,
    AISearchResultResponse,
)
from backend.app.services.ai_security_intelligence import AISecurityIntelligenceService


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai-security-intelligence"])
service = AISecurityIntelligenceService()


@router.get("/dashboard", response_model=AIDashboardResponse, summary="Return the executive AI security dashboard")
def get_ai_dashboard(db: Session = Depends(get_db)) -> AIDashboardResponse:
    return AIDashboardResponse.model_validate(service.build_dashboard(db))


@router.post("/risk-score", response_model=AIRiskScoreResponse, summary="Score a vulnerability or threat using hybrid AI weighting")
def score_risk(payload: AIRiskScoreRequest) -> AIRiskScoreResponse:
    return AIRiskScoreResponse.model_validate(service.score_risk(**payload.model_dump()))


@router.post(
    "/vulnerabilities/analyze",
    response_model=AIVulnerabilityAnalysisResponse,
    summary="Explain a vulnerability in simple language and recommend remediation",
)
def analyze_vulnerability(payload: AIVulnerabilityAnalysisRequest, db: Session = Depends(get_db)) -> AIVulnerabilityAnalysisResponse:
    try:
        return AIVulnerabilityAnalysisResponse.model_validate(service.analyze_vulnerability(db, payload.model_dump()))
    except Exception as exc:
        logger.exception("AI vulnerability analysis failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.post(
    "/correlate",
    response_model=AIThreatCorrelationResponse,
    summary="Correlate assets, CVEs, malware, threat feeds, and scan events",
)
def correlate(payload: AIThreatCorrelationRequest, db: Session = Depends(get_db)) -> AIThreatCorrelationResponse:
    try:
        return AIThreatCorrelationResponse.model_validate(service.correlate_entities(db, payload.model_dump()))
    except Exception as exc:
        logger.exception("AI threat correlation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.post(
    "/copilot",
    response_model=AICopilotResponse,
    summary="Chat with the VulnTrack AI security copilot",
)
def copilot(payload: AICopilotRequest, db: Session = Depends(get_db)) -> AICopilotResponse:
    try:
        return AICopilotResponse.model_validate(service.generate_copilot_answer(db, payload.model_dump()))
    except Exception as exc:
        logger.exception("AI copilot request failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.post(
    "/reports",
    response_model=AIReportResponse,
    summary="Generate an AI incident or executive report",
)
def generate_report(payload: AIReportRequest, db: Session = Depends(get_db)) -> AIReportResponse:
    try:
        return AIReportResponse.model_validate(service.generate_report(db, payload.model_dump()))
    except Exception as exc:
        logger.exception("AI report generation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.post(
    "/incident-summary",
    response_model=AIIncidentSummaryResponse,
    summary="Generate an AI incident summary for executives or analysts",
)
def incident_summary(payload: AIIncidentSummaryRequest, db: Session = Depends(get_db)) -> AIIncidentSummaryResponse:
    try:
        return AIIncidentSummaryResponse.model_validate(service.summarize_incident(db, payload.model_dump()))
    except Exception as exc:
        logger.exception("AI incident summary failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.get(
    "/search",
    response_model=list[AISearchResultResponse],
    summary="Search VulnTrack data through the AI retrieval layer",
)
def search(query: str = Query(..., min_length=1), limit: int = Query(default=5, ge=1, le=20), db: Session = Depends(get_db)) -> list[AISearchResultResponse]:
    try:
        results = service.search_vulntrack_data(db, query, limit=limit)
        return [AISearchResultResponse.model_validate(result) for result in results]
    except Exception as exc:
        logger.exception("AI search failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

