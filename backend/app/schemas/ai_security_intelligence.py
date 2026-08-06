from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AIRiskFactorResponse(BaseModel):
    label: str
    weight: int
    rationale: str


class AIRiskScoreRequest(BaseModel):
    cvss_score: float = 0.0
    threat_intelligence_score: int = 0
    malware_reputation_score: int = 100
    asset_criticality: str = "medium"
    exploit_available: bool = False
    internet_exposed: bool = False
    business_importance: str | None = None
    notes: str | None = None


class AIRiskScoreResponse(BaseModel):
    risk_score: int
    severity: str
    confidence: int
    explanation: str
    factors: list[AIRiskFactorResponse] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class AIVulnerabilityAnalysisRequest(BaseModel):
    cve_id: str | None = None
    description: str | None = None
    asset_id: int | None = None
    asset_name: str | None = None
    asset_criticality: str = "medium"
    exploit_available: bool = False
    internet_exposed: bool = False
    file_hash_ids: list[int] = Field(default_factory=list)
    indicator_ids: list[int] = Field(default_factory=list)


class AIVulnerabilityAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str | None = None
    risk_score: int
    severity: str
    simple_explanation: str
    attack_methods: list[str] = Field(default_factory=list)
    business_impact: str
    exploitation_likelihood: str
    remediation_steps: list[str] = Field(default_factory=list)
    patch_recommendations: list[str] = Field(default_factory=list)
    configuration_fixes: list[str] = Field(default_factory=list)
    hardening_guidance: list[str] = Field(default_factory=list)
    related_assets: list[str] = Field(default_factory=list)
    related_threats: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class AIThreatCorrelationRequest(BaseModel):
    asset_id: int | None = None
    cve_ids: list[str] = Field(default_factory=list)
    indicator_ids: list[int] = Field(default_factory=list)
    file_hash_ids: list[int] = Field(default_factory=list)
    scan_ids: list[int] = Field(default_factory=list)
    indicator_values: list[str] = Field(default_factory=list)
    notes: str | None = None


class AIThreatChainStepResponse(BaseModel):
    stage: str
    evidence: str
    impact: str


class AIThreatCorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    risk_score: int
    severity: str
    confidence: int
    summary: str
    business_impact: str
    attack_chain: list[AIThreatChainStepResponse] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    correlated_assets: list[str] = Field(default_factory=list)
    correlated_cves: list[str] = Field(default_factory=list)
    correlated_indicators: list[str] = Field(default_factory=list)
    correlated_files: list[str] = Field(default_factory=list)
    security_events: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class AICopilotRequest(BaseModel):
    question: str
    limit: int = 5


class AICopilotResponse(BaseModel):
    answer: str
    matched_assets: list[str] = Field(default_factory=list)
    matched_cves: list[str] = Field(default_factory=list)
    matched_indicators: list[str] = Field(default_factory=list)
    matched_files: list[str] = Field(default_factory=list)
    matched_scans: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    search_results: list[dict[str, Any]] = Field(default_factory=list)


class AIIncidentSummaryRequest(BaseModel):
    summary_type: Literal["executive", "technical", "risk"] = "executive"
    correlation_id: int | None = None
    asset_id: int | None = None
    cve_ids: list[str] = Field(default_factory=list)
    indicator_ids: list[int] = Field(default_factory=list)
    file_hash_ids: list[int] = Field(default_factory=list)
    scan_ids: list[int] = Field(default_factory=list)
    notes: str | None = None


class AIIncidentSummaryResponse(BaseModel):
    report_type: str
    title: str
    summary: str
    risk_score: int
    severity: str
    key_findings: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class AISecurityTrendResponse(BaseModel):
    date: str
    risk_score: int
    cve_count: int
    indicator_count: int
    malware_count: int
    scan_count: int
    correlation_count: int


class AIThreatWidgetResponse(BaseModel):
    title: str
    score: int
    severity: str
    summary: str
    impact: str
    recommended_actions: list[str] = Field(default_factory=list)


class AICriticalAssetWidgetResponse(BaseModel):
    asset_id: int
    asset_name: str
    criticality: str
    risk_score: int
    exposure: str
    recommendation: str


class AIDashboardResponse(BaseModel):
    organization_risk_score: int
    executive_summary: str
    top_threats: list[AIThreatWidgetResponse] = Field(default_factory=list)
    critical_assets: list[AICriticalAssetWidgetResponse] = Field(default_factory=list)
    ai_recommendations: list[str] = Field(default_factory=list)
    security_trends: list[AISecurityTrendResponse] = Field(default_factory=list)
    recent_incidents: list[dict[str, Any]] = Field(default_factory=list)
    risk_breakdown: dict[str, Any] = Field(default_factory=dict)


class AIReportRequest(BaseModel):
    report_type: Literal["executive", "technical", "risk_summary"] = "executive"
    title: str | None = None
    focus: str | None = None
    limit: int = 5


class AIReportSectionResponse(BaseModel):
    heading: str
    body: str
    bullets: list[str] = Field(default_factory=list)


class AIReportResponse(BaseModel):
    report_type: str
    title: str
    generated_at: datetime
    executive_summary: str
    sections: list[AIReportSectionResponse] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


class AISearchResultResponse(BaseModel):
    entity_type: str
    title: str
    snippet: str
    score: int
    reference: str | None = None
