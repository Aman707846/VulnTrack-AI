from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatCveResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    source_identifier: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[dict[str, Any]] = Field(default_factory=list)
    reference_urls: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    has_known_exploit: bool = False


class ThreatTechniqueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    technique_name: str
    tactic_name: str
    tactic_id: str | None = None
    description: str | None = None
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)
    is_subtechnique: bool = False


class ThreatAssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_name: str
    asset_type: str
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    criticality: str = "medium"
    owner: str | None = None
    business_unit: str | None = None
    software_inventory: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None
    last_seen_at: datetime | None = None


class ThreatIndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_type: str
    indicator_value: str
    normalized_value: str
    source: str | None = None
    reputation_score: int = 50
    reputation_level: str = "unknown"
    confidence: int = 50
    severity: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class ThreatCorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int | None = None
    cve_id: str | None = None
    indicator_id: int | None = None
    file_hash_id: int | None = None
    correlation_type: str = "unified"
    threat_score: int = 0
    severity: str = "unknown"
    confidence: int = 50
    threat_summary: str | None = None
    business_impact: str | None = None
    attack_scenario: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    correlation_evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    related_cve_ids: list[str] = Field(default_factory=list)
    related_indicator_values: list[str] = Field(default_factory=list)
    related_assets: list[str] = Field(default_factory=list)
    correlated_at: datetime


class ThreatSyncRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sync_type: str
    status: str
    source: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    records_ingested: int = 0
    records_updated: int = 0
    source_cursor: str | None = None
    sync_metadata: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None


class ThreatIntelTrendsResponse(BaseModel):
    date: str
    total_cves: int
    critical_cves: int
    high_cves: int
    indicators: int
    correlations: int
    average_threat_score: float


class ThreatIndicatorSummaryResponse(BaseModel):
    indicator_type: str
    value: str
    count: int
    reputation_level: str
    reputation_score: int


class MitreCoverageResponse(BaseModel):
    tactic_name: str
    technique_count: int
    mapped_cves: int
    mapped_indicators: int


class ThreatIntelDashboardResponse(BaseModel):
    total_cves: int
    critical_cves: int
    high_cves: int
    indicators_ingested: int
    correlations_generated: int
    mitre_coverage_percent: float
    latest_critical_cves: list[ThreatCveResponse] = Field(default_factory=list)
    threat_feed_summary: dict[str, Any] = Field(default_factory=dict)
    mitre_attack_coverage: list[MitreCoverageResponse] = Field(default_factory=list)
    top_threat_indicators: list[ThreatIndicatorSummaryResponse] = Field(default_factory=list)
    threat_trends: list[ThreatIntelTrendsResponse] = Field(default_factory=list)


class ThreatIntelAssetRequest(BaseModel):
    asset_name: str
    asset_type: str = "server"
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    criticality: str = "medium"
    owner: str | None = None
    business_unit: str | None = None
    software_inventory: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class ThreatIndicatorIngestRequest(BaseModel):
    indicator_type: str
    indicator_value: str
    source: str | None = None
    reputation_score: int | None = None
    reputation_level: str | None = None
    confidence: int | None = None
    severity: str | None = None
    labels: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class ThreatCorrelationRequest(BaseModel):
    asset_id: int | None = None
    cve_ids: list[str] = Field(default_factory=list)
    indicator_ids: list[int] = Field(default_factory=list)
    file_hash_ids: list[int] = Field(default_factory=list)
    indicator_values: list[str] = Field(default_factory=list)
    notes: str | None = None


class ThreatIntelSyncRequest(BaseModel):
    sync_nvd: bool = True
    sync_attack: bool = True
    sync_indicators: bool = False
    lookback_days: int = 7
    force: bool = False


class ThreatAnalysisResponse(BaseModel):
    threat_score: int
    severity: str
    explanation: str
    business_impact: str
    attack_scenario: str
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    correlated_cve_ids: list[str] = Field(default_factory=list)
    correlated_indicator_values: list[str] = Field(default_factory=list)
    correlated_assets: list[str] = Field(default_factory=list)
