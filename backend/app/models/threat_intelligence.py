from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatCveRecord(Base):
    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)
    source_identifier: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    descriptions: Mapped[list[dict]] = mapped_column(JSON, default=list, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attack_vector: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attack_complexity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    privileges_required: Mapped[str | None] = mapped_column(String(32), nullable=True)
    user_interaction: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scope: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidentiality_impact: Mapped[str | None] = mapped_column(String(32), nullable=True)
    integrity_impact: Mapped[str | None] = mapped_column(String(32), nullable=True)
    availability_impact: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_products: Mapped[list[dict]] = mapped_column(JSON, default=list, nullable=False)
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    attack_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    has_known_exploit: Mapped[bool] = mapped_column(default=False, nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    correlations = relationship("ThreatCorrelation", back_populates="cve_record")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tactic_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tactic_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platforms: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    data_sources: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    external_references: Mapped[list[dict]] = mapped_column(JSON, default=list, nullable=False)
    is_subtechnique: Mapped[bool] = mapped_column(default=False, nullable=False)
    stix_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stix_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class ThreatAsset(Base):
    __tablename__ = "threat_assets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    software_inventory: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    correlations = relationship("ThreatCorrelation", back_populates="asset")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    indicator_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    normalized_value: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reputation_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    reputation_level: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    labels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    correlations = relationship("ThreatCorrelation", back_populates="indicator")


class ThreatCorrelation(Base):
    __tablename__ = "threat_correlations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("threat_assets.id"), nullable=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(ForeignKey("cve_records.cve_id"), nullable=True, index=True)
    indicator_id: Mapped[int | None] = mapped_column(ForeignKey("threat_indicators.id"), nullable=True, index=True)
    file_hash_id: Mapped[int | None] = mapped_column(ForeignKey("file_hashes.id"), nullable=True, index=True)
    correlation_type: Mapped[str] = mapped_column(String(50), default="unified", nullable=False, index=True)
    threat_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    threat_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    correlation_evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    related_cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    related_indicator_values: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    related_assets: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    correlated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    asset = relationship("ThreatAsset", back_populates="correlations")
    cve_record = relationship("ThreatCveRecord", back_populates="correlations")
    indicator = relationship("ThreatIndicator", back_populates="correlations")


class ThreatSyncRun(Base):
    __tablename__ = "threat_sync_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    sync_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="running", nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_cursor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sync_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
