from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.threat_intelligence import (
    AttackTechnique,
    ThreatAsset,
    ThreatCorrelation,
    ThreatCveRecord,
    ThreatIndicator,
    ThreatSyncRun,
)


DEFAULT_ATTACK_TECHNIQUES: list[dict[str, Any]] = [
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_name": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries exploit a vulnerability in a public-facing application to gain access.",
        "platforms": ["Windows", "Linux", "IaaS", "Network Devices"],
        "data_sources": ["Application Logs", "Network Traffic"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic_name": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries execute commands and scripts.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process Monitoring", "PowerShell Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic_name": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries exploit software vulnerabilities to elevate privileges.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Application Logs", "Process Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1068"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic_name": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries abuse scheduled tasks or cron jobs for persistence.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Scheduled Job Monitoring", "Process Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1053"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_name": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries attempt repeated authentication attempts to obtain valid credentials.",
        "platforms": ["Windows", "Linux", "SaaS"],
        "data_sources": ["Authentication Logs", "Application Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1556",
        "technique_name": "Modify Authentication Process",
        "tactic_name": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries modify authentication mechanisms to capture or bypass credentials.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Authentication Logs", "Process Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1556"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic_name": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries obfuscate payloads to evade detection.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["File Monitoring", "Process Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic_name": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries use application layer protocols for C2 communications.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic", "Proxy Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic_name": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries transfer tools or payloads from an external system into a compromised environment.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic", "File Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1105"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic_name": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries send malicious content to victims to gain initial access.",
        "platforms": ["Windows", "Linux", "macOS", "SaaS"],
        "data_sources": ["Email Collection", "Application Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic_name": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries use stolen or compromised credentials to authenticate.",
        "platforms": ["Windows", "Linux", "macOS", "SaaS"],
        "data_sources": ["Authentication Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1078"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic_name": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries exfiltrate data over command and control channels.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic", "Proxy Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1041"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_name": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries encrypt data to disrupt business operations.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["File Monitoring", "Backup Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1486"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1489",
        "technique_name": "Service Stop",
        "tactic_name": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may stop services to impair operations.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Service Control Manager Logs"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1489"}],
        "is_subtechnique": False,
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic_name": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries inject malicious code into legitimate processes.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process Monitoring", "API Monitoring"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
        "is_subtechnique": False,
    },
]


class ThreatIntelligenceRepository:
    def seed_default_attack_techniques(self, db: Session) -> None:
        existing = {row[0] for row in db.execute(select(AttackTechnique.technique_id))}
        created = False
        for technique in DEFAULT_ATTACK_TECHNIQUES:
            if technique["technique_id"] in existing:
                continue
            db.add(AttackTechnique(**technique))
            created = True
        if created:
            db.commit()

    def start_sync_run(
        self,
        db: Session,
        *,
        sync_type: str,
        source: str | None = None,
        source_cursor: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatSyncRun:
        run = ThreatSyncRun(
            sync_type=sync_type,
            status="running",
            source=source,
            source_cursor=source_cursor,
            sync_metadata=metadata or {},
        )
        db.add(run)
        db.flush()
        return run

    def finish_sync_run(
        self,
        db: Session,
        run: ThreatSyncRun,
        *,
        status: str,
        records_ingested: int = 0,
        records_updated: int = 0,
        source_cursor: str | None = None,
        metadata: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> ThreatSyncRun:
        run.status = status
        run.records_ingested = records_ingested
        run.records_updated = records_updated
        run.source_cursor = source_cursor or run.source_cursor
        run.sync_metadata = metadata or run.sync_metadata or {}
        run.error_message = error_message
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
        db.flush()
        return run

    def upsert_cve(self, db: Session, record: ThreatCveRecord) -> ThreatCveRecord:
        existing = db.get(ThreatCveRecord, record.cve_id)
        if existing is None:
            db.add(record)
            db.flush()
            return record

        self._copy_attrs(
            existing,
            record,
            [
                "source_identifier",
                "published_at",
                "last_modified_at",
                "descriptions",
                "cvss_score",
                "cvss_version",
                "cvss_severity",
                "cvss_vector",
                "attack_vector",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "scope",
                "confidentiality_impact",
                "integrity_impact",
                "availability_impact",
                "cwe_ids",
                "affected_products",
                "reference_urls",
                "attack_tactics",
                "attack_techniques",
                "has_known_exploit",
                "raw_payload",
            ],
        )
        db.flush()
        return existing

    def upsert_attack_technique(self, db: Session, technique: AttackTechnique) -> AttackTechnique:
        existing = db.get(AttackTechnique, technique.technique_id)
        if existing is None:
            db.add(technique)
            db.flush()
            return technique

        self._copy_attrs(
            existing,
            technique,
            [
                "technique_name",
                "tactic_name",
                "tactic_id",
                "description",
                "platforms",
                "data_sources",
                "external_references",
                "is_subtechnique",
                "stix_created_at",
                "stix_modified_at",
                "raw_payload",
            ],
        )
        db.flush()
        return existing

    def upsert_asset(self, db: Session, asset: ThreatAsset) -> ThreatAsset:
        existing = None
        if asset.id is not None:
            existing = db.get(ThreatAsset, asset.id)
        if existing is None:
            existing = db.scalar(
                select(ThreatAsset).where(
                    ThreatAsset.asset_name == asset.asset_name,
                    ThreatAsset.asset_type == asset.asset_type,
                )
            )
        if existing is None:
            db.add(asset)
            db.flush()
            return asset

        self._copy_attrs(
            existing,
            asset,
            [
                "asset_name",
                "asset_type",
                "hostname",
                "ip_address",
                "environment",
                "criticality",
                "owner",
                "business_unit",
                "software_inventory",
                "tags",
                "notes",
                "last_seen_at",
            ],
        )
        db.flush()
        return existing

    def upsert_indicator(self, db: Session, indicator: ThreatIndicator) -> ThreatIndicator:
        existing = db.scalar(select(ThreatIndicator).where(ThreatIndicator.normalized_value == indicator.normalized_value))
        if existing is None:
            db.add(indicator)
            db.flush()
            return indicator

        self._copy_attrs(
            existing,
            indicator,
            [
                "indicator_type",
                "indicator_value",
                "source",
                "reputation_score",
                "reputation_level",
                "confidence",
                "severity",
                "first_seen_at",
                "last_seen_at",
                "expires_at",
                "labels",
                "mitre_tactics",
                "mitre_techniques",
                "raw_payload",
            ],
        )
        db.flush()
        return existing

    def upsert_correlation(self, db: Session, correlation: ThreatCorrelation) -> ThreatCorrelation:
        db.add(correlation)
        db.flush()
        return correlation

    def list_cves(
        self,
        db: Session,
        *,
        limit: int = 100,
        severity: str | None = None,
        critical_only: bool = False,
    ) -> list[ThreatCveRecord]:
        query = select(ThreatCveRecord).order_by(
            ThreatCveRecord.cvss_score.desc().nullslast(),
            ThreatCveRecord.last_modified_at.desc().nullslast(),
        )
        if severity:
            query = query.where(ThreatCveRecord.cvss_severity == severity)
        if critical_only:
            query = query.where(ThreatCveRecord.cvss_severity.in_(["CRITICAL", "HIGH"]))
        return list(db.scalars(query.limit(limit)))

    def list_attack_techniques(self, db: Session) -> list[AttackTechnique]:
        return list(db.scalars(select(AttackTechnique).order_by(AttackTechnique.tactic_name, AttackTechnique.technique_name)))

    def list_assets(self, db: Session) -> list[ThreatAsset]:
        return list(db.scalars(select(ThreatAsset).order_by(ThreatAsset.updated_at.desc())))

    def list_indicators(self, db: Session, *, limit: int = 100) -> list[ThreatIndicator]:
        return list(
            db.scalars(
                select(ThreatIndicator).order_by(ThreatIndicator.reputation_score.desc(), ThreatIndicator.last_seen_at.desc().nullslast()).limit(limit)
            )
        )

    def list_sync_runs(self, db: Session, *, limit: int = 20) -> list[ThreatSyncRun]:
        return list(db.scalars(select(ThreatSyncRun).order_by(ThreatSyncRun.started_at.desc()).limit(limit)))

    def list_correlations(self, db: Session, *, limit: int = 100) -> list[ThreatCorrelation]:
        return list(
            db.scalars(
                select(ThreatCorrelation)
                .options(
                    selectinload(ThreatCorrelation.asset),
                    selectinload(ThreatCorrelation.cve_record),
                    selectinload(ThreatCorrelation.indicator),
                )
                .order_by(ThreatCorrelation.threat_score.desc(), ThreatCorrelation.correlated_at.desc())
                .limit(limit)
            )
        )

    def get_asset(self, db: Session, asset_id: int) -> ThreatAsset | None:
        return db.get(ThreatAsset, asset_id)

    def get_cve(self, db: Session, cve_id: str) -> ThreatCveRecord | None:
        return db.get(ThreatCveRecord, cve_id)

    def get_indicator(self, db: Session, indicator_id: int) -> ThreatIndicator | None:
        return db.get(ThreatIndicator, indicator_id)

    def get_correlation(self, db: Session, correlation_id: int) -> ThreatCorrelation | None:
        return db.get(ThreatCorrelation, correlation_id)

    def get_latest_sync_run(self, db: Session, sync_type: str) -> ThreatSyncRun | None:
        return db.scalar(
            select(ThreatSyncRun)
            .where(ThreatSyncRun.sync_type == sync_type)
            .order_by(ThreatSyncRun.started_at.desc())
        )

    def get_dashboard_context(self, db: Session) -> dict[str, Any]:
        cves = self.list_cves(db, limit=250)
        indicators = self.list_indicators(db, limit=250)
        correlations = self.list_correlations(db, limit=250)
        techniques = self.list_attack_techniques(db)
        assets = self.list_assets(db)
        sync_runs = self.list_sync_runs(db, limit=10)
        return {
            "cves": cves,
            "indicators": indicators,
            "correlations": correlations,
            "techniques": techniques,
            "assets": assets,
            "sync_runs": sync_runs,
        }

    @staticmethod
    def _copy_attrs(target: Any, source: Any, fields: list[str]) -> None:
        for field in fields:
            setattr(target, field, getattr(source, field))


def normalize_indicator_value(indicator_type: str, value: str) -> str:
    normalized = (value or "").strip().lower()
    indicator_type = (indicator_type or "").strip().lower()
    if indicator_type == "hash":
        return normalized.replace("sha256:", "").replace("sha1:", "").replace("md5:", "")
    if indicator_type == "ip":
        return normalized
    if indicator_type in {"domain", "url"}:
        return normalized.rstrip("/")
    return normalized
