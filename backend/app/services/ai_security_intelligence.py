from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.malware_intelligence import FileHash, HashAnalysisHistory
from backend.app.models.scan import Scan
from backend.app.models.scan_result import ScanResult
from backend.app.models.threat_intelligence import (
    AttackTechnique,
    ThreatAsset,
    ThreatCorrelation,
    ThreatCveRecord,
    ThreatIndicator,
)
from backend.app.repositories.malware_intelligence import MalwareIntelligenceRepository
from backend.app.repositories.threat_intelligence import ThreatIntelligenceRepository, normalize_indicator_value
from backend.app.services.threat_intelligence import ThreatAnalysisEngine, ThreatIntelMapper


_CRITICALITY_WEIGHTS = {
    "low": 6,
    "medium": 14,
    "high": 24,
    "critical": 34,
}

_KEYWORD_PATTERNS = {
    "remote code execution": ["RCE", "code execution"],
    "command injection": ["command injection", "script execution"],
    "privilege escalation": ["privilege escalation"],
    "authentication bypass": ["auth bypass", "authentication bypass"],
    "sql injection": ["SQL injection", "database compromise"],
    "path traversal": ["path traversal", "arbitrary file access"],
    "server-side request forgery": ["SSRF", "backend request abuse"],
    "phishing": ["phishing", "credential theft"],
    "ransomware": ["ransomware", "extortion"],
}


@dataclass(frozen=True)
class SearchHit:
    entity_type: str
    title: str
    snippet: str
    score: int
    reference: str | None = None


class AISecurityIntelligenceService:
    def __init__(
        self,
        threat_repository: ThreatIntelligenceRepository | None = None,
        malware_repository: MalwareIntelligenceRepository | None = None,
        threat_engine: ThreatAnalysisEngine | None = None,
        mapper: ThreatIntelMapper | None = None,
    ) -> None:
        self.threat_repository = threat_repository or ThreatIntelligenceRepository()
        self.malware_repository = malware_repository or MalwareIntelligenceRepository()
        self.threat_engine = threat_engine or ThreatAnalysisEngine(self.threat_repository)
        self.mapper = mapper or ThreatIntelMapper(self.threat_repository)

    def score_risk(
        self,
        *,
        cvss_score: float = 0.0,
        threat_intelligence_score: int = 0,
        malware_reputation_score: int = 100,
        asset_criticality: str = "medium",
        exploit_available: bool = False,
        internet_exposed: bool = False,
        business_importance: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        factors: list[dict[str, Any]] = []
        score = 0

        def add(weight: int, label: str, rationale: str) -> None:
            nonlocal score
            if weight <= 0:
                return
            score = min(100, score + weight)
            factors.append({"label": label, "weight": weight, "rationale": rationale})

        cvss_component = min(40, max(0, round(float(cvss_score) * 4)))
        add(cvss_component, "CVSS", f"Base CVSS of {cvss_score:.1f} contributes {cvss_component} points.")

        intel_component = min(30, max(0, round(threat_intelligence_score * 0.30)))
        add(intel_component, "Threat intelligence", f"Threat feed evidence contributes {intel_component} points.")

        malware_component = min(25, max(0, round((100 - int(malware_reputation_score)) * 0.25)))
        add(malware_component, "Malware reputation", f"Malware reputation score of {malware_reputation_score} adds {malware_component} points.")

        asset_component = _CRITICALITY_WEIGHTS.get((asset_criticality or "medium").lower(), 14)
        add(asset_component, "Asset criticality", f"Asset criticality '{asset_criticality}' adds {asset_component} points.")

        if exploit_available:
            add(15, "Exploit availability", "Known exploit availability materially increases likelihood.")

        if internet_exposed:
            add(10, "Exposure", "Internet exposure increases attack surface.")

        if business_importance:
            importance = business_importance.strip().lower()
            importance_bonus = {"support": 0, "standard": 0, "important": 4, "high": 8, "critical": 12}.get(importance, 3)
            add(importance_bonus, "Business importance", f"Business importance '{business_importance}' adds {importance_bonus} points.")

        if notes and any(keyword in notes.lower() for keyword in ("active exploit", "weaponized", "in the wild")):
            add(8, "Narrative signals", "Narrative context suggests active exploitation.")

        risk_score = max(0, min(100, score))
        severity = self._severity_from_score(risk_score)
        confidence = max(35, min(95, 45 + len(factors) * 8))
        explanation = self._build_risk_explanation(severity, factors, notes)
        recommended_actions = self._build_risk_actions(severity, exploit_available, internet_exposed, asset_criticality)

        return {
            "risk_score": risk_score,
            "severity": severity,
            "confidence": confidence,
            "explanation": explanation,
            "factors": factors,
            "recommended_actions": recommended_actions,
        }

    def analyze_vulnerability(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        cve_id = (payload.get("cve_id") or "").strip() or None
        cve = self.threat_repository.get_cve(db, cve_id) if cve_id else None

        asset = self.threat_repository.get_asset(db, payload.get("asset_id")) if payload.get("asset_id") else None
        asset_name = payload.get("asset_name") or (asset.asset_name if asset else "the affected system")
        asset_criticality = payload.get("asset_criticality") or (asset.criticality if asset else "medium")
        internet_exposed = bool(payload.get("internet_exposed") or self._is_public_facing(asset))
        exploit_available = bool(payload.get("exploit_available") or (cve.has_known_exploit if cve else False))

        indicator_ids = [int(value) for value in payload.get("indicator_ids") or [] if str(value).isdigit()]
        file_hash_ids = [int(value) for value in payload.get("file_hash_ids") or [] if str(value).isdigit()]
        indicators = [item for item in (self.threat_repository.get_indicator(db, indicator_id) for indicator_id in indicator_ids) if item]
        file_hashes = [item for item in (db.get(FileHash, file_hash_id) for file_hash_id in file_hash_ids) if item]

        cvss_score = float(cve.cvss_score or 0.0) if cve else self._estimate_cvss(payload.get("description"))
        threat_intelligence_score = self._estimate_threat_intelligence_score(cve, indicators, file_hashes)
        malware_reputation_score = self._estimate_malware_reputation(file_hashes)

        risk = self.score_risk(
            cvss_score=cvss_score,
            threat_intelligence_score=threat_intelligence_score,
            malware_reputation_score=malware_reputation_score,
            asset_criticality=asset_criticality,
            exploit_available=exploit_available,
            internet_exposed=internet_exposed,
            business_importance=payload.get("business_importance"),
            notes=payload.get("description"),
        )

        simple_explanation = self._build_plain_language_summary(
            cve=cve,
            description=payload.get("description"),
            asset_name=asset_name,
            severity=risk["severity"],
        )
        attack_methods = self._build_attack_methods(cve, payload.get("description"), indicators, file_hashes)
        business_impact = self._build_business_impact(asset_name, asset_criticality, risk["severity"], exploit_available)
        exploitation_likelihood = self._build_likelihood_statement(risk["severity"], exploit_available, internet_exposed, cve)
        remediation_steps = self._build_remediation_steps(cve, asset_name, asset_criticality, indicators, file_hashes, exploit_available)
        patch_recommendations = self._build_patch_recommendations(cve)
        configuration_fixes = self._build_configuration_fixes(cve, asset_criticality, internet_exposed)
        hardening_guidance = self._build_hardening_guidance(asset_criticality, internet_exposed, exploit_available)

        correlated_assets = self._collect_related_assets(db, cve, asset)
        related_threats = self._collect_related_threat_signals(cve, indicators, file_hashes)

        evidence = {
            "cve": cve_id,
            "cvss_score": round(cvss_score, 1),
            "threat_intelligence_score": threat_intelligence_score,
            "malware_reputation_score": malware_reputation_score,
            "asset_criticality": asset_criticality,
            "exploit_available": exploit_available,
            "internet_exposed": internet_exposed,
            "indicator_ids": [indicator.id for indicator in indicators],
            "file_hash_ids": [file_hash.id for file_hash in file_hashes],
            "related_correlations": self._related_correlation_ids(db, cve),
        }

        return {
            "cve_id": cve_id,
            "risk_score": risk["risk_score"],
            "severity": risk["severity"],
            "simple_explanation": simple_explanation,
            "attack_methods": attack_methods,
            "business_impact": business_impact,
            "exploitation_likelihood": exploitation_likelihood,
            "remediation_steps": remediation_steps,
            "patch_recommendations": patch_recommendations,
            "configuration_fixes": configuration_fixes,
            "hardening_guidance": hardening_guidance,
            "related_assets": correlated_assets,
            "related_threats": related_threats,
            "evidence": evidence,
        }

    def correlate_entities(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        asset = self.threat_repository.get_asset(db, payload.get("asset_id")) if payload.get("asset_id") else None
        cves = [item for item in (self.threat_repository.get_cve(db, cve_id) for cve_id in payload.get("cve_ids") or []) if item]
        indicators = [item for item in (self.threat_repository.get_indicator(db, indicator_id) for indicator_id in payload.get("indicator_ids") or []) if item]
        file_hashes = [item for item in (db.get(FileHash, file_hash_id) for file_hash_id in payload.get("file_hash_ids") or []) if item]
        scans = [item for item in (self._load_scan(db, scan_id) for scan_id in payload.get("scan_ids") or []) if item]

        for value in payload.get("indicator_values") or []:
            normalized = normalize_indicator_value("generic", value)
            matched = db.scalar(select(ThreatIndicator).where(ThreatIndicator.normalized_value == normalized))
            if matched is not None and matched not in indicators:
                indicators.append(matched)

        for scan in scans:
            for vulnerability in scan.vulnerabilities or []:
                if vulnerability.cve_id:
                    cve = self.threat_repository.get_cve(db, vulnerability.cve_id)
                    if cve is not None and cve not in cves:
                        cves.append(cve)

        analysis = self.threat_engine.analyze(
            asset=asset,
            cves=cves,
            indicators=indicators,
            file_hashes=file_hashes,
            technique_map={technique.technique_id: technique for technique in self.threat_repository.list_attack_techniques(db)},
        )

        attack_chain = self._build_attack_chain(asset, cves, indicators, file_hashes, scans)
        security_events = self._build_security_events(cves, indicators, file_hashes, scans)
        summary = self._build_correlation_summary(analysis.severity, attack_chain, asset, scans)
        business_impact = self._build_correlation_impact(analysis.severity, asset, scans)
        recommended_actions = self._merge_actions(
            analysis.recommended_actions,
            self._build_correlation_actions(analysis.severity, asset, cves, indicators, file_hashes, scans),
        )

        return {
            "risk_score": analysis.threat_score,
            "severity": analysis.severity,
            "confidence": min(100, max(50, 50 + len(cves) * 4 + len(indicators) * 4 + len(file_hashes) * 5 + len(scans) * 3)),
            "summary": summary,
            "business_impact": business_impact,
            "attack_chain": attack_chain,
            "recommended_actions": recommended_actions,
            "correlated_assets": analysis.correlated_assets or ([asset.asset_name] if asset else []),
            "correlated_cves": analysis.correlated_cve_ids,
            "correlated_indicators": analysis.correlated_indicator_values,
            "correlated_files": [file_hash.sha256 for file_hash in file_hashes],
            "security_events": security_events,
            "evidence": analysis.evidence | {"notes": payload.get("notes")},
        }

    def generate_copilot_answer(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        question = (payload.get("question") or "").strip()
        search_hits = self.search_vulntrack_data(db, question, limit=int(payload.get("limit") or 5))
        matched_assets = sorted({hit["title"] for hit in search_hits if hit["entity_type"] == "asset"})
        matched_cves = sorted({hit["title"] for hit in search_hits if hit["entity_type"] == "cve"})
        matched_indicators = sorted({hit["title"] for hit in search_hits if hit["entity_type"] == "indicator"})
        matched_files = sorted({hit["title"] for hit in search_hits if hit["entity_type"] == "file_hash"})
        matched_scans = sorted({hit["title"] for hit in search_hits if hit["entity_type"] == "scan"})

        top_hit = search_hits[0] if search_hits else None
        answer = self._build_copilot_answer(question, search_hits, top_hit)
        recommended_actions = self._build_copilot_actions(search_hits)

        return {
            "answer": answer,
            "matched_assets": matched_assets,
            "matched_cves": matched_cves,
            "matched_indicators": matched_indicators,
            "matched_files": matched_files,
            "matched_scans": matched_scans,
            "recommended_actions": recommended_actions,
            "search_results": search_hits,
        }

    def build_dashboard(self, db: Session) -> dict[str, Any]:
        cves = self.threat_repository.list_cves(db, limit=250)
        indicators = self.threat_repository.list_indicators(db, limit=250)
        correlations = self.threat_repository.list_correlations(db, limit=100)
        assets = self.threat_repository.list_assets(db)
        file_hashes = self.malware_repository.list_file_hashes(db)
        scans = self._list_scans(db, limit=200)
        history_rows = list(db.scalars(select(HashAnalysisHistory).order_by(HashAnalysisHistory.analyzed_at.desc()).limit(200)))

        organization_risk_score = self._calculate_organization_risk_score(cves, indicators, correlations, assets, file_hashes, scans)
        top_threats = self._build_top_threats(db, cves, correlations, file_hashes, limit=5)
        critical_assets = self._build_critical_assets(db, assets, correlations, cves, indicators, file_hashes, limit=5)
        ai_recommendations = self._build_dashboard_recommendations(organization_risk_score, top_threats, critical_assets)
        security_trends = self._build_security_trends(cves, indicators, correlations, file_hashes, scans, history_rows)
        recent_incidents = self._build_recent_incidents(correlations, scans, cves, file_hashes)
        executive_summary = self._build_executive_summary(organization_risk_score, cves, indicators, correlations, assets, file_hashes, scans)

        return {
            "organization_risk_score": organization_risk_score,
            "executive_summary": executive_summary,
            "top_threats": top_threats,
            "critical_assets": critical_assets,
            "ai_recommendations": ai_recommendations,
            "security_trends": security_trends,
            "recent_incidents": recent_incidents,
            "risk_breakdown": {
                "cves": len(cves),
                "indicators": len(indicators),
                "correlations": len(correlations),
                "assets": len(assets),
                "malware_files": len(file_hashes),
                "scan_events": len(scans),
            },
        }

    def generate_report(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        report_type = (payload.get("report_type") or "executive").strip().lower()
        title = payload.get("title") or {
            "executive": "Executive Security Intelligence Report",
            "technical": "Technical Analyst Security Report",
            "risk_summary": "Security Risk Summary",
        }.get(report_type, "Security Intelligence Report")
        dashboard = self.build_dashboard(db)
        limit = max(1, min(int(payload.get("limit") or 5), 10))

        if report_type == "technical":
            sections = [
                {
                    "heading": "Attack Chains",
                    "body": "Correlated attack paths across assets, vulnerabilities, indicators, malware, and scans.",
                    "bullets": [incident["summary"] for incident in dashboard["recent_incidents"][:limit]],
                },
                {
                    "heading": "Evidence",
                    "body": "Technical context extracted from the most relevant correlations and threat records.",
                    "bullets": [
                        threat["summary"]
                        for threat in dashboard["top_threats"][:limit]
                    ],
                },
            ]
        elif report_type == "risk_summary":
            sections = [
                {
                    "heading": "Risk Posture",
                    "body": dashboard["executive_summary"],
                    "bullets": dashboard["ai_recommendations"][:limit],
                },
                {
                    "heading": "Trend Watch",
                    "body": "Recent trend changes in CVEs, indicators, malware, and correlation volume.",
                    "bullets": [f"{row['date']}: risk score {row['risk_score']}" for row in dashboard["security_trends"][-limit:]],
                },
            ]
        else:
            sections = [
                {
                    "heading": "Executive Summary",
                    "body": dashboard["executive_summary"],
                    "bullets": dashboard["ai_recommendations"][:limit],
                },
                {
                    "heading": "Top Risks",
                    "body": "The most important risks currently affecting the environment.",
                    "bullets": [threat["summary"] for threat in dashboard["top_threats"][:limit]],
                },
            ]

        return {
            "report_type": report_type,
            "title": title,
            "generated_at": datetime.now(timezone.utc),
            "executive_summary": dashboard["executive_summary"],
            "sections": sections,
            "recommended_actions": dashboard["ai_recommendations"][:limit],
            "metrics": {
                "organization_risk_score": dashboard["organization_risk_score"],
                "critical_assets": len(dashboard["critical_assets"]),
                "top_threats": len(dashboard["top_threats"]),
                "recent_incidents": len(dashboard["recent_incidents"]),
            },
        }

    def search_vulntrack_data(self, db: Session, query: str, limit: int = 5) -> list[dict[str, Any]]:
        normalized_query = (query or "").strip().lower()
        if not normalized_query:
            return []

        tokens = [token for token in re.split(r"[^a-z0-9]+", normalized_query) if token]
        hits: list[SearchHit] = []

        for cve in self.threat_repository.list_cves(db, limit=200):
            cve_description = self._flatten_cve_description(cve)
            haystack = " ".join(
                [
                    cve.cve_id,
                    cve_description,
                    " ".join(cve.cwe_ids or []),
                    " ".join(cve.attack_tactics or []),
                    " ".join(cve.attack_techniques or []),
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="cve",
                        title=cve.cve_id,
                        snippet=self._truncate(cve_description or "CVE record with no description."),
                        score=score + int((cve.cvss_score or 0.0) * 3),
                        reference=cve.cve_id,
                    )
                )

        for asset in self.threat_repository.list_assets(db):
            haystack = " ".join(
                [
                    asset.asset_name,
                    asset.asset_type,
                    asset.hostname or "",
                    asset.ip_address or "",
                    asset.environment or "",
                    asset.criticality,
                    " ".join(asset.software_inventory or []),
                    " ".join(asset.tags or []),
                    asset.notes or "",
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="asset",
                        title=asset.asset_name,
                        snippet=self._truncate(asset.notes or asset.environment or asset.asset_type),
                        score=score + _CRITICALITY_WEIGHTS.get((asset.criticality or "medium").lower(), 0),
                        reference=str(asset.id),
                    )
                )

        for indicator in self.threat_repository.list_indicators(db, limit=200):
            haystack = " ".join(
                [
                    indicator.indicator_type,
                    indicator.indicator_value,
                    indicator.normalized_value,
                    indicator.source or "",
                    " ".join(indicator.labels or []),
                    " ".join(indicator.mitre_tactics or []),
                    " ".join(indicator.mitre_techniques or []),
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="indicator",
                        title=indicator.indicator_value,
                        snippet=self._truncate(", ".join(indicator.labels or []) or indicator.source or indicator.indicator_type),
                        score=score + max(0, 100 - int(indicator.reputation_score or 0)),
                        reference=str(indicator.id),
                    )
                )

        for file_hash in self.malware_repository.list_file_hashes(db):
            haystack = " ".join(
                [
                    file_hash.sha256,
                    file_hash.file_name or "",
                    file_hash.sanitized_file_name or "",
                    file_hash.vendor_name or "",
                    file_hash.reputation_classification,
                    " ".join(file_hash.virus_total_threat_labels or []),
                    file_hash.threat_summary or "",
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="file_hash",
                        title=file_hash.sha256,
                        snippet=self._truncate(file_hash.file_name or file_hash.threat_summary or file_hash.reputation_classification),
                        score=score + max(0, 100 - int(file_hash.reputation_score or 0)),
                        reference=str(file_hash.id),
                    )
                )

        for scan in self._list_scans(db, limit=100):
            haystack = " ".join(
                [
                    scan.target_value,
                    scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                    " ".join(result.explanation or "" for result in scan.results or []),
                    " ".join(vulnerability.cve_id for vulnerability in scan.vulnerabilities or []),
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="scan",
                        title=scan.target_value,
                        snippet=self._truncate((scan.results[0].explanation if scan.results else None) or scan.target_value),
                        score=score + len(scan.results or []) * 6,
                        reference=str(scan.id),
                    )
                )

        for correlation in self.threat_repository.list_correlations(db, limit=150):
            haystack = " ".join(
                [
                    correlation.threat_summary or "",
                    correlation.business_impact or "",
                    correlation.attack_scenario or "",
                    " ".join(correlation.related_cve_ids or []),
                    " ".join(correlation.related_indicator_values or []),
                    " ".join(correlation.related_assets or []),
                ]
            ).lower()
            score = self._keyword_score(tokens, haystack)
            if score:
                hits.append(
                    SearchHit(
                        entity_type="correlation",
                        title=f"Correlation {correlation.id}",
                        snippet=self._truncate(correlation.threat_summary or correlation.business_impact or "Correlated threat record."),
                        score=score + int(correlation.threat_score or 0),
                        reference=str(correlation.id),
                    )
                )

        unique_hits = self._dedupe_hits(hits)
        unique_hits.sort(key=lambda hit: hit.score, reverse=True)
        return [hit.__dict__ for hit in unique_hits[:limit]]

    def summarize_incident(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        correlation = None
        if payload.get("correlation_id"):
            correlation = self.threat_repository.get_correlation(db, int(payload["correlation_id"]))

        if correlation is None:
            correlation = self._build_transient_correlation(db, payload)

        report_type = (payload.get("summary_type") or "executive").lower()
        if report_type == "technical":
            title = "Technical Incident Summary"
            summary = self._incident_summary_text(correlation)
            sections = [
                "Attack chain and evidence are listed in the correlation output.",
                "Technical responders should validate endpoint telemetry, authentication logs, and network flow data.",
            ]
        elif report_type == "risk":
            title = "Risk Summary"
            summary = self._incident_summary_text(correlation)
            sections = [
                f"Risk score: {self._incident_metric(correlation, 'risk_score')}",
                f"Severity: {self._incident_metric(correlation, 'severity')}",
            ]
        else:
            title = "Executive Incident Summary"
            summary = self._incident_summary_text(correlation)
            sections = [
                "Focus on business impact, downtime risk, and response ownership.",
                "Prioritize patching, containment, and executive stakeholder communication.",
            ]

        return {
            "report_type": report_type,
            "title": title,
            "summary": summary,
            "risk_score": self._incident_metric(correlation, "risk_score"),
            "severity": self._incident_metric(correlation, "severity"),
            "key_findings": sections,
            "next_steps": self._incident_actions(correlation)[:5],
        }

    def _build_transient_correlation(self, db: Session, payload: dict[str, Any]) -> dict[str, Any]:
        return self.correlate_entities(db, payload)

    def _load_scan(self, db: Session, scan_id: int) -> Scan | None:
        if scan_id is None:
            return None
        return db.scalar(
            select(Scan)
            .options(
                selectinload(Scan.results),
                selectinload(Scan.vulnerabilities),
            )
            .where(Scan.id == int(scan_id))
        )

    def _list_scans(self, db: Session, limit: int = 100) -> list[Scan]:
        return list(
            db.scalars(
                select(Scan)
                .options(
                    selectinload(Scan.results),
                    selectinload(Scan.vulnerabilities),
                )
                .order_by(Scan.created_at.desc())
                .limit(limit)
            )
        )

    def _calculate_organization_risk_score(
        self,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        correlations: list[ThreatCorrelation],
        assets: list[ThreatAsset],
        file_hashes: list[FileHash],
        scans: list[Scan],
    ) -> int:
        cve_pressure = min(40, round(mean([cve.cvss_score or 0.0 for cve in cves]) * 4) if cves else 0)
        indicator_pressure = min(20, round(mean([100 - int(indicator.reputation_score or 0) for indicator in indicators]) * 0.2) if indicators else 0)
        malware_pressure = min(20, round(mean([100 - int(file_hash.reputation_score or 0) for file_hash in file_hashes]) * 0.2) if file_hashes else 0)
        scan_pressure = min(15, round(mean([getattr(result, "score", 0) or 0 for scan in scans for result in scan.results or []]) * 0.15) if scans and any(scan.results for scan in scans) else 0)
        critical_asset_pressure = min(20, sum(_CRITICALITY_WEIGHTS.get((asset.criticality or "medium").lower(), 0) for asset in assets[:8]) // 4)
        correlation_pressure = min(15, len(correlations) * 2)
        exploit_pressure = 10 if any(cve.has_known_exploit for cve in cves) else 0
        return max(
            0,
            min(100, cve_pressure + indicator_pressure + malware_pressure + scan_pressure + critical_asset_pressure + correlation_pressure + exploit_pressure),
        )

    def _build_top_threats(
        self,
        db: Session,
        cves: list[ThreatCveRecord],
        correlations: list[ThreatCorrelation],
        file_hashes: list[FileHash],
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        widgets: list[dict[str, Any]] = []
        for correlation in correlations[:limit]:
            widgets.append(
                {
                    "title": f"Correlation {correlation.id}",
                    "score": int(correlation.threat_score or 0),
                    "severity": correlation.severity,
                    "summary": correlation.threat_summary or "Correlated threat record.",
                    "impact": correlation.business_impact or "Business impact not recorded.",
                    "recommended_actions": list(correlation.recommended_actions or []),
                }
            )
        if len(widgets) < limit:
            for cve in sorted(cves, key=lambda item: (item.cvss_score or 0.0, item.has_known_exploit), reverse=True):
                widgets.append(
                    {
                        "title": cve.cve_id,
                        "score": int(round((cve.cvss_score or 0.0) * 10)),
                        "severity": cve.cvss_severity or "UNKNOWN",
                        "summary": self._truncate(self._flatten_cve_description(cve), 160),
                        "impact": self._build_cve_impact(cve),
                        "recommended_actions": self._build_patch_recommendations(cve),
                    }
                )
                if len(widgets) >= limit:
                    break
        if len(widgets) < limit:
            for file_hash in file_hashes:
                widgets.append(
                    {
                        "title": file_hash.file_name or file_hash.sha256[:12],
                        "score": int(file_hash.reputation_score or 0),
                        "severity": file_hash.reputation_classification,
                        "summary": file_hash.threat_summary or "Malware intelligence record.",
                        "impact": file_hash.business_impact or "Potential endpoint compromise or malware execution.",
                        "recommended_actions": list(file_hash.recommended_actions or []),
                    }
                )
                if len(widgets) >= limit:
                    break
        return widgets[:limit]

    def _build_critical_assets(
        self,
        db: Session,
        assets: list[ThreatAsset],
        correlations: list[ThreatCorrelation],
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        scored_assets: list[dict[str, Any]] = []
        correlation_scores = Counter()
        for correlation in correlations:
            for asset_name in correlation.related_assets or []:
                correlation_scores[asset_name] += int(correlation.threat_score or 0)
        for asset in assets:
            risk_score = _CRITICALITY_WEIGHTS.get((asset.criticality or "medium").lower(), 14)
            risk_score += correlation_scores.get(asset.asset_name, 0) // 3
            if asset.environment and asset.environment.lower() in {"prod", "production", "internet-facing"}:
                risk_score += 10
            if any(asset.asset_name.lower() in (correlation.threat_summary or "").lower() for correlation in correlations):
                risk_score += 6
            if any(asset.asset_name.lower() in self._flatten_cve_description(cve).lower() for cve in cves):
                risk_score += 4
            exposure = self._describe_asset_exposure(asset, indicators, file_hashes)
            recommendation = self._asset_recommendation(asset, risk_score)
            scored_assets.append(
                {
                    "asset_id": asset.id,
                    "asset_name": asset.asset_name,
                    "criticality": asset.criticality,
                    "risk_score": min(100, risk_score),
                    "exposure": exposure,
                    "recommendation": recommendation,
                }
            )
        scored_assets.sort(key=lambda item: item["risk_score"], reverse=True)
        return scored_assets[:limit]

    def _build_dashboard_recommendations(
        self,
        organization_risk_score: int,
        top_threats: list[dict[str, Any]],
        critical_assets: list[dict[str, Any]],
    ) -> list[str]:
        actions = [
            "Validate the newest correlations against your asset inventory and patch ownership matrix.",
        ]
        if organization_risk_score >= 80:
            actions.append("Activate incident response review and prioritize containment for externally exposed assets.")
        elif organization_risk_score >= 60:
            actions.append("Schedule emergency remediation for the highest-risk vulnerabilities and malicious indicators.")
        else:
            actions.append("Continue continuous monitoring and close any stale detections or expired alerts.")
        if top_threats:
            actions.append(f"Focus on {top_threats[0]['title']} because it is the highest-priority threat cluster.")
        if critical_assets:
            actions.append(f"Review {critical_assets[0]['asset_name']} first because it is the most exposed critical asset.")
        actions.append("Keep threat feeds, malware verdicts, and scan events synchronized so the model remains current.")
        return actions

    def _build_security_trends(
        self,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        correlations: list[ThreatCorrelation],
        file_hashes: list[FileHash],
        scans: list[Scan],
        history_rows: list[HashAnalysisHistory],
    ) -> list[dict[str, Any]]:
        bucket: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"cve_count": 0, "indicator_count": 0, "malware_count": 0, "scan_count": 0, "correlation_count": 0, "score_total": 0}
        )
        for cve in cves:
            date_key = (cve.last_modified_at or cve.published_at or datetime.now(timezone.utc)).date().isoformat()
            row = bucket[date_key]
            row["cve_count"] += 1
            row["score_total"] += int(round((cve.cvss_score or 0.0) * 10))
        for indicator in indicators:
            date_key = (indicator.last_seen_at or indicator.first_seen_at or datetime.now(timezone.utc)).date().isoformat()
            row = bucket[date_key]
            row["indicator_count"] += 1
            row["score_total"] += max(0, 100 - int(indicator.reputation_score or 0))
        for file_hash in file_hashes:
            date_key = (file_hash.last_analyzed_at or file_hash.created_at).date().isoformat()
            row = bucket[date_key]
            row["malware_count"] += 1
            row["score_total"] += max(0, 100 - int(file_hash.reputation_score or 0))
        for scan in scans:
            date_key = scan.created_at.date().isoformat()
            row = bucket[date_key]
            row["scan_count"] += 1
            row["score_total"] += sum(int(result.score or 0) for result in scan.results or [])
        for correlation in correlations:
            date_key = correlation.correlated_at.date().isoformat()
            row = bucket[date_key]
            row["correlation_count"] += 1
            row["score_total"] += int(correlation.threat_score or 0)
        for history in history_rows:
            date_key = history.analyzed_at.date().isoformat()
            row = bucket[date_key]
            row["malware_count"] += 1
            row["score_total"] += int(history.reputation_score or 0)

        trend_rows: list[dict[str, Any]] = []
        for date_key in sorted(bucket.keys()):
            row = bucket[date_key]
            divisor = max(row["cve_count"] + row["indicator_count"] + row["malware_count"] + row["scan_count"] + row["correlation_count"], 1)
            trend_rows.append(
                {
                    "date": date_key,
                    "risk_score": max(0, min(100, round(row["score_total"] / divisor))),
                    "cve_count": row["cve_count"],
                    "indicator_count": row["indicator_count"],
                    "malware_count": row["malware_count"],
                    "scan_count": row["scan_count"],
                    "correlation_count": row["correlation_count"],
                }
            )
        return trend_rows[-14:]

    def _build_recent_incidents(
        self,
        correlations: list[ThreatCorrelation],
        scans: list[Scan],
        cves: list[ThreatCveRecord],
        file_hashes: list[FileHash],
    ) -> list[dict[str, Any]]:
        incidents: list[dict[str, Any]] = []
        for correlation in correlations[:5]:
            incidents.append(
                {
                    "type": "correlation",
                    "title": correlation.threat_summary or f"Correlation {correlation.id}",
                    "severity": correlation.severity,
                    "risk_score": int(correlation.threat_score or 0),
                    "when": correlation.correlated_at.isoformat(),
                }
            )
        for scan in scans[:3]:
            incidents.append(
                {
                    "type": "scan",
                    "title": scan.target_value,
                    "severity": (scan.results[0].risk_level if scan.results else "unknown"),
                    "risk_score": int(scan.results[0].score or 0) if scan.results else 0,
                    "when": scan.created_at.isoformat(),
                }
            )
        for cve in cves[:2]:
            incidents.append(
                {
                    "type": "cve",
                    "title": cve.cve_id,
                    "severity": cve.cvss_severity or "unknown",
                    "risk_score": int(round((cve.cvss_score or 0.0) * 10)),
                    "when": (cve.last_modified_at or cve.published_at or datetime.now(timezone.utc)).isoformat(),
                }
            )
        if file_hashes:
            file_hash = file_hashes[0]
            incidents.append(
                {
                    "type": "malware",
                    "title": file_hash.file_name or file_hash.sha256[:12],
                    "severity": file_hash.reputation_classification,
                    "risk_score": int(file_hash.reputation_score or 0),
                    "when": file_hash.last_analyzed_at.isoformat() if file_hash.last_analyzed_at else None,
                }
            )
        return incidents[:8]

    def _build_executive_summary(
        self,
        organization_risk_score: int,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        correlations: list[ThreatCorrelation],
        assets: list[ThreatAsset],
        file_hashes: list[FileHash],
        scans: list[Scan],
    ) -> str:
        critical_assets = [asset for asset in assets if (asset.criticality or "").lower() == "critical"]
        exploit_count = sum(1 for cve in cves if cve.has_known_exploit)
        return (
            f"The current organization risk score is {organization_risk_score}/100. "
            f"The platform is tracking {len(cves)} CVEs, {len(indicators)} indicators, {len(file_hashes)} malware records, "
            f"{len(correlations)} correlations, and {len(scans)} recent scan events. "
            f"{exploit_count} vulnerabilities already have known exploit signals, and {len(critical_assets)} assets are marked critical. "
            f"Immediate focus should be on exposed high-value assets, active exploit paths, and any malware-linked indicators that overlap with open CVEs."
        )

    def _build_correlation_summary(
        self,
        severity: str,
        attack_chain: list[dict[str, Any]],
        asset: ThreatAsset | None,
        scans: list[Scan],
    ) -> str:
        asset_text = f" against {asset.asset_name}" if asset else ""
        if attack_chain:
            lead = attack_chain[0]["evidence"]
        else:
            lead = "cross-domain threat evidence"
        return (
            f"The correlated threat posture is {severity.lower()}{asset_text} because {lead}. "
            f"The analysis connected {len(scans)} security events with the most relevant vulnerabilities and threat indicators."
        )

    def _build_correlation_impact(self, severity: str, asset: ThreatAsset | None, scans: list[Scan]) -> str:
        asset_text = asset.asset_name if asset else "the monitored environment"
        if severity == "Critical":
            return f"An attacker could compromise {asset_text}, disrupt operations, and pivot into adjacent systems."
        if severity == "High":
            return f"The exposure could enable unauthorized access or service disruption on {asset_text}."
        if severity == "Medium":
            return f"The issue raises the chance of compromise for {asset_text} and should be remediated promptly."
        return f"The current evidence suggests limited immediate impact on {asset_text}, but monitoring should continue."

    def _build_correlation_actions(
        self,
        severity: str,
        asset: ThreatAsset | None,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        scans: list[Scan],
    ) -> list[str]:
        actions = [
            "Confirm ownership for all correlated records and assign remediation to the responsible teams.",
            "Validate whether any indicators are already blocked in firewall, proxy, and endpoint controls.",
        ]
        if severity in {"Critical", "High"}:
            actions.append("Isolate exposed or suspicious assets until patching and containment are complete.")
            actions.append("Review authentication logs, process telemetry, and network flows for exploitation evidence.")
        if any(file_hash.reputation_classification in {"Critical", "High Risk", "Malicious"} for file_hash in file_hashes):
            actions.append("Quarantine the associated malware hashes and search for matching executions.")
        if any(indicator.indicator_type in {"domain", "url"} for indicator in indicators):
            actions.append("Add web and DNS detections for the matching phishing or C2 infrastructure.")
        if any(scan.results for scan in scans):
            actions.append("Investigate scan results for follow-on activity in adjacent assets.")
        if asset and (asset.criticality or "").lower() == "critical":
            actions.append("Escalate the issue to incident response and business continuity owners.")
        return actions

    def _build_attack_chain(
        self,
        asset: ThreatAsset | None,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        scans: list[Scan],
    ) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        if cves:
            primary_cve = max(cves, key=lambda cve: (cve.cvss_score or 0.0, cve.has_known_exploit))
            access_text = self._build_cve_access_text(primary_cve)
            steps.append({"stage": "Initial Access", "evidence": access_text, "impact": "The attacker can enter the target through the vulnerable service."})
        if any(indicator.indicator_type in {"domain", "url", "ip"} for indicator in indicators):
            matched = indicators[0]
            steps.append(
                {
                    "stage": "Command and Control",
                    "evidence": f"Matched indicator {matched.indicator_value} and reputation level {matched.reputation_level}.",
                    "impact": "The attacker can maintain remote control or deliver payloads.",
                }
            )
        if file_hashes:
            malware = max(file_hashes, key=lambda item: int(item.reputation_score or 0))
            steps.append(
                {
                    "stage": "Execution",
                    "evidence": f"Malware record {malware.sha256[:12]} has reputation {malware.reputation_classification}.",
                    "impact": "Execution of malicious code or loader activity is plausible.",
                }
            )
        if scans:
            scan = scans[0]
            steps.append(
                {
                    "stage": "Validation",
                    "evidence": f"Scan target {scan.target_value} recorded {len(scan.results or [])} analytic result(s).",
                    "impact": "The event stream confirms exposure and helps validate the attack path.",
                }
            )
        if asset:
            steps.append(
                {
                    "stage": "Impact",
                    "evidence": f"High-value asset {asset.asset_name} is classified as {asset.criticality}.",
                    "impact": "Business disruption or data exposure is the likely end state.",
                }
            )
        return steps

    def _build_security_events(
        self,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        scans: list[Scan],
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for cve in cves[:5]:
            events.append(
                {
                    "type": "cve",
                    "name": cve.cve_id,
                    "severity": cve.cvss_severity,
                    "detail": self._truncate(self._flatten_cve_description(cve), 120),
                }
            )
        for indicator in indicators[:5]:
            events.append(
                {
                    "type": "indicator",
                    "name": indicator.indicator_value,
                    "severity": indicator.reputation_level,
                    "detail": self._truncate(", ".join(indicator.labels or []) or indicator.indicator_type, 120),
                }
            )
        for file_hash in file_hashes[:5]:
            events.append(
                {
                    "type": "malware",
                    "name": file_hash.file_name or file_hash.sha256[:12],
                    "severity": file_hash.reputation_classification,
                    "detail": self._truncate(file_hash.threat_summary or file_hash.business_impact or "", 120),
                }
            )
        for scan in scans[:5]:
            events.append(
                {
                    "type": "scan",
                    "name": scan.target_value,
                    "severity": scan.results[0].risk_level if scan.results else "unknown",
                    "detail": self._truncate(scan.results[0].explanation if scan.results else scan.target_value, 120),
                }
            )
        return events

    def _build_copilot_answer(
        self,
        question: str,
        search_hits: list[dict[str, Any]],
        top_hit: dict[str, Any] | None,
    ) -> str:
        if not search_hits:
            return "I could not find a strong match in VulnTrack data. Try naming a CVE, asset, indicator, hash, or scan target."

        lead = top_hit or search_hits[0]
        answer = (
            f"I found {len(search_hits)} related record(s). "
            f"The strongest match is {lead['entity_type']} '{lead['title']}' with score {lead['score']}. "
            f"Context: {lead['snippet']}."
        )
        if any(word in question.lower() for word in ("fix", "remediate", "patch", "recommend")):
            answer += " Focus on patching the exposed vulnerability, blocking related indicators, and isolating critical assets until validation is complete."
        elif any(word in question.lower() for word in ("explain", "what is", "why")):
            answer += " In simple terms, this is the highest-priority item currently visible in the security data."
        else:
            answer += " I can also narrow this down by asset, CVE, malware hash, or incident type."
        return answer

    def _build_copilot_actions(self, search_hits: list[dict[str, Any]]) -> list[str]:
        actions = [
            "Open the highest-scoring result and validate whether it affects production systems.",
            "Check whether the same asset is already covered by an active patch or containment plan.",
        ]
        if any(hit["entity_type"] == "indicator" for hit in search_hits):
            actions.append("Block matching indicators in DNS, proxy, firewall, and EDR controls.")
        if any(hit["entity_type"] == "file_hash" for hit in search_hits):
            actions.append("Quarantine matching malware hashes and look for process execution telemetry.")
        if any(hit["entity_type"] == "cve" for hit in search_hits):
            actions.append("Prioritize patch validation and service restarts for the matching CVE.")
        return actions

    def _build_remediation_steps(
        self,
        cve: ThreatCveRecord | None,
        asset_name: str,
        asset_criticality: str,
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        exploit_available: bool,
    ) -> list[str]:
        steps = [
            f"Patch or mitigate the vulnerable component affecting {asset_name}.",
            "Verify that the issue is removed on a staging host before production rollout.",
            "Confirm service health and regression-test the application after remediation.",
        ]
        if exploit_available:
            steps.insert(0, "Treat this as an actively weaponized issue and patch immediately.")
        if any(indicator.indicator_type in {"domain", "url"} for indicator in indicators):
            steps.append("Block related phishing or command-and-control domains at DNS and proxy layers.")
        if any(file_hash.reputation_classification in {"Critical", "High Risk", "Malicious"} for file_hash in file_hashes):
            steps.append("Search for the matching malware hashes across endpoints and quarantine detections.")
        if (asset_criticality or "").lower() == "critical":
            steps.append("Coordinate change management and incident response so the critical asset remains protected during the fix.")
        if cve and cve.reference_urls:
            steps.append("Use vendor advisories and reference URLs to confirm the exact fixed version.")
        return steps

    def _build_patch_recommendations(self, cve: ThreatCveRecord | None) -> list[str]:
        if cve is None:
            return ["Apply the vendor patch for the affected service and confirm the fix in a controlled test window."]
        recommendations = [
            f"Install the vendor patch for {cve.cve_id} as soon as a maintenance window is available.",
            "Confirm the fixed version with the software owner and change record.",
        ]
        for product in cve.affected_products or []:
            criteria = product.get("criteria")
            if criteria:
                recommendations.append(f"Validate whether CPE {criteria} maps to any installed asset or container image.")
        return recommendations[:4]

    def _build_configuration_fixes(
        self,
        cve: ThreatCveRecord | None,
        asset_criticality: str,
        internet_exposed: bool,
    ) -> list[str]:
        fixes = [
            "Remove unnecessary public exposure and restrict access to trusted source networks.",
            "Ensure authentication, authorization, and logging are enabled on the affected service.",
        ]
        if internet_exposed:
            fixes.append("Place the service behind a WAF or reverse proxy while remediation is underway.")
        if (asset_criticality or "").lower() in {"high", "critical"}:
            fixes.append("Tighten admin access using MFA, least privilege, and network segmentation.")
        if cve and cve.cwe_ids:
            fixes.append(f"Address the underlying weakness types: {', '.join(cve.cwe_ids[:3])}.")
        return fixes

    def _build_hardening_guidance(
        self,
        asset_criticality: str,
        internet_exposed: bool,
        exploit_available: bool,
    ) -> list[str]:
        guidance = [
            "Enable continuous asset inventory, vulnerability scanning, and alert routing.",
            "Keep detection rules tuned for exploit chain behavior, not only single indicators.",
        ]
        if asset_criticality.lower() in {"high", "critical"}:
            guidance.append("Separate critical assets into restricted network zones with strong monitoring.")
        if internet_exposed:
            guidance.append("Enforce rate limiting, bot protection, and stronger authentication on external services.")
        if exploit_available:
            guidance.append("Pre-stage emergency patching and rollback plans for the affected platform.")
        return guidance

    def _build_business_impact(
        self,
        asset_name: str,
        asset_criticality: str,
        severity: str,
        exploit_available: bool,
    ) -> str:
        if severity == "Critical":
            return f"Compromise of {asset_name} could disrupt business operations, expose data, and trigger downstream incident response."
        if severity == "High":
            return f"{asset_name} could be abused to steal data, escalate privileges, or move into adjacent systems."
        if severity == "Medium":
            return f"The issue could affect {asset_name} if the exposure is reachable, so it should be fixed promptly."
        return f"The immediate business impact to {asset_name} is limited, but the control should still be hardened."

    def _build_likelihood_statement(
        self,
        severity: str,
        exploit_available: bool,
        internet_exposed: bool,
        cve: ThreatCveRecord | None,
    ) -> str:
        if exploit_available and internet_exposed:
            return "Exploitation is highly likely because the issue is externally reachable and known exploit activity exists."
        if exploit_available:
            return "Exploitation is likely because attackers already have known techniques for this issue."
        if severity in {"Critical", "High"}:
            return "The vulnerability is likely to be targeted because of its severity and operational exposure."
        return "Exploitation is possible, but the current evidence does not suggest immediate widespread weaponization."

    def _build_cve_access_text(self, cve: ThreatCveRecord) -> str:
        description = self._flatten_cve_description(cve)
        for phrase, aliases in _KEYWORD_PATTERNS.items():
            if any(alias.lower() in description.lower() for alias in aliases):
                return f"{phrase.title()} evidence from {cve.cve_id}."
        return f"{cve.cve_id} indicates a path into the target service."

    def _build_plain_language_summary(
        self,
        *,
        cve: ThreatCveRecord | None,
        description: str | None,
        asset_name: str,
        severity: str,
    ) -> str:
        if cve is not None:
            text = self._flatten_cve_description(cve)
            if text:
                return f"{cve.cve_id} is a {severity.lower()} vulnerability that may let an attacker compromise {asset_name}. {self._truncate(text, 220)}"
            return f"{cve.cve_id} is a {severity.lower()} vulnerability that may let an attacker compromise {asset_name}."
        if description:
            return f"The vulnerability description suggests a {severity.lower()} issue affecting {asset_name}. {self._truncate(description, 220)}"
        return f"This is a {severity.lower()} issue affecting {asset_name}; treat it as a security exposure that needs review."

    def _build_attack_methods(
        self,
        cve: ThreatCveRecord | None,
        description: str | None,
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> list[str]:
        methods: list[str] = []
        if cve is not None:
            methods.extend([f"{tactic}" for tactic in cve.attack_tactics or []])
            methods.extend([f"{technique}" for technique in cve.attack_techniques or []])
        indicator_text = " ".join(" ".join(indicator.labels or []) for indicator in indicators)
        malware_text = " ".join(" ".join(file_hash.virus_total_threat_labels or []) for file_hash in file_hashes)
        text = " ".join(
            [
                description or "",
                self._flatten_cve_description(cve) if cve else "",
                indicator_text,
                malware_text,
            ]
        ).lower()
        for phrase in _KEYWORD_PATTERNS:
            if phrase in text:
                methods.append(phrase.title())
        if not methods and text:
            methods.extend(["Initial access", "Execution", "Privilege escalation"])
        return self._dedupe_strings(methods)[:6]

    def _collect_related_assets(
        self,
        db: Session,
        cve: ThreatCveRecord | None,
        asset: ThreatAsset | None,
    ) -> list[str]:
        names: list[str] = []
        if asset is not None:
            names.append(asset.asset_name)
        if cve is not None:
            for correlation in self.threat_repository.list_correlations(db, limit=100):
                if cve.cve_id in (correlation.related_cve_ids or []) and correlation.related_assets:
                    names.extend(correlation.related_assets)
        return self._dedupe_strings(names)

    def _collect_related_threat_signals(
        self,
        cve: ThreatCveRecord | None,
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> list[str]:
        signals: list[str] = []
        if cve is not None:
            signals.extend(cve.attack_techniques or [])
            signals.extend(cve.attack_tactics or [])
        for indicator in indicators:
            signals.extend(indicator.labels or [])
            signals.extend(indicator.mitre_techniques or [])
        for file_hash in file_hashes:
            signals.extend(file_hash.virus_total_threat_labels or [])
            signals.append(file_hash.reputation_classification)
        return self._dedupe_strings([signal for signal in signals if signal])

    def _related_correlation_ids(self, db: Session, cve: ThreatCveRecord | None) -> list[int]:
        if cve is None:
            return []
        return [
            correlation.id
            for correlation in self.threat_repository.list_correlations(db, limit=100)
            if cve.cve_id in (correlation.related_cve_ids or [])
        ]

    def _estimate_cvss(self, description: str | None) -> float:
        text = (description or "").lower()
        if any(keyword in text for keyword in ("remote code execution", "command injection", "authentication bypass")):
            return 9.8
        if any(keyword in text for keyword in ("privilege escalation", "sql injection", "path traversal")):
            return 8.8
        if any(keyword in text for keyword in ("phishing", "malicious attachment")):
            return 7.5
        return 5.0

    def _estimate_threat_intelligence_score(
        self,
        cve: ThreatCveRecord | None,
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> int:
        score = 0
        if cve is not None:
            score += 35 if cve.has_known_exploit else 18
            score += min(25, len(cve.attack_techniques or []) * 6 + len(cve.attack_tactics or []) * 4)
            score += 10 if cve.reference_urls else 0
        score += sum(max(0, 100 - int(indicator.reputation_score or 0)) // 6 for indicator in indicators)
        score += sum(max(0, 100 - int(file_hash.reputation_score or 0)) // 8 for file_hash in file_hashes)
        return max(0, min(100, score))

    def _estimate_malware_reputation(self, file_hashes: list[FileHash]) -> int:
        if not file_hashes:
            return 100
        return int(mean([float(file_hash.reputation_score or 0) for file_hash in file_hashes]))

    def _build_impact(self, severity: str, asset_name: str) -> str:
        if severity == "Critical":
            return f"Critical business processes tied to {asset_name} could be interrupted or fully compromised."
        if severity == "High":
            return f"{asset_name} could lose confidentiality or availability if the vulnerability is exploited."
        if severity == "Medium":
            return f"{asset_name} remains at meaningful risk unless the vulnerability is remediated quickly."
        return f"{asset_name} is not under immediate pressure, but defense-in-depth should still be reinforced."

    @staticmethod
    def _truncate(value: str | None, length: int = 140) -> str:
        text = (value or "").strip()
        if len(text) <= length:
            return text
        return text[: length - 1].rstrip() + "…"

    @staticmethod
    def _flatten_cve_description(cve: ThreatCveRecord | None) -> str:
        if cve is None:
            return ""
        descriptions = cve.descriptions or []
        for item in descriptions:
            if item.get("value"):
                return str(item["value"])
        return ""

    @staticmethod
    def _keyword_score(tokens: list[str], haystack: str) -> int:
        score = 0
        for token in tokens:
            if token and token in haystack:
                score += 5
        return score

    @staticmethod
    def _dedupe_hits(hits: list[SearchHit]) -> list[SearchHit]:
        seen: set[tuple[str, str]] = set()
        deduped: list[SearchHit] = []
        for hit in hits:
            key = (hit.entity_type, hit.title)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hit)
        return deduped

    @staticmethod
    def _dedupe_strings(values: list[str]) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for value in values:
            normalized = value.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)
        return output

    @staticmethod
    def _merge_actions(primary: list[str], secondary: list[str]) -> list[str]:
        return AISecurityIntelligenceService._dedupe_strings([*(primary or []), *(secondary or [])])

    @staticmethod
    def _severity_from_score(score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 65:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    @staticmethod
    def _build_risk_explanation(severity: str, factors: list[dict[str, Any]], notes: str | None) -> str:
        if not factors:
            return "No major risk factors were identified."
        top_factors = ", ".join(factor["label"] for factor in factors[:4])
        if notes:
            return f"The issue is assessed as {severity.lower()} because {top_factors}. Narrative context also suggests additional exposure."
        return f"The issue is assessed as {severity.lower()} because {top_factors}."

    @staticmethod
    def _build_risk_actions(severity: str, exploit_available: bool, internet_exposed: bool, asset_criticality: str) -> list[str]:
        actions = ["Patch the vulnerable service and verify the fix on a test system."]
        if exploit_available:
            actions.append("Treat the issue as weaponized and accelerate patching.")
        if internet_exposed:
            actions.append("Reduce exposure with WAF, access control, or temporary isolation.")
        if (asset_criticality or "").lower() in {"high", "critical"}:
            actions.append("Notify asset owners and align remediation with change management.")
        if severity in {"Critical", "High"}:
            actions.append("Review for active exploitation and collect endpoint telemetry.")
        return actions

    @staticmethod
    def _describe_asset_exposure(
        asset: ThreatAsset,
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> str:
        exposure = []
        if asset.environment:
            exposure.append(asset.environment)
        if asset.software_inventory:
            exposure.append(f"{len(asset.software_inventory)} software package(s)")
        if any(indicator.indicator_type in {"domain", "url"} for indicator in indicators):
            exposure.append("matches hostile web infrastructure")
        if any(file_hash.reputation_classification in {"Critical", "High Risk", "Malicious"} for file_hash in file_hashes):
            exposure.append("paired with malicious file activity")
        return ", ".join(exposure) if exposure else "baseline exposure only"

    @staticmethod
    def _asset_recommendation(asset: ThreatAsset, risk_score: int) -> str:
        if risk_score >= 80:
            return "Isolate and patch immediately."
        if risk_score >= 60:
            return "Prioritize remediation in the next maintenance window."
        if risk_score >= 40:
            return "Validate exposure and schedule remediation."
        return "Monitor and maintain standard hardening."

    @staticmethod
    @staticmethod
    def _is_public_facing(asset: ThreatAsset | None) -> bool:
        if asset is None:
            return False
        values = " ".join(
            filter(
                None,
                [
                    asset.environment or "",
                    asset.asset_type or "",
                    asset.tags and " ".join(asset.tags),
                ],
            )
        ).lower()
        return any(keyword in values for keyword in ("prod", "production", "internet", "public", "external"))

    @staticmethod
    def _build_cve_impact(cve: ThreatCveRecord) -> str:
        if cve.cvss_severity == "CRITICAL":
            return "High-confidence exploitation could cause major service outage or data exposure."
        if cve.cvss_severity == "HIGH":
            return "Likely to enable unauthorized access or privilege escalation if exposed."
        if cve.cvss_severity == "MEDIUM":
            return "Moderate exploitation impact with targeted remediation required."
        return "Low immediate impact, but still worth tracking for defense in depth."

    @staticmethod
    def _incident_summary_text(correlation: Any) -> str:
        if isinstance(correlation, dict):
            return str(correlation.get("summary") or correlation.get("threat_summary") or "No summary available.")
        return str(getattr(correlation, "threat_summary", None) or "No summary available.")

    @staticmethod
    def _incident_metric(correlation: Any, field_name: str) -> Any:
        if isinstance(correlation, dict):
            return correlation.get(field_name)
        if field_name == "risk_score":
            return getattr(correlation, "threat_score", None)
        return getattr(correlation, field_name, None)

    @staticmethod
    def _incident_actions(correlation: Any) -> list[str]:
        if isinstance(correlation, dict):
            return list(correlation.get("recommended_actions") or [])
        return list(getattr(correlation, "recommended_actions", None) or [])


class AISecuritySummaryService:
    def __init__(self, intelligence_service: AISecurityIntelligenceService | None = None) -> None:
        self.intelligence_service = intelligence_service or AISecurityIntelligenceService()
