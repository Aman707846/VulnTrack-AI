from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models.malware_intelligence import FileHash
from backend.app.models.threat_intelligence import (
    AttackTechnique,
    ThreatAsset,
    ThreatCorrelation,
    ThreatCveRecord,
    ThreatIndicator,
    ThreatSyncRun,
)
from backend.app.repositories.malware_intelligence import MalwareIntelligenceRepository
from backend.app.repositories.threat_intelligence import (
    DEFAULT_ATTACK_TECHNIQUES,
    ThreatIntelligenceRepository,
    normalize_indicator_value,
)


logger = logging.getLogger(__name__)

NVD_BASE_URL = os.getenv("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0").rstrip("/")
NVD_API_KEY = (os.getenv("NVD_API_KEY") or "").strip()
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
NVD_LOOKBACK_DAYS = int(os.getenv("NVD_LOOKBACK_DAYS", "7"))
ATTACK_BUNDLE_URL = os.getenv(
    "ATTACK_BUNDLE_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
)
THREAT_INTEL_SYNC_INTERVAL_MINUTES = int(os.getenv("THREAT_INTEL_SYNC_INTERVAL_MINUTES", "360"))
THREAT_INTEL_SCHEDULER_ENABLED = os.getenv("THREAT_INTEL_SCHEDULER_ENABLED", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
THREAT_INTEL_MAX_PAGE_SIZE = 2000


class ThreatIntelError(RuntimeError):
    pass


@dataclass(frozen=True)
class ThreatIntelSyncResult:
    sync_run: ThreatSyncRun
    ingested: int
    updated: int


@dataclass(frozen=True)
class ThreatAnalysisResult:
    threat_score: int
    severity: str
    explanation: str
    business_impact: str
    attack_scenario: str
    recommended_actions: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    correlated_cve_ids: list[str]
    correlated_indicator_values: list[str]
    correlated_assets: list[str]
    evidence: dict[str, Any]


_CVE_TECHNIQUE_RULES: list[tuple[tuple[str, ...], list[str]]] = [
    (("remote code execution", "arbitrary code execution", "code execution", "command injection"), ["T1190", "T1059"]),
    (("privilege escalation", "elevation of privilege", "local privilege escalation"), ["T1068"]),
    (("authentication bypass", "auth bypass", "credential theft", "credential disclosure", "login bypass"), ["T1556", "T1110"]),
    (("phishing", "malicious attachment", "malicious document"), ["T1566"]),
    (("deserialization", "serialization", "pickle", "yaml load"), ["T1190", "T1059"]),
    (("path traversal", "directory traversal", "file write", "arbitrary file write"), ["T1190"]),
    (("sql injection", "sqli"), ["T1190", "T1059"]),
    (("server-side request forgery", "ssrf"), ["T1190"]),
    (("buffer overflow", "memory corruption", "out-of-bounds", "use-after-free"), ["T1190"]),
    (("cross-site scripting", "xss"), ["T1190"]),
]

_INDICATOR_TECHNIQUE_RULES: list[tuple[tuple[str, ...], list[str]]] = [
    (("phish", "spoof", "fake login", "credential"), ["T1566", "T1071"]),
    (("c2", "command and control", "beacon", "callback", "botnet"), ["T1071", "T1041"]),
    (("ransom", "encrypt", "locker"), ["T1486", "T1489"]),
    (("dropper", "loader", "downloader"), ["T1105", "T1059"]),
    (("stealer", "keylogger", "credential", "password"), ["T1556", "T1110"]),
    (("obfus", "packed", "encoded"), ["T1027"]),
]

_MALWARE_LABEL_TECHNIQUE_RULES: list[tuple[tuple[str, ...], list[str]]] = [
    (("trojan", "backdoor", "remote access", "rAT"), ["T1071", "T1059"]),
    (("ransom", "encrypt", "locker"), ["T1486", "T1489"]),
    (("stealer", "keylogger", "credential"), ["T1556", "T1110"]),
    (("dropper", "loader"), ["T1105", "T1027"]),
    (("rootkit", "kernel"), ["T1055"]),
]

_TTP_BY_ID = {
    technique["technique_id"]: technique
    for technique in DEFAULT_ATTACK_TECHNIQUES
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso8601(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: Any) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _safe_get_string(values: list[dict[str, Any]] | None, lang: str = "en") -> str | None:
    if not values:
        return None
    for item in values:
        if item.get("lang") == lang and item.get("value"):
            return str(item["value"])
    for item in values:
        if item.get("value"):
            return str(item["value"])
    return None


class NvdClient:
    def __init__(self, *, base_url: str = NVD_BASE_URL, api_key: str = NVD_API_KEY, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def fetch_recent_cves(
        self,
        *,
        start_date: datetime,
        end_date: datetime,
        page_size: int = NVD_RESULTS_PER_PAGE,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        start_index = 0
        total_results: int | None = None

        while total_results is None or start_index < total_results:
            payload = self._fetch_page(
                start_date=start_date,
                end_date=end_date,
                start_index=start_index,
                page_size=page_size,
            )
            vulnerabilities = payload.get("vulnerabilities") or []
            total_results = int(payload.get("totalResults") or len(vulnerabilities))
            results.extend(vulnerabilities)
            if not vulnerabilities or len(vulnerabilities) < page_size:
                break
            start_index += page_size
        return results

    def _fetch_page(
        self,
        *,
        start_date: datetime,
        end_date: datetime,
        start_index: int,
        page_size: int,
    ) -> dict[str, Any]:
        params = {
            "lastModStartDate": _to_iso8601(start_date),
            "lastModEndDate": _to_iso8601(end_date),
            "startIndex": str(start_index),
            "resultsPerPage": str(min(page_size, THREAT_INTEL_MAX_PAGE_SIZE)),
        }
        query = urllib.parse.urlencode({key: value for key, value in params.items() if value})
        url = f"{self.base_url}?{query}"
        headers = {
            "accept": "application/json",
            "user-agent": "VulnTrack-AI/Phase2-Threat-Intel",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        request = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class AttackTechniquesClient:
    def __init__(self, *, bundle_url: str = ATTACK_BUNDLE_URL, timeout: int = 30) -> None:
        self.bundle_url = bundle_url
        self.timeout = timeout

    def fetch_bundle(self) -> dict[str, Any]:
        request = urllib.request.Request(
            self.bundle_url,
            headers={"accept": "application/json", "user-agent": "VulnTrack-AI/Phase2-Threat-Intel"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class ThreatIntelMapper:
    def __init__(self, repository: ThreatIntelligenceRepository | None = None) -> None:
        self.repository = repository or ThreatIntelligenceRepository()

    def map_cve(self, cve: ThreatCveRecord) -> tuple[list[str], list[str]]:
        text = " ".join(
            part
            for part in [
                cve.cve_id,
                cve.source_identifier or "",
                self._flatten_descriptions(cve.descriptions),
                " ".join(cve.cwe_ids or []),
                " ".join(product.get("criteria", "") for product in cve.affected_products or []),
            ]
            if part
        ).lower()
        technique_ids: set[str] = set(cve.attack_techniques or [])
        tactic_names: set[str] = set(cve.attack_tactics or [])
        for keywords, mapped_ids in _CVE_TECHNIQUE_RULES:
            if any(keyword in text for keyword in keywords):
                technique_ids.update(mapped_ids)
        for technique_id in list(technique_ids):
            technique = _TTP_BY_ID.get(technique_id)
            if technique:
                tactic_names.add(technique["tactic_name"])
        return sorted(tactic_names), sorted(technique_ids)

    def map_indicator(self, indicator: ThreatIndicator) -> tuple[list[str], list[str]]:
        text = f"{indicator.indicator_type} {indicator.indicator_value} {' '.join(indicator.labels or [])}".lower()
        technique_ids: set[str] = set(indicator.mitre_techniques or [])
        tactic_names: set[str] = set(indicator.mitre_tactics or [])
        for keywords, mapped_ids in _INDICATOR_TECHNIQUE_RULES:
            if any(keyword in text for keyword in keywords):
                technique_ids.update(mapped_ids)
        if indicator.indicator_type in {"ip", "domain", "url"} and any(label in text for label in ("malware", "c2", "botnet")):
            technique_ids.update({"T1071"})
        for technique_id in list(technique_ids):
            technique = _TTP_BY_ID.get(technique_id)
            if technique:
                tactic_names.add(technique["tactic_name"])
        return sorted(tactic_names), sorted(technique_ids)

    def map_malware_hash(self, file_hash: FileHash) -> tuple[list[str], list[str]]:
        text = " ".join(
            part
            for part in [
                file_hash.file_name or "",
                file_hash.sanitized_file_name or "",
                " ".join(file_hash.virus_total_threat_labels or []),
                file_hash.signature_status or "",
                file_hash.reputation_classification or "",
            ]
            if part
        ).lower()
        technique_ids: set[str] = set()
        tactic_names: set[str] = set()
        for keywords, mapped_ids in _MALWARE_LABEL_TECHNIQUE_RULES:
            if any(keyword.lower() in text for keyword in keywords):
                technique_ids.update(mapped_ids)
        if file_hash.signature_status == "unsigned":
            technique_ids.add("T1027")
        for technique_id in list(technique_ids):
            technique = _TTP_BY_ID.get(technique_id)
            if technique:
                tactic_names.add(technique["tactic_name"])
        return sorted(tactic_names), sorted(technique_ids)

    @staticmethod
    def _flatten_descriptions(descriptions: list[dict[str, Any]]) -> str:
        return " ".join(
            str(item.get("value") or "")
            for item in descriptions or []
            if item.get("value")
        )


class ThreatAnalysisEngine:
    def __init__(self, repository: ThreatIntelligenceRepository | None = None) -> None:
        self.repository = repository or ThreatIntelligenceRepository()

    def analyze(
        self,
        *,
        asset: ThreatAsset | None,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        technique_map: dict[str, AttackTechnique],
    ) -> ThreatAnalysisResult:
        factor_rows: list[tuple[int, str, str]] = []
        correlated_cve_ids = [cve.cve_id for cve in cves]
        correlated_indicator_values = [indicator.indicator_value for indicator in indicators]
        correlated_assets = [asset.asset_name] if asset else []
        mitre_techniques: set[str] = set()
        mitre_tactics: set[str] = set()

        score = 0
        for cve in cves:
            cve_score = int(round((cve.cvss_score or 0.0) * 10))
            if cve.cvss_severity == "CRITICAL":
                cve_score += 20
            elif cve.cvss_severity == "HIGH":
                cve_score += 12
            if cve.has_known_exploit:
                cve_score += 12
            if cve.reference_urls:
                cve_score += 3
            if cve_score:
                factor_rows.append((cve_score, "CVE exposure", f"{cve.cve_id} contributes {cve_score} threat points"))
            score += cve_score
            mitre_techniques.update(cve.attack_techniques or [])
            mitre_tactics.update(cve.attack_tactics or [])

        for indicator in indicators:
            indicator_score = max(0, 100 - int(indicator.reputation_score or 50))
            indicator_score += 10 if indicator.indicator_type in {"ip", "domain", "url"} else 6
            indicator_score += 8 if indicator.reputation_level in {"malicious", "high", "critical"} else 0
            if indicator_score:
                factor_rows.append((indicator_score, "Threat indicator", f"{indicator.indicator_value} contributes {indicator_score} threat points"))
            score += indicator_score
            mitre_techniques.update(indicator.mitre_techniques or [])
            mitre_tactics.update(indicator.mitre_tactics or [])

        for file_hash in file_hashes:
            file_score = max(0, 100 - int(file_hash.reputation_score or 0))
            if file_hash.reputation_classification in {"Critical", "High Risk", "Malicious"}:
                file_score += 15
            elif file_hash.reputation_classification in {"Medium Risk", "Suspicious"}:
                file_score += 8
            elif file_hash.reputation_classification in {"Low Risk", "Trusted", "Likely Trusted"}:
                file_score += 2
            else:
                file_score += 5
            if file_hash.signature_status == "unsigned":
                file_score += 10
            if file_score:
                factor_rows.append((file_score, "Malware reputation", f"{file_hash.sha256[:12]} contributes {file_score} threat points"))
            score += file_score
            file_tactics, file_techniques = ThreatIntelMapper(self.repository).map_malware_hash(file_hash)
            mitre_techniques.update(file_techniques)
            mitre_tactics.update(file_tactics)

        if asset is not None:
            asset_weight = {
                "low": 5,
                "medium": 12,
                "high": 22,
                "critical": 32,
            }.get((asset.criticality or "medium").lower(), 12)
            if asset.environment and asset.environment.lower() in {"prod", "production", "internet-facing"}:
                asset_weight += 10
            if asset_weight:
                factor_rows.append((asset_weight, "Asset criticality", f"{asset.asset_name} adds {asset_weight} threat points"))
            score += asset_weight

        overlap_bonus = self._overlap_bonus(cves=cves, indicators=indicators, file_hashes=file_hashes)
        if overlap_bonus:
            factor_rows.append((overlap_bonus, "Threat correlation", f"Cross-domain evidence adds {overlap_bonus} threat points"))
            score += overlap_bonus

        if score >= 85:
            severity = "Critical"
        elif score >= 65:
            severity = "High"
        elif score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        score = max(0, min(100, score))
        sorted_factors = sorted(factor_rows, key=lambda item: item[0], reverse=True)
        explanation = self._build_explanation(severity, sorted_factors, asset, cves, indicators, file_hashes)
        business_impact = self._build_business_impact(severity, asset, cves, indicators, file_hashes)
        attack_scenario = self._predict_attack_scenario(sorted(mitre_techniques), sorted(mitre_tactics), asset)
        recommended_actions = self._recommended_actions(severity, cves, indicators, file_hashes, asset)
        evidence = {
            "top_factors": [
                {"score": score_value, "category": category, "detail": detail}
                for score_value, category, detail in sorted_factors[:5]
            ],
            "overlap_bonus": overlap_bonus,
            "asset_criticality": asset.criticality if asset else None,
        }
        return ThreatAnalysisResult(
            threat_score=score,
            severity=severity,
            explanation=explanation,
            business_impact=business_impact,
            attack_scenario=attack_scenario,
            recommended_actions=recommended_actions,
            mitre_tactics=sorted(mitre_tactics),
            mitre_techniques=sorted(mitre_techniques),
            correlated_cve_ids=correlated_cve_ids,
            correlated_indicator_values=correlated_indicator_values,
            correlated_assets=correlated_assets,
            evidence=evidence,
        )

    @staticmethod
    def _overlap_bonus(
        *,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> int:
        bonus = 0
        if cves and indicators:
            bonus += 12
        if cves and file_hashes:
            bonus += 10
        if indicators and file_hashes:
            bonus += 10
        if len(cves) + len(indicators) + len(file_hashes) > 2:
            bonus += 8
        return bonus

    @staticmethod
    def _build_explanation(
        severity: str,
        factors: list[tuple[int, str, str]],
        asset: ThreatAsset | None,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> str:
        asset_text = f" for asset {asset.asset_name}" if asset else ""
        if not factors:
            return f"No substantial correlated threat evidence was identified{asset_text}."
        top_details = "; ".join(detail for _, _, detail in factors[:3])
        return (
            f"The correlated threat posture is {severity.lower()}{asset_text} because {top_details}. "
            f"The analysis combined {len(cves)} CVEs, {len(indicators)} indicators, and {len(file_hashes)} malware records."
        )

    @staticmethod
    def _build_business_impact(
        severity: str,
        asset: ThreatAsset | None,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
    ) -> str:
        asset_text = asset.asset_name if asset else "the environment"
        if severity == "Critical":
            return (
                f"Immediate exploitation could lead to service outage, privilege escalation, credential theft, "
                f"and broad compromise of {asset_text}."
            )
        if severity == "High":
            return (
                f"The combined exposure materially increases the chance of initial compromise and lateral movement "
                f"against {asset_text}."
            )
        if severity == "Medium":
            return (
                f"The exposure requires prioritized remediation to prevent exploitation of {asset_text} and adjacent systems."
            )
        return f"The current evidence suggests limited immediate impact on {asset_text}, but control validation is still recommended."

    @staticmethod
    def _predict_attack_scenario(techniques: list[str], tactics: list[str], asset: ThreatAsset | None) -> str:
        technique_text = ", ".join(techniques[:3]) if techniques else "generic adversary tradecraft"
        tactic_text = ", ".join(tactics[:3]) if tactics else "multi-stage compromise"
        asset_text = asset.asset_name if asset else "the target environment"
        return (
            f"An attacker may chain {tactic_text} activity using {technique_text} against {asset_text}, "
            f"progressing from initial access to execution and impact."
        )

    @staticmethod
    def _recommended_actions(
        severity: str,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        file_hashes: list[FileHash],
        asset: ThreatAsset | None,
    ) -> list[str]:
        actions = [
            "Validate all correlated assets against the latest threat feed and patch status.",
            "Block or monitor matched indicators at DNS, proxy, firewall, and endpoint layers.",
        ]
        if severity in {"Critical", "High"}:
            actions.extend(
                [
                    "Prioritize emergency patching for exposed CVEs.",
                    "Isolate vulnerable or actively targeted assets until remediation is complete.",
                    "Review endpoint telemetry for signs of exploit chaining or malware execution.",
                ]
            )
        elif severity == "Medium":
            actions.extend(
                [
                    "Schedule remediation in the next maintenance window.",
                    "Increase monitoring on affected subnets and privileged identities.",
                ]
            )
        else:
            actions.append("Maintain routine monitoring and re-evaluate when the threat feed updates.")
        if any(indicator.indicator_type in {"domain", "url"} for indicator in indicators):
            actions.append("Add phishing and web filtering detections for the matching domains and URLs.")
        if any(file_hash.signature_status == "unsigned" for file_hash in file_hashes):
            actions.append("Quarantine unsigned binaries that align with the same threat cluster.")
        if asset is not None and asset.criticality.lower() == "critical":
            actions.append("Escalate the incident to incident response and business continuity stakeholders.")
        return actions


class ThreatIntelSyncService:
    def __init__(
        self,
        repository: ThreatIntelligenceRepository | None = None,
        malware_repository: MalwareIntelligenceRepository | None = None,
        nvd_client: NvdClient | None = None,
        attack_client: AttackTechniquesClient | None = None,
        mapper: ThreatIntelMapper | None = None,
    ) -> None:
        self.repository = repository or ThreatIntelligenceRepository()
        self.malware_repository = malware_repository or MalwareIntelligenceRepository()
        self.nvd_client = nvd_client or NvdClient()
        self.attack_client = attack_client or AttackTechniquesClient()
        self.mapper = mapper or ThreatIntelMapper(self.repository)
        self.analysis_engine = ThreatAnalysisEngine(self.repository)

    def sync_nvd(self, db: Session, *, lookback_days: int = NVD_LOOKBACK_DAYS, force: bool = False) -> ThreatIntelSyncResult:
        last_run = self.repository.get_latest_sync_run(db, "nvd")
        if not force and last_run and last_run.finished_at:
            start_date = last_run.finished_at - timedelta(minutes=5)
        else:
            start_date = _utc_now() - timedelta(days=max(1, min(lookback_days, 120)))
        end_date = _utc_now()
        run = self.repository.start_sync_run(
            db,
            sync_type="nvd",
            source=NVD_BASE_URL,
            metadata={"lookback_days": lookback_days, "force": force},
        )
        ingested = 0
        updated = 0
        try:
            raw_records = self.nvd_client.fetch_recent_cves(start_date=start_date, end_date=end_date)
            for raw_record in raw_records:
                cve_record, created = self._build_cve_record(raw_record)
                existing = self.repository.get_cve(db, cve_record.cve_id)
                cve_record.attack_tactics, cve_record.attack_techniques = self.mapper.map_cve(cve_record)
                stored = self.repository.upsert_cve(db, cve_record)
                if created or existing is None:
                    ingested += 1
                else:
                    updated += 1
                db.flush()
            self.repository.finish_sync_run(
                db,
                run,
                status="completed",
                records_ingested=ingested,
                records_updated=updated,
                metadata={
                    "start_date": _to_iso8601(start_date),
                    "end_date": _to_iso8601(end_date),
                    "total_results": len(raw_records),
                },
            )
            db.commit()
            return ThreatIntelSyncResult(sync_run=run, ingested=ingested, updated=updated)
        except Exception as exc:
            db.rollback()
            self.repository.finish_sync_run(
                db,
                run,
                status="failed",
                records_ingested=ingested,
                records_updated=updated,
                error_message=str(exc),
                metadata={
                    "start_date": _to_iso8601(start_date),
                    "end_date": _to_iso8601(end_date),
                },
            )
            db.commit()
            raise

    def sync_attack_techniques(self, db: Session, *, force: bool = False) -> ThreatIntelSyncResult:
        run = self.repository.start_sync_run(
            db,
            sync_type="attack",
            source=ATTACK_BUNDLE_URL,
            metadata={"force": force},
        )
        ingested = 0
        updated = 0
        try:
            bundle = self.attack_client.fetch_bundle()
            objects = bundle.get("objects") or []
            for obj in objects:
                if obj.get("type") != "attack-pattern":
                    continue
                technique = self._build_attack_technique(obj)
                preexisting = db.get(AttackTechnique, technique.technique_id)
                self.repository.upsert_attack_technique(db, technique)
                if preexisting is None:
                    ingested += 1
                else:
                    updated += 1
            self.repository.finish_sync_run(
                db,
                run,
                status="completed",
                records_ingested=ingested,
                records_updated=updated,
                metadata={"source_objects": len(objects)},
            )
            db.commit()
            return ThreatIntelSyncResult(sync_run=run, ingested=ingested, updated=updated)
        except Exception as exc:
            db.rollback()
            self.repository.finish_sync_run(
                db,
                run,
                status="failed",
                error_message=str(exc),
            )
            db.commit()
            raise

    def seed_defaults(self, db: Session) -> None:
        self.repository.seed_default_attack_techniques(db)

    def ingest_indicator(
        self,
        db: Session,
        *,
        indicator_type: str,
        indicator_value: str,
        source: str | None = None,
        reputation_score: int | None = None,
        reputation_level: str | None = None,
        confidence: int | None = None,
        severity: str | None = None,
        labels: list[str] | None = None,
        expires_at: datetime | None = None,
        first_seen_at: datetime | None = None,
        last_seen_at: datetime | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> ThreatIndicator:
        normalized_value = normalize_indicator_value(indicator_type, indicator_value)
        indicator = ThreatIndicator(
            indicator_type=indicator_type.lower().strip(),
            indicator_value=indicator_value.strip(),
            normalized_value=normalized_value,
            source=source,
            reputation_score=reputation_score if reputation_score is not None else self._default_indicator_score(indicator_type, labels or []),
            reputation_level=reputation_level or self._default_indicator_level(reputation_score, labels or []),
            confidence=confidence if confidence is not None else self._default_confidence(labels or []),
            severity=severity,
            labels=labels or [],
            first_seen_at=first_seen_at or _utc_now(),
            last_seen_at=last_seen_at or _utc_now(),
            expires_at=expires_at,
            mitre_tactics=[],
            mitre_techniques=[],
            raw_payload=raw_payload or {},
        )
        mapped_tactics, mapped_techniques = self.mapper.map_indicator(indicator)
        indicator.mitre_tactics = mapped_tactics
        indicator.mitre_techniques = mapped_techniques
        stored = self.repository.upsert_indicator(db, indicator)
        db.commit()
        db.refresh(stored)
        return stored

    def correlate(
        self,
        db: Session,
        *,
        asset_id: int | None = None,
        cve_ids: list[str] | None = None,
        indicator_ids: list[int] | None = None,
        file_hash_ids: list[int] | None = None,
        indicator_values: list[str] | None = None,
        notes: str | None = None,
    ) -> ThreatAnalysisResult:
        asset = self.repository.get_asset(db, asset_id) if asset_id else None
        cves = [self.repository.get_cve(db, cve_id) for cve_id in (cve_ids or [])]
        cves = [cve for cve in cves if cve is not None]
        indicators = [self.repository.get_indicator(db, indicator_id) for indicator_id in (indicator_ids or [])]
        indicators = [indicator for indicator in indicators if indicator is not None]
        if indicator_values:
            for value in indicator_values:
                normalized = normalize_indicator_value("generic", value)
                matched = db.scalar(select(ThreatIndicator).where(ThreatIndicator.normalized_value == normalized))
                if matched is not None:
                    indicators.append(matched)
        file_hashes = [
            db.get(FileHash, file_hash_id)
            for file_hash_id in (file_hash_ids or [])
        ]
        file_hashes = [file_hash for file_hash in file_hashes if file_hash is not None]

        analysis = self.analysis_engine.analyze(
            asset=asset,
            cves=cves,
            indicators=indicators,
            file_hashes=file_hashes,
            technique_map={technique.technique_id: technique for technique in self.repository.list_attack_techniques(db)},
        )

        correlation = ThreatCorrelation(
            asset_id=asset.id if asset else None,
            cve_id=cves[0].cve_id if len(cves) == 1 else None,
            indicator_id=indicators[0].id if len(indicators) == 1 else None,
            file_hash_id=file_hashes[0].id if len(file_hashes) == 1 else None,
            correlation_type="unified",
            threat_score=analysis.threat_score,
            severity=analysis.severity,
            confidence=min(100, max(0, 50 + len(cves) * 5 + len(indicators) * 5 + len(file_hashes) * 3)),
            threat_summary=analysis.explanation,
            business_impact=analysis.business_impact,
            attack_scenario=analysis.attack_scenario,
            recommended_actions=analysis.recommended_actions,
            correlation_evidence={
                "notes": notes,
                "asset_id": asset.id if asset else None,
                "cve_ids": analysis.correlated_cve_ids,
                "indicator_values": analysis.correlated_indicator_values,
                "file_hash_ids": [file_hash.id for file_hash in file_hashes],
                "evidence": analysis.evidence,
            },
            mitre_tactics=analysis.mitre_tactics,
            mitre_techniques=analysis.mitre_techniques,
            related_cve_ids=analysis.correlated_cve_ids,
            related_indicator_values=analysis.correlated_indicator_values,
            related_assets=analysis.correlated_assets,
        )
        stored = self.repository.upsert_correlation(db, correlation)
        db.commit()
        db.refresh(stored)
        return analysis

    def build_dashboard(self, db: Session) -> dict[str, Any]:
        context = self.repository.get_dashboard_context(db)
        cves: list[ThreatCveRecord] = context["cves"]
        indicators: list[ThreatIndicator] = context["indicators"]
        correlations: list[ThreatCorrelation] = context["correlations"]
        techniques: list[AttackTechnique] = context["techniques"]
        assets: list[ThreatAsset] = context["assets"]
        sync_runs: list[ThreatSyncRun] = context["sync_runs"]

        critical_cves = [cve for cve in cves if (cve.cvss_severity or "").upper() == "CRITICAL"]
        high_cves = [cve for cve in cves if (cve.cvss_severity or "").upper() == "HIGH"]
        threat_feed_summary = {
            "cve_count": len(cves),
            "indicator_count": len(indicators),
            "asset_count": len(assets),
            "correlation_count": len(correlations),
            "recent_sync_runs": [
                {
                    "sync_type": run.sync_type,
                    "status": run.status,
                    "records_ingested": run.records_ingested,
                    "records_updated": run.records_updated,
                    "started_at": _to_iso8601(run.started_at),
                    "finished_at": _to_iso8601(run.finished_at),
                }
                for run in sync_runs[:5]
            ],
        }
        tactic_coverage = self._build_coverage(cves, indicators, techniques)
        top_indicators = self._build_top_indicators(indicators, correlations)
        latest_critical_cves = sorted(
            critical_cves,
            key=lambda record: (record.cvss_score or 0.0, record.last_modified_at or record.published_at or _utc_now()),
            reverse=True,
        )[:8]
        trends = self._build_trends(cves, indicators, correlations)
        technique_ids = {
            technique_id
            for record in cves
            for technique_id in record.attack_techniques or []
        } | {
            technique_id
            for indicator in indicators
            for technique_id in indicator.mitre_techniques or []
        }
        coverage_percent = round((len(technique_ids) / max(len(techniques), 1)) * 100, 2)

        return {
            "total_cves": len(cves),
            "critical_cves": len(critical_cves),
            "high_cves": len(high_cves),
            "indicators_ingested": len(indicators),
            "correlations_generated": len(correlations),
            "mitre_coverage_percent": coverage_percent,
            "latest_critical_cves": latest_critical_cves,
            "threat_feed_summary": threat_feed_summary,
            "mitre_attack_coverage": tactic_coverage,
            "top_threat_indicators": top_indicators,
            "threat_trends": trends,
        }

    def sync_all(self, db: Session, *, request: dict[str, Any] | None = None) -> dict[str, Any]:
        request = request or {}
        results: dict[str, Any] = {}
        if request.get("sync_attack", True):
            results["attack"] = self._serialize_sync_result(
                self.sync_attack_techniques(db, force=bool(request.get("force")))
            )
        if request.get("sync_nvd", True):
            results["nvd"] = self._serialize_sync_result(
                self.sync_nvd(
                    db,
                    lookback_days=int(request.get("lookback_days") or NVD_LOOKBACK_DAYS),
                    force=bool(request.get("force")),
                )
            )
        if request.get("sync_indicators"):
            results["indicators"] = {"status": "skipped", "message": "Indicator feed sync is configured via ingest API."}
        return results

    @staticmethod
    def _serialize_sync_result(result: ThreatIntelSyncResult) -> dict[str, Any]:
        return {
            "sync_run": {
                "id": result.sync_run.id,
                "sync_type": result.sync_run.sync_type,
                "status": result.sync_run.status,
                "source": result.sync_run.source,
                "started_at": _to_iso8601(result.sync_run.started_at),
                "finished_at": _to_iso8601(result.sync_run.finished_at),
                "records_ingested": result.sync_run.records_ingested,
                "records_updated": result.sync_run.records_updated,
                "source_cursor": result.sync_run.source_cursor,
                "metadata": result.sync_run.sync_metadata,
                "error_message": result.sync_run.error_message,
            },
            "records_ingested": result.ingested,
            "records_updated": result.updated,
        }

    def start_scheduler(self, session_factory: Any) -> "ThreatIntelScheduler":
        scheduler = ThreatIntelScheduler(self, session_factory)
        scheduler.start()
        return scheduler

    def _build_cve_record(self, raw_record: dict[str, Any]) -> tuple[ThreatCveRecord, bool]:
        cve = (raw_record.get("cve") or {})
        cve_id = cve.get("id") or raw_record.get("cveId")
        descriptions = cve.get("descriptions") or []
        refs = cve.get("references") or []
        metrics = cve.get("metrics") or {}
        weakness = cve.get("weaknesses") or []
        configurations = cve.get("configurations") or []
        published_at = _parse_datetime(cve.get("published"))
        last_modified_at = _parse_datetime(cve.get("lastModified"))
        cvss = self._extract_cvss(metrics)
        record = ThreatCveRecord(
            cve_id=str(cve_id),
            source_identifier=cve.get("sourceIdentifier"),
            published_at=published_at,
            last_modified_at=last_modified_at,
            descriptions=descriptions,
            cvss_score=cvss["score"],
            cvss_version=cvss["version"],
            cvss_severity=cvss["severity"],
            cvss_vector=cvss["vector"],
            attack_vector=cvss["attack_vector"],
            attack_complexity=cvss["attack_complexity"],
            privileges_required=cvss["privileges_required"],
            user_interaction=cvss["user_interaction"],
            scope=cvss["scope"],
            confidentiality_impact=cvss["confidentiality_impact"],
            integrity_impact=cvss["integrity_impact"],
            availability_impact=cvss["availability_impact"],
            cwe_ids=self._extract_cwe_ids(weakness),
            affected_products=self._extract_affected_products(configurations),
            reference_urls=self._extract_reference_urls(refs),
            attack_tactics=[],
            attack_techniques=[],
            has_known_exploit=self._detect_exploit_signals(cve, refs, cvss),
            raw_payload=raw_record,
        )
        return record, True

    def _build_attack_technique(self, raw_object: dict[str, Any]) -> AttackTechnique:
        technique_id = None
        for reference in raw_object.get("external_references") or []:
            if reference.get("source_name") in {"mitre-attack", "mitre-cti"} and reference.get("external_id"):
                technique_id = str(reference["external_id"])
                break
        if technique_id is None:
            raise ThreatIntelError("ATT&CK object missing external technique identifier.")

        kill_chain_phases = raw_object.get("kill_chain_phases") or []
        tactic_name = (kill_chain_phases[0].get("phase_name") if kill_chain_phases else "unknown") or "unknown"
        tactic_id = None
        for phase in kill_chain_phases:
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
                tactic_name = str(phase["phase_name"]).replace("-", " ").title()
                tactic_id = None
                break

        return AttackTechnique(
            technique_id=technique_id,
            technique_name=str(raw_object.get("name") or technique_id),
            tactic_name=tactic_name.title(),
            tactic_id=tactic_id,
            description=raw_object.get("description"),
            platforms=[str(item) for item in raw_object.get("x_mitre_platforms") or []],
            data_sources=[str(item) for item in raw_object.get("x_mitre_data_sources") or []],
            external_references=list(raw_object.get("external_references") or []),
            is_subtechnique=bool(raw_object.get("x_mitre_is_subtechnique")),
            stix_created_at=_parse_datetime(raw_object.get("created")),
            stix_modified_at=_parse_datetime(raw_object.get("modified")),
            raw_payload=raw_object,
        )

    @staticmethod
    def _extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
        for version_key, version_label in (
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV2", "2.0"),
        ):
            metric_list = metrics.get(version_key) or []
            if not metric_list:
                continue
            first = metric_list[0]
            data = first.get("cvssData") or first.get("cvssData".lower()) or {}
            severity = first.get("baseSeverity") or data.get("baseSeverity")
            score = first.get("cvssData", {}).get("baseScore") if first.get("cvssData") else data.get("baseScore")
            if score is None:
                score = first.get("baseScore")
            return {
                "score": float(score) if score is not None else None,
                "version": version_label,
                "severity": str(severity).upper() if severity else None,
                "vector": data.get("vectorString"),
                "attack_vector": data.get("attackVector"),
                "attack_complexity": data.get("attackComplexity"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "confidentiality_impact": data.get("confidentialityImpact"),
                "integrity_impact": data.get("integrityImpact"),
                "availability_impact": data.get("availabilityImpact"),
            }
        return {
            "score": None,
            "version": None,
            "severity": None,
            "vector": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality_impact": None,
            "integrity_impact": None,
            "availability_impact": None,
        }

    @staticmethod
    def _extract_cwe_ids(weaknesses: list[dict[str, Any]]) -> list[str]:
        cwe_ids: set[str] = set()
        for weakness in weaknesses or []:
            for description in weakness.get("description") or []:
                value = description.get("value")
                if value:
                    cwe_ids.add(str(value))
        return sorted(cwe_ids)

    @staticmethod
    def _extract_reference_urls(references: list[dict[str, Any]]) -> list[str]:
        urls: list[str] = []
        for reference in references or []:
            url = reference.get("url")
            if url:
                urls.append(str(url))
        return urls

    @staticmethod
    def _extract_affected_products(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        products: list[dict[str, Any]] = []
        for node in configurations or []:
            for child in node.get("nodes") or [node]:
                for cpe_match in child.get("cpeMatch") or []:
                    products.append(
                        {
                            "criteria": cpe_match.get("criteria"),
                            "vulnerable": bool(cpe_match.get("vulnerable")),
                            "matchCriteriaId": cpe_match.get("matchCriteriaId"),
                            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                            "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                        }
                    )
        return products

    @staticmethod
    def _detect_exploit_signals(cve: dict[str, Any], references: list[dict[str, Any]], cvss: dict[str, Any]) -> bool:
        text = " ".join(
            [
                cve.get("descriptions", [{}])[0].get("value", ""),
                " ".join(reference.get("url", "") for reference in references or []),
            ]
        ).lower()
        if any(token in text for token in ("exploit", "weaponized", "proof of concept", "poc", "kev")):
            return True
        score = cvss.get("score")
        return bool(score is not None and float(score) >= 9.0)

    @staticmethod
    def _default_indicator_score(indicator_type: str, labels: list[str]) -> int:
        text = " ".join(labels or []).lower()
        if indicator_type in {"ip", "domain", "url"}:
            return 80 if any(keyword in text for keyword in ("malicious", "c2", "phish", "botnet")) else 65
        if indicator_type == "hash":
            return 85 if any(keyword in text for keyword in ("trojan", "ransom", "malware")) else 60
        return 55

    @staticmethod
    def _default_indicator_level(reputation_score: int | None, labels: list[str]) -> str:
        score = reputation_score if reputation_score is not None else ThreatIntelSyncService._default_indicator_score("generic", labels)
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 50:
            return "medium"
        return "low"

    @staticmethod
    def _default_confidence(labels: list[str]) -> int:
        if not labels:
            return 55
        return min(95, 60 + len(labels) * 5)

    def _build_coverage(
        self,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        techniques: list[AttackTechnique],
    ) -> list[dict[str, Any]]:
        coverage: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"tactic_name": "", "technique_count": 0, "mapped_cves": 0, "mapped_indicators": 0}
        )
        tactic_index = {technique.technique_id: technique.tactic_name for technique in techniques}
        for cve in cves:
            for technique_id in cve.attack_techniques or []:
                tactic_name = tactic_index.get(technique_id, "Unknown")
                row = coverage[tactic_name]
                row["tactic_name"] = tactic_name
                row["technique_count"] += 1
                row["mapped_cves"] += 1
        for indicator in indicators:
            for technique_id in indicator.mitre_techniques or []:
                tactic_name = tactic_index.get(technique_id, "Unknown")
                row = coverage[tactic_name]
                row["tactic_name"] = tactic_name
                row["technique_count"] += 1
                row["mapped_indicators"] += 1
        return sorted(coverage.values(), key=lambda row: row["technique_count"], reverse=True)

    def _build_top_indicators(self, indicators: list[ThreatIndicator], correlations: list[ThreatCorrelation]) -> list[dict[str, Any]]:
        correlation_counts = Counter()
        for correlation in correlations:
            for value in correlation.related_indicator_values or []:
                correlation_counts[value] += 1
        rows: list[dict[str, Any]] = []
        for indicator in sorted(indicators, key=lambda item: (item.reputation_score or 0, item.confidence or 0), reverse=True):
            rows.append(
                {
                    "indicator_type": indicator.indicator_type,
                    "value": indicator.indicator_value,
                    "count": correlation_counts.get(indicator.indicator_value, 1),
                    "reputation_level": indicator.reputation_level,
                    "reputation_score": indicator.reputation_score,
                }
            )
        return rows[:10]

    def _build_trends(
        self,
        cves: list[ThreatCveRecord],
        indicators: list[ThreatIndicator],
        correlations: list[ThreatCorrelation],
    ) -> list[dict[str, Any]]:
        bucket: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "total_cves": 0,
                "critical_cves": 0,
                "high_cves": 0,
                "indicators": 0,
                "correlations": 0,
                "threat_score_total": 0,
            }
        )
        for cve in cves:
            date_key = (cve.last_modified_at or cve.published_at or _utc_now()).date().isoformat()
            row = bucket[date_key]
            row["total_cves"] += 1
            row["threat_score_total"] += int(round((cve.cvss_score or 0.0) * 10))
            if (cve.cvss_severity or "").upper() == "CRITICAL":
                row["critical_cves"] += 1
            if (cve.cvss_severity or "").upper() == "HIGH":
                row["high_cves"] += 1
        for indicator in indicators:
            date_key = (indicator.last_seen_at or indicator.first_seen_at or _utc_now()).date().isoformat()
            row = bucket[date_key]
            row["indicators"] += 1
            row["threat_score_total"] += max(0, 100 - int(indicator.reputation_score or 0))
        for correlation in correlations:
            date_key = correlation.correlated_at.date().isoformat()
            row = bucket[date_key]
            row["correlations"] += 1
            row["threat_score_total"] += int(correlation.threat_score or 0)
        rows: list[dict[str, Any]] = []
        for date_key in sorted(bucket.keys()):
            row = bucket[date_key]
            item_count = max(row["total_cves"] + row["indicators"] + row["correlations"], 1)
            rows.append(
                {
                    "date": date_key,
                    "total_cves": row["total_cves"],
                    "critical_cves": row["critical_cves"],
                    "high_cves": row["high_cves"],
                    "indicators": row["indicators"],
                    "correlations": row["correlations"],
                    "average_threat_score": round(row["threat_score_total"] / item_count, 2),
                }
            )
        return rows[-14:]


class ThreatIntelScheduler:
    def __init__(self, service: ThreatIntelSyncService, session_factory: Any, interval_minutes: int = THREAT_INTEL_SYNC_INTERVAL_MINUTES) -> None:
        self.service = service
        self.session_factory = session_factory
        self.interval_seconds = max(int(interval_minutes) * 60, 60)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if not THREAT_INTEL_SCHEDULER_ENABLED:
            logger.info("Threat intelligence scheduler disabled by configuration.")
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="threat-intel-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            session = self.session_factory()
            try:
                try:
                    self.service.seed_defaults(session)
                    self.service.sync_attack_techniques(session)
                except Exception:
                    logger.exception("Threat intel sync failed during scheduled run.")
                    session.rollback()
                else:
                    try:
                        self.service.sync_nvd(session)
                    except Exception:
                        logger.exception("NVD sync failed during scheduled run.")
                        session.rollback()
            finally:
                session.close()

            self._stop_event.wait(self.interval_seconds)


def load_attack_seed_data(db: Session, repository: ThreatIntelligenceRepository | None = None) -> None:
    repo = repository or ThreatIntelligenceRepository()
    repo.seed_default_attack_techniques(db)
