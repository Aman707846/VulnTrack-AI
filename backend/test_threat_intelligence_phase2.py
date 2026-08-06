import os
import sys
from pathlib import Path
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.db.base import Base  # noqa: E402
from backend.app.models.malware_intelligence import FileHash  # noqa: E402
from backend.app.models.threat_intelligence import (  # noqa: E402
    ThreatAsset,
    ThreatCveRecord,
    ThreatIndicator,
)
from backend.app.repositories.threat_intelligence import ThreatIntelligenceRepository  # noqa: E402
from backend.app.services.threat_intelligence import ThreatAnalysisEngine, ThreatIntelMapper  # noqa: E402


class ThreatIntelligencePhase2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.SessionLocal()

    def tearDown(self) -> None:
        self.db.close()

    def test_default_attack_techniques_seeded(self) -> None:
        repository = ThreatIntelligenceRepository()
        repository.seed_default_attack_techniques(self.db)

        techniques = repository.list_attack_techniques(self.db)
        technique_ids = {technique.technique_id for technique in techniques}

        self.assertIn("T1190", technique_ids)
        self.assertIn("T1566", technique_ids)
        self.assertGreaterEqual(len(techniques), 10)

    def test_mapper_links_rce_and_phishing_context(self) -> None:
        mapper = ThreatIntelMapper()
        cve = ThreatCveRecord(
            cve_id="CVE-2026-0001",
            descriptions=[{"lang": "en", "value": "Remote code execution via command injection in public-facing application."}],
            cwe_ids=["CWE-78"],
            affected_products=[{"criteria": "cpe:2.3:a:example:example_app:*"}],
            reference_urls=["https://example.com/advisory"],
        )
        tactics, techniques = mapper.map_cve(cve)
        indicator = ThreatIndicator(
            indicator_type="domain",
            indicator_value="login-microsoft-security.example",
            normalized_value="login-microsoft-security.example",
            labels=["phish"],
        )
        indicator_tactics, indicator_techniques = mapper.map_indicator(indicator)

        self.assertIn("T1190", techniques)
        self.assertIn("T1059", techniques)
        self.assertIn("Initial Access", tactics)
        self.assertIn("T1566", indicator_techniques)
        self.assertIn("Initial Access", indicator_tactics)

    def test_analysis_engine_generates_critical_threat(self) -> None:
        engine = ThreatAnalysisEngine()
        asset = ThreatAsset(
            asset_name="Payroll API",
            asset_type="application",
            criticality="critical",
            environment="production",
            software_inventory=["example-app"],
        )
        cve = ThreatCveRecord(
            cve_id="CVE-2026-0002",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            has_known_exploit=True,
            attack_tactics=["Initial Access"],
            attack_techniques=["T1190"],
        )
        indicator = ThreatIndicator(
            indicator_type="ip",
            indicator_value="203.0.113.10",
            normalized_value="203.0.113.10",
            reputation_score=15,
            reputation_level="critical",
            confidence=90,
            mitre_tactics=["Command and Control"],
            mitre_techniques=["T1071"],
        )
        file_hash = FileHash(
            sha256="a" * 64,
            reputation_score=10,
            reputation_classification="Critical",
            signature_status="unsigned",
            virus_total_threat_labels=["Trojan"],
        )

        analysis = engine.analyze(
            asset=asset,
            cves=[cve],
            indicators=[indicator],
            file_hashes=[file_hash],
            technique_map={},
        )

        self.assertEqual(analysis.severity, "Critical")
        self.assertGreaterEqual(analysis.threat_score, 85)
        self.assertIn("Payroll API", analysis.correlated_assets)
        self.assertIn("CVE-2026-0002", analysis.correlated_cve_ids)
        self.assertIn("203.0.113.10", analysis.correlated_indicator_values)
        self.assertTrue(analysis.recommended_actions)


if __name__ == "__main__":
    unittest.main()
