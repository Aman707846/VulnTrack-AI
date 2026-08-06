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
from backend.app.models.threat_intelligence import ThreatAsset, ThreatCveRecord, ThreatIndicator  # noqa: E402
from backend.app.services.ai_security_intelligence import AISecurityIntelligenceService  # noqa: E402


class AISecurityIntelligencePhase3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.SessionLocal()
        self.service = AISecurityIntelligenceService()

    def tearDown(self) -> None:
        self.db.close()

    def _seed_core_records(self) -> tuple[ThreatAsset, ThreatCveRecord, ThreatIndicator, FileHash]:
        asset = ThreatAsset(
            asset_name="Payroll API",
            asset_type="application",
            criticality="critical",
            environment="production",
            software_inventory=["example-app"],
        )
        cve = ThreatCveRecord(
            cve_id="CVE-2026-1000",
            descriptions=[{"lang": "en", "value": "Remote code execution in a public-facing web service."}],
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            has_known_exploit=True,
            attack_tactics=["Initial Access"],
            attack_techniques=["T1190"],
            reference_urls=["https://example.com/advisory"],
        )
        indicator = ThreatIndicator(
            indicator_type="domain",
            indicator_value="login-payroll.example",
            normalized_value="login-payroll.example",
            reputation_score=12,
            reputation_level="critical",
            confidence=92,
            labels=["phish", "c2"],
            mitre_tactics=["Initial Access"],
            mitre_techniques=["T1566"],
        )
        file_hash = FileHash(
            sha256="a" * 64,
            reputation_score=9,
            reputation_classification="Critical",
            signature_status="unsigned",
            virus_total_threat_labels=["Trojan", "Ransomware"],
        )
        self.db.add_all([asset, cve, indicator, file_hash])
        self.db.commit()
        self.db.refresh(asset)
        self.db.refresh(cve)
        self.db.refresh(indicator)
        self.db.refresh(file_hash)
        return asset, cve, indicator, file_hash

    def test_risk_scoring_combines_multiple_signals(self) -> None:
        result = self.service.score_risk(
            cvss_score=9.8,
            threat_intelligence_score=72,
            malware_reputation_score=18,
            asset_criticality="critical",
            exploit_available=True,
            internet_exposed=True,
        )

        self.assertEqual(result["severity"], "Critical")
        self.assertGreaterEqual(result["risk_score"], 85)
        self.assertTrue(result["recommended_actions"])
        self.assertTrue(any(factor["label"] == "CVSS" for factor in result["factors"]))

    def test_vulnerability_analysis_explains_and_recommends(self) -> None:
        asset, cve, indicator, file_hash = self._seed_core_records()

        analysis = self.service.analyze_vulnerability(
            self.db,
            {
                "cve_id": cve.cve_id,
                "asset_id": asset.id,
                "asset_name": asset.asset_name,
                "file_hash_ids": [file_hash.id],
                "indicator_ids": [indicator.id],
            },
        )

        self.assertEqual(analysis["cve_id"], cve.cve_id)
        self.assertEqual(analysis["severity"], "Critical")
        self.assertIn("remote code execution", analysis["simple_explanation"].lower())
        self.assertTrue(analysis["remediation_steps"])
        self.assertTrue(analysis["patch_recommendations"])
        self.assertTrue(analysis["hardening_guidance"])

    def test_dashboard_and_copilot_search_surface_records(self) -> None:
        asset, cve, indicator, file_hash = self._seed_core_records()

        dashboard = self.service.build_dashboard(self.db)
        self.assertGreaterEqual(dashboard["organization_risk_score"], 0)
        self.assertTrue(dashboard["top_threats"])
        self.assertTrue(dashboard["critical_assets"])

        copilot = self.service.generate_copilot_answer(
            self.db,
            {"question": "Explain CVE-2026-1000 and recommend actions", "limit": 5},
        )

        self.assertTrue(copilot["search_results"])
        self.assertIn(cve.cve_id, copilot["matched_cves"])
        self.assertTrue(copilot["recommended_actions"])


if __name__ == "__main__":
    unittest.main()
