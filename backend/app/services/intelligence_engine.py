from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from ipaddress import ip_address
import logging
import math
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import parse_qs, urlparse

from sklearn.linear_model import LogisticRegression


logger = logging.getLogger(__name__)


_URL_KEYWORDS = (
    "account",
    "auth",
    "bank",
    "confirm",
    "login",
    "password",
    "pay",
    "secure",
    "signin",
    "token",
    "update",
    "verify",
    "wallet",
)

_PHISHING_KEYWORDS = (
    "login",
    "secure",
    "verify",
)

_SUSPICIOUS_FILE_MARKERS = (
    "powershell -enc",
    "powershell -encodedcommand",
    "pwsh -enc",
    "invoke-expression",
    "frombase64string",
    "wscript.shell",
    "cmd.exe",
    "certutil",
    "autoopen",
    "createobject",
    "eicar",
    "trojan",
    "malware",
)

_SUSPICIOUS_FILE_KEYWORDS = (
    "hack",
    "keygen",
    "malware",
    "payload",
    "phish",
    "ransomware",
    "stealer",
    "trojan",
)

_HIGH_RISK_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".docm",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".ps1",
    ".rar",
    ".scr",
    ".vbe",
    ".vbs",
    ".xlsm",
    ".zip",
}

_ACTIVE_RISK_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".hta",
    ".js",
    ".lnk",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
}

_MACRO_RISK_EXTENSIONS = {
    ".docm",
    ".xlsm",
}

_SOFTWARE_PACKAGE_EXTENSIONS = {
    ".dll",
    ".exe",
    ".iso",
    ".jar",
    ".msi",
    ".rar",
    ".zip",
}

_SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}

_TRUSTED_DOMAINS = {
    "adobe.com",
    "amazon.com",
    "apple.com",
    "cloudflare.com",
    "docker.com",
    "github.com",
    "google.com",
    "intel.com",
    "jetbrains.com",
    "linkedin.com",
    "microsoft.com",
    "mongodb.com",
    "mozilla.org",
    "netlify.app",
    "netlify.com",
    "nodejs.org",
    "npmjs.com",
    "nvidia.com",
    "office.com",
    "openai.com",
    "paypal.com",
    "postman.com",
    "postgresql.org",
    "python.org",
    "supabase.com",
    "vercel.app",
    "vercel.com",
}

_DOMAIN_WHITELIST = {
    "github.com",
    "google.com",
    "microsoft.com",
    "openai.com",
    "python.org",
    "npmjs.com",
    "vercel.com",
}

_KNOWN_FILE_SOURCE_MARKERS = {
    "adobe",
    "amazon",
    "apple",
    "cloudflare",
    "docker",
    "github",
    "google",
    "google chrome",
    "intel",
    "git for windows",
    "git scm",
    "jetbrains",
    "linkedin",
    "microsoft",
    "microsoft corporation",
    "mongodb",
    "mozilla",
    "netlify",
    "node.js",
    "nodejs",
    "nvidia",
    "office",
    "openai",
    "openai inc",
    "paypal",
    "postman",
    "postgresql",
    "python foundation",
    "python software foundation",
    "supabase",
    "vercel",
}

_TRUSTED_FILE_NAMES = {
    "changelog",
    "documentation",
    "license",
    "manual",
    "readme",
    "release-notes",
}

_CLEAN_FILE_NAME_MARKERS = (
    "install",
    "installer",
    "official",
    "setup",
    "signed",
)

_KNOWN_SOFTWARE_NAME_PATTERNS = (
    r"adobe",
    r"androidstudio",
    r"chatgpt",
    r"cloudflare",
    r"cursor",
    r"docker(?:desktop)?",
    r"chrome(?:setup|installer)?",
    r"githubdesktop",
    r"git(?:forwindows|scm|installer)",
    r"intel",
    r"intellij(?:idea)?",
    r"jetbrains(?:toolbox)?",
    r"datagrip",
    r"goland",
    r"mongodb",
    r"mozilla",
    r"netlify",
    r"node(?:js)?",
    r"nvidia",
    r"phpstorm",
    r"postman",
    r"postgres(?:ql)?",
    r"pycharm",
    r"rider",
    r"rubymine",
    r"supabase",
    r"vercel",
    r"webstorm",
    r"vscode",
    r"visualstudiocode",
    r"python(?:\d+)?",
    r"openai",
    r"clion",
)

_SOFTWARE_DISTRIBUTION_MARKERS = (
    "community",
    "desktop",
    "enterprise",
    "install",
    "installer",
    "professional",
    "setup",
    "studio",
    "toolbox",
    "ultimate",
    "usersetup",
)

_ARCHITECTURE_MARKERS = (
    "x64",
    "x86",
    "amd64",
    "arm64",
    "win64",
)

_DOUBLE_EXTENSION_LURE_EXTENSIONS = {
    "7z",
    "bmp",
    "csv",
    "doc",
    "docm",
    "docx",
    "gif",
    "gz",
    "jpeg",
    "jpg",
    "pdf",
    "png",
    "ppt",
    "pptx",
    "rar",
    "rtf",
    "svg",
    "tar",
    "txt",
    "xls",
    "xlsm",
    "xlsx",
    "zip",
}

_SIGNATURE_MARKERS = (
    "authenticode",
    "digitally signed",
    "signature verified",
    "signed by",
    "signed installer",
    "valid signature",
)

_POWERSHELL_OBFUSCATION_MARKERS = (
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "iex(",
    "iex ",
    "invoke-expression",
)

_RANSOMWARE_MARKERS = (
    "bitcoin",
    "decrypt your files",
    "encrypted files",
    "ransomware",
    "recover your files",
    "vssadmin delete shadows",
    "we have encrypted",
    "your files have been encrypted",
)

_TROJAN_BEHAVIOR_MARKERS = (
    "cobalt strike",
    "credential theft",
    "dll injection",
    "keylogger",
    "meterpreter",
    "process hollowing",
    "remote access trojan",
    "stealer",
    "trojan",
)

_REGISTRY_PERSISTENCE_MARKERS = (
    "currentversion\\run",
    "currentversion\\runonce",
    "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run",
    "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run",
    "reg add ",
)

_NETWORK_EXECUTION_MARKERS = (
    "downloadfile",
    "downloadstring",
    "httpclient",
    "invoke-webrequest",
    "socket.connect",
    "tcpclient",
    "urlopen",
    "webclient",
    "wget ",
)

_KNOWN_MALWARE_SHA256 = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}

_TRUSTED_PUBLISHER_MARKERS = {
    "adobe",
    "apple",
    "cloudflare",
    "docker",
    "github",
    "google",
    "google llc",
    "google inc",
    "intel",
    "git for windows",
    "git scm",
    "jetbrains",
    "microsoft",
    "microsoft corporation",
    "mongodb",
    "mozilla",
    "netlify",
    "node.js",
    "nodejs",
    "nvidia",
    "openai",
    "openai inc",
    "openjs foundation",
    "postman",
    "postgresql",
    "python software foundation",
    "supabase",
    "vercel",
}

_POPULAR_SAFE_SOFTWARE_PATTERNS = {
    "ChatGPT Installer": r"chatgpt(?:installer)?",
    "Android Studio": r"androidstudio",
    "VS Code": r"(?:vscode|visualstudiocode)",
    "Cursor AI": r"cursor",
    "Docker Desktop": r"dockerdesktop",
    "Google Chrome": r"(?:googlechrome|chromesetup|chromeinstaller)",
    "Git Installer": r"(?:gitforwindows|gitscm|gitinstaller)",
    "Python Installer": r"python(?:\d+)?",
    "Node.js Installer": r"node(?:js)?",
}

_KNOWN_SAFE_SOFTWARE_HASHES: dict[str, str] = {}


@dataclass(frozen=True)
class TriggeredRule:
    name: str
    severity: str
    description: str


@dataclass(frozen=True)
class ThreatAnalysis:
    target: str
    target_type: str
    verdict: str
    confidence: float
    heuristic_score: int
    heuristic_label: str
    ml_probability: float
    ml_label: str
    triggered_rules: list[TriggeredRule]
    indicators: list[str]
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrustAssessment:
    reputation_score: int
    signals: list[str]
    is_whitelisted: bool = False
    is_trusted: bool = False


@dataclass(frozen=True)
class DigitalSignatureAssessment:
    is_signed: bool
    is_valid: bool
    publisher: str | None
    issuer: str | None
    status: str
    signals: list[str]
    is_trusted_publisher: bool = False


@dataclass(frozen=True)
class ReputationAssessment:
    signals: list[str]
    exact_safe_match: str | None = None
    popular_family_match: str | None = None


@dataclass(frozen=True)
class BehaviorAssessment:
    signals: list[str]
    risk_floor: str | None = None


@dataclass(frozen=True)
class ContextAssessment:
    signals: list[str]


class ThreatAnalyzer:
    def __init__(self) -> None:
        self.url_ml_model = self._train_url_model()
        logger.info("ThreatAnalyzer ML model initialized")

    def analyze_url(self, url: str) -> dict[str, Any]:
        normalized_url = (url or "").strip()
        parsed = urlparse(normalized_url if "://" in normalized_url else f"http://{normalized_url}")
        hostname = (parsed.hostname or "").lower()
        path_and_query = f"{parsed.path} {parsed.query}".lower()
        trust_assessment = self._assess_url_trust(hostname, path_and_query, parsed)
        context_assessment = self._assess_url_context(
            normalized_url=normalized_url,
            hostname=hostname,
            path_and_query=path_and_query,
            parsed=parsed,
            trust_assessment=trust_assessment,
        )
        behavior_assessment = self._assess_url_behavior(
            normalized_url=normalized_url,
            hostname=hostname,
            path_and_query=path_and_query,
            parsed=parsed,
            trust_assessment=trust_assessment,
        )
        is_trusted = trust_assessment.is_trusted
        is_whitelisted = trust_assessment.is_whitelisted
        trust_signals = trust_assessment.signals
        reasons: list[str] = []
        suspicious_tlds = (".xyz", ".ru", ".tk")
        phishing_hits = self._count_keyword_hits(f"{hostname} {path_and_query}", _PHISHING_KEYWORDS)
        has_random_pattern = self._has_random_url_pattern(hostname, path_and_query)
        has_typosquatting = self._is_typosquatting_domain(hostname)

        logger.info("URL analysis input: %s", normalized_url)

        if self._is_ip_host(hostname):
            reasons.append("IP address used")

        if any(hostname.endswith(tld) for tld in suspicious_tlds):
            reasons.append("Suspicious TLD")

        if len(normalized_url) > 75:
            reasons.append("Long URL")

        if hostname and len(hostname.split(".")) > 4:
            reasons.append("Excessive subdomains")

        if has_typosquatting:
            reasons.append("Typosquatting pattern detected")

        if (phishing_hits >= 2 and not is_trusted) or (phishing_hits >= 1 and not is_trusted and len(reasons) >= 1):
            reasons.append("Phishing keyword detected")

        if has_random_pattern and not is_trusted:
            reasons.append("Randomized URL pattern")

        ml_probability = self._predict_url_probability(normalized_url, hostname)
        ml_prediction = int(ml_probability >= 0.5)
        score, score_events = self._calculate_score_breakdown(reasons)
        self._log_score_events("url", normalized_url, score_events)
        if ml_prediction == 1 and score >= 18:
            score += 10
            self._log_score_adjustment("url", normalized_url, 10, "ML model corroborated suspicious signals")
        if is_whitelisted:
            original_score = score
            score = self._apply_whitelist_reduction(score)
            self._log_score_adjustment("url", normalized_url, score - original_score, "Matched trusted whitelist domain")
        elif is_trusted:
            original_score = score
            score = self._apply_trusted_domain_reduction(score)
            self._log_score_adjustment("url", normalized_url, score - original_score, "Matched known trusted domain")
        if trust_signals:
            logger.info("URL trust context for %s: %s", normalized_url, ", ".join(trust_signals))
        if context_assessment.signals:
            logger.info("URL structural context for %s: %s", normalized_url, ", ".join(context_assessment.signals))
        if behavior_assessment.signals:
            logger.info("URL behavior context for %s: %s", normalized_url, ", ".join(behavior_assessment.signals))
        confidence_level = self._classify_confidence(score, len(reasons), ml_probability)
        confidence = self._confidence_to_score(confidence_level)
        risk_level = self._classify_url_risk_level(
            score=score,
            reasons=reasons,
            trust_assessment=trust_assessment,
            context_assessment=context_assessment,
            behavior_assessment=behavior_assessment,
            ml_probability=ml_probability,
        )
        explanation = self._build_explanation(
            target_type="url",
            risk_level=risk_level,
            reasons=reasons,
            is_whitelisted=is_whitelisted,
            is_trusted=is_trusted,
            trust_signals=trust_signals,
            context_signals=context_assessment.signals,
            behavior_signals=behavior_assessment.signals,
        )
        logger.info("URL analysis score: %s", score)
        logger.info("URL risk decision: %s", risk_level)

        return {
            "confidence": confidence,
            "confidence_level": confidence_level,
            "score": score,
            "risk_level": risk_level,
            "reasons": reasons,
            "explanation": explanation,
            "ml_prediction": ml_prediction,
            "reputation_score": trust_assessment.reputation_score,
            "trust_score": trust_assessment.reputation_score,
            "trust_signals": trust_signals,
            "context_signals": context_assessment.signals,
            "behavioral_signals": behavior_assessment.signals,
        }

    def analyze_file(
        self,
        filename: str,
        content: bytes,
        *,
        sha256: str | None = None,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        normalized_name = (filename or "").strip()
        file_bytes = content or b""
        decoded_content = file_bytes.decode("utf-8", errors="ignore").lower()
        lowered_name = normalized_name.lower()
        file_sha256 = (sha256 or (hashlib.sha256(file_bytes).hexdigest() if file_bytes else "")).lower()
        reasons: list[str] = []
        extension = self._extension(lowered_name)
        reputation_assessment = self._assess_file_reputation(
            normalized_name=lowered_name,
            sha256=file_sha256,
        )
        has_double_extension = self._has_double_extension(lowered_name)
        has_known_software_name = self._has_known_software_name(lowered_name)
        has_distribution_pattern = self._has_software_distribution_pattern(lowered_name)
        has_signature_signal = self._has_signature_signal(decoded_content)
        has_trusted_domain_reference = self._has_trusted_domain_reference(decoded_content)
        has_trusted_vendor_match = self._has_trusted_vendor_match(lowered_name, decoded_content)
        is_trusted_source = self._is_trusted_file_source(lowered_name, decoded_content)
        has_suspicious_keywords = self._has_suspicious_file_keywords(lowered_name, decoded_content)
        has_random_name = self._has_random_file_name(lowered_name)
        is_trusted_name = self._is_trusted_file_name(lowered_name)
        is_unknown_source = not is_trusted_source
        has_clean_filename = self._has_clean_filename_signal(lowered_name)
        has_reasonable_filename = self._is_reasonable_filename(lowered_name)
        has_obfuscated_powershell = self._has_obfuscated_powershell(decoded_content)
        has_ransomware_behavior = self._has_ransomware_behavior(lowered_name, decoded_content)
        has_trojan_behavior = self._has_trojan_behavior(lowered_name, decoded_content)
        has_registry_persistence = self._has_registry_persistence(decoded_content)
        has_known_malware_hash = self._has_known_malware_hash(file_bytes)
        has_suspicious_network_activity = self._has_suspicious_network_activity(decoded_content)
        has_real_suspicious_behavior = any(
            (
                has_obfuscated_powershell,
                has_ransomware_behavior,
                has_trojan_behavior,
                has_registry_persistence,
                has_known_malware_hash,
                has_suspicious_network_activity,
            )
        )

        trusted_installer_fast_path = self._should_fast_track_official_installer(
            extension=extension,
            has_known_software_name=has_known_software_name,
            has_distribution_pattern=has_distribution_pattern,
            has_clean_filename=has_clean_filename,
            has_reasonable_filename=has_reasonable_filename,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_known_malware_hash=has_known_malware_hash,
            has_obfuscated_powershell=has_obfuscated_powershell,
            has_ransomware_behavior=has_ransomware_behavior,
            has_trojan_behavior=has_trojan_behavior,
            has_registry_persistence=has_registry_persistence,
            has_suspicious_network_activity=has_suspicious_network_activity,
            reputation_assessment=reputation_assessment,
        )
        if trusted_installer_fast_path:
            return self._build_trusted_installer_analysis(
                target=normalized_name,
                file_sha256=file_sha256,
                reputation_assessment=reputation_assessment,
                has_known_software_name=has_known_software_name,
                has_distribution_pattern=has_distribution_pattern,
                has_clean_filename=has_clean_filename,
                has_reasonable_filename=has_reasonable_filename,
                has_trusted_vendor_match=has_trusted_vendor_match,
                has_trusted_domain_reference=has_trusted_domain_reference,
                has_signature_signal=has_signature_signal,
                is_trusted_name=is_trusted_name,
            )

        signature_assessment = self._analyze_digital_signature(file_path)

        is_low_risk_executable = self._is_low_risk_executable(
            extension=extension,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_suspicious_markers=has_real_suspicious_behavior,
            is_reasonable_filename=has_reasonable_filename,
        )
        is_benign_software_package = self._is_benign_software_package(
            extension=extension,
            has_known_software_name=has_known_software_name,
            has_distribution_pattern=has_distribution_pattern,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_suspicious_markers=has_real_suspicious_behavior,
            is_reasonable_filename=has_reasonable_filename,
        )
        trust_assessment = self._assess_file_trust(
            normalized_name=lowered_name,
            decoded_content=decoded_content,
            extension=extension,
            is_trusted_source=is_trusted_source,
            is_trusted_name=is_trusted_name,
            signature_assessment=signature_assessment,
            reputation_assessment=reputation_assessment,
            has_signature_signal=has_signature_signal,
            has_trusted_vendor_match=has_trusted_vendor_match,
            has_trusted_domain_reference=has_trusted_domain_reference,
            has_clean_filename=has_clean_filename,
            has_known_software_name=has_known_software_name,
            has_distribution_pattern=has_distribution_pattern,
            has_random_name=has_random_name,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_suspicious_markers=has_real_suspicious_behavior,
            is_low_risk_executable=is_low_risk_executable,
            is_benign_software_package=is_benign_software_package,
        )
        context_assessment = self._assess_file_context(
            normalized_name=lowered_name,
            has_clean_filename=has_clean_filename,
            has_known_software_name=has_known_software_name,
            has_distribution_pattern=has_distribution_pattern,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            is_trusted_name=is_trusted_name,
        )
        trust_signals = trust_assessment.signals
        behavior_assessment = self._assess_file_behavior(
            normalized_name=lowered_name,
            extension=extension,
            is_unknown_source=is_unknown_source,
            has_random_name=has_random_name,
            has_double_extension=has_double_extension,
            has_obfuscated_powershell=has_obfuscated_powershell,
            has_ransomware_behavior=has_ransomware_behavior,
            has_trojan_behavior=has_trojan_behavior,
            has_registry_persistence=has_registry_persistence,
            has_suspicious_network_activity=has_suspicious_network_activity,
            has_known_malware_hash=has_known_malware_hash,
            is_low_risk_executable=is_low_risk_executable,
            is_benign_software_package=is_benign_software_package,
        )

        logger.info("File analysis input: %s", normalized_name)

        if has_double_extension:
            reasons.append("Double extension detected")

        if has_obfuscated_powershell:
            reasons.append("Obfuscated PowerShell detected")

        if has_ransomware_behavior:
            reasons.append("Ransomware behavior detected")

        if has_trojan_behavior:
            reasons.append("Trojan behavior detected")

        if has_registry_persistence:
            reasons.append("Registry persistence detected")

        if has_known_malware_hash:
            reasons.append("Known malware hash detected")

        if has_suspicious_network_activity:
            reasons.append("Suspicious network activity detected")

        ml_probability = self._classify_file(
            normalized_name=lowered_name,
            decoded_content=decoded_content,
            file_bytes=file_bytes,
            rule_count=len(reasons),
            indicator_count=len(behavior_assessment.signals),
        )
        ml_prediction = int(ml_probability >= 0.65)
        score, score_events = self._calculate_score_breakdown(reasons)
        self._log_score_events("file", normalized_name, score_events)
        if has_clean_filename:
            original_score = score
            score = self._apply_clean_filename_reduction(score)
            self._log_score_adjustment("file", normalized_name, score - original_score, "Filename matched clean installer-style trust signals")
        if reputation_assessment.exact_safe_match and not reasons:
            original_score = score
            score = self._apply_safe_software_reduction(score)
            self._log_score_adjustment("file", normalized_name, score - original_score, "Matched known safe software hash")
        if trust_assessment.is_trusted and not reasons:
            original_score = score
            score = self._apply_trusted_file_reduction(score)
            self._log_score_adjustment("file", normalized_name, score - original_score, "Matched trusted vendor, domain, or signature context")
        if trust_signals:
            logger.info("File trust context for %s: %s", normalized_name, ", ".join(trust_signals))
        if context_assessment.signals:
            logger.info("File structural context for %s: %s", normalized_name, ", ".join(context_assessment.signals))
        if behavior_assessment.signals:
            logger.info("File behavior context for %s: %s", normalized_name, ", ".join(behavior_assessment.signals))
        if is_low_risk_executable:
            logger.info("file score context for %s: clean .exe with reasonable filename and no suspicious keywords or markers", normalized_name)
        confidence_level = self._classify_confidence(score, len(reasons), ml_probability)
        confidence = self._confidence_to_score(confidence_level)
        risk_level = self._classify_file_risk_level(
            score=score,
            reasons=reasons,
            trust_assessment=trust_assessment,
            context_assessment=context_assessment,
            is_low_risk_executable=is_low_risk_executable,
            behavior_assessment=behavior_assessment,
            ml_probability=ml_probability,
        )
        explanation = self._build_explanation(
            target_type="file",
            risk_level=risk_level,
            reasons=reasons,
            is_trusted=trust_assessment.is_trusted,
            trust_signals=trust_signals,
            context_signals=context_assessment.signals,
            behavior_signals=behavior_assessment.signals,
        )
        verdict = self._verdict_from_file_analysis(
            risk_level=risk_level,
            trust_assessment=trust_assessment,
            signature_assessment=signature_assessment,
            reputation_assessment=reputation_assessment,
            reasons=reasons,
            trust_signals=trust_signals,
            context_signals=context_assessment.signals,
            behavior_signals=behavior_assessment.signals,
        )
        recommended_action = self._recommended_action_for_verdict(verdict)
        ai_summary = self._build_ai_summary(
            verdict=verdict,
            confidence=confidence,
            reasons=self._ai_reasons_for_file(
                verdict=verdict,
                reasons=reasons,
                trust_signals=trust_signals,
                context_signals=context_assessment.signals,
                behavior_signals=behavior_assessment.signals,
                signature_assessment=signature_assessment,
                reputation_assessment=reputation_assessment,
                trust_assessment=trust_assessment,
            ),
            recommended_action=recommended_action,
        )
        logger.info("File analysis score: %s", score)
        logger.info("File risk decision: %s", risk_level)

        return {
            "confidence": confidence,
            "confidence_level": confidence_level,
            "score": score,
            "risk_level": risk_level,
            "verdict": verdict,
            "confidence_percent": confidence,
            "reasons": reasons,
            "explanation": explanation,
            "ai_summary": ai_summary,
            "recommended_action": recommended_action,
            "file_sha256": file_sha256,
            "ml_prediction": ml_prediction,
            "reputation_score": trust_assessment.reputation_score,
            "trust_score": trust_assessment.reputation_score,
            "trust_signals": trust_signals,
            "reputation_signals": reputation_assessment.signals,
            "signature_status": signature_assessment.status,
            "signature_publisher": signature_assessment.publisher,
            "signature_issuer": signature_assessment.issuer,
            "signature_trusted_publisher": signature_assessment.is_trusted_publisher,
            "context_signals": context_assessment.signals,
            "behavioral_signals": behavior_assessment.signals,
        }

    def calculate_score(self, reasons: list[str]) -> int:
        score, _ = self._calculate_score_breakdown(reasons)
        return score

    def _train_url_model(self) -> LogisticRegression:
        training_features = [
            [18, 1, 0, 0, 1],
            [24, 1, 0, 0, 1],
            [28, 2, 0, 0, 1],
            [36, 1, 0, 1, 1],
            [32, 2, 0, 0, 0],
            [41, 2, 0, 1, 0],
            [58, 3, 0, 1, 0],
            [77, 4, 0, 0, 0],
            [83, 4, 0, 1, 0],
            [29, 0, 1, 0, 0],
            [66, 3, 1, 0, 0],
            [95, 5, 1, 1, 0],
            [72, 3, 0, 1, 1],
            [54, 2, 0, 1, 1],
            [64, 3, 0, 1, 0],
        ]
        training_labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1]

        model = LogisticRegression(random_state=42, max_iter=200)
        model.fit(training_features, training_labels)
        return model

    def _predict_url_risk(self, normalized_url: str, hostname: str) -> int:
        features = self._extract_url_ml_features(normalized_url, hostname)
        prediction = int(self.url_ml_model.predict([features])[0])
        logger.info("ML URL prediction: %s", prediction)
        return prediction

    def _predict_url_probability(self, normalized_url: str, hostname: str) -> float:
        features = self._extract_url_ml_features(normalized_url, hostname)
        probability = float(self.url_ml_model.predict_proba([features])[0][1])
        logger.info("ML URL probability: %.4f", probability)
        return probability

    def _extract_url_ml_features(self, normalized_url: str, hostname: str) -> list[int]:
        lowered_url = normalized_url.lower()
        suspicious_word = int(any(keyword in lowered_url for keyword in _URL_KEYWORDS))
        return [
            len(normalized_url),
            hostname.count("."),
            int(self._is_ip_host(hostname)),
            suspicious_word,
            int(self._is_trusted_domain(hostname)),
        ]

    @staticmethod
    def _classify_risk_level(score: int) -> str:
        if score <= 20:
            return "safe"
        if score <= 50:
            return "low_risk"
        if score <= 75:
            return "suspicious"
        return "malicious"

    def _classify_file_risk_level(
        self,
        *,
        score: int,
        reasons: list[str],
        trust_assessment: TrustAssessment,
        context_assessment: ContextAssessment,
        is_low_risk_executable: bool,
        behavior_assessment: BehaviorAssessment,
        ml_probability: float,
    ) -> str:
        if not reasons:
            if trust_assessment.reputation_score >= 85:
                return "safe"
            if is_low_risk_executable and trust_assessment.reputation_score >= 65:
                return "low_risk"
        risk_level = self._classify_human_like_risk_level(
            score=score,
            reasons=reasons,
            trust_assessment=trust_assessment,
            context_assessment=context_assessment,
            behavior_assessment=behavior_assessment,
            ml_probability=ml_probability,
        )
        return self._apply_behavior_risk_floor(risk_level, behavior_assessment.risk_floor)

    def _classify_url_risk_level(
        self,
        *,
        score: int,
        reasons: list[str],
        trust_assessment: TrustAssessment,
        context_assessment: ContextAssessment,
        behavior_assessment: BehaviorAssessment,
        ml_probability: float,
    ) -> str:
        if trust_assessment.is_trusted and not reasons and behavior_assessment.risk_floor is None:
            return "safe"
        risk_level = self._classify_human_like_risk_level(
            score=score,
            reasons=reasons,
            trust_assessment=trust_assessment,
            context_assessment=context_assessment,
            behavior_assessment=behavior_assessment,
            ml_probability=ml_probability,
        )
        return self._apply_behavior_risk_floor(risk_level, behavior_assessment.risk_floor)

    def _classify_human_like_risk_level(
        self,
        *,
        score: int,
        reasons: list[str],
        trust_assessment: TrustAssessment,
        context_assessment: ContextAssessment,
        behavior_assessment: BehaviorAssessment,
        ml_probability: float,
    ) -> str:
        strong_signal_count = self._count_strong_reasons(reasons)
        suspicious_reason_count = len(reasons)
        suspicious_context_count = self._count_suspicious_context_signals(context_assessment.signals)
        suspicious_behavior_count = self._count_suspicious_behavior_signals(behavior_assessment.signals)
        total_signal_count = suspicious_reason_count + suspicious_context_count + suspicious_behavior_count
        has_clean_trusted_profile = (
            (trust_assessment.is_trusted or trust_assessment.reputation_score >= 85)
            and suspicious_reason_count == 0
            and suspicious_context_count == 0
            and suspicious_behavior_count == 0
        )

        if has_clean_trusted_profile or (
            trust_assessment.reputation_score >= 70
            and total_signal_count == 0
            and score <= 20
        ):
            return "safe" if trust_assessment.reputation_score >= 85 else "low_risk"

        if (
            strong_signal_count >= 2
            or score >= 75
            or ml_probability >= 0.9
            or (strong_signal_count >= 1 and total_signal_count >= 4 and score >= 55)
        ):
            return "malicious"

        if (
            behavior_assessment.risk_floor == "suspicious"
            or strong_signal_count >= 1
            or suspicious_reason_count >= 2
            or total_signal_count >= 3
            or score > 50
            or ml_probability >= 0.8
        ):
            return "suspicious"

        if total_signal_count >= 1 or score > 20 or ml_probability >= 0.65:
            return "low_risk"

        return "safe"

    @staticmethod
    def _classify_confidence(score: int, reason_count: int, ml_probability: float) -> str:
        model_certainty = abs(min(max(ml_probability, 0.0), 1.0) - 0.5)
        if score <= 10 or score > 75 or reason_count >= 3 or model_certainty >= 0.25:
            return "high"
        if score <= 20 or score > 50 or reason_count >= 2 or model_certainty >= 0.12:
            return "medium"
        return "low"

    @staticmethod
    def _confidence_to_score(confidence_level: str) -> int:
        return {
            "low": 35,
            "medium": 65,
            "high": 90,
        }.get(confidence_level, 50)

    def _evaluate_url_rules(
        self,
        *,
        normalized_url: str,
        hostname: str,
        path_and_query: str,
        parsed: Any,
    ) -> tuple[list[TriggeredRule], list[str]]:
        rules: list[TriggeredRule] = []
        indicators: list[str] = []

        if self._is_ip_host(hostname):
            rules.append(
                TriggeredRule(
                    name="ip-host",
                    severity="high",
                    description="URL uses a raw IP address instead of a domain name.",
                )
            )
            indicators.append("raw_ip_host")

        if hostname in _SHORTENER_HOSTS:
            rules.append(
                TriggeredRule(
                    name="shortener",
                    severity="medium",
                    description="URL uses a shortening service that can obscure the final destination.",
                )
            )
            indicators.append("shortened_url")

        keyword_hits = [keyword for keyword in _URL_KEYWORDS if keyword in path_and_query or keyword in hostname]
        if len(keyword_hits) >= 2:
            rules.append(
                TriggeredRule(
                    name="credential-lure",
                    severity="high",
                    description="URL contains multiple credential or payment themed terms.",
                )
            )
            indicators.append("credential_keywords")

        if parsed.scheme and parsed.scheme.lower() != "https":
            rules.append(
                TriggeredRule(
                    name="insecure-transport",
                    severity="medium",
                    description="URL does not use HTTPS.",
                )
            )
            indicators.append("no_https")

        if "@" in normalized_url or "%40" in normalized_url:
            rules.append(
                TriggeredRule(
                    name="user-info-obfuscation",
                    severity="high",
                    description="URL includes user-info style obfuscation.",
                )
            )
            indicators.append("at_symbol_obfuscation")

        return rules, indicators

    def _evaluate_file_rules(
        self,
        *,
        normalized_name: str,
        decoded_content: str,
        file_bytes: bytes,
    ) -> tuple[list[TriggeredRule], list[str]]:
        rules: list[TriggeredRule] = []
        indicators: list[str] = []
        extension = self._extension(normalized_name)
        has_suspicious_keywords = self._has_suspicious_file_keywords(normalized_name, decoded_content)
        is_unknown_source = self._is_unknown_file_source(normalized_name, decoded_content)
        has_double_extension = self._has_double_extension(normalized_name)
        has_random_name = self._has_random_file_name(normalized_name)
        has_suspicious_markers = self._has_suspicious_file_markers(decoded_content)
        is_low_risk_executable = self._is_low_risk_executable(
            extension=extension,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_suspicious_markers=has_suspicious_markers,
            is_reasonable_filename=self._is_reasonable_filename(normalized_name),
        )

        if self._is_high_risk_file_extension(extension, normalized_name, decoded_content):
            rules.append(
                TriggeredRule(
                    name="high-risk-extension",
                    severity="high",
                    description="File extension is commonly associated with executable or macro-enabled content.",
                )
            )
            indicators.append("high_risk_extension")

        if extension == ".exe" and is_unknown_source and not is_low_risk_executable:
            rules.append(
                TriggeredRule(
                    name="unknown-file-source",
                    severity="medium",
                    description="Executable does not contain signals of a known trusted software source.",
                )
            )
            indicators.append("unknown_file_source")

        marker_hits = [marker for marker in _SUSPICIOUS_FILE_MARKERS if marker in decoded_content]
        if marker_hits:
            rules.append(
                TriggeredRule(
                    name="suspicious-content-marker",
                    severity="high",
                    description="File content matches known suspicious execution or malware markers.",
                )
            )
            indicators.append("suspicious_content_markers")

        if has_suspicious_keywords:
            rules.append(
                TriggeredRule(
                    name="suspicious-keywords",
                    severity="high",
                    description="File name or decoded content contains suspicious malware-related keywords.",
                )
            )
            indicators.append("suspicious_keywords")

        if len(file_bytes) > 0 and self._null_byte_ratio(file_bytes) > 0.3 and extension in {".js", ".vbs", ".ps1", ".bat"}:
            rules.append(
                TriggeredRule(
                    name="binary-script-mismatch",
                    severity="high",
                    description="Script-like extension contains strongly binary-looking content.",
                )
            )
            indicators.append("binary_script_mismatch")

        if any(marker in decoded_content for marker in ("autoopen", "document_open", "createobject", "wscript.shell")):
            rules.append(
                TriggeredRule(
                    name="macro-execution-pattern",
                    severity="high",
                    description="File content suggests macro or script-driven execution behavior.",
                )
            )
            indicators.append("macro_execution_pattern")

        return rules, indicators

    def _score_url_heuristics(
        self,
        *,
        normalized_url: str,
        hostname: str,
        path_and_query: str,
        parsed: Any,
        rule_count: int,
    ) -> int:
        score = rule_count * 18
        keyword_hits = sum(1 for keyword in _URL_KEYWORDS if keyword in path_and_query or keyword in hostname)
        score += min(keyword_hits * 8, 24)
        score += min(len(normalized_url) // 12, 10)
        score += min(hostname.count(".") * 4, 12)
        score += min(sum(character.isdigit() for character in hostname), 8)
        score += 8 if "-" in hostname else 0
        score += 8 if len(parse_qs(parsed.query)) >= 4 else 0
        score += 6 if normalized_url.count("%") >= 3 else 0
        if self._is_whitelisted_domain(hostname):
            score = self._apply_whitelist_reduction(score)
        elif self._is_trusted_domain(hostname):
            score = self._apply_trusted_domain_reduction(score)
        return min(score, 100)

    def _score_file_heuristics(
        self,
        *,
        normalized_name: str,
        decoded_content: str,
        file_bytes: bytes,
        rule_count: int,
    ) -> int:
        score = rule_count * 20
        if self._has_clean_filename_signal(normalized_name):
            score = self._apply_clean_filename_reduction(score)
        if self._has_obfuscated_powershell(decoded_content):
            score += 20
        if self._has_ransomware_behavior(normalized_name, decoded_content):
            score += 25
        if self._has_trojan_behavior(normalized_name, decoded_content):
            score += 20
        if self._has_registry_persistence(decoded_content):
            score += 15
        if self._has_known_malware_hash(file_bytes):
            score += 40
        if self._has_suspicious_network_activity(decoded_content):
            score += 15
        if self._is_trusted_file_source(normalized_name, decoded_content):
            score = self._apply_trusted_file_reduction(score)
        return min(score, 100)

    def _classify_url(
        self,
        *,
        normalized_url: str,
        hostname: str,
        parsed: Any,
        rule_count: int,
        indicator_count: int,
    ) -> float:
        special_ratio = self._character_ratio(normalized_url, lambda character: not character.isalnum())
        digit_ratio = self._character_ratio(hostname, str.isdigit)
        features = {
            "bias": -2.8,
            "rule_count": 0.95 * rule_count,
            "indicator_count": 0.45 * indicator_count,
            "url_length": 0.018 * min(len(normalized_url), 150),
            "subdomains": 0.35 * max(hostname.count(".") - 1, 0),
            "ip_host": 1.4 if self._is_ip_host(hostname) else 0.0,
            "not_https": 0.9 if parsed.scheme.lower() != "https" else 0.0,
            "special_ratio": 2.2 * special_ratio,
            "digit_ratio": 1.8 * digit_ratio,
        }
        return self._sigmoid(sum(features.values()))

    def _classify_file(
        self,
        *,
        normalized_name: str,
        decoded_content: str,
        file_bytes: bytes,
        rule_count: int,
        indicator_count: int,
    ) -> float:
        extension = self._extension(normalized_name)
        has_double_extension = self._has_double_extension(normalized_name)
        has_suspicious_keywords = self._has_suspicious_file_keywords(normalized_name, decoded_content)
        has_random_name = self._has_random_file_name(normalized_name)
        has_obfuscated_powershell = self._has_obfuscated_powershell(decoded_content)
        has_ransomware_behavior = self._has_ransomware_behavior(normalized_name, decoded_content)
        has_trojan_behavior = self._has_trojan_behavior(normalized_name, decoded_content)
        has_registry_persistence = self._has_registry_persistence(decoded_content)
        has_known_malware_hash = self._has_known_malware_hash(file_bytes)
        has_suspicious_network_activity = self._has_suspicious_network_activity(decoded_content)
        trusted_source = self._is_trusted_file_source(normalized_name, decoded_content)
        known_software_name = self._has_known_software_name(normalized_name)
        distribution_pattern = self._has_software_distribution_pattern(normalized_name)
        is_reasonable_filename = self._is_reasonable_filename(normalized_name)
        has_signature_signal = self._has_signature_signal(decoded_content)
        has_trusted_domain_reference = self._has_trusted_domain_reference(decoded_content)
        reputation_assessment = self._assess_file_reputation(
            normalized_name=normalized_name,
            sha256=hashlib.sha256(file_bytes).hexdigest() if file_bytes else "",
        )
        has_real_suspicious_behavior = any(
            (
                has_obfuscated_powershell,
                has_ransomware_behavior,
                has_trojan_behavior,
                has_registry_persistence,
                has_known_malware_hash,
                has_suspicious_network_activity,
            )
        )
        low_risk_executable = self._is_low_risk_executable(
            extension=extension,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_suspicious_markers=has_real_suspicious_behavior,
            is_reasonable_filename=is_reasonable_filename,
        )
        benign_software_package = self._is_benign_software_package(
            extension=extension,
            has_known_software_name=known_software_name,
            has_distribution_pattern=distribution_pattern,
            has_double_extension=has_double_extension,
            has_suspicious_keywords=has_suspicious_keywords,
            has_random_name=has_random_name,
            has_suspicious_markers=has_real_suspicious_behavior,
            is_reasonable_filename=is_reasonable_filename,
        )
        features = {
            "bias": -4.8,
            "rule_count": 0.9 * rule_count,
            "indicator_count": 0.5 * indicator_count,
            "double_extension": 1.5 if has_double_extension else 0.0,
            "obfuscated_powershell": 2.4 if has_obfuscated_powershell else 0.0,
            "ransomware_behavior": 2.7 if has_ransomware_behavior else 0.0,
            "trojan_behavior": 2.2 if has_trojan_behavior else 0.0,
            "registry_persistence": 1.6 if has_registry_persistence else 0.0,
            "known_malware_hash": 3.8 if has_known_malware_hash else 0.0,
            "suspicious_network_activity": 1.7 if has_suspicious_network_activity else 0.0,
            "trusted_source": -1.5 if trusted_source else 0.0,
            "known_software_name": -1.0 if known_software_name else 0.0,
            "safe_hash_match": -2.3 if reputation_assessment.exact_safe_match else 0.0,
            "popular_safe_family": -0.9 if reputation_assessment.popular_family_match else 0.0,
            "trusted_domain_reference": -0.8 if has_trusted_domain_reference else 0.0,
            "signature_signal": -1.6 if has_signature_signal else 0.0,
            "distribution_pattern": -0.6 if distribution_pattern else 0.0,
            "low_risk_executable": -0.7 if low_risk_executable else 0.0,
            "benign_software_package": -0.8 if benign_software_package else 0.0,
            "untrusted_active_script": 0.8 if extension in _ACTIVE_RISK_EXTENSIONS and not trusted_source else 0.0,
            "unknown_source": 0.2 if not trusted_source and not known_software_name and has_random_name else 0.0,
        }
        return self._sigmoid(sum(features.values()))

    def _build_analysis(
        self,
        *,
        target: str,
        target_type: str,
        heuristic_score: int,
        ml_probability: float,
        triggered_rules: list[TriggeredRule],
        indicators: list[str],
    ) -> ThreatAnalysis:
        heuristic_label = self._score_to_label(heuristic_score)
        verdict = self._classify_risk_level(heuristic_score)
        ml_label = "malicious" if ml_probability >= 0.65 else "benign"

        confidence = max(heuristic_score / 100, ml_probability)
        details = (
            f"Hybrid analysis classified this {target_type} as {verdict} "
            f"(heuristic={heuristic_score}, ml={ml_probability:.2f}, rules={len(triggered_rules)})."
        )

        return ThreatAnalysis(
            target=target,
            target_type=target_type,
            verdict=verdict,
            confidence=round(confidence, 2),
            heuristic_score=heuristic_score,
            heuristic_label=heuristic_label,
            ml_probability=round(ml_probability, 4),
            ml_label=ml_label,
            triggered_rules=triggered_rules,
            indicators=sorted(set(indicators)),
            details=details,
        )

    @staticmethod
    def _highest_rule_severity(triggered_rules: list[TriggeredRule]) -> str | None:
        severity_order = {"low": 1, "medium": 2, "high": 3}
        if not triggered_rules:
            return None
        return max(triggered_rules, key=lambda rule: severity_order.get(rule.severity, 0)).severity

    @staticmethod
    def _score_to_label(score: int) -> str:
        if score >= 80:
            return "high"
        if score >= 45:
            return "medium"
        return "low"

    @staticmethod
    def _extension(filename: str) -> str:
        dot_index = filename.rfind(".")
        if dot_index == -1:
            return ""
        return filename[dot_index:].lower()

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        base_name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        parts = [segment for segment in base_name.split(".") if segment]
        if len(parts) < 3:
            return False
        final_extension = parts[-1]
        if final_extension not in {"bat", "cmd", "com", "exe", "hta", "js", "lnk", "msi", "ps1", "scr", "vbe", "vbs"}:
            return False
        return any(segment in _DOUBLE_EXTENSION_LURE_EXTENSIONS for segment in parts[:-1])

    @staticmethod
    def _is_ip_host(hostname: str) -> bool:
        if not hostname:
            return False
        try:
            ip_address(hostname)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_trusted_domain(hostname: str) -> bool:
        normalized_host = hostname.lower().strip(".")
        if not normalized_host:
            return False
        return any(
            normalized_host == domain or normalized_host.endswith(f".{domain}")
            for domain in _TRUSTED_DOMAINS
        )

    @staticmethod
    def _apply_trusted_domain_reduction(score: int) -> int:
        return max(score - 40, 0)

    @staticmethod
    def _apply_whitelist_reduction(score: int) -> int:
        return max(score - 40, 0)

    @staticmethod
    def _apply_clean_filename_reduction(score: int) -> int:
        return max(score - 20, 0)

    @staticmethod
    def _apply_trusted_file_reduction(score: int) -> int:
        return max(score - 45, 0)

    @staticmethod
    def _apply_safe_software_reduction(score: int) -> int:
        return max(score - 65, 0)

    @staticmethod
    def _count_keyword_hits(value: str, keywords: tuple[str, ...]) -> int:
        searchable_value = value.lower()
        return sum(1 for keyword in keywords if keyword in searchable_value)

    @staticmethod
    def _normalize_name_token(filename: str) -> str:
        base_name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        stem = base_name.rsplit(".", 1)[0]
        return re.sub(r"[^a-z0-9-]+", "", stem.lower())

    def _is_trusted_file_name(self, filename: str) -> bool:
        normalized_name = self._normalize_name_token(filename)
        return normalized_name in _TRUSTED_FILE_NAMES or any(
            normalized_name.startswith(f"{trusted_name}-")
            for trusted_name in _TRUSTED_FILE_NAMES
        )

    @staticmethod
    def _has_clean_filename_signal(filename: str) -> bool:
        normalized_name = filename.lower()
        return any(marker in normalized_name for marker in _CLEAN_FILE_NAME_MARKERS)

    def _is_reasonable_filename(self, filename: str) -> bool:
        normalized_name = self._normalize_name_token(filename)
        if not normalized_name:
            return False
        if self._has_known_software_name(filename) and self._has_software_distribution_pattern(filename):
            return len(normalized_name) <= 64
        if self._looks_random_token(normalized_name):
            return False
        if len(normalized_name) < 3 or len(normalized_name) > 40:
            return False
        digit_ratio = sum(character.isdigit() for character in normalized_name) / len(normalized_name)
        return digit_ratio <= 0.35

    def _has_known_software_name(self, filename: str) -> bool:
        normalized_name = self._normalize_name_token(filename)
        if not normalized_name:
            return False
        if any(re.search(pattern, normalized_name) for pattern in _KNOWN_SOFTWARE_NAME_PATTERNS):
            return True
        return normalized_name.startswith("git") and (
            "setup" in normalized_name
            or "install" in normalized_name
            or bool(re.search(r"git\d", normalized_name))
        )

    def _has_software_distribution_pattern(self, filename: str) -> bool:
        normalized_name = self._normalize_name_token(filename)
        if not normalized_name:
            return False
        if any(marker in normalized_name for marker in _SOFTWARE_DISTRIBUTION_MARKERS):
            return True
        has_version_pattern = bool(re.search(r"\d{1,2}(?:[._-]?\d{1,2}){1,3}", normalized_name))
        has_architecture_marker = any(marker in normalized_name for marker in _ARCHITECTURE_MARKERS)
        return has_version_pattern and has_architecture_marker

    @staticmethod
    def _is_whitelisted_domain(hostname: str) -> bool:
        normalized_host = hostname.lower().strip(".")
        if not normalized_host:
            return False
        return any(
            normalized_host == domain or normalized_host.endswith(f".{domain}")
            for domain in _DOMAIN_WHITELIST
        )

    @staticmethod
    def _registered_domain(hostname: str) -> str:
        normalized_host = hostname.lower().strip(".")
        labels = [label for label in normalized_host.split(".") if label]
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return normalized_host

    @staticmethod
    def _normalize_domain_sld(hostname: str) -> str:
        registered_domain = ThreatAnalyzer._registered_domain(hostname)
        labels = registered_domain.split(".")
        if len(labels) < 2:
            return ""
        sld = re.sub(r"[^a-z0-9]", "", labels[0])
        substitutions = str.maketrans({
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
        })
        return sld.translate(substitutions)

    @staticmethod
    def _edit_distance(left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)
        previous = list(range(len(right) + 1))
        for left_index, left_character in enumerate(left, start=1):
            current = [left_index]
            for right_index, right_character in enumerate(right, start=1):
                insertion = current[right_index - 1] + 1
                deletion = previous[right_index] + 1
                substitution = previous[right_index - 1] + (left_character != right_character)
                current.append(min(insertion, deletion, substitution))
            previous = current
        return previous[-1]

    def _is_typosquatting_domain(self, hostname: str) -> bool:
        registered_domain = self._registered_domain(hostname)
        if not registered_domain or self._is_trusted_domain(registered_domain) or self._is_ip_host(registered_domain):
            return False

        candidate_labels = registered_domain.split(".")
        if len(candidate_labels) < 2:
            return False
        candidate_tld = candidate_labels[-1]
        candidate_sld = self._normalize_domain_sld(registered_domain)
        if len(candidate_sld) < 4:
            return False

        for trusted_domain in _TRUSTED_DOMAINS | _DOMAIN_WHITELIST:
            trusted_labels = trusted_domain.split(".")
            if len(trusted_labels) < 2 or candidate_tld != trusted_labels[-1]:
                continue
            trusted_sld = re.sub(r"[^a-z0-9]", "", trusted_labels[0])
            distance = self._edit_distance(candidate_sld, trusted_sld)
            if distance == 1:
                return True
            if candidate_sld.startswith(trusted_sld) and len(candidate_sld) - len(trusted_sld) == 1:
                return True
            if trusted_sld.startswith(candidate_sld) and len(trusted_sld) - len(candidate_sld) == 1:
                return True
        return False

    def _assess_url_trust(self, hostname: str, path_and_query: str, parsed: Any) -> TrustAssessment:
        normalized_host = hostname.lower().strip(".")
        reputation_score = 45
        signals: list[str] = []
        if not normalized_host:
            return TrustAssessment(reputation_score=0, signals=signals)
        if self._is_whitelisted_domain(normalized_host):
            reputation_score += 50
            signals.append("Trusted whitelist domain")
        elif self._is_trusted_domain(normalized_host):
            reputation_score += 35
            signals.append("Known trusted domain")
        if normalized_host in _SHORTENER_HOSTS:
            reputation_score -= 20
            signals.append("Shortened redirect domain")
        if self._is_ip_host(normalized_host):
            reputation_score -= 25
            signals.append("Raw IP destination")
        if any(normalized_host.endswith(tld) for tld in (".xyz", ".ru", ".tk")):
            reputation_score -= 20
            signals.append("Low-trust TLD")
        if self._has_random_url_pattern(normalized_host, path_and_query):
            reputation_score -= 15
            signals.append("Randomized host or path token")
        if self._is_typosquatting_domain(normalized_host):
            reputation_score -= 35
            signals.append("Possible typosquatting domain")
        if parsed.scheme.lower() == "https":
            reputation_score += 5
            signals.append("HTTPS transport")
        else:
            signals.append("No HTTPS transport")
        return TrustAssessment(
            reputation_score=max(0, min(reputation_score, 100)),
            signals=signals,
            is_whitelisted=self._is_whitelisted_domain(normalized_host),
            is_trusted=self._is_trusted_domain(normalized_host),
        )

    def _assess_url_context(
        self,
        *,
        normalized_url: str,
        hostname: str,
        path_and_query: str,
        parsed: Any,
        trust_assessment: TrustAssessment,
    ) -> ContextAssessment:
        signals: list[str] = []
        if hostname and len(hostname.split(".")) > 4:
            signals.append("Deep domain structure")
        if "-" in hostname and not self._is_trusted_domain(hostname):
            signals.append("Hyphenated domain pattern")
        if len(normalized_url) > 75:
            signals.append("Long URL length pattern")
        digit_ratio = self._character_ratio(hostname, str.isdigit)
        if digit_ratio >= 0.2:
            signals.append("Digit-heavy hostname pattern")
        if parsed.scheme.lower() != "https":
            signals.append("No HTTPS transport")
        if self._is_typosquatting_domain(hostname):
            signals.append("Typosquatting resemblance")
        if self._count_keyword_hits(path_and_query, _URL_KEYWORDS) >= 2 and not trust_assessment.is_trusted:
            signals.append("Credential-oriented path semantics")
        return ContextAssessment(signals=signals)

    def _assess_url_behavior(
        self,
        *,
        normalized_url: str,
        hostname: str,
        path_and_query: str,
        parsed: Any,
        trust_assessment: TrustAssessment,
    ) -> BehaviorAssessment:
        signals: list[str] = []
        risk_floor: str | None = None
        phishing_hits = self._count_keyword_hits(f"{hostname} {path_and_query}", _PHISHING_KEYWORDS)
        if self._is_typosquatting_domain(hostname):
            signals.append("Typosquatting delivery pattern")
            risk_floor = "suspicious"
        if phishing_hits >= 2 and not trust_assessment.is_trusted:
            signals.append("Credential-themed URL pattern")
            risk_floor = "suspicious"
        if hostname in _SHORTENER_HOSTS and ("@" in normalized_url or "%40" in normalized_url):
            signals.append("Obfuscated redirect pattern")
            risk_floor = "suspicious"
        if parsed.scheme.lower() != "https" and phishing_hits >= 1 and not trust_assessment.is_trusted:
            signals.append("Insecure login-style delivery pattern")
            risk_floor = "suspicious"
        return BehaviorAssessment(signals=signals, risk_floor=risk_floor)

    @staticmethod
    def _assess_file_trust(
        *,
        normalized_name: str,
        decoded_content: str,
        extension: str,
        is_trusted_source: bool,
        is_trusted_name: bool,
        signature_assessment: DigitalSignatureAssessment,
        reputation_assessment: ReputationAssessment,
        has_signature_signal: bool,
        has_trusted_vendor_match: bool,
        has_trusted_domain_reference: bool,
        has_clean_filename: bool,
        has_known_software_name: bool,
        has_distribution_pattern: bool,
        has_random_name: bool,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_suspicious_markers: bool,
        is_low_risk_executable: bool,
        is_benign_software_package: bool,
    ) -> TrustAssessment:
        reputation_score = 50
        signals: list[str] = []
        if signature_assessment.is_valid:
            reputation_score += 30
            signals.append("Valid digital signature")
        if signature_assessment.is_trusted_publisher:
            reputation_score += 25
            publisher = signature_assessment.publisher or "trusted publisher"
            signals.append(f"Trusted publisher certificate ({publisher})")
        if reputation_assessment.exact_safe_match:
            reputation_score += 35
            signals.append(f"Known safe software hash ({reputation_assessment.exact_safe_match})")
        if reputation_assessment.popular_family_match:
            reputation_score += 15
            signals.append(f"Recognized popular installer family ({reputation_assessment.popular_family_match})")
        if has_signature_signal:
            reputation_score += 10
            signals.append("Digital signature markers")
        if has_trusted_vendor_match:
            reputation_score += 25
            signals.append("Trusted vendor markers")
        if has_trusted_domain_reference:
            reputation_score += 15
            signals.append("Trusted vendor domain reference")
        if is_trusted_source:
            reputation_score += 15
            signals.append("Known software source markers")
        if has_known_software_name:
            reputation_score += 20
            signals.append("Recognized software vendor or product name")
        if has_distribution_pattern:
            reputation_score += 5
            signals.append("Common software distribution pattern")
        if has_clean_filename:
            reputation_score += 10
            signals.append("Clean installer-style filename")
        if is_trusted_name:
            reputation_score += 10
            signals.append("Trusted documentation-style filename")
        if is_benign_software_package:
            reputation_score += 8
            signals.append("Benign packaged software profile")
        if is_low_risk_executable:
            reputation_score += 10
            signals.append("Reasonable executable filename with no suspicious keywords")
        if extension in _SOFTWARE_PACKAGE_EXTENSIONS and not has_random_name and not has_suspicious_keywords and not has_suspicious_markers:
            reputation_score += 5
        if has_random_name:
            reputation_score -= 20
        if has_double_extension:
            reputation_score -= 30
        if has_suspicious_keywords:
            reputation_score -= 10
        if has_suspicious_markers:
            reputation_score -= 30
        return TrustAssessment(
            reputation_score=max(0, min(reputation_score, 100)),
            signals=signals,
            is_trusted=any(
                (
                    is_trusted_source,
                    is_trusted_name,
                    has_known_software_name,
                    signature_assessment.is_valid,
                    signature_assessment.is_trusted_publisher,
                    bool(reputation_assessment.exact_safe_match),
                    has_signature_signal,
                    has_trusted_vendor_match,
                    has_trusted_domain_reference,
                )
            ),
        )

    def _assess_file_context(
        self,
        *,
        normalized_name: str,
        has_clean_filename: bool,
        has_known_software_name: bool,
        has_distribution_pattern: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        is_trusted_name: bool,
    ) -> ContextAssessment:
        signals: list[str] = []
        normalized_token = self._normalize_name_token(normalized_name)
        if has_clean_filename:
            signals.append("Installer-style filename semantics")
        if has_known_software_name:
            signals.append("Recognized software product naming")
        if has_distribution_pattern:
            signals.append("Common software distribution naming pattern")
        if has_suspicious_keywords:
            signals.append("Payload-oriented filename semantics")
        if is_trusted_name:
            signals.append("Documentation-style filename semantics")
        if has_random_name:
            signals.append("Randomized filename semantics")
        if normalized_token and (len(normalized_token) < 3 or len(normalized_token) > 40):
            signals.append("Abnormal filename length pattern")
        elif normalized_token:
            digit_ratio = self._character_ratio(normalized_token, str.isdigit)
            if digit_ratio > 0.35:
                signals.append("Digit-heavy filename pattern")
        return ContextAssessment(signals=signals)

    @staticmethod
    def _assess_file_behavior(
        *,
        normalized_name: str,
        extension: str,
        is_unknown_source: bool,
        has_random_name: bool,
        has_double_extension: bool,
        has_obfuscated_powershell: bool,
        has_ransomware_behavior: bool,
        has_trojan_behavior: bool,
        has_registry_persistence: bool,
        has_suspicious_network_activity: bool,
        has_known_malware_hash: bool,
        is_low_risk_executable: bool,
        is_benign_software_package: bool,
    ) -> BehaviorAssessment:
        signals: list[str] = []
        risk_floor: str | None = None
        if extension == ".exe" and has_double_extension:
            signals.append("Executable masquerading through double extension")
            risk_floor = "suspicious"
        if has_obfuscated_powershell:
            signals.append("Obfuscated PowerShell execution pattern")
            risk_floor = "suspicious"
        if has_ransomware_behavior:
            signals.append("Ransomware execution pattern")
            risk_floor = "malicious"
        if has_trojan_behavior:
            signals.append("Trojan-like execution behavior")
            risk_floor = "suspicious"
        if has_registry_persistence:
            signals.append("Registry-based persistence pattern")
            risk_floor = "suspicious"
        if has_suspicious_network_activity:
            signals.append("Suspicious outbound network behavior")
            risk_floor = "suspicious"
        if has_known_malware_hash:
            signals.append("Known malware fingerprint matched")
            risk_floor = "malicious"
        if extension == ".exe" and has_random_name and is_unknown_source and not signals:
            signals.append("Unknown executable provenance")
        if is_benign_software_package:
            signals.append("Benign software packaging pattern")
        if is_low_risk_executable and not signals:
            signals.append("Standalone executable without suspicious behavioral context")
        return BehaviorAssessment(signals=signals, risk_floor=risk_floor)

    @staticmethod
    def _apply_behavior_risk_floor(risk_level: str, risk_floor: str | None) -> str:
        if not risk_floor:
            return risk_level
        severity_order = {
            "safe": 0,
            "low_risk": 1,
            "suspicious": 2,
            "malicious": 3,
        }
        if severity_order.get(risk_level, 0) >= severity_order.get(risk_floor, 0):
            return risk_level
        return risk_floor

    @staticmethod
    def _count_strong_reasons(reasons: list[str]) -> int:
        strong_reasons = {
            "IP address used",
            "Typosquatting pattern detected",
            "Double extension detected",
            "Known malware hash detected",
            "Obfuscated PowerShell detected",
            "Ransomware behavior detected",
            "Registry persistence detected",
            "Suspicious network activity detected",
            "Trojan behavior detected",
        }
        return sum(1 for reason in reasons if reason in strong_reasons)

    @staticmethod
    def _count_suspicious_context_signals(context_signals: list[str]) -> int:
        benign_context_signals = {
            "Abnormal filename length pattern",
            "Common software distribution naming pattern",
            "Digit-heavy filename pattern",
            "Installer-style filename semantics",
            "Documentation-style filename semantics",
            "Payload-oriented filename semantics",
            "Recognized software product naming",
            "Randomized filename semantics",
        }
        return sum(1 for signal in context_signals if signal not in benign_context_signals)

    @staticmethod
    def _count_suspicious_behavior_signals(behavior_signals: list[str]) -> int:
        benign_behavior_signals = {
            "Benign software packaging pattern",
            "Unknown executable provenance",
            "Standalone executable without suspicious behavioral context",
        }
        return sum(1 for signal in behavior_signals if signal not in benign_behavior_signals)

    @staticmethod
    def _looks_random_token(token: str) -> bool:
        normalized_token = re.sub(r"[^a-z0-9]", "", token.lower())
        if len(normalized_token) < 10 or normalized_token.isalpha() or normalized_token.isdigit():
            return False

        digit_ratio = sum(character.isdigit() for character in normalized_token) / len(normalized_token)
        alpha_characters = [character for character in normalized_token if character.isalpha()]
        vowel_ratio = (
            sum(character in "aeiou" for character in alpha_characters) / len(alpha_characters)
            if alpha_characters
            else 0.0
        )
        unique_ratio = len(set(normalized_token)) / len(normalized_token)
        return digit_ratio >= 0.25 and vowel_ratio <= 0.35 and unique_ratio >= 0.7

    def _has_random_url_pattern(self, hostname: str, path_and_query: str) -> bool:
        host_tokens = [token for token in hostname.split(".") if token]
        path_tokens = [token for token in re.split(r"[/?&=_-]+", path_and_query) if token]
        return any(self._looks_random_token(token) for token in [*host_tokens, *path_tokens])

    def _has_random_file_name(self, filename: str) -> bool:
        if self._has_known_software_name(filename) and self._has_software_distribution_pattern(filename):
            return False
        return self._looks_random_token(self._normalize_name_token(filename))

    @staticmethod
    def _calculate_confidence(detection_count: int, ml_probability: float) -> int:
        normalized_ml_probability = min(max(ml_probability, 0.0), 1.0)
        baseline = 30 if detection_count == 0 else 20
        detection_component = min(detection_count * 15, 45)
        ml_component = int(round(normalized_ml_probability * 35))
        return min(baseline + detection_component + ml_component, 100)

    @staticmethod
    def _has_suspicious_file_keywords(normalized_name: str, decoded_content: str) -> bool:
        searchable_text = f"{normalized_name} {decoded_content}"
        return any(keyword in searchable_text for keyword in _SUSPICIOUS_FILE_KEYWORDS)

    @staticmethod
    def _has_suspicious_file_markers(decoded_content: str) -> bool:
        return any(marker in decoded_content for marker in _SUSPICIOUS_FILE_MARKERS)

    @staticmethod
    def _has_trusted_vendor_match(normalized_name: str, decoded_content: str) -> bool:
        searchable_text = f"{normalized_name} {decoded_content[:8192]}"
        return any(marker in searchable_text for marker in _KNOWN_FILE_SOURCE_MARKERS)

    @staticmethod
    def _has_signature_signal(decoded_content: str) -> bool:
        return any(marker in decoded_content for marker in _SIGNATURE_MARKERS)

    @staticmethod
    def _match_popular_safe_software(normalized_name: str) -> str | None:
        for label, pattern in _POPULAR_SAFE_SOFTWARE_PATTERNS.items():
            if re.search(pattern, normalized_name):
                return label
        return None

    def _assess_file_reputation(self, *, normalized_name: str, sha256: str) -> ReputationAssessment:
        signals: list[str] = []
        exact_safe_match = _KNOWN_SAFE_SOFTWARE_HASHES.get((sha256 or "").lower())
        if exact_safe_match:
            signals.append(f"Known safe software hash ({exact_safe_match})")

        popular_family_match = self._match_popular_safe_software(normalized_name)
        if popular_family_match:
            signals.append(f"Recognized popular installer family ({popular_family_match})")

        return ReputationAssessment(
            signals=signals,
            exact_safe_match=exact_safe_match,
            popular_family_match=popular_family_match,
        )

    @staticmethod
    def _should_fast_track_official_installer(
        *,
        extension: str,
        has_known_software_name: bool,
        has_distribution_pattern: bool,
        has_clean_filename: bool,
        has_reasonable_filename: bool,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        has_known_malware_hash: bool,
        has_obfuscated_powershell: bool,
        has_ransomware_behavior: bool,
        has_trojan_behavior: bool,
        has_registry_persistence: bool,
        has_suspicious_network_activity: bool,
        reputation_assessment: ReputationAssessment,
    ) -> bool:
        if extension != ".exe":
            return False
        if has_double_extension or has_known_malware_hash:
            return False
        if any(
            (
                has_obfuscated_powershell,
                has_ransomware_behavior,
                has_trojan_behavior,
                has_registry_persistence,
                has_suspicious_network_activity,
            )
        ):
            return False
        if not has_reasonable_filename or has_random_name or has_suspicious_keywords:
            return False
        return bool(
            reputation_assessment.exact_safe_match
            or reputation_assessment.popular_family_match
            or (has_known_software_name and has_distribution_pattern)
            or (has_known_software_name and has_clean_filename)
        )

    def _build_trusted_installer_analysis(
        self,
        *,
        target: str,
        file_sha256: str,
        reputation_assessment: ReputationAssessment,
        has_known_software_name: bool,
        has_distribution_pattern: bool,
        has_clean_filename: bool,
        has_reasonable_filename: bool,
        has_trusted_vendor_match: bool,
        has_trusted_domain_reference: bool,
        has_signature_signal: bool,
        is_trusted_name: bool,
    ) -> dict[str, Any]:
        trust_signals = list(reputation_assessment.signals)
        if has_known_software_name:
            trust_signals.append("Recognized software vendor or product name")
        if has_distribution_pattern:
            trust_signals.append("Common software distribution pattern")
        if has_clean_filename:
            trust_signals.append("Clean installer-style filename")
        if has_trusted_vendor_match:
            trust_signals.append("Trusted vendor markers")
        if has_trusted_domain_reference:
            trust_signals.append("Trusted vendor domain reference")
        if has_signature_signal:
            trust_signals.append("Digital signature markers")
        if is_trusted_name:
            trust_signals.append("Trusted documentation-style filename")

        reputation_score = 95 if (
            reputation_assessment.exact_safe_match
            or has_trusted_vendor_match
            or has_signature_signal
            or has_trusted_domain_reference
        ) else 88
        risk_level = "safe" if reputation_score >= 95 else "low_risk"
        context_signals = [
            "Installer-style filename semantics",
            "Recognized software product naming",
            "Common software distribution naming pattern",
        ]
        if is_trusted_name:
            context_signals.append("Documentation-style filename semantics")
        behavioral_signals = [
            "Benign software packaging pattern",
            "Standalone executable without suspicious behavioral context",
        ]
        explanation = (
            "Recognized official installer family and no malicious behavior indicators were found. "
            "Trusted installer scans are short-circuited so the result stays fast and positive."
        )
        return {
            "confidence": 92,
            "confidence_level": "high",
            "score": 0,
            "risk_level": risk_level,
            "verdict": "Trusted" if risk_level == "safe" else "Likely Trusted",
            "confidence_percent": 92,
            "reasons": [],
            "explanation": explanation,
            "ai_summary": self._build_ai_summary(
                verdict="Trusted" if risk_level == "safe" else "Likely Trusted",
                confidence=92,
                reasons=trust_signals[:4] if trust_signals else ["No malware indicators"],
                recommended_action="Allow with standard controls",
            ),
            "recommended_action": "Allow with standard controls",
            "file_sha256": file_sha256,
            "ml_prediction": 0,
            "reputation_score": reputation_score,
            "trust_score": reputation_score,
            "trust_signals": self._dedupe_signals(trust_signals),
            "reputation_signals": self._dedupe_signals(trust_signals),
            "signature_status": "not_checked",
            "signature_publisher": None,
            "signature_issuer": None,
            "signature_trusted_publisher": False,
            "context_signals": context_signals,
            "behavioral_signals": behavioral_signals,
        }

    @staticmethod
    def _is_trusted_publisher(publisher: str | None, issuer: str | None = None) -> bool:
        searchable_text = " ".join(part for part in (publisher, issuer) if part).lower()
        if not searchable_text:
            return False
        return any(marker in searchable_text for marker in _TRUSTED_PUBLISHER_MARKERS)

    def _has_trusted_domain_reference(self, decoded_content: str) -> bool:
        hostnames = re.findall(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", decoded_content[:8192])
        return any(self._is_trusted_domain(hostname) for hostname in hostnames)

    def _analyze_digital_signature(self, file_path: str | None) -> DigitalSignatureAssessment:
        if not file_path:
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="not_checked",
                signals=[],
            )

        path = Path(file_path)
        if not path.exists():
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="missing_file",
                signals=[],
            )

        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell is None:
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="unavailable",
                signals=[],
            )

        escaped_path = str(path).replace("'", "''")
        command = (
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
            "[pscustomobject]@{"
            "Status = [string]$sig.Status; "
            "StatusMessage = [string]$sig.StatusMessage; "
            "Publisher = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }; "
            "Issuer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Issuer } else { '' }"
            "} | ConvertTo-Json -Compress"
        )

        try:
            completed = subprocess.run(
                [powershell, "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="error",
                signals=[],
            )

        if completed.returncode != 0 or not completed.stdout.strip():
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="error",
                signals=[],
            )

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return DigitalSignatureAssessment(
                is_signed=False,
                is_valid=False,
                publisher=None,
                issuer=None,
                status="error",
                signals=[],
            )

        status = str(payload.get("Status") or "unknown")
        publisher = re.sub(r"\s+", " ", str(payload.get("Publisher") or "")).strip(" ,") or None
        issuer = re.sub(r"\s+", " ", str(payload.get("Issuer") or "")).strip(" ,") or None
        is_signed = publisher is not None or status.lower() not in {"notsigned", "not_signed"}
        is_valid = status.lower() == "valid"
        is_trusted_publisher = is_valid and self._is_trusted_publisher(publisher, issuer)
        signals: list[str] = []
        if is_valid:
            signals.append("Valid digital signature")
        if is_trusted_publisher and publisher:
            signals.append(f"Trusted publisher certificate ({publisher})")

        return DigitalSignatureAssessment(
            is_signed=is_signed,
            is_valid=is_valid,
            publisher=publisher,
            issuer=issuer,
            status=status,
            signals=signals,
            is_trusted_publisher=is_trusted_publisher,
        )

    def _is_trusted_file_source(self, normalized_name: str, decoded_content: str) -> bool:
        return any(
            (
                self._has_trusted_vendor_match(normalized_name, decoded_content),
                self._has_signature_signal(decoded_content),
                self._has_trusted_domain_reference(decoded_content),
            )
        )

    def _is_unknown_file_source(self, normalized_name: str, decoded_content: str) -> bool:
        return not self._is_trusted_file_source(normalized_name, decoded_content)

    @staticmethod
    def _has_obfuscated_powershell(decoded_content: str) -> bool:
        if "powershell" not in decoded_content and "pwsh" not in decoded_content:
            return False
        return any(marker in decoded_content for marker in _POWERSHELL_OBFUSCATION_MARKERS)

    @staticmethod
    def _has_ransomware_behavior(normalized_name: str, decoded_content: str) -> bool:
        searchable_text = f"{normalized_name} {decoded_content}"
        return any(marker in searchable_text for marker in _RANSOMWARE_MARKERS)

    @staticmethod
    def _has_trojan_behavior(normalized_name: str, decoded_content: str) -> bool:
        searchable_text = f"{normalized_name} {decoded_content}"
        return any(marker in searchable_text for marker in _TROJAN_BEHAVIOR_MARKERS)

    @staticmethod
    def _has_registry_persistence(decoded_content: str) -> bool:
        return any(marker in decoded_content for marker in _REGISTRY_PERSISTENCE_MARKERS)

    @staticmethod
    def _has_known_malware_hash(file_bytes: bytes) -> bool:
        if not file_bytes:
            return False
        return hashlib.sha256(file_bytes).hexdigest() in _KNOWN_MALWARE_SHA256

    def _has_suspicious_network_activity(self, decoded_content: str) -> bool:
        if not any(marker in decoded_content for marker in _NETWORK_EXECUTION_MARKERS):
            return False

        hostnames = re.findall(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", decoded_content[:8192])
        raw_ip_hosts = re.findall(r"(?:https?://)?((?:\d{1,3}\.){3}\d{1,3})", decoded_content[:8192])
        if any(self._is_ip_host(hostname) for hostname in raw_ip_hosts):
            return True
        if any(self._is_ip_host(hostname) for hostname in hostnames):
            return True

        untrusted_hosts = [
            hostname
            for hostname in hostnames
            if not self._is_trusted_domain(hostname)
        ]
        return bool(untrusted_hosts)

    def _is_suspicious_executable(
        self,
        *,
        normalized_name: str,
        decoded_content: str,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        has_suspicious_markers: bool,
    ) -> bool:
        return (
            has_double_extension
            or has_suspicious_markers
            or (
                self._is_unknown_file_source(normalized_name, decoded_content)
                and (has_suspicious_markers or (has_random_name and has_suspicious_keywords))
            )
        )

    @staticmethod
    def _is_low_risk_executable(
        *,
        extension: str,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        has_suspicious_markers: bool,
        is_reasonable_filename: bool,
    ) -> bool:
        return (
            extension == ".exe"
            and not has_double_extension
            and not has_suspicious_keywords
            and not has_random_name
            and not has_suspicious_markers
            and is_reasonable_filename
        )

    @staticmethod
    def _is_benign_software_package(
        *,
        extension: str,
        has_known_software_name: bool,
        has_distribution_pattern: bool,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        has_suspicious_markers: bool,
        is_reasonable_filename: bool,
    ) -> bool:
        return (
            extension in _SOFTWARE_PACKAGE_EXTENSIONS
            and has_known_software_name
            and not has_double_extension
            and not has_suspicious_keywords
            and not has_random_name
            and not has_suspicious_markers
            and is_reasonable_filename
        )

    @staticmethod
    def _should_flag_unknown_executable_source(
        *,
        is_unknown_source: bool,
        has_double_extension: bool,
        has_suspicious_keywords: bool,
        has_random_name: bool,
        has_suspicious_markers: bool,
        phishing_hits: int,
    ) -> bool:
        return is_unknown_source and any(
            (
                has_double_extension,
                has_suspicious_keywords,
                has_random_name,
                has_suspicious_markers,
                phishing_hits >= 1,
            )
        )

    @staticmethod
    def _dedupe_signals(signals: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for signal in signals:
            normalized = signal.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    @staticmethod
    def _build_explanation(
        *,
        target_type: str,
        risk_level: str,
        reasons: list[str],
        is_whitelisted: bool = False,
        is_trusted: bool = False,
        trust_signals: list[str] | None = None,
        context_signals: list[str] | None = None,
        behavior_signals: list[str] | None = None,
    ) -> str:
        trust_signals = trust_signals or []
        context_signals = context_signals or []
        behavior_signals = behavior_signals or []

        if risk_level == "safe":
            if target_type == "file" and any(
                signal.startswith("Valid digital signature") or signal.startswith("Trusted publisher certificate")
                for signal in trust_signals
            ):
                return "Digitally signed by trusted publisher and matches legitimate software behavior."
            if target_type == "url" and (is_whitelisted or is_trusted):
                if "HTTPS transport" in trust_signals:
                    return "Trusted domain uses HTTPS and shows no phishing or typosquatting indicators."
                return "Trusted domain matched and no phishing or typosquatting indicators were found."
            return "No malicious behavior detected and the item matches legitimate software or domain trust signals."

        if risk_level == "suspicious":
            if target_type == "file" and "Obfuscated PowerShell detected" in reasons:
                if not trust_signals:
                    return "Uses obfuscated commands and lacks trusted signature."
                return "Uses obfuscated commands despite some trust context, so it should be treated cautiously."
            if target_type == "url" and "Typosquatting pattern detected" in reasons:
                return "Looks like a typosquatted domain and shows phishing-style delivery patterns."
            primary_reason = reasons[0] if reasons else "suspicious indicators"
            return f"Shows {primary_reason.lower()} and should be treated with caution."

        if risk_level == "malicious":
            if "Ransomware behavior detected" in reasons and len(reasons) >= 2:
                return "Detected ransomware-like behavior and multiple engine detections."
            if target_type == "url" and "Typosquatting pattern detected" in reasons and "Phishing keyword detected" in reasons:
                return "Detected typosquatting and phishing indicators consistent with credential theft."
            joined_reasons = ", ".join(reason.lower() for reason in reasons[:2]) if reasons else "multiple high-risk indicators"
            return f"Detected {joined_reasons} and classified it as malicious."

        if trust_signals and not reasons:
            return "Trust signals are present, but the item should still be reviewed because it is not fully clean."
        if reasons:
            return f"Mostly safe overall, but {reasons[0].lower()} was observed."
        return "No strong malicious behavior was detected, but trust remains limited."

    @staticmethod
    def _verdict_from_file_analysis(
        *,
        risk_level: str,
        trust_assessment: TrustAssessment,
        signature_assessment: DigitalSignatureAssessment,
        reputation_assessment: ReputationAssessment,
        reasons: list[str],
        trust_signals: list[str],
        context_signals: list[str],
        behavior_signals: list[str],
    ) -> str:
        clean_context = not reasons and not context_signals and not behavior_signals
        trusted_signature = signature_assessment.is_valid and signature_assessment.is_trusted_publisher
        trusted_reputation = bool(reputation_assessment.exact_safe_match or reputation_assessment.popular_family_match)
        trusted_context = trust_assessment.is_trusted or trust_assessment.reputation_score >= 85 or trusted_signature or trusted_reputation

        if risk_level == "malicious":
            return "Malicious"
        if risk_level == "suspicious":
            return "Suspicious"
        if trusted_signature and trusted_context and clean_context:
            return "Trusted"
        if trust_signals and (trusted_context or risk_level == "safe"):
            return "Likely Trusted"
        if risk_level == "safe" and trusted_context:
            return "Trusted"
        if risk_level == "safe" and not trust_signals:
            return "Unknown"
        if risk_level == "low_risk" and not trusted_context:
            return "Unknown"
        if risk_level == "low_risk":
            return "Likely Trusted"
        return "Unknown"

    @staticmethod
    def _recommended_action_for_verdict(verdict: str) -> str:
        return {
            "Trusted": "Allow",
            "Likely Trusted": "Allow with standard monitoring",
            "Unknown": "Review provenance before deployment",
            "Suspicious": "Inspect in a controlled sandbox",
            "Malicious": "Block and quarantine",
        }.get(verdict, "Review manually")

    @staticmethod
    def _ai_reasons_for_file(
        *,
        verdict: str,
        reasons: list[str],
        trust_signals: list[str],
        context_signals: list[str],
        behavior_signals: list[str],
        signature_assessment: DigitalSignatureAssessment,
        reputation_assessment: ReputationAssessment,
        trust_assessment: TrustAssessment,
    ) -> list[str]:
        if verdict in {"Trusted", "Likely Trusted"}:
            output = []
            if signature_assessment.is_valid:
                output.append("Valid Digital Signature")
            if signature_assessment.is_trusted_publisher:
                output.append(f"Trusted Publisher Certificate ({signature_assessment.publisher or 'verified'})")
            if reputation_assessment.exact_safe_match or reputation_assessment.popular_family_match:
                output.append("Known Safe Software Family")
            output.extend(signal for signal in trust_signals if signal not in output)
            if not output:
                output.append("No Malware Indicators")
            return output[:5]
        if verdict == "Unknown":
            output = ["Unknown Hash / No Reputation Data"]
            if trust_assessment.reputation_score >= 70:
                output.append("Limited but non-malicious reputation context")
            return output
        output = []
        output.extend(reasons[:3])
        output.extend(context_signals[:2])
        output.extend(behavior_signals[:2])
        if not output:
            output.append("No strong trust or threat indicators")
        return output[:5]

    @staticmethod
    def _build_ai_summary(*, verdict: str, confidence: int, reasons: list[str], recommended_action: str) -> str:
        reason_lines = "\n".join(f"✓ {reason}" for reason in reasons) if reasons else "✓ No strong malicious indicators"
        return (
            f"Verdict: {verdict}\n"
            f"Confidence: {confidence}%\n\n"
            f"Reasons:\n{reason_lines}\n\n"
            f"Recommended Action: {recommended_action}"
        )

    @staticmethod
    def _calculate_score_breakdown(reasons: list[str]) -> tuple[int, list[tuple[int, str]]]:
        score = 0
        adjustments: list[tuple[int, str]] = []
        weight_map = {
            "IP address used": 28,
            "Suspicious TLD": 18,
            "Long URL": 10,
            "Excessive subdomains": 12,
            "Phishing keyword detected": 14,
            "Randomized URL pattern": 16,
            "Typosquatting pattern detected": 32,
            "Double extension detected": 35,
            "Known malware hash detected": 90,
            "Obfuscated PowerShell detected": 40,
            "Ransomware behavior detected": 45,
            "Registry persistence detected": 30,
            "Suspicious network activity detected": 28,
            "Trojan behavior detected": 38,
        }
        for reason in reasons:
            weight = weight_map.get(reason)
            if weight is None:
                continue
            score += weight
            adjustments.append((weight, reason))
        return score, adjustments

    @staticmethod
    def _log_score_events(target_type: str, target: str, adjustments: list[tuple[int, str]]) -> None:
        if not adjustments:
            logger.info("%s score base for %s: no score increases triggered", target_type, target)
            return
        for delta, reason in adjustments:
            logger.info("%s score change for %s: +%s because %s", target_type, target, delta, reason)

    @staticmethod
    def _log_score_adjustment(target_type: str, target: str, delta: int, reason: str) -> None:
        direction = "+" if delta >= 0 else ""
        logger.info("%s score change for %s: %s%s because %s", target_type, target, direction, delta, reason)

    def _is_high_risk_file_extension(self, extension: str, normalized_name: str, decoded_content: str) -> bool:
        if extension != ".exe":
            return (
                extension in _ACTIVE_RISK_EXTENSIONS | _MACRO_RISK_EXTENSIONS
                and not self._is_trusted_file_source(normalized_name, decoded_content)
            )
        return self._is_suspicious_executable(
            normalized_name=normalized_name,
            decoded_content=decoded_content,
            has_double_extension=self._has_double_extension(normalized_name),
            has_suspicious_keywords=self._has_suspicious_file_keywords(normalized_name, decoded_content),
            has_random_name=self._has_random_file_name(normalized_name),
            has_suspicious_markers=self._has_suspicious_file_markers(decoded_content),
        )

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            return 1 / (1 + math.exp(-value))
        exp_value = math.exp(value)
        return exp_value / (1 + exp_value)

    @staticmethod
    def _character_ratio(value: str, predicate: Any) -> float:
        if not value:
            return 0.0
        matches = sum(1 for character in value if predicate(character))
        return matches / len(value)

    @staticmethod
    def _null_byte_ratio(content: bytes) -> float:
        if not content:
            return 0.0
        return content.count(0) / len(content)

    @staticmethod
    def _shannon_entropy(content: bytes) -> float:
        if not content:
            return 0.0
        counts: dict[int, int] = {}
        for byte in content:
            counts[byte] = counts.get(byte, 0) + 1
        entropy = 0.0
        total = len(content)
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy


__all__ = ["ThreatAnalyzer"]
