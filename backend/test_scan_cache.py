import os
import sys
from pathlib import Path
import unittest



from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.api.scans import (  # noqa: E402
    _append_cache_reuse_note,
    _append_cache_explanation_note,
    _build_stored_scan_result,
    _calculate_sha256,
    _clone_cached_file_scan,
    _find_cached_file_scan,
)
from backend.app.db.base import Base  # noqa: E402
from backend.app.models.scan import Scan, ScanStatus, ScanTargetType  # noqa: E402
from backend.app.models.scan_result import ScanResult  # noqa: E402
from backend.app.models.user import User  # noqa: E402
from backend.app.models.vulnerability import Vulnerability  # noqa: E402


class ScanCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db: Session = self.SessionLocal()
        self.user = User(email="cache@test.local", password_hash="hash")
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

    def tearDown(self) -> None:
        self.db.close()

    def test_calculate_sha256_is_stable(self) -> None:
        first = _calculate_sha256(b"sample content")
        second = _calculate_sha256(b"sample content")

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_find_cached_file_scan_returns_latest_matching_fingerprint(self) -> None:
        fingerprint = _calculate_sha256(b"cached payload")
        older_scan = self._create_cached_scan("older.exe", fingerprint, "Older details")
        newer_scan = self._create_cached_scan("newer.exe", fingerprint, "Newer details")

        cached_scan = _find_cached_file_scan(self.db, fingerprint)

        self.assertIsNotNone(cached_scan)
        self.assertEqual(cached_scan.id, newer_scan.id)
        self.assertNotEqual(cached_scan.id, older_scan.id)

    def test_clone_cached_file_scan_copies_result_and_vulnerabilities(self) -> None:
        fingerprint = _calculate_sha256(b"cached payload")
        cached_scan = self._create_cached_scan("payload.exe", fingerprint, "Original details")
        cloned_scan = Scan(
            user_id=self.user.id,
            target_type=ScanTargetType.FILE,
            target_value="payload-copy.exe",
            status=ScanStatus.PROCESSING,
        )
        self.db.add(cloned_scan)
        self.db.commit()
        self.db.refresh(cloned_scan)

        _clone_cached_file_scan(
            db=self.db,
            destination_scan=cloned_scan,
            file_sha256=fingerprint,
            cached_scan=cached_scan,
        )
        self.db.commit()
        self.db.refresh(cloned_scan)

        cloned_result = cloned_scan.results[0]
        self.assertEqual(cloned_result.sha256, fingerprint)
        self.assertEqual(cloned_result.score, cached_scan.results[0].score)
        self.assertEqual(cloned_result.risk_level, cached_scan.results[0].risk_level)
        self.assertIn("Reused cached result for matching SHA256 fingerprint.", cloned_result.details or "")
        self.assertIn("Cached explanation.", cloned_result.explanation or "")
        self.assertIn("previously analyzed SHA256 fingerprint", cloned_result.explanation or "")
        self.assertEqual(len(cloned_scan.vulnerabilities), len(cached_scan.vulnerabilities))
        self.assertEqual(cloned_scan.target_value, "payload-copy.exe")

    def test_append_cache_reuse_note_is_idempotent(self) -> None:
        details = _append_cache_reuse_note("Scanner result.")
        duplicated = _append_cache_reuse_note(details)

        self.assertEqual(details, duplicated)

    def test_append_cache_explanation_note_is_idempotent(self) -> None:
        explanation = _append_cache_explanation_note("Safe because prior analysis found no malicious indicators.")
        duplicated = _append_cache_explanation_note(explanation)

        self.assertEqual(explanation, duplicated)

    def test_build_stored_scan_result_preserves_explanation(self) -> None:
        stored = _build_stored_scan_result(
            {
                "score": 12,
                "risk_level": "safe",
                "reasons": ["Known software source markers"],
                "explanation": "This file appears safe because it matches common installer patterns and lacks malicious indicators.",
            },
            "Scanner details.",
            sha256="abc123",
        )

        self.assertEqual(
            stored["explanation"],
            "This file appears safe because it matches common installer patterns and lacks malicious indicators.",
        )
        self.assertEqual(stored["sha256"], "abc123")

    def _create_cached_scan(self, filename: str, fingerprint: str, details: str) -> Scan:
        scan = Scan(
            user_id=self.user.id,
            target_type=ScanTargetType.FILE,
            target_value=filename,
            status=ScanStatus.COMPLETED,
        )
        self.db.add(scan)
        self.db.flush()
        self.db.add(
            ScanResult(
                scan_id=scan.id,
                sha256=fingerprint,
                verdict="suspicious",
                details=details,
                explanation="Cached explanation.",
                score=55,
                risk_level="suspicious",
                reasons=["Suspicious file extension", "Unknown file source"],
            )
        )
        self.db.add(
            Vulnerability(
                scan_id=scan.id,
                cve_id="MOCK-CVE-CACHE-001",
                severity="medium",
                summary="Cached vulnerability clone check.",
            )
        )
        self.db.commit()
        self.db.refresh(scan)
        return scan


if __name__ == "__main__":
    unittest.main()
