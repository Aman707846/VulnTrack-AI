import hashlib
from pathlib import Path
import tempfile
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.db.session import get_db
from backend.app.models.scan import Scan
from backend.app.models.scan import ScanStatus, ScanTargetType
from backend.app.models.scan_result import ScanResult
from backend.app.models.user import User
from backend.app.models.vulnerability import Vulnerability
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.services.intelligence_engine import ThreatAnalyzer
from backend.app.services.malware_scanner import scan_content, scan_target_value
from backend.app.services.vulnerability_analyzer import analyze_target


router = APIRouter(tags=["scans"])
analyzer = ThreatAnalyzer()


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> JSONResponse:
    user = db.get(User, payload.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    scan = Scan(
        user_id=payload.user_id,
        target_type=payload.target_type,
        target_value=payload.target_value,
        status=ScanStatus.PROCESSING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    analysis = {"confidence": 0, "score": 0, "risk_level": "safe", "reasons": [], "explanation": ""}
    try:
        if payload.target_type == ScanTargetType.URL:
            analysis = analyzer.analyze_url(payload.target_value)

        malware_result = scan_target_value(payload.target_value)
        vulnerabilities = analyze_target(payload.target_value)
        stored_result = _build_stored_scan_result(analysis, malware_result.details)

        db.add(
            ScanResult(
                scan_id=scan.id,
                verdict=malware_result.verdict,
                details=stored_result["malware_details"],
                explanation=stored_result["explanation"],
                score=stored_result["score"],
                risk_level=stored_result["risk_level"],
                reasons=stored_result["reasons"],
            )
        )
        db.add_all(
            [
                Vulnerability(
                    scan_id=scan.id,
                    cve_id=vulnerability.cve_id,
                    severity=vulnerability.severity,
                    summary=vulnerability.summary,
                )
                for vulnerability in vulnerabilities
            ]
        )
        scan.status = ScanStatus.COMPLETED
        db.commit()
    except Exception:
        db.rollback()
        scan = db.get(Scan, scan.id)
        if scan is not None:
            scan.status = ScanStatus.FAILED
            db.commit()
        raise

    return _build_scan_response(db, scan.id, analysis=analysis)


@router.post("/scan/file", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_file_scan(
    user_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> JSONResponse:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    filename = file.filename or "uploaded_file"
    file_content = await file.read()
    file_sha256 = _calculate_sha256(file_content)
    scan = Scan(
        user_id=user_id,
        target_type=ScanTargetType.FILE,
        target_value=filename,
        status=ScanStatus.PROCESSING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    cached_scan = _find_cached_file_scan(db, file_sha256)
    temp_file_path: Path | None = None
    try:
        if cached_scan is not None:
            _clone_cached_file_scan(
                db=db,
                destination_scan=scan,
                file_sha256=file_sha256,
                cached_scan=cached_scan,
            )
            scan.status = ScanStatus.COMPLETED
            db.commit()
            return _build_scan_response(db, scan.id)

        temp_file_path = _write_uploaded_file_to_temp(filename, file_content)
        analysis = analyzer.analyze_file(
            filename,
            file_content,
            sha256=file_sha256,
            file_path=str(temp_file_path),
        )
        malware_result = scan_content(filename, file_content)
        vulnerabilities = analyze_target(filename)
        stored_result = _build_stored_scan_result(analysis, malware_result.details, sha256=file_sha256)

        db.add(
            ScanResult(
                scan_id=scan.id,
                sha256=stored_result["sha256"],
                verdict=malware_result.verdict,
                details=stored_result["malware_details"],
                explanation=stored_result["explanation"],
                score=stored_result["score"],
                risk_level=stored_result["risk_level"],
                reasons=stored_result["reasons"],
            )
        )
        db.add_all(
            [
                Vulnerability(
                    scan_id=scan.id,
                    cve_id=vulnerability.cve_id,
                    severity=vulnerability.severity,
                    summary=vulnerability.summary,
                )
                for vulnerability in vulnerabilities
            ]
        )
        scan.status = ScanStatus.COMPLETED
        db.commit()
    except Exception:
        db.rollback()
        scan = db.get(Scan, scan.id)
        if scan is not None:
            scan.status = ScanStatus.FAILED
            db.commit()
        raise
    finally:
        _cleanup_temp_file(temp_file_path)

    return _build_scan_response(db, scan.id, analysis=analysis)


@router.get("/scans", response_model=list[ScanResponse], response_model_exclude={"confidence"})
def list_scans(
    user_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[ScanResponse]:
    query = (
        select(Scan)
        .options(
            selectinload(Scan.results),
            selectinload(Scan.vulnerabilities),
        )
        .order_by(Scan.created_at.desc())
    )
    if user_id is not None:
        query = query.where(Scan.user_id == user_id)

    scans = db.scalars(query).all()
    return [ScanResponse.model_validate(scan) for scan in scans]


def _get_scan_with_details(db: Session, scan_id: int) -> Scan:
    scan = db.scalar(
        select(Scan)
        .options(
            selectinload(Scan.results),
            selectinload(Scan.vulnerabilities),
        )
        .where(Scan.id == scan_id)
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return scan


def _build_scan_response(
    db: Session,
    scan_id: int,
    analysis: dict[str, Any] | None = None,
) -> JSONResponse:
    scan = _get_scan_with_details(db, scan_id)
    result = scan.results[0] if scan.results else None
    response_payload = {
        "id": scan.id,
        "target": scan.target_value,
        "status": getattr(scan, "status", ScanStatus.PENDING).value if getattr(scan, "status", None) else "pending",
        "confidence": analysis.get("confidence") if analysis else None,
        "score": (getattr(result, "score", 0) or 0),
        "risk_level": (getattr(result, "risk_level", None) or "safe"),
        "reasons": (getattr(result, "reasons", None) or []),
        "details": (result.details if result and result.details else ""),
        "explanation": (result.explanation if result and result.explanation else ""),
    }
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=jsonable_encoder(ScanResponse.model_validate(response_payload)),
    )


def _build_stored_scan_result(
    result: dict[str, Any] | None,
    malware_details: str | None,
    sha256: str | None = None,
) -> dict[str, Any]:
    normalized_result = result or {}
    normalized_reasons = normalized_result.get("reasons")
    if not isinstance(normalized_reasons, list):
        normalized_reasons = []

    return {
        "malware_details": malware_details or "",
        "explanation": str(normalized_result.get("explanation") or ""),
        "score": normalized_result.get("score") or 0,
        "risk_level": normalized_result.get("risk_level") or "safe",
        "reasons": normalized_reasons,
        "sha256": sha256,
    }


def _calculate_sha256(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()


def _write_uploaded_file_to_temp(filename: str, file_content: bytes) -> Path:
    workspace_root = Path(__file__).resolve().parents[3]
    temp_dir = workspace_root / ".tmp" / "scan_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(filename or "uploaded_file").suffix
    with tempfile.NamedTemporaryFile(dir=temp_dir, suffix=suffix, delete=False) as handle:
        handle.write(file_content)
        return Path(handle.name)


def _cleanup_temp_file(temp_file_path: Path | None) -> None:
    if temp_file_path is None:
        return
    try:
        temp_file_path.unlink(missing_ok=True)
    except OSError:
        pass


def _find_cached_file_scan(db: Session, file_sha256: str) -> Scan | None:
    return db.scalar(
        select(Scan)
        .join(Scan.results)
        .options(
            selectinload(Scan.results),
            selectinload(Scan.vulnerabilities),
        )
        .where(
            Scan.target_type == ScanTargetType.FILE,
            ScanResult.sha256 == file_sha256,
        )
        .order_by(ScanResult.created_at.desc(), ScanResult.id.desc())
    )


def _clone_cached_file_scan(
    *,
    db: Session,
    destination_scan: Scan,
    file_sha256: str,
    cached_scan: Scan,
) -> None:
    cached_result = cached_scan.results[0] if cached_scan.results else None
    db.add(
        ScanResult(
            scan_id=destination_scan.id,
            sha256=file_sha256,
            verdict=(cached_result.verdict if cached_result else "clean"),
            details=_append_cache_reuse_note(cached_result.details if cached_result else ""),
            explanation=_append_cache_explanation_note(
                cached_result.explanation if cached_result else None
            ),
            score=(cached_result.score if cached_result else 0),
            risk_level=(cached_result.risk_level if cached_result else "safe"),
            reasons=list(cached_result.reasons if cached_result and cached_result.reasons else []),
        )
    )
    db.add_all(
        [
            Vulnerability(
                scan_id=destination_scan.id,
                cve_id=vulnerability.cve_id,
                severity=vulnerability.severity,
                summary=vulnerability.summary,
            )
            for vulnerability in cached_scan.vulnerabilities
        ]
    )


def _append_cache_reuse_note(details: str | None) -> str:
    base_details = (details or "").strip()
    reuse_note = "Reused cached result for matching SHA256 fingerprint."
    if not base_details:
        return reuse_note
    if reuse_note in base_details:
        return base_details
    return f"{base_details} {reuse_note}"


def _append_cache_explanation_note(explanation: str | None) -> str:
    base_explanation = (explanation or "").strip()
    reuse_note = "This result was reused from a previously analyzed SHA256 fingerprint."
    if not base_explanation:
        return reuse_note
    if reuse_note in base_explanation:
        return base_explanation
    return f"{base_explanation} {reuse_note}"
