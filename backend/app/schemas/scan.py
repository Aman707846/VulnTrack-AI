from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.models.scan import ScanTargetType


class ScanCreate(BaseModel):
    user_id: int
    target_type: ScanTargetType
    target_value: str


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    verdict: str
    details: str | None
    explanation: str | None = None
    score: int = 0
    risk_level: str = "safe"
    reasons: list[str] = Field(default_factory=list)
    created_at: datetime


class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    severity: str | None
    summary: str | None
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str = "pending"
    score: int = 0
    risk_level: str = "safe"
    confidence: int = 0
    details: str = ""
    explanation: str = ""
    reasons: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def flatten_scan_payload(cls, value: Any) -> Any:
        if isinstance(value, dict):
            if "target" in value:
                reasons = cls._normalize_reasons(value.get("reasons"))
                return {
                    "id": value.get("id"),
                    "target": value.get("target", ""),
                    "status": value.get("status") or "pending",
                    "score": value.get("score") or 0,
                    "risk_level": value.get("risk_level") or "safe",
                    "confidence": cls._normalize_confidence(
                        value.get("confidence"),
                        value.get("score"),
                        reasons,
                    ),
                    "details": value.get("details") or "",
                    "explanation": value.get("explanation") or "",
                    "reasons": reasons,
                }

            result = (value.get("results") or [None])[0]
            score = getattr(result, "score", 0) or 0
            reasons = cls._normalize_reasons(getattr(result, "reasons", None) if result else None)
            return {
                "id": value.get("id"),
                "target": value.get("target_value", ""),
                "status": value.get("status") or "pending",
                "score": score,
                "risk_level": (getattr(result, "risk_level", None) or "safe"),
                "confidence": cls._normalize_confidence(
                    getattr(result, "confidence", None) if result else None,
                    score,
                    reasons,
                ),
                "details": (result.details if result and result.details else ""),
                "explanation": (result.explanation if result and result.explanation else ""),
                "reasons": reasons,
            }

        result = value.results[0] if getattr(value, "results", None) else None
        score = getattr(result, "score", 0) or 0
        reasons = cls._normalize_reasons(getattr(result, "reasons", None) if result else None)
        return {
            "id": value.id,
            "target": value.target_value,
            "status": getattr(value, "status", "pending"),
            "score": score,
            "risk_level": (getattr(result, "risk_level", None) or "safe"),
            "confidence": cls._normalize_confidence(
                getattr(result, "confidence", None) if result else None,
                score,
                reasons,
            ),
            "details": (result.details if result and result.details else ""),
            "explanation": (result.explanation if result and result.explanation else ""),
            "reasons": reasons,
        }

    @staticmethod
    def _normalize_reasons(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(reason) for reason in value if reason is not None]

    @staticmethod
    def _normalize_confidence(value: Any, score: Any, reasons: Any) -> int:
        if value is None:
            return ScanResponse._derive_confidence(score, reasons)
        try:
            normalized_value = int(round(float(value)))
        except (TypeError, ValueError):
            return ScanResponse._derive_confidence(score, reasons)
        return max(0, min(normalized_value, 100))

    @staticmethod
    def _derive_confidence(score: Any, reasons: Any) -> int:
        normalized_score = max(0, min(int(score or 0), 100))
        normalized_reasons = reasons if isinstance(reasons, list) else []
        detection_bonus = min(len(normalized_reasons) * 10, 30)
        return min(normalized_score + detection_bonus, 100)


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
