from enum import Enum

from pydantic import BaseModel, Field


class Recommendation(str, Enum):
    allow = "Allow"
    block = "Block"
    rescan = "Rescan"
    detonate = "Detonate"
    human_review = "Human Review"


class VerdictLabel(str, Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    mixed = "mixed"
    likely_clean = "likely_clean"
    unknown = "unknown"


class HealthResponse(BaseModel):
    status: str = "ok"


class FileMetadata(BaseModel):
    sha256: str
    file_name: str
    file_type: str
    file_size_bytes: int | None = Field(default=None, ge=0)
    first_seen_days_ago: int | None = Field(default=None, ge=0)
    prevalence_score: int | None = Field(default=None, ge=0, le=100)
    signed: bool | None = None


class DetectionCounts(BaseModel):
    malicious: int = Field(ge=0)
    suspicious: int = Field(ge=0)
    undetected: int = Field(ge=0)
    harmless: int = Field(default=0, ge=0)


class VerdictResult(BaseModel):
    verdict: VerdictLabel
    recommendation: Recommendation
    confidence: str
    risk_score: int = Field(ge=0, le=100)
    rules_triggered: list[str]
    explanation: str
    safety_note: str = "Zero detections do not prove a file is safe."


class FileLookupResponse(BaseModel):
    synthetic_data: bool = True
    synthetic_notice: str | None = (
        "This response comes from bundled synthetic fixtures for MVP demonstration only."
    )
    metadata: FileMetadata
    detections: DetectionCounts
    verdict: VerdictResult
