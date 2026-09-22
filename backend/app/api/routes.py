from fastapi import APIRouter, HTTPException

from app.core.validators import normalize_sha256
from app.models.schemas import FileLookupResponse, HealthResponse
from app.services.reputation_store import SyntheticReputationStore
from app.services.verdict_service import calculate_verdict

router = APIRouter()
store = SyntheticReputationStore()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/api/v1/files/{sha256}", response_model=FileLookupResponse)
def get_file_by_sha256(sha256: str) -> FileLookupResponse:
    try:
        normalized_sha = normalize_sha256(sha256)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = store.get_by_sha256(normalized_sha)
    if record is None:
        raise HTTPException(status_code=404, detail="Synthetic sample not found")

    verdict = calculate_verdict(record)
    return FileLookupResponse(
        metadata=record["metadata"],
        detections=record["detections"],
        verdict=verdict,
    )
