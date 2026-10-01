from fastapi import APIRouter, HTTPException

from app.core.validators import normalize_sha256
from app.models.schemas import FileLookupResponse, HealthResponse
from app.services.reputation_store import SyntheticReputationStore
from app.services.verdict_service import calculate_verdict
from app.services.virustotal_service import (
    VirusTotalNotConfiguredError,
    VirusTotalRequestError,
    VirusTotalService,
)

router = APIRouter()
store = SyntheticReputationStore()
virustotal = VirusTotalService()


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
        try:
            result = virustotal.lookup_file(normalized_sha)
        except VirusTotalNotConfiguredError as exc:
            raise HTTPException(
                status_code=503,
                detail="VirusTotal lookup is not configured. Set VIRUSTOTAL_API_KEY on the backend.",
            ) from exc
        except VirusTotalRequestError as exc:
            raise HTTPException(
                status_code=502,
                detail="VirusTotal lookup failed. Check the API key, rate limit, and service status.",
            ) from exc

        if result is None:
            raise HTTPException(
                status_code=404, detail="VirusTotal has no report for this hash"
            )
        return result

    verdict = calculate_verdict(record)
    return FileLookupResponse(
        metadata=record["metadata"],
        detections=record["detections"],
        verdict=verdict,
    )
