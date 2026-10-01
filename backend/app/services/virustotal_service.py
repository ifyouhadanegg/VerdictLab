import os
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.schemas import (
    DetectionCounts,
    FileLookupResponse,
    FileMetadata,
)
from app.services.verdict_service import calculate_virustotal_verdict

VIRUSTOTAL_FILES_URL = "https://www.virustotal.com/api/v3/files"


class VirusTotalNotConfiguredError(Exception):
    pass


class VirusTotalRequestError(Exception):
    pass


class VirusTotalService:
    def lookup_file(self, sha256: str) -> FileLookupResponse | None:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise VirusTotalNotConfiguredError

        try:
            response = httpx.get(
                f"{VIRUSTOTAL_FILES_URL}/{sha256}",
                headers={"x-apikey": api_key},
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            raise VirusTotalRequestError from exc

        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise VirusTotalRequestError

        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            if not isinstance(stats, dict):
                raise VirusTotalRequestError
            detections = DetectionCounts(
                malicious=_count(stats, "malicious"),
                suspicious=_count(stats, "suspicious"),
                undetected=_count(stats, "undetected"),
                harmless=_count(stats, "harmless"),
            )
            first_seen_days_ago = _days_since(attributes.get("first_submission_date"))
            names = attributes.get("names") or []
            file_name = attributes.get("meaningful_name") or (names[0] if names else sha256)
            file_type = attributes.get("type_description") or "Unknown"
            file_size = attributes.get("size")
            if not isinstance(file_size, int) or file_size < 0:
                file_size = None
        except (KeyError, TypeError, ValueError, IndexError) as exc:
            raise VirusTotalRequestError from exc

        analyzed_engines = sum(detections.model_dump().values())
        verdict = calculate_virustotal_verdict(
            malicious=detections.malicious,
            suspicious=detections.suspicious,
            analyzed_engines=analyzed_engines,
        )
        return FileLookupResponse(
            synthetic_data=False,
            synthetic_notice=None,
            metadata=FileMetadata(
                sha256=sha256,
                file_name=file_name,
                file_type=file_type,
                file_size_bytes=file_size,
                first_seen_days_ago=first_seen_days_ago,
                prevalence_score=None,
                signed=None,
            ),
            detections=detections,
            verdict=verdict,
        )


def _count(stats: dict[str, Any], category: str) -> int:
    value = stats.get(category, 0)
    if not isinstance(value, int) or value < 0:
        return 0
    return value


def _days_since(timestamp: Any) -> int | None:
    if not isinstance(timestamp, int) or timestamp < 0:
        return None
    submitted = datetime.fromtimestamp(timestamp, timezone.utc)
    return max(0, (datetime.now(timezone.utc) - submitted).days)