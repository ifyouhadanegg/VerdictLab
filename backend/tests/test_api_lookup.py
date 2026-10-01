from fastapi.testclient import TestClient

from app.main import app
from app.api import routes
from app.models.schemas import (
    DetectionCounts,
    FileLookupResponse,
    FileMetadata,
    Recommendation,
    VerdictLabel,
    VerdictResult,
)

client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_lookup_returns_synthetic_fixture() -> None:
    response = client.get("/api/v1/files/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert response.status_code == 200
    body = response.json()
    assert body["synthetic_data"] is True
    assert "synthetic" in body["synthetic_notice"].lower()
    assert body["metadata"]["sha256"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert body["verdict"]["recommendation"] == "Block"


def test_lookup_rejects_invalid_hash() -> None:
    response = client.get("/api/v1/files/not-a-valid-sha256")
    assert response.status_code == 400
    assert "sha256" in response.json()["detail"].lower()


def test_lookup_handles_not_found(monkeypatch) -> None:
    monkeypatch.setattr(routes.virustotal, "lookup_file", lambda _: None)
    response = client.get("/api/v1/files/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    assert response.status_code == 404
    assert "no report" in response.json()["detail"].lower()


def test_lookup_requires_virustotal_api_key_for_unknown_hash(
    monkeypatch,
) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    response = client.get(
        "/api/v1/files/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    )
    assert response.status_code == 503
    assert "VIRUSTOTAL_API_KEY" in response.json()["detail"]


def test_lookup_uses_virustotal_for_unknown_hash(monkeypatch) -> None:
    sha256 = "e" * 64
    result = FileLookupResponse(
        synthetic_data=False,
        synthetic_notice=None,
        metadata=FileMetadata(
            sha256=sha256,
            file_name="sample.exe",
            file_type="Windows Executable",
        ),
        detections=DetectionCounts(malicious=4, suspicious=0, undetected=20),
        verdict=VerdictResult(
            verdict=VerdictLabel.suspicious,
            recommendation=Recommendation.detonate,
            confidence="medium",
            risk_score=62,
            rules_triggered=["VirusTotal reported detections."],
            explanation="Review recommended.",
        ),
    )
    monkeypatch.setattr(routes.virustotal, "lookup_file", lambda _: result)

    response = client.get(f"/api/v1/files/{sha256}")

    assert response.status_code == 200
    assert response.json()["synthetic_data"] is False
    assert response.json()["metadata"]["file_name"] == "sample.exe"
