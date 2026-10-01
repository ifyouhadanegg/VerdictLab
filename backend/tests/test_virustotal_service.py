from typing import Any

from app.services.virustotal_service import VirusTotalService


class FakeResponse:
    status_code = 200

    def json(self) -> dict[str, Any]:
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 22,
                        "harmless": 40,
                    },
                    "meaningful_name": "sample.exe",
                    "type_description": "Windows Executable",
                    "size": 2048,
                }
            }
        }


def test_lookup_maps_virustotal_report_and_keeps_zero_detections_unknown(
    monkeypatch,
) -> None:
    sha256 = "e" * 64
    request: dict[str, Any] = {}

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> FakeResponse:
        request.update(url=url, headers=headers, timeout=timeout)
        return FakeResponse()

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr("app.services.virustotal_service.httpx.get", fake_get)

    result = VirusTotalService().lookup_file(sha256)

    assert request["url"] == f"https://www.virustotal.com/api/v3/files/{sha256}"
    assert request["headers"] == {"x-apikey": "test-key"}
    assert result is not None
    assert result.synthetic_data is False
    assert result.metadata.file_name == "sample.exe"
    assert result.metadata.signed is None
    assert result.detections.harmless == 40
    assert result.verdict.recommendation.value == "Human Review"