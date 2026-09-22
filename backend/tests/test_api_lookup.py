from fastapi.testclient import TestClient

from app.main import app

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


def test_lookup_handles_not_found() -> None:
    response = client.get("/api/v1/files/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    assert response.status_code == 404
