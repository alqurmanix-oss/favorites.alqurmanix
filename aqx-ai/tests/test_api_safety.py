import os

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_reports_auto_publish_disabled():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["auto_publish_enabled"] is False


def test_missing_internal_token_fails_closed(monkeypatch):
    monkeypatch.delenv("AQX_AI_INTERNAL_TOKEN", raising=False)
    response = client.post("/v1/analyze", data={"text": "hello"})
    assert response.status_code == 503


def test_invalid_internal_token_is_rejected(monkeypatch):
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", "a" * 40)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": "Bearer " + "b" * 40},
        data={"text": "hello"},
    )
    assert response.status_code == 401


def test_empty_content_is_rejected_after_auth(monkeypatch):
    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
