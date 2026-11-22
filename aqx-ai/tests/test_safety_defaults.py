import os
from fastapi.testclient import TestClient

os.environ.setdefault("AQX_AI_INTERNAL_TOKEN", "test-secret-that-is-long-enough-for-aqx")
os.environ.setdefault("AQX_AUTO_PUBLISH_ENABLED", "false")

from app.main import app

client = TestClient(app)


def test_health_is_available():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "aqx-ai"
    assert response.json()["auto_publish_enabled"] is False


def test_analyze_requires_internal_token():
    response = client.post("/v1/analyze", data={"text": "A normal review"})
    assert response.status_code == 401


def test_analyze_requires_content():
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": "Bearer test-secret-that-is-long-enough-for-aqx"},
        data={"text": ""},
    )
    assert response.status_code == 400
