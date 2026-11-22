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


def test_low_confidence_rejection_goes_to_human_review():
    from app.main import _apply_safety_gate

    result = _apply_safety_gate({
        "decision": "reject",
        "confidence": 0.72,
        "categories": ["possible_harassment"],
        "rationale": "model rationale",
    })
    assert result["decision"] == "human_review"


def test_high_confidence_rejection_is_preserved_for_review_workflow():
    from app.main import _apply_safety_gate

    result = _apply_safety_gate({
        "decision": "reject",
        "confidence": 0.99,
        "categories": ["credible_threat"],
        "rationale": "model rationale",
    })
    assert result["decision"] == "reject"


def test_model_cannot_authorize_publication():
    from app.main import _apply_safety_gate

    result = _apply_safety_gate({
        "decision": "publish",
        "confidence": 1.0,
        "categories": [],
        "rationale": "clean",
    })
    assert result["decision"] == "human_review"



def test_inference_exception_fails_closed(monkeypatch):
    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)

    def fail_inference(_text):
        raise RuntimeError("simulated model failure")

    monkeypatch.setattr("app.main._classify_text", fail_inference)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "A harmless test review"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert payload["decision"] == "human_review"
    assert payload["publish_allowed"] is False
    assert payload["categories"] == ["analysis_unavailable"]


def test_invalid_image_is_rejected_as_unsupported_input(monkeypatch):
    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "Review with invalid image"},
        files={"image": ("broken.png", b"not-an-image", "image/png")},
    )
    assert response.status_code == 415


def test_upload_size_limit_is_enforced(monkeypatch):
    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr("app.main.MAX_UPLOAD_BYTES", 4)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "Review"},
        files={"image": ("large.png", b"12345", "image/png")},
    )
    assert response.status_code == 413
