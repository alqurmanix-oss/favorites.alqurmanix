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



def test_malformed_audio_is_rejected_before_model_inference(monkeypatch):
    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "Review with invalid audio"},
        files={"audio": ("broken.wav", b"not-audio", "audio/wav")},
    )
    assert response.status_code == 415


def test_audio_duration_is_checked_before_decoding(monkeypatch):
    from types import SimpleNamespace

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr(
        "app.main.sf.info",
        lambda _stream: SimpleNamespace(
            samplerate=16000,
            frames=16000 * 901,
            channels=1,
        ),
    )

    def decoding_must_not_run(*_args, **_kwargs):
        raise AssertionError("audio decoding ran before duration validation")

    monkeypatch.setattr("app.main.sf.read", decoding_must_not_run)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "Review"},
        files={"audio": ("long.wav", b"metadata-placeholder", "audio/wav")},
    )
    assert response.status_code == 413

def test_image_reviews_never_auto_publish(monkeypatch):
    import io
    from PIL import Image

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr("app.main.pytesseract.image_to_string", lambda *_a, **_k: "safe image text")
    monkeypatch.setattr(
        "app.main._image_pipeline",
        lambda: lambda _image: [{"label": "normal", "score": 0.99}],
    )
    monkeypatch.setattr(
        "app.main._classify_text",
        lambda _text: {
            "decision": "publish",
            "confidence": 0.999,
            "categories": [],
            "rationale": "safe",
        },
    )
    image = Image.new("RGB", (8, 8), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "A harmless review"},
        files={"image": ("safe.png", stream.getvalue(), "image/png")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "human_review"
    assert payload["publish_allowed"] is False


def test_high_confidence_explicit_image_is_rejected(monkeypatch):
    import io
    from PIL import Image

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr("app.main.pytesseract.image_to_string", lambda *_a, **_k: "")
    monkeypatch.setattr(
        "app.main._image_pipeline",
        lambda: lambda _image: [{"label": "nsfw", "score": 0.99}],
    )
    image = Image.new("RGB", (8, 8), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        files={"image": ("unsafe.png", stream.getvalue(), "image/png")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "reject"
    assert payload["publish_allowed"] is False


def test_audio_transcript_is_analyzed_but_never_auto_published(monkeypatch):
    import io
    import soundfile as sf

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr(
        "app.main._asr_pipeline",
        lambda: lambda *_a, **_k: {"text": "A harmless spoken review"},
    )
    monkeypatch.setattr(
        "app.main._classify_text",
        lambda _text: {
            "decision": "publish",
            "confidence": 0.999,
            "categories": [],
            "rationale": "safe",
        },
    )
    audio = io.BytesIO()
    sf.write(audio, [0.0] * 1600, 16000, format="WAV")
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        data={"text": "A harmless review"},
        files={"audio": ("review.wav", audio.getvalue(), "audio/wav")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "human_review"
    assert payload["publish_allowed"] is False
    assert payload["extracted"]["transcript"] == "A harmless spoken review"

def test_audio_is_resampled_to_whisper_rate(monkeypatch):
    import io
    import soundfile as sf

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    observed = {}

    def transcribe(payload, **_kwargs):
        observed["sampling_rate"] = payload["sampling_rate"]
        observed["sample_count"] = len(payload["raw"])
        return {"text": "spoken review"}

    monkeypatch.setattr("app.main._asr_pipeline", lambda: transcribe)
    monkeypatch.setattr(
        "app.main._classify_text",
        lambda _text: {
            "decision": "publish",
            "confidence": 0.999,
            "categories": [],
            "rationale": "safe",
        },
    )
    audio = io.BytesIO()
    sf.write(audio, [0.0] * 800, 8000, format="WAV")
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        files={"audio": ("review.wav", audio.getvalue(), "audio/wav")},
    )
    assert response.status_code == 200
    assert observed["sampling_rate"] == 16000
    assert observed["sample_count"] == 1600
    assert response.json()["decision"] == "human_review"

def test_browser_audio_container_uses_bounded_local_ffmpeg_decode(monkeypatch):
    import io
    import json
    from types import SimpleNamespace

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr("app.main.sf.info", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("unsupported container")))
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command[0])
        if command[0] == "ffprobe":
            return SimpleNamespace(
                stdout=json.dumps({
                    "format": {"duration": "0.1"},
                    "streams": [{
                        "codec_type": "audio",
                        "sample_rate": "48000",
                        "channels": 2,
                        "duration": "0.1",
                    }],
                }).encode(),
                stderr=b"",
            )
        return SimpleNamespace(stdout=b"\x00" * (1600 * 4), stderr=b"")

    monkeypatch.setattr("app.main.subprocess.run", fake_run)
    observed = {}

    def transcribe(payload, **_kwargs):
        observed["sampling_rate"] = payload["sampling_rate"]
        observed["sample_count"] = len(payload["raw"])
        return {"text": "browser recording"}

    monkeypatch.setattr("app.main._asr_pipeline", lambda: transcribe)
    monkeypatch.setattr(
        "app.main._classify_text",
        lambda _text: {
            "decision": "publish",
            "confidence": 0.999,
            "categories": [],
            "rationale": "safe",
        },
    )
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        files={"audio": ("recording.webm", b"webm-placeholder", "audio/webm")},
    )
    assert response.status_code == 200
    assert calls == ["ffprobe", "ffmpeg"]
    assert observed == {"sampling_rate": 16000, "sample_count": 1600}
    assert response.json()["decision"] == "human_review"


def test_oversized_browser_audio_is_rejected_before_ffmpeg_decode(monkeypatch):
    import json
    from types import SimpleNamespace

    token = "aqx-test-secret-" + "x" * 40
    monkeypatch.setenv("AQX_AI_INTERNAL_TOKEN", token)
    monkeypatch.setattr("app.main.sf.info", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("unsupported container")))
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command[0])
        return SimpleNamespace(
            stdout=json.dumps({
                "format": {"duration": "901"},
                "streams": [{
                    "codec_type": "audio",
                    "sample_rate": "48000",
                    "channels": 2,
                    "duration": "901",
                }],
            }).encode(),
            stderr=b"",
        )

    monkeypatch.setattr("app.main.subprocess.run", fake_run)
    response = client.post(
        "/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        files={"audio": ("long.webm", b"webm-placeholder", "audio/webm")},
    )
    assert response.status_code == 413
    assert calls == ["ffprobe"]

