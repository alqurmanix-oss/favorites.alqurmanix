from __future__ import annotations

import hmac
import io
import json
import math
import os
import re
import subprocess
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import numpy as np
import pytesseract
import soundfile as sf
import torch
import httpx
from scipy.signal import resample_poly
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from PIL import Image, UnidentifiedImageError
from transformers import (
    AutoImageProcessor,
    AutoModelForCausalLM,
    AutoModelForImageClassification,
    AutoModelForSpeechSeq2Seq,
    AutoProcessor,
    AutoTokenizer,
    pipeline,
)

APP_NAME = "AQX AI"
TEXT_MODEL = os.getenv("AQX_TEXT_MODEL", "/models/text")
ASR_MODEL = os.getenv("AQX_ASR_MODEL", "/models/asr")
IMAGE_MODEL = os.getenv("AQX_IMAGE_SAFETY_MODEL", "/models/image")
MAX_UPLOAD_BYTES = int(os.getenv("AQX_MAX_UPLOAD_MB", "10")) * 1024 * 1024
MAX_AUDIO_SECONDS = int(os.getenv("AQX_MAX_AUDIO_SECONDS", "900"))
MAX_IMAGE_PIXELS = int(os.getenv("AQX_MAX_IMAGE_PIXELS", "20000000"))
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
# Deliberately hard-disabled until AQX completes a documented multilingual/media validation campaign.
AUTO_PUBLISH_ENABLED = False

app = FastAPI(title=APP_NAME, version="0.1.0")
torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))

POLICY = """You are AQX's review-safety classifier. Classify the supplied review text
and transcript, including multilingual content and context. Respectful criticism,
negative opinions, complaints, and disagreement are allowed.
Reject only clear violations: credible threats, targeted hate, harassment,
sexual exploitation, fraud/scams, spam, illegal promotion, or exposed highly
sensitive personal data. Ambiguous, quoted, reclaimed, contextual, or uncertain
content must be sent to human_review, not rejected.
Return ONLY valid JSON with keys:
decision (publish|reject|human_review), confidence (number 0..1),
categories (array of short strings), rationale (short string).
Do not infer a violation merely from negative sentiment.
"""


def _require_token(authorization: str | None) -> None:
    expected = os.getenv("AQX_AI_INTERNAL_TOKEN", "")
    if not expected or len(expected) < 32:
        raise HTTPException(status_code=503, detail="AQX_AI_NOT_CONFIGURED")
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="UNAUTHORIZED")


@lru_cache(maxsize=1)
def _text_components():
    tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        TEXT_MODEL,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
        local_files_only=True,
    )
    model.eval()
    return tokenizer, model


@lru_cache(maxsize=1)
def _asr_pipeline():
    model = AutoModelForSpeechSeq2Seq.from_pretrained(ASR_MODEL, local_files_only=True)
    processor = AutoProcessor.from_pretrained(ASR_MODEL, local_files_only=True)
    return pipeline(
        "automatic-speech-recognition",
        model=model,
        tokenizer=processor.tokenizer,
        feature_extractor=processor.feature_extractor,
        device=-1,
    )


@lru_cache(maxsize=1)
def _image_pipeline():
    model = AutoModelForImageClassification.from_pretrained(IMAGE_MODEL, local_files_only=True)
    processor = AutoImageProcessor.from_pretrained(IMAGE_MODEL, local_files_only=True)
    return pipeline("image-classification", model=model, image_processor=processor, device=-1)


def _apply_safety_gate(result: dict[str, Any]) -> dict[str, Any]:
    """Conservative decision gate: uncertain model outputs go to a human."""
    decision = result.get("decision")
    confidence = float(result.get("confidence", 0.0))
    if decision == "reject" and confidence < 0.98:
        return {
            **result,
            "decision": "human_review",
            "rationale": "Potential violation requires human confirmation.",
        }
    # Publishing is never authorized by this prototype, regardless of model output.
    if decision == "publish":
        return {
            **result,
            "decision": "human_review",
            "rationale": "Automatic publication is disabled pending validation.",
        }
    return result


def _classify_text(text: str) -> dict[str, Any]:
    if not text.strip():
        return {
            "decision": "human_review",
            "confidence": 0.0,
            "categories": ["empty_or_unreadable_text"],
            "rationale": "No usable text was extracted.",
        }

    tokenizer, model = _text_components()
    messages = [
        {"role": "system", "content": POLICY},
        {"role": "user", "content": text[:12000]},
    ]
    prompt = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096)
    with torch.inference_mode():
        generated = model.generate(
            **inputs,
            max_new_tokens=220,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    answer = tokenizer.decode(
        generated[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
    ).strip()
    match = re.search(r"\{[\s\S]*\}", answer)
    if not match:
        raise RuntimeError("MODEL_RETURNED_INVALID_JSON")
    parsed = json.loads(match.group(0))
    decision = parsed.get("decision")
    confidence = float(parsed.get("confidence", 0))
    if decision not in {"publish", "reject", "human_review"}:
        raise RuntimeError("MODEL_RETURNED_INVALID_DECISION")
    if not 0 <= confidence <= 1:
        raise RuntimeError("MODEL_RETURNED_INVALID_CONFIDENCE")
    return {
        "decision": decision,
        "confidence": confidence,
        "categories": parsed.get("categories", [])[:12],
        "rationale": str(parsed.get("rationale", ""))[:500],
    }


async def _read_upload(file: UploadFile | None) -> bytes | None:
    if file is None:
        return None
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="UPLOAD_TOO_LARGE")
    return data



def _decode_audio_with_ffmpeg(audio_bytes: bytes):
    """Decode browser/container audio formats locally after bounded metadata probing."""
    try:
        probe = subprocess.run(
            [
                "ffprobe", "-v", "error",
                "-show_entries", "format=duration:stream=codec_type,sample_rate,channels,duration",
                "-of", "json", "pipe:0",
            ],
            input=audio_bytes,
            capture_output=True,
            timeout=20,
            check=True,
        )
        metadata = json.loads(probe.stdout.decode("utf-8"))
        audio_stream = next(
            (stream for stream in metadata.get("streams", []) if stream.get("codec_type") == "audio"),
            None,
        )
        if not audio_stream:
            raise ValueError("No audio stream")
        sample_rate = int(audio_stream.get("sample_rate") or 0)
        channels = int(audio_stream.get("channels") or 0)
        duration_raw = metadata.get("format", {}).get("duration") or audio_stream.get("duration")
        duration = float(duration_raw or 0)
    except Exception as exc:
        raise HTTPException(status_code=415, detail="INVALID_AUDIO") from exc

    if sample_rate <= 0 or sample_rate > 96000 or channels <= 0 or channels > 8 or duration <= 0:
        raise HTTPException(status_code=415, detail="INVALID_AUDIO")
    if duration > MAX_AUDIO_SECONDS:
        raise HTTPException(status_code=413, detail="AUDIO_TOO_LONG")

    try:
        decoded = subprocess.run(
            [
                "ffmpeg", "-nostdin", "-v", "error", "-i", "pipe:0",
                "-t", str(MAX_AUDIO_SECONDS), "-ac", "1", "-ar", "16000",
                "-f", "f32le", "pipe:1",
            ],
            input=audio_bytes,
            capture_output=True,
            timeout=120,
            check=True,
        )
        max_output = MAX_AUDIO_SECONDS * 16000 * 4
        if not decoded.stdout or len(decoded.stdout) > max_output:
            raise ValueError("Decoded audio size is invalid")
        samples = np.frombuffer(decoded.stdout, dtype=np.float32).copy()
        if samples.size == 0 or not np.isfinite(samples).all():
            raise ValueError("Decoded audio samples are invalid")
        return samples, 16000
    except Exception as exc:
        raise HTTPException(status_code=415, detail="INVALID_AUDIO") from exc


def _decode_audio(audio_bytes: bytes):
    try:
        audio_info = sf.info(io.BytesIO(audio_bytes))
    except (RuntimeError, ValueError, OSError):
        return _decode_audio_with_ffmpeg(audio_bytes)

    if (
        audio_info.samplerate <= 0
        or audio_info.frames <= 0
        or audio_info.channels <= 0
        or audio_info.channels > 8
        or audio_info.samplerate > 96000
    ):
        raise HTTPException(status_code=415, detail="INVALID_AUDIO")
    if audio_info.frames / audio_info.samplerate > MAX_AUDIO_SECONDS:
        raise HTTPException(status_code=413, detail="AUDIO_TOO_LONG")
    try:
        samples, sample_rate = sf.read(io.BytesIO(audio_bytes), dtype="float32")
    except (RuntimeError, ValueError, OSError):
        return _decode_audio_with_ffmpeg(audio_bytes)
    if sample_rate != audio_info.samplerate or len(samples) == 0:
        raise HTTPException(status_code=415, detail="INVALID_AUDIO")
    if getattr(samples, "ndim", 1) == 2:
        samples = samples.mean(axis=1)
    if sample_rate != 16000:
        divisor = math.gcd(int(sample_rate), 16000)
        samples = resample_poly(
            samples, 16000 // divisor, int(sample_rate) // divisor
        )
        sample_rate = 16000
    return samples, sample_rate

@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "aqx-ai",
        "version": "0.1.0",
        "models_loaded": {
            "text": _text_components.cache_info().currsize == 1,
            "audio": _asr_pipeline.cache_info().currsize == 1,
            "image": _image_pipeline.cache_info().currsize == 1,
        },
        "auto_publish_enabled": AUTO_PUBLISH_ENABLED,
    }


@app.post("/v1/analyze")
async def analyze(
    authorization: str | None = Header(default=None),
    text: str = Form(default=""),
    image: UploadFile | None = File(default=None),
    audio: UploadFile | None = File(default=None),
):
    _require_token(authorization)
    image_bytes = await _read_upload(image)
    audio_bytes = await _read_upload(audio)

    if not text.strip() and image_bytes is None and audio_bytes is None:
        raise HTTPException(status_code=400, detail="CONTENT_REQUIRED")

    extracted: dict[str, Any] = {"transcript": None, "ocr_text": None, "image_safety": None}
    has_image = image_bytes is not None
    combined_text = text.strip()

    try:
        if audio_bytes is not None:
            # Validate duration before decoding; use local FFmpeg for browser containers.
            samples, sample_rate = _decode_audio(audio_bytes)
            audio_result = _asr_pipeline()(
                {"raw": samples, "sampling_rate": sample_rate},
                generate_kwargs={"task": "transcribe"},
            )
            transcript = str(audio_result.get("text", "")).strip()
            extracted["transcript"] = transcript
            if transcript:
                combined_text = (combined_text + "\n" + transcript).strip()

        if image_bytes is not None:
            try:
                with Image.open(io.BytesIO(image_bytes)) as source_image:
                    if source_image.width * source_image.height > MAX_IMAGE_PIXELS:
                        raise HTTPException(status_code=413, detail="IMAGE_TOO_LARGE")
                    pil_image = source_image.convert("RGB")
            except (UnidentifiedImageError, OSError):
                raise HTTPException(status_code=415, detail="INVALID_IMAGE")
            extracted["ocr_text"] = pytesseract.image_to_string(
                pil_image, lang="eng+ara"
            )[:8000]
            scores = _image_pipeline()(pil_image)
            extracted["image_safety"] = scores[:5]
            ocr = extracted["ocr_text"].strip()
            if ocr:
                combined_text = (combined_text + "\n[Text extracted from image]\n" + ocr).strip()

        text_result = _classify_text(combined_text) if combined_text else {
            "decision": "human_review",
            "confidence": 0.0,
            "categories": ["no_text_for_semantic_review"],
            "rationale": "No text or transcript was available for semantic moderation.",
        }

        text_result = _apply_safety_gate(text_result)

        # Explicit high-confidence NSFW detection is a reject signal.
        nsfw_score = 0.0
        for row in extracted["image_safety"] or []:
            label = str(row.get("label", "")).lower()
            if "nsfw" in label or "porn" in label or "unsafe" in label:
                nsfw_score = max(nsfw_score, float(row.get("score", 0)))
        if has_image and nsfw_score >= 0.90:
            decision = "reject"
            categories = list(text_result["categories"]) + ["explicit_sexual_image"]
            rationale = "The local image-safety model detected a high-confidence explicit-content signal."
        elif has_image:
            # This CPU starter has OCR + safety classification, not full visual
            # scene understanding. Never auto-approve an image-bearing review.
            decision = "human_review"
            categories = list(text_result["categories"]) + ["image_semantics_require_human_review"]
            rationale = "Image text and explicit-content signals were checked; full visual context needs human review."
        else:
            decision = text_result["decision"]
            categories = text_result["categories"]
            rationale = text_result["rationale"]

        confidence = float(text_result["confidence"])
        publish_allowed = bool(
            AUTO_PUBLISH_ENABLED
            and decision == "publish"
            and confidence >= 0.98
            and not has_image
        )
        if decision == "publish" and not publish_allowed:
            decision = "human_review"

        return {
            "ok": True,
            "engine": "AQX AI",
            "engine_version": "0.1.0",
            "decision": decision,
            "confidence": confidence,
            "publish_allowed": publish_allowed,
            "categories": categories,
            "rationale": rationale,
            "extracted": extracted,
            "policy": "aqx-review-safety-v1",
        }
    except HTTPException:
        raise
    except Exception as exc:
        # Fail closed. Never leak model internals or turn a failed inference into approval.
        print(f"AQX_AI_INFERENCE_FAILURE: {type(exc).__name__}: {exc}", flush=True)
        return {
            "ok": False,
            "engine": "AQX AI",
            "decision": "human_review",
            "confidence": 0.0,
            "publish_allowed": False,
            "categories": ["analysis_unavailable"],
            "rationale": "The content could not be fully analyzed.",
        }


def _review_image_from_signed_url(raw_url: str) -> Image.Image:
    try:
        parsed = urlparse(raw_url)
        allowed_hosts = {
            host.strip().lower()
            for host in os.getenv(
                "AQX_ALLOWED_MEDIA_HOSTS", "vuszqzgldbsscuxdfhdz.supabase.co"
            ).split(",")
            if host.strip()
        }
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() not in allowed_hosts
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or not parsed.path.startswith(
                "/storage/v1/object/sign/aqx-favorites-review-media/"
            )
        ):
            raise ValueError("Untrusted image URL")
        with httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False) as client:
            response = client.get(
                raw_url,
                headers={"Accept": "image/jpeg,image/png,image/webp"},
            )
        response.raise_for_status()
        if len(response.content) > 1536 * 1024:
            raise ValueError("Image exceeds review media limit")
        if not response.headers.get("content-type", "").lower().startswith("image/"):
            raise ValueError("URL did not return an image")
        with Image.open(io.BytesIO(response.content)) as source:
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed configured limit")
            return source.convert("RGB")
    except Exception as exc:
        raise HTTPException(status_code=422, detail="REVIEW_IMAGE_UNAVAILABLE") from exc


@app.post("/v1/audio/transcriptions")
async def audio_transcriptions(
    authorization: str | None = Header(default=None),
    file: UploadFile = File(...),
    model: str = Form(default="whisper-tiny"),
):
    _require_token(authorization)
    audio_bytes = await _read_upload(file)
    if audio_bytes is None:
        raise HTTPException(status_code=400, detail="AUDIO_REQUIRED")
    samples, sample_rate = _decode_audio(audio_bytes)
    result = _asr_pipeline()(
        {"raw": samples, "sampling_rate": sample_rate},
        generate_kwargs={"task": "transcribe"},
    )
    transcript = str(result.get("text", "")).strip()
    if not transcript:
        raise HTTPException(status_code=422, detail="AUDIO_TRANSCRIPT_EMPTY")
    return {"text": transcript, "model": "aqx-whisper-tiny"}


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str | None = Header(default=None),
):
    _require_token(authorization)
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="INVALID_REQUEST_JSON") from exc

    messages = body.get("messages", []) if isinstance(body, dict) else []
    user_message = next(
        (message for message in reversed(messages) if message.get("role") == "user"),
        None,
    )
    if not user_message:
        raise HTTPException(status_code=400, detail="USER_MESSAGE_REQUIRED")
    raw_content = user_message.get("content", "")
    text_parts: list[str] = []
    image_urls: list[str] = []
    if isinstance(raw_content, str):
        text_parts.append(raw_content)
    elif isinstance(raw_content, list):
        for part in raw_content:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "text" and isinstance(part.get("text"), str):
                text_parts.append(part["text"])
            elif part.get("type") == "image_url":
                image_url = part.get("image_url", {}).get("url")
                if isinstance(image_url, str):
                    image_urls.append(image_url)
    else:
        raise HTTPException(status_code=400, detail="UNSUPPORTED_MESSAGE_CONTENT")

    review_payload: dict[str, Any] = {}
    combined_text = "\\n".join(text_parts).strip()
    if combined_text:
        try:
            decoded = json.loads(combined_text)
            if isinstance(decoded, dict):
                combined_text = str(decoded.get("review", combined_text)).strip()
        except json.JSONDecodeError:
            pass

    extracted_ocr: list[str] = []
    image_scores: list[dict[str, Any]] = []
    for image_url in image_urls:
        pil_image = _review_image_from_signed_url(image_url)
        ocr_text = pytesseract.image_to_string(pil_image, lang="eng+ara")[:8000]
        if ocr_text.strip():
            extracted_ocr.append(ocr_text.strip())
        image_scores.extend(_image_pipeline()(pil_image)[:5])

    if extracted_ocr:
        combined_text = (
            combined_text + "\\n[Text extracted from attached images]\\n"
            + "\\n".join(extracted_ocr)
        ).strip()

    text_result = _classify_text(combined_text) if combined_text else {
        "decision": "human_review",
        "confidence": 0.0,
        "categories": ["no_text_for_semantic_review"],
        "rationale": "No readable text was available for semantic moderation.",
    }
    text_result = _apply_safety_gate(text_result)

    nsfw_score = max(
        (
            float(row.get("score", 0))
            for row in image_scores
            if any(
                marker in str(row.get("label", "")).lower()
                for marker in ("nsfw", "porn", "unsafe")
            )
        ),
        default=0.0,
    )
    if image_urls and nsfw_score >= 0.90:
        decision = "reject"
        categories = list(text_result["categories"]) + ["explicit_sexual_image"]
        reason = "The local image-safety model detected a high-confidence explicit-content signal."
    elif image_urls:
        decision = "human_review"
        categories = list(text_result["categories"]) + ["image_semantics_require_human_review"]
        reason = "Image OCR and explicit-content screening completed; full visual context requires human review."
    else:
        decision = text_result["decision"]
        categories = list(text_result["categories"])
        reason = text_result["rationale"]

    # Keep the OpenAI-compatible envelope expected by the existing AQX Favorites
    # Edge Function, while all inference stays inside the AQX local runtime.
    result = {
        "decision": "publish" if decision == "publish" else (
            "reject" if decision == "reject" else "review"
        ),
        "reason": str(reason)[:500],
        "labels": list(dict.fromkeys(categories))[:12],
    }
    return {
        "id": "aqx-local-moderation",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": json.dumps(result, ensure_ascii=False)},
            "finish_reason": "stop",
        }],
    }
