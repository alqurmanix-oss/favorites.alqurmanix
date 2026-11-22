from __future__ import annotations

import hmac
import io
import json
import math
import os
import re
from functools import lru_cache
from typing import Any

import pytesseract
import soundfile as sf
import torch
from scipy.signal import resample_poly
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
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
            # Inspect container metadata before decoding to avoid allocating memory
            # for an oversized or pathological audio stream.
            try:
                audio_info = sf.info(io.BytesIO(audio_bytes))
            except (RuntimeError, ValueError, OSError):
                raise HTTPException(status_code=415, detail="INVALID_AUDIO")
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
                raise HTTPException(status_code=415, detail="INVALID_AUDIO")
            if sample_rate != audio_info.samplerate or len(samples) == 0:
                raise HTTPException(status_code=415, detail="INVALID_AUDIO")
            if getattr(samples, "ndim", 1) == 2:
                samples = samples.mean(axis=1)
            # Whisper expects 16 kHz audio. Resample locally instead of passing
            # a mismatched sample rate that would fail inference or distort timing.
            if sample_rate != 16000:
                divisor = math.gcd(int(sample_rate), 16000)
                samples = resample_poly(
                    samples, 16000 // divisor, int(sample_rate) // divisor
                )
                sample_rate = 16000
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
