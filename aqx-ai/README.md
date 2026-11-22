# AQX AI — Private, self-hostable moderation engine

AQX AI is an AQX-owned application layer for review moderation. It runs open-weight models inside the AQX-controlled runtime; it does **not** call a hosted LLM inference API.

## Current bootstrap scope

- Text moderation: Qwen2.5-0.5B-Instruct, loaded locally.
- Audio: Whisper tiny speech-to-text, loaded locally, then the transcript is moderated.
- Images: local NSFW image classifier plus OCR. The current small CPU profile does not perform reliable general visual-semantic understanding, so image-bearing reviews are routed to human review unless a high-confidence explicit violation is detected.
- Fail-closed: missing models, malformed output, unsupported media, or runtime errors never produce an approval.
- Auto-publish is hard-disabled in code; the current prototype cannot approve publication.

Model weights are third-party open-weight artifacts, not AQX-authored intellectual property. The current manifest preparation utility verifies the declared Apache-2.0 license, resolves each model to an immutable commit, and mirrors it into the persistent AQX model volume. Inference loads only local paths with `local_files_only=True`; it does not call a hosted AI inference API or the model hub. AQX owns the orchestration, moderation policy, API, evaluation data, and deployment code. Third-party model copyrights and licenses remain with their respective authors.

## Run locally

```bash
cp .env.example .env
# Set AQX_AI_INTERNAL_TOKEN to a random secret of at least 32 characters.
docker compose build
# One-time model acquisition into the AQX-owned persistent Docker volume:
docker compose run --rm aqx-ai python scripts/prepare_models.py
# Runtime inference is offline and reads only /models:
docker compose up -d
```

The preparation step requires internet access once to acquire public model artifacts. Subsequent inference is local-only. The current model set is:
- Text: [Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct) — Apache-2.0.
- Audio: [Whisper tiny](https://huggingface.co/openai/whisper-tiny) — Apache-2.0 as declared on the model card.
- Image safety: [Falconsai NSFW image detection](https://huggingface.co/Falconsai/nsfw_image_detection) — Apache-2.0.

The exact commit revisions and per-file SHA-256 checksums are recorded in `/models/model-manifest.json`. The container verifies this manifest before starting the API. Review the licenses and model cards before commercial production use.

Set a long random `AQX_AI_INTERNAL_TOKEN` before exposing the API. Do not expose this token to browsers.

## API

- `GET /health`: process liveness and model-cache status (no secret required).
- `POST /v1/analyze`: multipart form with optional `text`, `image`, and/or `audio`; requires `Authorization: Bearer <AQX_AI_INTERNAL_TOKEN>`.

Response decisions: `publish`, `reject`, or `human_review`. The `publish_allowed` field is the authoritative gate and is currently hard-coded false; no environment variable can enable auto-publication.

## Deployment status

This is source code only. It has not been deployed, connected to AQX Favorites, or tested against the pending WAV review. The small CPU models are a prototype, not a validated moderation authority. Image processing currently combines OCR and an explicit-content classifier; it does not understand general image context, so image-bearing reviews are held for human review. Do not enable automatic publication until security tests and a representative multilingual/media evaluation set pass.
