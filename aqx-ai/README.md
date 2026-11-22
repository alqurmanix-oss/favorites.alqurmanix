# AQX AI — Private, self-hostable moderation engine

AQX AI is an AQX-owned application layer for review moderation. It runs open-weight models inside the AQX-controlled runtime; it does **not** call a hosted LLM inference API.

## Current bootstrap scope

- Text moderation: Qwen2.5-0.5B-Instruct, loaded locally.
- Audio: Whisper tiny speech-to-text, loaded locally, then the transcript is moderated.
- Images: local NSFW image classifier plus OCR. The current small CPU profile does not perform reliable general visual-semantic understanding, so image-bearing reviews are routed to human review unless a high-confidence explicit violation is detected.
- Fail-closed: missing models, malformed output, unsupported media, or runtime errors never produce an approval.
- Auto-publish is disabled by default and requires an explicit server-side setting after validation.

Model weights are open-weight third-party projects, but inference runs in this service. The first startup downloads weights into the local Hugging Face cache; mount a persistent volume at `/models` to avoid downloading them again. To achieve literal end-to-end infrastructure independence later, mirror the approved model artifacts into AQX-owned storage and point the runtime at those local paths.

## Run locally

```bash
cp .env.example .env
docker compose up --build
```

Set a long random `AQX_AI_INTERNAL_TOKEN` before exposing the API. Do not expose this token to browsers.

## API

- `GET /health`: runtime readiness (no secret required).
- `POST /v1/analyze`: multipart form with optional `text`, `image`, and/or `audio`; requires `Authorization: Bearer <AQX_AI_INTERNAL_TOKEN>`.

Response decisions: `publish`, `reject`, or `human_review`. The `publish_allowed` field is the authoritative gate. It is false by default.

## Deployment status

This is source code only. It has not been deployed, connected to AQX Favorites, or tested against the pending WAV review. Do not enable automatic publication until the test suite and a representative multilingual/media evaluation set pass.
