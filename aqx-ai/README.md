# AQX AI — Private, self-hostable moderation engine

AQX AI is an AQX-owned application layer for review moderation. It runs open-weight models inside the AQX-controlled runtime; it does **not** call a hosted LLM inference API.

## Current bootstrap scope

- Text moderation: Qwen2.5-0.5B-Instruct, loaded locally.
- Audio: Whisper tiny speech-to-text, loaded locally, then the transcript is moderated. WAV/MP3/OGG use SoundFile when supported; browser/container formats such as WebM/MP4 use a bounded local FFmpeg decode path. Audio is normalized to Whisper's 16 kHz input rate.
- Images: local NSFW image classifier plus OCR. The current small CPU profile does not perform reliable general visual-semantic understanding, so image-bearing reviews are routed to human review unless a high-confidence explicit violation is detected.
- Fail-closed: missing models, malformed output, unsupported media, or runtime errors never produce an approval.
- Auto-publish is hard-disabled in code; the current prototype cannot approve publication.

Model weights are third-party open-weight artifacts, not AQX-authored intellectual property. The current manifest preparation utility verifies the declared Apache-2.0 license, resolves each model to an immutable commit, and mirrors it into the persistent AQX model volume. Inference loads only local paths with `local_files_only=True`; it does not call a hosted AI inference API or the model hub. AQX owns the orchestration, moderation policy, API, evaluation data, and deployment code. Third-party model copyrights and licenses remain with their respective authors.

## Run locally (one command)

Requirements: Docker Engine/Desktop with Compose v2, Python 3, and an internet connection for the initial model download. From this directory run:

```bash
chmod +x scripts/start_local.sh
./scripts/start_local.sh
```

The launcher creates a private `.env` file and a random internal token if needed, builds the CPU container, downloads the models only when the persistent volume is empty or invalid, verifies every recorded SHA-256 checksum, and starts the service. Keep `.env` private. Subsequent inference uses local model files and does not call a hosted AI inference API.

To run the steps manually, copy `.env.example` to `.env`, set a random `AQX_AI_INTERNAL_TOKEN` of at least 32 characters, then run `docker compose build`, `docker compose run --rm aqx-ai python scripts/prepare_models.py`, and `docker compose up -d`.

The preparation step requires internet access once to acquire public model artifacts. Subsequent inference is local-only. The current model set is:
- Text: [Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct) — Apache-2.0.
- Audio: [Whisper tiny](https://huggingface.co/openai/whisper-tiny) — Apache-2.0 as declared on the model card.
- Image safety: [Falconsai NSFW image detection](https://huggingface.co/Falconsai/nsfw_image_detection) — Apache-2.0.

The exact commit revisions and per-file SHA-256 checksums are recorded in `/models/model-manifest.json`. Runtime dependencies are pinned, including Accelerate for low-memory model loading, NumPy/SciPy for audio processing, and the container's FFmpeg binary for browser audio containers. The container verifies this manifest before starting the API. Review the licenses and model cards before commercial production use.

Set a long random `AQX_AI_INTERNAL_TOKEN` before exposing the API. Do not expose this token to browsers. To connect the existing AQX Favorites Edge Function without changing its code, set these Supabase Edge Function secrets after the local AQX AI service has a reachable HTTPS endpoint: `AQX_AI_BASE_URL=https://<AQX-AI-HOST>/v1/`, `AQX_AI_API_KEY=<same AQX_AI_INTERNAL_TOKEN>`, `AQX_AI_MODEL=aqx-local`, `AQX_AUDIO_MODEL=whisper-tiny`, and `AQX_VISION_MODEL=aqx-local-vision`. The existing Favorites moderation worker then calls only the AQX local compatibility endpoints; keep its existing fail-closed behavior.

## Bounded load handling

Inference endpoints now use per-process admission control. Defaults are one active inference and up to eight admitted requests waiting for that slot. Requests beyond that bounded capacity receive HTTP 429 with a `Retry-After: 5` header instead of accumulating without limit. The `/health` response reports the configured limits and current admitted-request count.

Configure `AQX_MAX_CONCURRENT_INFERENCES` and `AQX_MAX_QUEUED_INFERENCES` to match the actual CPU/RAM budget. Keep concurrency at 1 for the small CPU model profile until measured otherwise. These limits are per application process, not global across replicas; each replica needs its own resource budget and an upstream load balancer. This is overload protection, not proof of a specific requests-per-second or user capacity. A real load test on the target host is still required before production.

## Load-control verification

The inference routes use bounded per-process admission control (default: one active inference plus eight admitted requests). Model loading, audio decoding/transcription, OCR, image classification, and text inference are dispatched through the worker thread pool so CPU-heavy work does not block the ASGI event loop. Requests beyond the configured capacity receive HTTP 429 with `Retry-After: 5`. Individual requests are bounded to 12,000 text characters and four attached review images by default; oversized requests are rejected with HTTP 413. The `/health` response reports configured capacity and current admitted requests; Docker Compose also checks process health through `/health`.

Run the admission-control tests from this directory after building the image:

```bash
docker compose build
docker compose run --rm --no-deps aqx-ai pytest -q tests/test_load_control.py
```

These are software-level tests only. They do not establish production throughput. Before production, run a load test on the actual host with representative text, image, and audio payloads, then tune concurrency to measured CPU/RAM and latency. Limits are per process, not global across replicas.

## API

- `GET /health`: process liveness and model-cache status (no secret required).
- `POST /v1/analyze`: multipart form with optional `text`, `image`, and/or `audio`; requires `Authorization: Bearer <AQX_AI_INTERNAL_TOKEN>`.
- `POST /v1/audio/transcriptions`: OpenAI-compatible local Whisper transcription endpoint.
- `POST /v1/chat/completions`: OpenAI-compatible local moderation endpoint used by the existing AQX Favorites Edge Function. It accepts review text and signed review-image URLs, but only fetches images from the exact host and signed path configured by `AQX_ALLOWED_MEDIA_HOSTS`.

Response decisions: `publish`, `reject`, or `human_review`. The `publish_allowed` field is the authoritative gate and is currently hard-coded false; no environment variable can enable auto-publication.

## Community compute

The proposed AQX Community Compute program is documented in [COMMUNITY_COMPUTE_POLICY.md](COMMUNITY_COMPUTE_POLICY.md). It is **not implemented, deployed, or active**. It is intended for registered users only, requires explicit consent before any device work, and provides an immediate opt-out control. Guest devices are excluded. Participant devices must never receive private reviews, personal data, credentials, or production moderation authority. AQX core services must remain functional when no community devices participate.

## Deployment status

This is source code only. It has not been deployed, connected to AQX Favorites, or tested against the pending WAV review. The small CPU models are a prototype, not a validated moderation authority. Image processing currently combines OCR and an explicit-content classifier; it does not understand general image context, so image-bearing reviews are held for human review. Do not enable automatic publication until security tests and a representative multilingual/media evaluation set pass.
