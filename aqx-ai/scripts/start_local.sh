#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine/Desktop with Compose v2, then retry." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required only to generate the local API secret." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
fi

python3 - <<'PY'
from pathlib import Path
import secrets

path = Path(".env")
lines = path.read_text(encoding="utf-8").splitlines()
key = "AQX_AI_INTERNAL_TOKEN="
found = False
for index, line in enumerate(lines):
    if line.startswith(key):
        found = True
        value = line[len(key):].strip()
        if not value or value == "replace-with-a-long-random-secret":
            lines[index] = key + secrets.token_urlsafe(48)
        break
if not found:
    lines.append(key + secrets.token_urlsafe(48))
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

echo "Building AQX AI CPU container..."
docker compose build

echo "Checking the persistent local model volume..."
if docker compose run --rm --no-deps aqx-ai python scripts/verify_models.py >/dev/null 2>&1; then
  echo "Existing model files and checksums are valid; skipping download."
else
  echo "Downloading open model files once into the persistent Docker volume..."
  docker compose run --rm --no-deps aqx-ai python scripts/prepare_models.py
  docker compose run --rm --no-deps aqx-ai python scripts/verify_models.py
fi

echo "Starting AQX AI locally..."
docker compose up -d
docker compose ps
echo "AQX AI container started. Local endpoint: http://127.0.0.1:8080"
echo "The generated internal token is stored privately in aqx-ai/.env; do not share it."
