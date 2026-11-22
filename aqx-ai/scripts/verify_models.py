from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.getenv("AQX_MODEL_DIR", "/models")).resolve()
MANIFEST = ROOT / "model-manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    if not MANIFEST.is_file():
        raise SystemExit("AQX model manifest is missing; prepare local models first.")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("owner") != "AQX":
        raise SystemExit("Unexpected model manifest owner.")

    required = {"text", "asr", "image"}
    models = manifest.get("models", {})
    if set(models) != required:
        raise SystemExit("Model manifest is incomplete.")

    for name, entry in models.items():
        model_root = (ROOT / name).resolve()
        if not model_root.is_dir():
            raise SystemExit(f"Missing local model directory: {name}")
        hashes = entry.get("files_sha256", {})
        if not hashes:
            raise SystemExit(f"Missing file hashes for model: {name}")

        for relative_path, expected_hash in hashes.items():
            candidate = (model_root / relative_path).resolve()
            if model_root not in candidate.parents or not candidate.is_file():
                raise SystemExit(f"Invalid or missing model artifact: {name}/{relative_path}")
            if sha256_file(candidate) != expected_hash:
                raise SystemExit(f"Model artifact checksum mismatch: {name}/{relative_path}")

    print("AQX local model manifest and SHA-256 checks passed.")


if __name__ == "__main__":
    main()
