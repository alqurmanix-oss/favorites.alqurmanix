from __future__ import annotations

import json
import os
from pathlib import Path

from huggingface_hub import HfApi, snapshot_download

ROOT = Path(os.getenv("AQX_MODEL_DIR", "/models"))
MODELS = {
    "text": ("Qwen/Qwen2.5-0.5B-Instruct", "apache-2.0"),
    "asr": ("openai/whisper-tiny", "apache-2.0"),
    "image": ("Falconsai/nsfw_image_detection", "apache-2.0"),
}


def main() -> None:
    api = HfApi()
    ROOT.mkdir(parents=True, exist_ok=True)
    manifest = {"owner": "AQX", "models": {}}

    for name, (repo_id, expected_license) in MODELS.items():
        info = api.model_info(repo_id)
        card = info.card_data
        declared_license = getattr(card, "license", None) if card else None
        if declared_license != expected_license:
            raise RuntimeError(
                f"License review required for {repo_id}: "
                f"expected {expected_license}, found {declared_license!r}"
            )
        if not info.sha:
            raise RuntimeError(f"Could not resolve immutable revision for {repo_id}")

        destination = ROOT / name
        snapshot_download(
            repo_id=repo_id,
            revision=info.sha,
            local_dir=str(destination),
        )
        manifest["models"][name] = {
            "repo_id": repo_id,
            "revision": info.sha,
            "license": declared_license,
            "local_path": str(destination),
        }

    manifest_path = ROOT / "model-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Prepared AQX model artifacts and manifest: {manifest_path}")


if __name__ == "__main__":
    main()
