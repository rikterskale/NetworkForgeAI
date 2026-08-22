#!/usr/bin/env python3
"""Create a reproducible build provenance manifest for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return os.getenv("GITHUB_SHA", "unknown")


def artifact_record(path: Path) -> dict[str, object]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": str(path), "sha256": digest, "size_bytes": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("artifact", type=Path, nargs="+")
    args = parser.parse_args()
    payload = {
        "schema_version": 1,
        "git_revision": git_revision(),
        "workflow": os.getenv("GITHUB_WORKFLOW"),
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "repository": os.getenv("GITHUB_REPOSITORY"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "artifacts": [artifact_record(path) for path in args.artifact],
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
