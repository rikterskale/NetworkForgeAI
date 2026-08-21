"""Minimal authenticated read-only dashboard API."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Header, HTTPException
except ImportError:  # pragma: no cover - deployment dependency
    FastAPI = None  # type: ignore[assignment,misc]


def create_app() -> FastAPI:
    if FastAPI is None:
        raise RuntimeError("FastAPI is required to run the dashboard")
    app = FastAPI(title="NetworkForgeAI Dashboard")
    report_dir = Path(os.getenv("REPORT_OUTPUT_DIR", "./reports"))
    expected_token = os.getenv("DASHBOARD_AUTH_TOKEN", "")

    def authorize(authorization: str | None) -> None:
        if (
            not expected_token
            or expected_token == "changeme"
            or authorization != f"Bearer {expected_token}"
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/reports")
    def reports(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        report_dir.mkdir(parents=True, exist_ok=True)
        return {"reports": _relative_files(report_dir)}

    @app.get("/reports/{report_path:path}")
    def report_detail(
        report_path: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorize(authorization)
        requested = _safe_child(report_dir, report_path)
        if not requested.is_file():
            raise HTTPException(status_code=404, detail="Report not found")
        content = requested.read_text(encoding="utf-8")
        if requested.suffix == ".json":
            try:
                return {"path": report_path, "content": json.loads(content)}
            except json.JSONDecodeError:
                pass
        return {"path": report_path, "content": content}

    @app.get("/scans")
    def scans(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        scan_root = report_dir
        entries = []
        for state_file in scan_root.glob("*/scan_state.json"):
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
                entries.append(
                    {
                        "scan_id": state.get("scan_id", state_file.parent.name),
                        "status": state.get("status", "unknown"),
                        "target": state.get("config", {}).get("target"),
                        "finding_count": state.get("finding_count", 0),
                    }
                )
            except (OSError, json.JSONDecodeError):
                continue
        return {"scans": sorted(entries, key=lambda item: item["scan_id"])}

    @app.get("/scans/{scan_id}")
    def scan_detail(
        scan_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorize(authorization)
        state_file = _safe_child(report_dir, f"{scan_id}/scan_state.json")
        if not state_file.is_file():
            raise HTTPException(status_code=404, detail="Scan not found")
        try:
            state: dict[str, Any] = json.loads(state_file.read_text(encoding="utf-8"))
            return state
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail="Invalid scan state") from exc

    return app


def _safe_child(root: Path, relative_path: str) -> Path:
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Path escapes report directory")
    return candidate


def _relative_files(root: Path) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    return sorted(str(path.relative_to(root)) for path in root.glob("**/*") if path.is_file())


app: FastAPI | None = create_app() if FastAPI is not None else None
