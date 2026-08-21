"""Minimal authenticated read-only dashboard API."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from fastapi import FastAPI, Header, HTTPException
except ImportError:  # pragma: no cover - deployment dependency
    FastAPI = None


def create_app():
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
    def health():
        return {"status": "ok"}

    @app.get("/reports")
    def reports(authorization: str | None = Header(default=None)):
        authorize(authorization)
        report_dir.mkdir(parents=True, exist_ok=True)
        return {"reports": [path.name for path in report_dir.glob("**/*") if path.is_file()]}

    return app


app = create_app() if FastAPI is not None else None
