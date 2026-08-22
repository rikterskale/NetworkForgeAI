"""Authenticated dashboard API.

Read-only report/scan surfaces are always available. When a live
``ScanOrchestrator`` is attached via ``create_app(orchestrator=...)``, operator
endpoints (approval queue, steering, agent status) are enabled. All state-
changing endpoints fail closed without an attached scan.

Roles: ``DASHBOARD_AUTH_TOKEN`` grants full operator access. An optional
``DASHBOARD_VIEWER_TOKEN`` grants read-only access to report/scan/agent
surfaces; it is rejected on approval and steering endpoints.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    from fastapi import Body, FastAPI, Header, HTTPException
    from fastapi.responses import PlainTextResponse
except ImportError:  # pragma: no cover - deployment dependency
    FastAPI = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..core.approval_gateway import ApprovalRequest
    from ..core.orchestrator import ScanOrchestrator

from .operator_page import OPERATOR_PAGE


def create_app(orchestrator: ScanOrchestrator | None = None) -> FastAPI:
    if FastAPI is None:
        raise RuntimeError("FastAPI is required to run the dashboard")
    from ..observability import configure_logging

    configure_logging()
    app = FastAPI(title="NetworkForgeAI Dashboard")
    report_dir = Path(os.getenv("REPORT_OUTPUT_DIR", "./reports"))
    expected_token = os.getenv("DASHBOARD_AUTH_TOKEN", "")
    viewer_token = os.getenv("DASHBOARD_VIEWER_TOKEN", "")
    scan = orchestrator

    def authorize(authorization: str | None, required_role: str = "operator") -> None:
        if authorization is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
        if (
            expected_token
            and expected_token != "changeme"
            and (authorization == f"Bearer {expected_token}")
        ):
            return
        if (
            required_role == "viewer"
            and viewer_token
            and (authorization == f"Bearer {viewer_token}" and viewer_token != expected_token)
        ):
            return
        raise HTTPException(status_code=401, detail="Unauthorized")

    def require_scan() -> ScanOrchestrator:
        if scan is None:
            raise HTTPException(status_code=503, detail="No live scan attached to this dashboard")
        return scan

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(authorization: str | None = Header(default=None)) -> str:
        """Expose secret-free operational counters to authenticated viewers."""
        authorize(authorization, required_role="viewer")
        from ..observability import prometheus_metrics

        return prometheus_metrics()

    @app.get("/", include_in_schema=False)
    def operator_console() -> Any:
        """Serve the dependency-free operator console shell.

        The page contains no data; it authenticates to the JSON API with the
        bearer token the operator enters in the browser.
        """
        from fastapi.responses import HTMLResponse

        return HTMLResponse(OPERATOR_PAGE)

    @app.get("/reports")
    def reports(
        authorization: str | None = Header(default=None),
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
        _page_bounds(limit, offset)
        report_dir.mkdir(parents=True, exist_ok=True)
        all_reports = _relative_files(report_dir)
        return {
            "reports": all_reports[offset : offset + limit],
            "total": len(all_reports),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/reports/{report_path:path}")
    def report_detail(
        report_path: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
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
    def scans(
        authorization: str | None = Header(default=None),
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
    ) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
        _page_bounds(limit, offset)
        entries = []
        for state_file in report_dir.glob("*/scan_state.json"):
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
        all_scans = sorted(entries, key=lambda item: item["scan_id"])
        if status:
            all_scans = [item for item in all_scans if item["status"] == status]
        return {
            "scans": all_scans[offset : offset + limit],
            "total": len(all_scans),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/scans/{scan_id}")
    def scan_detail(
        scan_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
        state_file = _safe_child(report_dir, f"{scan_id}/scan_state.json")
        if not state_file.is_file():
            raise HTTPException(status_code=404, detail="Scan not found")
        try:
            state: dict[str, Any] = json.loads(state_file.read_text(encoding="utf-8"))
            return state
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail="Invalid scan state") from exc

    @app.get("/scans/{scan_id}/findings")
    def scan_findings(
        scan_id: str,
        authorization: str | None = Header(default=None),
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
        _page_bounds(limit, offset)
        findings_file = _safe_child(report_dir, f"{scan_id}/findings.json")
        if not findings_file.is_file():
            raise HTTPException(status_code=404, detail="Findings not found")
        try:
            findings: list[dict[str, Any]] = json.loads(findings_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail="Invalid findings file") from exc
        if severity:
            findings = [item for item in findings if item.get("severity") == severity]
        if status:
            findings = [item for item in findings if item.get("status") == status]
        return {
            "scan_id": scan_id,
            "count": len(findings),
            "findings": findings[offset : offset + limit],
            "limit": limit,
            "offset": offset,
        }

    @app.get("/agents")
    def agents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization, required_role="viewer")
        live = require_scan()
        rows = [
            {
                "id": agent.id,
                "name": agent.name,
                "status": agent.status.value,
                "capabilities": agent.get_capabilities(),
            }
            for agent in live.agents.values()
        ]
        return {
            "scan_id": live.scan_id,
            "scan_status": live.status.value,
            "agents": sorted(rows, key=lambda row: row["id"]),
        }

    @app.get("/approvals")
    def approvals(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        pending: list[ApprovalRequest] = live.approval_gateway.get_pending_requests()
        return {
            "pending": [request.to_dict() for request in pending],
            "emergency_stop": live.approval_gateway.emergency_stop_active,
        }

    @app.post("/approvals/{request_id}/approve")
    def approve_request(
        request_id: str,
        authorization: str | None = Header(default=None),
        response_data: dict[str, Any] | None = Body(default=None),
    ) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        approved = _run_coroutine(
            live.approval_gateway.approve(request_id, "dashboard_operator", response_data)
        )
        if not approved:
            raise HTTPException(status_code=409, detail="Request not found or not pending")
        return {"request_id": request_id, "status": "approved"}

    @app.post("/approvals/{request_id}/reject")
    def reject_request(
        request_id: str,
        authorization: str | None = Header(default=None),
        reason: str | None = Body(default=None),
    ) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        rejected = _run_coroutine(
            live.approval_gateway.reject(
                request_id, "dashboard_operator", reason or "rejected via dashboard"
            )
        )
        if not rejected:
            raise HTTPException(status_code=409, detail="Request not found or not pending")
        return {"request_id": request_id, "status": "rejected"}

    @app.post("/scan/pause")
    def pause_scan(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        _run_coroutine(live.pause())
        return {"scan_id": live.scan_id, "status": live.status.value}

    @app.post("/scan/resume")
    def resume_scan(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        _run_coroutine(live.resume())
        return {"scan_id": live.scan_id, "status": live.status.value}

    @app.post("/scan/stop")
    def stop_scan(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authorize(authorization)
        live = require_scan()
        _run_coroutine(live.stop())
        return {"scan_id": live.scan_id, "status": live.status.value}

    return app


def _run_coroutine(coroutine: Any) -> Any:
    """Run an orchestrator/gateway coroutine from sync route handlers."""
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    raise HTTPException(status_code=500, detail="Dashboard cannot nest event loops")


def _safe_child(root: Path, relative_path: str) -> Path:
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Path escapes report directory")
    return candidate


def _page_bounds(limit: int, offset: int) -> None:
    if limit < 1 or limit > 1000 or offset < 0:
        raise HTTPException(
            status_code=422, detail="limit must be 1..1000 and offset must be non-negative"
        )


def _relative_files(root: Path) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    return sorted(str(path.relative_to(root)) for path in root.glob("**/*") if path.is_file())


app: FastAPI | None = create_app() if FastAPI is not None else None
