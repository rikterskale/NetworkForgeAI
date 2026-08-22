"""Additional dashboard coverage for report/scan read endpoints and guards."""

import pytest
from fastapi.testclient import TestClient

from networkforgeai.interface.dashboard import create_app


@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "tok")
    return tmp_path / "reports"


AUTH = {"Authorization": "Bearer tok"}


@pytest.fixture()
def client(env):
    return TestClient(create_app())


def test_reports_listing_and_detail_json_and_text(env, client):
    (env / "run").mkdir(parents=True)
    (env / "run" / "findings.json").write_text('{"ok": true}', encoding="utf-8")
    (env / "run" / "report.md").write_text("# Report", encoding="utf-8")

    listing = client.get("/reports", headers=AUTH).json()
    assert "run/findings.json" in listing["reports"]

    as_json = client.get("/reports/run/findings.json", headers=AUTH).json()
    assert as_json["content"] == {"ok": True}

    as_text = client.get("/reports/run/report.md", headers=AUTH).json()
    assert as_text["content"] == "# Report"

    assert client.get("/reports/run/missing.md", headers=AUTH).status_code == 404


def test_report_detail_invalid_json_falls_back_to_text(env, client):
    (env / "run").mkdir(parents=True)
    (env / "run" / "broken.json").write_text("{not json", encoding="utf-8")
    body = client.get("/reports/run/broken.json", headers=AUTH).json()
    assert body["content"] == "{not json"


def test_safe_child_rejects_escape(tmp_path):
    from fastapi import HTTPException

    from networkforgeai.interface.dashboard import _safe_child

    # A child path resolves fine; an escaping path raises a 400.
    assert _safe_child(tmp_path, "run/report.md").name == "report.md"
    with pytest.raises(HTTPException) as exc:
        _safe_child(tmp_path, "../../etc/passwd")
    assert exc.value.status_code == 400


def test_scan_detail_and_listing(env, client):
    scan = env / "scan-1"
    scan.mkdir(parents=True)
    (scan / "scan_state.json").write_text(
        '{"scan_id": "scan-1", "status": "completed", "config": {"target": "example.com"},'
        ' "finding_count": 2}',
        encoding="utf-8",
    )
    listing = client.get("/scans", headers=AUTH).json()
    assert listing["scans"][0]["scan_id"] == "scan-1"

    detail = client.get("/scans/scan-1", headers=AUTH).json()
    assert detail["status"] == "completed"

    assert client.get("/scans/missing", headers=AUTH).status_code == 404


def test_scan_detail_invalid_json_returns_500(env, client):
    scan = env / "bad"
    scan.mkdir(parents=True)
    (scan / "scan_state.json").write_text("{broken", encoding="utf-8")
    assert client.get("/scans/bad", headers=AUTH).status_code == 500


def test_dashboard_supports_pagination_and_finding_filters(env, client):
    scan = env / "scan-filter"
    scan.mkdir(parents=True)
    (scan / "findings.json").write_text(
        '[{"type":"xss","severity":"high","status":"validated"},'
        '{"type":"open_port","severity":"low","status":"suspected"}]'
    )
    response = client.get(
        "/scans/scan-filter/findings?severity=high&limit=1&offset=0", headers=AUTH
    )
    body = response.json()
    assert body["count"] == 1
    assert body["findings"][0]["type"] == "xss"
    assert body["limit"] == 1


def test_reject_missing_request_returns_409(env):
    from tests.test_dashboard_api import FakeOrchestrator

    client = TestClient(create_app(orchestrator=FakeOrchestrator()))
    assert client.post("/approvals/nope/reject", json="x", headers=AUTH).status_code == 409
