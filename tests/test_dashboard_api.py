import pytest
from fastapi.testclient import TestClient

from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalRequest
from networkforgeai.core.orchestrator import ScanConfig, ScanOrchestrator
from networkforgeai.interface.dashboard import create_app


@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "test-token-123")
    return tmp_path / "reports"


AUTH = {"Authorization": "Bearer test-token-123"}


class FakeAgent:
    def __init__(self, agent_id: str, status_value: str = "idle"):
        self.id = agent_id
        self.name = f"agent-{agent_id}"
        self.status = type("Status", (), {"value": status_value})()

    def get_capabilities(self):
        return ["reconnaissance"]


class FakeGateway(ApprovalGateway):
    pass


class FakeOrchestrator:
    """Duck-typed stand-in exposing the surfaces the dashboard touches."""

    def __init__(self, scan_id="scan-1"):
        self.scan_id = scan_id
        from networkforgeai.core.orchestrator import ScanStatus

        self.status = ScanStatus.RUNNING
        self.agents = {"a1": FakeAgent("a1", "running"), "a2": FakeAgent("a2", "idle")}
        self.approval_gateway = FakeGateway(mode="manual")
        self.paused = False
        self.stopped = False

    async def pause(self):
        self.paused = True

    async def resume(self):
        self.paused = False

    async def stop(self):
        self.stopped = True


@pytest.fixture()
def client(env):
    return TestClient(create_app())


@pytest.fixture()
def live_client(env):
    orch = FakeOrchestrator()
    return TestClient(create_app(orchestrator=orch)), orch


def test_health_is_unauthenticated(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_all_other_routes_require_auth(client):
    for method, path in [
        ("get", "/agents"),
        ("get", "/approvals"),
        ("get", "/scans"),
        ("post", "/scan/pause"),
        ("post", "/scan/stop"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code == 401, path


def test_operator_endpoints_fail_closed_without_live_scan(client):
    for method, path in [("get", "/agents"), ("get", "/approvals"), ("post", "/scan/pause")]:
        response = getattr(client, method)(path, headers=AUTH)
        assert response.status_code == 503, path


def test_agent_listing_and_scan_status(live_client):
    client, _orch = live_client
    payload = client.get("/agents", headers=AUTH).json()
    assert payload["scan_id"] == "scan-1"
    assert [row["id"] for row in payload["agents"]] == ["a1", "a2"]
    assert payload["scan_status"] == "running"


def test_approval_queue_and_decisions(live_client):
    client, orch = live_client
    request = ApprovalRequest(
        agent_id="a1",
        action_type="exploit_validation",
        description="probe",
        target="example.com",
    )
    orch.approval_gateway.requests[request.id] = request

    pending = client.get("/approvals", headers=AUTH).json()
    assert len(pending["pending"]) == 1
    assert pending["pending"][0]["action_type"] == "exploit_validation"

    ok = client.post(f"/approvals/{request.id}/approve", headers=AUTH)
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert orch.approval_gateway.get_request(request.id).status.value == "approved"

    conflict = client.post(f"/approvals/{request.id}/approve", headers=AUTH)
    assert conflict.status_code == 409


def test_reject_records_reason(live_client):
    client, orch = live_client
    request = ApprovalRequest(agent_id="a1", action_type="x", description="d", target="t")
    orch.approval_gateway.requests[request.id] = request
    response = client.post(f"/approvals/{request.id}/reject", json="out of scope", headers=AUTH)
    assert response.status_code == 200
    stored = orch.approval_gateway.get_request(request.id)
    assert stored.status.value == "rejected"
    assert stored.rejection_reason == "out of scope"


def test_steering_controls(live_client):
    client, orch = live_client
    assert client.post("/scan/pause", headers=AUTH).status_code == 200
    assert orch.paused is True
    assert client.post("/scan/resume", headers=AUTH).status_code == 200
    assert orch.paused is False
    assert client.post("/scan/stop", headers=AUTH).status_code == 200
    assert orch.stopped is True


def test_findings_endpoint_reads_persisted_file(env, client):
    scan_dir = env / "scan-42"
    scan_dir.mkdir(parents=True)
    (scan_dir / "findings.json").write_text('[{"type": "xss", "target": "example.com"}]')
    payload = client.get("/scans/scan-42/findings", headers=AUTH).json()
    assert payload["count"] == 1
    assert payload["findings"][0]["type"] == "xss"
    missing = client.get("/scans/scan-99/findings", headers=AUTH)
    assert missing.status_code == 404


def test_real_orchestrator_attach(tmp_path, env, monkeypatch):
    monkeypatch.chdir(tmp_path)
    orchestrator = ScanOrchestrator(ScanConfig(target="example.com", scope=["example.com"]))
    client = TestClient(create_app(orchestrator=orchestrator))
    payload = client.get("/agents", headers=AUTH).json()
    assert payload["scan_id"] == orchestrator.scan_id
    assert payload["agents"] == []


def test_operator_console_shell_served_without_data(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Operator Console" in body
    assert 'id="agentgraph"' in body  # GUI-003: agent graph canvas present
    assert "test-token-123" not in body  # no secrets baked into the shell
    assert "example.com" not in body  # no data in the static shell


def test_operator_console_tabbed_gui_shell(client):
    body = client.get("/").text
    for marker in (
        'id="tabpanel-live"',
        'id="tabpanel-scans"',
        'id="tabpanel-reports"',
        "switchTab(",
        "loadFindings(",
        "loadReports(",
        "showReport(",
        'id="findings"',
        'id="reportview"',
    ):
        assert marker in body


@pytest.fixture()
def viewer_client(env, monkeypatch):
    monkeypatch.setenv("DASHBOARD_VIEWER_TOKEN", "viewer-token-456")
    return TestClient(create_app(orchestrator=FakeOrchestrator()))


VIEWER_AUTH = {"Authorization": "Bearer viewer-token-456"}


def test_viewer_token_reads_reports_scans_and_agents(env, viewer_client):
    scan_dir = env / "scan-7"
    scan_dir.mkdir(parents=True)
    (scan_dir / "findings.json").write_text("[]")
    (scan_dir / "scan_state.json").write_text('{"scan_id": "scan-7", "status": "complete"}')
    for path in ["/scans", "/scans/scan-7", "/scans/scan-7/findings", "/agents"]:
        assert viewer_client.get(path, headers=VIEWER_AUTH).status_code == 200, path


def test_viewer_token_cannot_mutate_or_approve(viewer_client):
    for method, path in [
        ("get", "/approvals"),
        ("post", "/approvals/req/approve"),
        ("post", "/approvals/req/reject"),
        ("post", "/scan/pause"),
        ("post", "/scan/resume"),
        ("post", "/scan/stop"),
    ]:
        response = getattr(viewer_client, method)(path, headers=VIEWER_AUTH)
        assert response.status_code == 401, path


def test_operator_token_still_has_full_access(viewer_client):
    assert viewer_client.get("/agents", headers=AUTH).status_code == 200
    assert viewer_client.get("/approvals", headers=AUTH).status_code == 200


def test_viewer_role_requires_distinct_token(env, monkeypatch):
    # If the viewer token equals the operator token it grants nothing extra and
    # a missing token still fails closed.
    monkeypatch.setenv("DASHBOARD_VIEWER_TOKEN", "test-token-123")
    client = TestClient(create_app())
    assert client.get("/reports").status_code == 401
