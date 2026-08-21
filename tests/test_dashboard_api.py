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
    assert "test-token-123" not in body  # no secrets baked into the shell
    assert "example.com" not in body  # no data in the static shell
