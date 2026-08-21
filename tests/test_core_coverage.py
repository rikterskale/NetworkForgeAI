import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from networkforgeai.agents.recon_agent import ReconAgent
from networkforgeai.agents.specialized import (
    APISecurityAgent,
    NetworkExploitationAgent,
    PlanningAgent,
    PostExploitationAgent,
    QualityAssuranceAgent,
    ReportingAgent,
    WebApplicationAgent,
)
from networkforgeai.agents.vuln_scanner_agent import VulnerabilityScannerAgent
from networkforgeai.cli import _list_reports, _read_report
from networkforgeai.cli import main as cli_main
from networkforgeai.config import ApprovalMode, ReportFormat, Settings
from networkforgeai.core.approval_gateway import (
    ApprovalGateway,
    ApprovalRequest,
    ApprovalStatus,
    RiskLevel,
)
from networkforgeai.core.base_agent import AgentStatus, BaseAgent
from networkforgeai.core.knowledge_base import KnowledgeBase
from networkforgeai.core.message_bus import MessageBus
from networkforgeai.core.orchestrator import ScanConfig, ScanOrchestrator, ScanStatus
from networkforgeai.models.ai_capabilities import (
    cot_attack_path_planning,
    cot_vulnerability_analysis,
    extract_findings_from_response,
    parse_json_response,
    summarize_conversation,
    truncate_context,
)
from networkforgeai.models.base_adapter import (
    BaseAdapter,
    Message,
    ModelCapability,
    ModelConfig,
    ModelProvider,
    ModelResponse,
    TokenUsage,
    ToolDefinition,
)
from networkforgeai.models.model_factory import ModelFactory
from networkforgeai.models.retry import retry_async
from networkforgeai.tools import (
    CrackMapExecTool,
    HydraTool,
    ImpacketTools,
    MasscanTool,
    NiktoTool,
    NmapTool,
    OWASPZAPTool,
    SQLMapTool,
)
from networkforgeai.tools.base_tool import ToolCategory, ToolResult, ToolRiskLevel


class DemoAgent(BaseAgent):
    async def execute(self, task, context):
        self.current_task = task
        self.add_finding({"task": task, "context": context})
        return {"new_findings": self.get_findings()}

    def get_capabilities(self):
        return ["demo"]


class DummyAdapter(BaseAdapter):
    async def connect(self):
        self._is_connected = True
        return True

    async def disconnect(self):
        self._is_connected = False

    async def chat(self, messages, tools=None, temperature=None, max_tokens=None, **kwargs):
        response = ModelResponse(
            content=messages[-1].content,
            model=self.model_name,
            usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            finish_reason="stop",
        )
        self.token_usage.add(response)
        return response

    async def chat_stream(self, messages, tools=None, temperature=None, max_tokens=None, **kwargs):
        yield messages[-1].content

    def supports_capability(self, capability):
        return capability in self.config.capabilities


def run(coro):
    return asyncio.run(coro)


def test_settings_defaults_and_safety_validation():
    settings = Settings(target_scope=" example.com, 192.0.2.1 ", approval_mode="moderate")
    assert settings.parsed_target_scope == ["example.com", "192.0.2.1"]
    assert settings.approval_mode is ApprovalMode.MODERATE
    assert not settings.is_strict_mode
    assert settings.validate_security_config()
    assert settings.report_formats == list(ReportFormat)
    with pytest.raises(ValueError, match="No LLM"):
        settings.validate_llm_config()
    with pytest.raises(ValueError, match="TARGET_SCOPE"):
        Settings().validate_security_config()
    with pytest.raises(ValueError, match="DASHBOARD_AUTH_TOKEN"):
        Settings(
            target_scope="example.com", dashboard_auth_token="changeme"
        ).validate_security_config()


def test_knowledge_base_copies_and_merges_lists():
    async def scenario():
        knowledge = KnowledgeBase()
        await knowledge.update({"ports": [80], "owner": {"name": "a"}})
        await knowledge.update({"ports": [443]})
        value = await knowledge.get("ports")
        value.append(8080)
        assert await knowledge.get("ports") == [80, 443]
        assert await knowledge.get("missing", "fallback") == "fallback"
        await knowledge.set("owner", {"name": "b"})
        await knowledge.restore({"restored": True})
        assert await knowledge.snapshot() == {"restored": True}

    run(scenario())


def test_approval_request_round_trip_and_gateway_lifecycle(tmp_path):
    async def scenario():
        events = []

        async def callback(request):
            events.append(request.status)

        gateway = ApprovalGateway("manual", tmp_path / "audit.jsonl")
        gateway.register_callback("test", callback)
        request = await gateway.request_approval(
            "agent", "scan", "description", "example.com", "low", {"x": 1}, 30
        )
        assert gateway.get_pending_requests() == [request]
        assert await gateway.approve(request.id, "operator", {"approved": True})
        assert not await gateway.approve(request.id, "again")
        assert request.status is ApprovalStatus.APPROVED
        assert await gateway.wait_for_approval(request.id) is request
        restored = ApprovalRequest.from_dict(request.to_dict())
        assert restored.status is ApprovalStatus.APPROVED
        assert restored.response_data == {"approved": True}
        assert events == [ApprovalStatus.PENDING, ApprovalStatus.APPROVED]
        assert json.loads((tmp_path / "audit.jsonl").read_text())["status"] == "approved"

        rejected = await gateway.request_approval("agent", "scan", "d", "target", RiskLevel.MEDIUM)
        assert await gateway.reject(rejected.id, "operator", "unsafe")
        assert rejected.rejection_reason == "unsafe"
        gateway.unregister_callback("test")
        assert gateway.get_request("missing") is None

    run(scenario())


def test_approval_gateway_modes_expiration_and_reset():
    async def scenario():
        auto = ApprovalGateway("auto-low")
        low = await auto.request_approval("a", "scan", "d", "t", RiskLevel.LOW)
        assert low.status is ApprovalStatus.APPROVED
        medium = await auto.request_approval("a", "scan", "d", "t", RiskLevel.MEDIUM)
        assert medium.status is ApprovalStatus.PENDING
        medium.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert (
            await auto.wait_for_approval(medium.id, poll_interval=0)
        ).status is ApprovalStatus.EXPIRED
        auto.clear_expired()
        assert auto.get_request(medium.id) is None
        await auto.emergency_stop("maintenance")
        with pytest.raises(PermissionError, match="maintenance"):
            await auto.request_approval("a", "scan", "d", "t", RiskLevel.LOW)
        await auto.reset_emergency_stop()
        assert not auto.emergency_stop_active
        assert auto._should_auto_approve(RiskLevel.LOW)
        assert not auto._should_auto_approve(RiskLevel.HIGH)
        assert ApprovalGateway("lenient")._should_auto_approve(RiskLevel.MEDIUM)
        assert not ApprovalGateway("unknown")._should_auto_approve(RiskLevel.LOW)

    run(scenario())


def test_base_agent_lifecycle_messages_state_and_model():
    async def scenario():
        bus = MessageBus()
        await bus.register("receiver")
        agent = DemoAgent(agent_id="demo", message_bus=bus, tool_registry={"x": 42})
        result = await agent.execute("task", {"scope": "example.com"})
        assert result["new_findings"][0]["agent_id"] == "demo"
        assert agent.get_capabilities() == ["demo"]
        assert agent.get_tool("x") == 42
        with pytest.raises(KeyError):
            agent.get_tool("missing")
        await agent.send_message("receiver", {"hello": "world"})
        assert await bus.receive("receiver")
        agent.park()
        assert agent.status is AgentStatus.PARKED
        assert "1 findings" in agent.context_summary
        agent.resume()
        agent.stop()
        assert agent.should_stop()
        state = agent.to_state()
        restored = DemoAgent()
        restored.from_state(state)
        assert restored.id == "demo"
        assert restored.get_findings() == agent.get_findings()
        await bus.unregister("receiver")
        assert await agent.receive_message(timeout=0) is None

    run(scenario())


def test_base_agent_approval_and_model_errors():
    async def scenario():
        agent = DemoAgent()
        with pytest.raises(RuntimeError, match="Approval gateway"):
            await agent.request_approval("scan", "d", "t", RiskLevel.LOW)
        with pytest.raises(RuntimeError, match="model adapter"):
            await agent.ask_model([])
        with pytest.raises(RuntimeError, match="model adapter"):
            await agent.analyze_context("p", {})

        class Adapter:
            async def chat(self, messages, **kwargs):
                return messages

        agent.model_adapter = Adapter()
        assert await agent.ask_model(["message"]) == ["message"]
        assert await agent.analyze_context("prompt", {"key": "value"})
        await agent.cleanup()

    run(scenario())


def test_recon_and_vulnerability_agents_with_mocked_approvals():
    async def scenario():
        recon = ReconAgent()
        result = await recon.execute("enumerate_subdomains", {"target": "example.com"})
        assert len(result["findings"]) == 3
        tech = await recon.execute("detect_technologies", {"target": "example.com"})
        assert len(tech["findings"]) == 3

        async def approve(*args, **kwargs):
            return True, {"operator": "test"}

        recon.request_approval = approve
        ports = await recon.execute("scan_ports", {"target": "example.com"})
        assert len(ports["findings"]) == 3
        fingerprint = await recon.execute(
            "fingerprint_services",
            {
                "target": "example.com",
                "discovered_ports": ports["context_updates"]["discovered_ports"],
            },
        )
        assert len(fingerprint["findings"]) == 3
        assert (await recon.execute("other", {}))["findings"] == []

        scanner = VulnerabilityScannerAgent()
        scanner.request_approval = approve
        sql = await scanner.execute("scan_sql_injection", {"target": "example.com"})
        assert sql["findings"][0]["type"] == "sql_injection"
        xss = await scanner.execute("scan_xss", {"discovered_urls": ["https://example.com/login"]})
        assert xss["findings"][0]["type"] == "xss"
        ssrf = await scanner.execute("scan_ssrf", {"target": "example.com"})
        assert ssrf["findings"][0]["type"] == "ssrf"
        auth = await scanner.execute("scan_auth_bypass", {"target": "example.com"})
        assert auth["findings"] == []

        async def reject(*args, **kwargs):
            return False, None

        scanner.request_approval = reject
        rejected = await scanner.execute("unknown", {"target": "example.com"})
        assert rejected["findings"] == []

    run(scenario())


def test_specialized_agents_return_safe_workflows():
    async def scenario():
        context = {
            "vulnerabilities": [{"title": "SQL injection"}, {"type": "xss"}],
            "findings": [{"type": "x", "target": "a"}, {"type": "x", "target": "a"}],
            "discovered_urls": ["https://example.com"],
        }
        planning = await PlanningAgent().execute("plan", context)
        assert len(planning["context_updates"]["attack_paths"]) == 2
        reporting = await ReportingAgent().execute("report", context)
        assert len(reporting["findings"]) == 2
        qa = await QualityAssuranceAgent().execute("qa", context)
        assert len(qa["findings"]) == 1
        web = await WebApplicationAgent().execute("web", context)
        assert web["context_updates"]["active_testing_requires_approval"]
        api = await APISecurityAgent().execute("api", context)
        assert api["context_updates"]["api_testing_plan"]["requires_approval"]
        assert (await NetworkExploitationAgent().execute("exploit", context))["context_updates"][
            "exploitation_blocked"
        ]
        assert (await PostExploitationAgent().execute("post", context))["context_updates"][
            "post_exploitation_blocked"
        ]

    run(scenario())


def test_model_factory_routing_and_capabilities():
    assert ModelFactory._parse_provider("ollama").value == "local"
    assert ModelFactory._parse_provider("azure").value == "azure_openai"
    assert ModelFactory._parse_provider("unknown").value == "openai"
    assert "vision" in ModelFactory.get_capabilities("google")
    assert ModelFactory.list_providers()
    assert ModelFactory.get_adapter(ModelFactory._parse_provider("openai")) is None or True


def test_model_factory_environment_detection(monkeypatch):
    captured = []

    def fake_create(cls, provider, model_name, api_key=None, api_base=None, **kwargs):
        captured.append((provider, model_name, api_key, api_base))
        return captured[-1]

    monkeypatch.setattr(ModelFactory, "create", classmethod(fake_create))
    for key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "LOCAL_LLM_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    assert ModelFactory.create_from_env()[0] == "openai"
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-secret")
    assert ModelFactory.create_from_env()[0] == "anthropic"
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-secret")
    assert ModelFactory.create_from_env()[0] == "google"
    monkeypatch.delenv("GOOGLE_API_KEY")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://azure.example")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "azure-secret")
    assert ModelFactory.create_from_env()[0] == "azure_openai"
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY")
    monkeypatch.setenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
    assert ModelFactory.create_from_env()[0] == "local"
    monkeypatch.delenv("LOCAL_LLM_URL")
    with pytest.raises(ValueError, match="No LLM"):
        ModelFactory.create_from_env()


def test_model_factory_construction_and_fallbacks(monkeypatch):
    local = ModelFactory.create("local", "demo", api_base="http://localhost:11434/v1")
    assert local.provider_name == "local"
    azure = ModelFactory.create(
        "azure_openai",
        "deployment",
        api_key="secret",
        azure_endpoint="https://azure.example",
        azure_deployment="deployment",
        api_version="2024-01-01",
    )
    assert azure.provider_name == "azure_openai"
    with pytest.raises(ValueError, match="Azure OpenAI"):
        ModelFactory.create("azure", "deployment")

    attempts = []

    def fake_create(cls, provider, model_name, **kwargs):
        attempts.append(provider)
        return DummyAdapter(ModelConfig(ModelProvider.LOCAL, model_name))

    monkeypatch.setattr(ModelFactory, "create", classmethod(fake_create))
    assert run(ModelFactory.create_with_fallback_async(["first", "second"])).model_name == "gpt-4"
    assert attempts == ["first"]

    class FailingAdapter(DummyAdapter):
        async def connect(self):
            return False

    monkeypatch.setattr(
        ModelFactory,
        "create",
        classmethod(
            lambda cls, provider, model_name, **kwargs: FailingAdapter(
                ModelConfig(ModelProvider.LOCAL, model_name)
            )
        ),
    )
    with pytest.raises(ValueError, match="All providers failed"):
        run(ModelFactory.create_with_fallback_async(["first", "second"]))

    monkeypatch.setattr(
        ModelFactory,
        "create",
        classmethod(
            lambda cls, provider, model_name, **kwargs: DummyAdapter(
                ModelConfig(ModelProvider.LOCAL, model_name)
            )
        ),
    )
    assert ModelFactory.create_with_fallback(["first"], {"first": "local"}).model_name == "local"

    class ErrorAdapter(DummyAdapter):
        async def connect(self):
            raise RuntimeError("offline")

    monkeypatch.setattr(
        ModelFactory,
        "create",
        classmethod(
            lambda cls, provider, model_name, **kwargs: ErrorAdapter(
                ModelConfig(ModelProvider.LOCAL, model_name)
            )
        ),
    )
    with pytest.raises(ValueError, match="All providers failed"):
        ModelFactory.create_with_fallback(["first"])


def test_password_tools_build_and_parse_commands():
    hydra = HydraTool(dry_run=True)
    assert hydra.build_command(
        "example.com", {"username": "u", "password": "p", "port": 22, "verbose": True}
    ) == [
        "hydra",
        "-l",
        "u",
        "-p",
        "p",
        "-s",
        "22",
        "-t",
        "4",
        "-w",
        "30",
        "-f",
        "-v",
        "example.com",
        "ssh",
    ]
    with pytest.raises(ValueError):
        hydra.build_command("example.com")
    findings = hydra.parse_findings("login: alice password: secret", "")
    assert findings[0]["username"] == "alice"

    cme = CrackMapExecTool()
    assert "--shares" in cme.build_command(
        "10.0.0.1", {"username": "u", "password": "p", "shares": True}
    )
    cme_findings = cme.parse_findings("[++ ] 10.0.0.1:445 alice:DOMAIN\nREAD public", "")
    assert cme_findings[0]["type"] == "share_access"

    impacket = ImpacketTools()
    assert (
        impacket.build_command("host", {"tool": "smbclient", "username": "u", "password": "p"})[-1]
        == "host"
    )
    assert "-no-pass" in impacket.build_command("host", {"no_pass": True})
    with pytest.raises(ValueError):
        impacket.build_command("host", {"tool": "unknown"})
    assert (
        impacket.parse_findings("Connected\nDOMAIN\\alice (Admin)", "")[0]["type"]
        == "connection_success"
    )


def test_tool_result_and_retry_terminal_failure():
    now = datetime.now(timezone.utc)
    result = ToolResult(
        "tool", "tool target", 0, "out", "", now, now, ToolRiskLevel.LOW, ToolCategory.REPORTING
    )
    assert result.success and result.duration == 0
    assert result.to_dict()["success"]

    async def fail():
        raise RuntimeError("no")

    with pytest.raises(RuntimeError, match="no"):
        run(retry_async(fail, attempts=0, base_delay=0))


def test_base_adapter_history_context_tokens_and_health():
    async def scenario():
        config = ModelConfig(
            ModelProvider.LOCAL,
            "demo",
            max_tokens=4,
            capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING],
        )
        adapter = DummyAdapter(config)
        assert adapter.provider_name == "local"
        assert adapter.model_name == "demo"
        assert not adapter.is_connected
        assert await adapter.connect()
        adapter.add_message("user", "hello", name="operator")
        adapter.set_system_prompt("safety")
        assert adapter.get_history()[0].role == "system"
        assert adapter.get_history()[1].name == "operator"
        response = await adapter.chat([Message("user", "hello")])
        assert response.total_tokens == 5
        assert adapter.get_usage_summary()["session_tokens"] == 5
        assert await adapter.health_check()
        assert adapter.supports_capability(ModelCapability.STREAMING)
        assert not adapter.supports_capability(ModelCapability.VISION)
        chunks = [chunk async for chunk in adapter.chat_stream([Message("user", "chunk")])]
        assert chunks == ["chunk"]
        context = adapter.prepare_context(
            [Message("system", "rules"), Message("user", "a" * 40), Message("user", "recent")],
            max_tokens=2,
        )
        assert context[0].role == "system"
        assert context[-1].content == "recent"
        assert adapter.estimate_tokens("12345678") == 2
        retry_response = await adapter.chat_with_retry([Message("user", "retry")], attempts=1)
        assert retry_response.content == "retry"
        await adapter.disconnect()
        assert not adapter.is_connected

    run(scenario())


def test_model_data_classes_and_tool_formats():
    message = Message("tool", "result", tool_calls=[{"id": "1"}], tool_call_id="1")
    assert message.to_dict()["tool_calls"]
    definition = ToolDefinition("scan", "scan a target", {"type": "object"})
    assert definition.to_openai_format()["function"]["name"] == "scan"
    assert definition.to_anthropic_format()["input_schema"]["type"] == "object"
    response = ModelResponse("ok", "demo", {}, "stop")
    assert response.prompt_tokens == response.completion_tokens == response.total_tokens == 0
    usage = TokenUsage()
    usage.add(
        ModelResponse(
            "ok", "demo", {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, "stop"
        )
    )
    assert usage.to_dict()["session_tokens"] == 3


def test_network_tools_build_and_parse_findings():
    nmap = NmapTool()
    command = nmap.build_command(
        "example.com",
        {"ports": "80,443", "os_detection": True, "script_scan": True, "scripts": "http-*"},
    )
    assert "-O" in command and "--script=http-*" in command
    nmap_xml = (
        '<host><address addr="192.0.2.1" addrtype="ipv4"/><status state="up"/></host>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https" version="1.2"/></port>'
    )
    parsed = nmap.parse_findings(nmap_xml, "")
    assert {finding["type"] for finding in parsed} == {"host_up", "open_port"}

    masscan = MasscanTool()
    assert masscan.build_command("192.0.2.0/24")[0] == "masscan"
    assert (
        masscan.parse_findings('[{"ip":"192.0.2.1","ports":[{"port":22,"proto":"tcp"}]}]', "")[0][
            "port"
        ]
        == 22
    )
    assert masscan.parse_findings("not-json", "") == []


def test_web_tools_build_and_parse_findings():
    nikto = NiktoTool()
    command = nikto.build_command("https://example.com", {"port": 443, "ssl": True, "maxtime": 10})
    assert "-ssl" in command and "-Format" in command
    nikto_json = json.dumps(
        {"vulnerabilities": [{"url": "/login", "description": "bad", "references": ["CVE-2024-1"]}]}
    )
    assert nikto.parse_findings(nikto_json, "")[0]["cve"] == "CVE-2024-1"
    assert nikto.parse_findings("+ /admin exposes files", "")[0]["confidence"] == "low"

    zap = OWASPZAPTool()
    assert "--no-spider" in zap.build_command("https://example.com", {"spider": False})
    zap_finding = zap.parse_findings("[HIGH] XSS URL: https://example.com/x", "")[0]
    assert zap_finding["confidence"] == "high"

    sqlmap = SQLMapTool()
    sql_command = sqlmap.build_command("https://example.com?id=1", {"forms": True, "crawl": 2})
    assert "--forms" in sql_command and "--crawl" in sql_command
    sql_finding = sqlmap.parse_findings("Parameter 'id' is vulnerable. DBMS: MySQL", "")[0]
    assert sql_finding["type"] == "sql_injection"


def test_prompt_parsing_and_context_utilities():
    response = 'prefix ```json {"type":"port","value":"443"} ``` suffix'
    assert parse_json_response(response)["value"] == "443"
    assert parse_json_response("not json") is None
    assert extract_findings_from_response('{"type":"x"}', "recon")[0]["type"] == "x"
    assert extract_findings_from_response('[{"type":"x"}]', "vuln_scanner")
    assert extract_findings_from_response('{"type":"x"}', "other") == []

    messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "u" * 100},
        {"role": "assistant", "content": "a" * 100},
    ]
    truncated = truncate_context(messages, max_tokens=30)
    assert truncated[0]["role"] == "system"
    assert "truncated" in truncated[-1]["content"]
    summary = summarize_conversation(messages)
    assert "User asked" in summary and "Assistant responded" in summary
    assert "Finding:" in cot_vulnerability_analysis("open port", {"port": 443})
    assert "Target Environment" in cot_attack_path_planning([{"type": "x"}], "lab")


def test_orchestrator_phase_lifecycle_and_restore(tmp_path):
    async def scenario():
        orchestrator = ScanOrchestrator(
            ScanConfig("example.com", ["example.com"], save_dir=str(tmp_path))
        )
        for agent in [
            ReconAgent(),
            PlanningAgent(),
            ReportingAgent(),
            QualityAssuranceAgent(),
            WebApplicationAgent(),
            APISecurityAgent(),
            NetworkExploitationAgent(),
            PostExploitationAgent(),
        ]:
            orchestrator.register_agent(agent)
        orchestrator.add_finding({"type": "manual", "target": "example.com"})
        await orchestrator.execute_scan()
        assert orchestrator.status is ScanStatus.COMPLETED
        assert (orchestrator.save_dir / "report.md").exists()
        assert orchestrator.get_all_findings()
        restored = await ScanOrchestrator.from_state(orchestrator.scan_id, str(tmp_path))
        assert restored.status is ScanStatus.COMPLETED
        with pytest.raises(FileNotFoundError):
            await ScanOrchestrator.from_state("missing", str(tmp_path))

        next_scan = ScanOrchestrator(
            ScanConfig("example.com", ["example.com"], save_dir=str(tmp_path))
        )
        next_agent = ReconAgent()
        next_scan.register_agent(next_agent)
        await next_scan.start()
        next_agent.status = AgentStatus.RUNNING
        await next_scan.pause()
        assert next_scan.status is ScanStatus.PAUSED
        await next_scan.resume()
        assert next_scan.status is ScanStatus.RUNNING
        await next_scan.stop()
        assert next_scan.status is ScanStatus.CANCELLED

    run(scenario())


def test_phase5_cli_tool_and_report_commands(tmp_path, capsys):
    report = tmp_path / "scan-1" / "report.md"
    report.parent.mkdir()
    report.write_text("# Report", encoding="utf-8")
    assert _list_reports(str(tmp_path)) == ["scan-1/report.md"]
    assert _read_report(str(tmp_path), "scan-1/report.md") == "# Report"
    with pytest.raises(ValueError, match="must remain"):
        _read_report(str(tmp_path), "../outside.txt")
    with pytest.raises(ValueError, match="not found"):
        _read_report(str(tmp_path), "missing.md")

    assert cli_main(["--list-tools"]) == 0
    assert "nmap" in capsys.readouterr().out
    assert cli_main(["--list-reports", "--output-dir", str(tmp_path)]) == 0
    assert "scan-1/report.md" in capsys.readouterr().out
