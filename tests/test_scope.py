from networkforgeai.core.scope import ScopePolicy
from networkforgeai.core.message_bus import AgentMessage, MessageBus
from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalStatus, RiskLevel
import asyncio


def test_scope_accepts_cidr_member_and_rejects_external_ip():
    policy = ScopePolicy(["192.168.10.0/24"])
    assert policy.contains("192.168.10.42")
    assert not policy.contains("192.168.11.42")


def test_scope_accepts_subdomains_and_exclusions():
    policy = ScopePolicy(["example.com"], ["admin.example.com"])
    assert policy.contains("https://www.example.com/login")
    assert not policy.contains("admin.example.com")


def test_empty_scope_denies_by_default():
    assert not ScopePolicy([]).contains("example.com")


def test_message_bus_delivers_between_agents():
    async def scenario():
        bus = MessageBus()
        await bus.register("receiver")
        assert await bus.send(AgentMessage("sender", "receiver", {"ok": True}))
        message = await bus.receive("receiver")
        assert message.payload == {"ok": True}
    asyncio.run(scenario())


def test_emergency_stop_cancels_approval_requests():
    async def scenario():
        gateway = ApprovalGateway()
        request = await gateway.request_approval("agent", "test", "test", "example.com", RiskLevel.HIGH)
        await gateway.emergency_stop("test")
        result = await gateway.wait_for_approval(request.id)
        assert result.status == ApprovalStatus.CANCELLED
    asyncio.run(scenario())
