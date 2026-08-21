import asyncio

from networkforgeai.core.orchestrator import ScanConfig, ScanOrchestrator
from networkforgeai.core.task_queue import AgentTask, TaskQueue, TaskStatus
from networkforgeai.models.retry import retry_async


def test_task_queue_tracks_completion():
    async def scenario():
        queue = TaskQueue()
        task = AgentTask("reconnaissance", "reconnaissance")
        await queue.put(task)
        received = await queue.get()
        queue.complete(received)
        assert queue.snapshot()[0]["status"] == TaskStatus.COMPLETED.value

    asyncio.run(scenario())


def test_retry_retries_then_succeeds():
    attempts = 0

    async def operation():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("transient")
        return "ok"

    assert asyncio.run(retry_async(operation, attempts=3, base_delay=0)) == "ok"
    assert attempts == 3


def test_orchestrator_persists_agent_and_task_state():
    async def scenario():
        import tempfile

        from networkforgeai.agents import ReconAgent

        with tempfile.TemporaryDirectory() as directory:
            orchestrator = ScanOrchestrator(
                ScanConfig("example.com", ["example.com"], save_dir=directory)
            )
            orchestrator.register_agent(ReconAgent())
            await orchestrator.start()
            await orchestrator.execute_scan()
            state = (orchestrator.save_dir / "scan_state.json").read_text()
            assert "agent_states" in state
            assert "task_queue" in state

    asyncio.run(scenario())
