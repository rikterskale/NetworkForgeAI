"""Command-line entry point for a controlled, scope-bound scan workflow."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from . import __version__
from .agents.recon_agent import ReconAgent
from .agents.specialized import PlanningAgent, QualityAssuranceAgent
from .agents.vuln_scanner_agent import VulnerabilityScannerAgent
from .core.orchestrator import ScanConfig, ScanOrchestrator
from .core.scope import ScopePolicy
from .tools import get_available_tools, get_tool_by_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetworkForgeAI authorized security validation")
    parser.add_argument("--target", help="Authorized hostname, URL, IP, or CIDR member")
    parser.add_argument(
        "--scope", action="append", default=[], help="Allowed target or CIDR; repeatable"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="Excluded target; repeatable"
    )
    parser.add_argument("--mode", choices=["strict", "moderate", "lenient"], default="strict")
    parser.add_argument(
        "--tool", choices=["nmap", "masscan", "nikto", "owasp-zap"], help="Run one tool"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Build commands without executing them"
    )
    parser.add_argument(
        "--host-execution",
        action="store_true",
        help="Explicitly disable Docker sandboxing (authorized development use only)",
    )
    parser.add_argument("--output-dir", default="./scans")
    parser.add_argument("--orchestrate", action="store_true", help="Run the basic agent workflow")
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "google", "local", "litellm"],
        help="Optional LLM provider configured through environment variables",
    )
    parser.add_argument(
        "--list-tools", action="store_true", help="List available tool integrations"
    )
    parser.add_argument(
        "--list-reports", action="store_true", help="List reports under --output-dir"
    )
    parser.add_argument("--show-report", metavar="PATH", help="Print a report under --output-dir")
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate environment configuration and safety defaults",
    )
    parser.add_argument("--version", action="version", version=f"NetworkForgeAI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_tools:
        for name, tool_class in get_available_tools().items():
            print(f"{name}\t{tool_class.risk_level.value}\t{tool_class.category.value}")
        return 0
    if args.list_reports:
        for path in _list_reports(args.output_dir):
            print(path)
        return 0
    if args.show_report:
        try:
            print(_read_report(args.output_dir, args.show_report))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        return 0
    if args.validate_config:
        from .config import Settings

        settings = Settings()
        settings.validate_security_config()
        print("Configuration is valid for authorized scanning.")
        return 0
    if not args.target or not args.scope:
        raise SystemExit("--target and --scope are required for scan operations")
    policy = ScopePolicy(args.scope, args.exclude)
    if not policy.contains(args.target):
        raise SystemExit(f"Target is outside the explicitly supplied scope: {args.target}")

    if args.tool:
        tool = get_tool_by_name(
            args.tool,
            dry_run=args.dry_run,
            sandbox_mode=not args.host_execution,
            scope_policy=policy,
        )
        result = tool.execute(args.target)
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0 if result.success else 1

    config = ScanConfig(
        target=args.target,
        scope=args.scope,
        excluded=args.exclude,
        approval_mode=args.mode,
        save_dir=args.output_dir,
    )
    orchestrator = ScanOrchestrator(config)
    model_adapter = None
    if args.provider:
        from .models.model_factory import ModelFactory

        model_adapter = ModelFactory.create_from_env(override_provider=args.provider)
    orchestrator.register_agent(ReconAgent(model_adapter=model_adapter))
    orchestrator.register_agent(VulnerabilityScannerAgent(model_adapter=model_adapter))
    orchestrator.register_agent(PlanningAgent())
    orchestrator.register_agent(QualityAssuranceAgent())
    asyncio.run(_run(orchestrator, args.orchestrate))
    print(f"Scan {orchestrator.scan_id} completed: {orchestrator.save_dir}")
    return 0


def _list_reports(output_dir: str) -> list[str]:
    """Return stable, relative report paths without exposing directory details."""
    root = Path(output_dir).resolve()
    if not root.exists():
        return []
    return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())


def _read_report(output_dir: str, report_path: str) -> str:
    """Read a report only when it remains inside the configured report directory."""
    root = Path(output_dir).resolve()
    requested = (root / report_path).resolve()
    if requested != root and root not in requested.parents:
        raise ValueError("Report path must remain under --output-dir")
    if not requested.is_file():
        raise ValueError(f"Report not found: {report_path}")
    return requested.read_text(encoding="utf-8")


async def _run(orchestrator: ScanOrchestrator, execute: bool) -> None:
    from .interface.cli_ui import ApprovalPrompt, StatusDisplay

    prompt = ApprovalPrompt(orchestrator.approval_gateway)
    orchestrator.approval_gateway.register_callback("cli_prompt", prompt)
    display = StatusDisplay()
    await orchestrator.start()
    if not execute:
        return
    scan_task = asyncio.create_task(orchestrator.execute_scan())
    try:
        while not scan_task.done():
            for agent_id, agent in orchestrator.agents.items():
                display.update(agent_id, agent.status.value)
            await asyncio.sleep(0.25)
        await scan_task
    finally:
        for agent_id, agent in orchestrator.agents.items():
            display.update(agent_id, agent.status.value)
        print(display.render())


if __name__ == "__main__":
    raise SystemExit(main())
