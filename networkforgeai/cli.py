"""Command-line entry point for a controlled, scope-bound scan workflow."""

from __future__ import annotations

import argparse
import asyncio
import json

from .agents.recon_agent import ReconAgent
from .agents.vuln_scanner_agent import VulnerabilityScannerAgent
from .core.orchestrator import ScanConfig, ScanOrchestrator
from .core.scope import ScopePolicy
from .tools import get_tool_by_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetworkForgeAI authorized security validation")
    parser.add_argument(
        "--target", required=True, help="Authorized hostname, URL, IP, or CIDR member"
    )
    parser.add_argument(
        "--scope", action="append", required=True, help="Allowed target or CIDR; repeatable"
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
    asyncio.run(_run(orchestrator, args.orchestrate))
    print(f"Scan {orchestrator.scan_id} completed: {orchestrator.save_dir}")
    return 0


async def _run(orchestrator: ScanOrchestrator, execute: bool) -> None:
    await orchestrator.start()
    if execute:
        await orchestrator.execute_scan()


if __name__ == "__main__":
    raise SystemExit(main())
