"""Command-line entry point for a controlled, scope-bound scan workflow."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .core.orchestrator import ScanConfig, ScanOrchestrator
from .core.scope import ScopePolicy
from .agents.recon_agent import ReconAgent
from .agents.vuln_scanner_agent import VulnerabilityScannerAgent
from .tools import get_tool_by_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetworkForgeAI authorized security validation")
    parser.add_argument("--target", required=True, help="Authorized hostname, URL, IP, or CIDR member")
    parser.add_argument("--scope", action="append", required=True, help="Allowed target or CIDR; repeatable")
    parser.add_argument("--exclude", action="append", default=[], help="Excluded target; repeatable")
    parser.add_argument("--mode", choices=["strict", "moderate", "lenient"], default="strict")
    parser.add_argument("--tool", choices=["nmap", "masscan", "nikto", "owasp-zap"], help="Run one tool")
    parser.add_argument("--dry-run", action="store_true", help="Build commands without executing them")
    parser.add_argument("--output-dir", default="./scans")
    parser.add_argument("--orchestrate", action="store_true", help="Run the basic agent workflow")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = ScopePolicy(args.scope, args.exclude)
    if not policy.contains(args.target):
        raise SystemExit(f"Target is outside the explicitly supplied scope: {args.target}")

    if args.tool:
        tool = get_tool_by_name(args.tool, dry_run=args.dry_run, scope_policy=policy)
        result = tool.execute(args.target)
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0 if result.success else 1

    config = ScanConfig(target=args.target, scope=args.scope, excluded=args.exclude,
                        approval_mode=args.mode, save_dir=args.output_dir)
    orchestrator = ScanOrchestrator(config)
    orchestrator.register_agent(ReconAgent())
    orchestrator.register_agent(VulnerabilityScannerAgent())
    asyncio.run(_run(orchestrator, args.orchestrate))
    print(f"Scan {orchestrator.scan_id} completed: {orchestrator.save_dir}")
    return 0


async def _run(orchestrator: ScanOrchestrator, execute: bool) -> None:
    await orchestrator.start()
    if execute:
        await orchestrator.execute_scan()


if __name__ == "__main__":
    raise SystemExit(main())

