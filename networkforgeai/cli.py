"""Command-line entry point for a controlled, scope-bound scan workflow."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from . import __version__
from .agents.recon_agent import ReconAgent
from .agents.specialized import (
    APISecurityAgent,
    NetworkExploitationAgent,
    PlanningAgent,
    PostExploitationAgent,
    QualityAssuranceAgent,
    WebApplicationAgent,
)
from .agents.vuln_scanner_agent import VulnerabilityScannerAgent
from .core.approval_gateway import ApprovalStatus, RiskLevel, action_requires_approval
from .core.orchestrator import ScanConfig, ScanOrchestrator
from .core.scope import ScopePolicy
from .tools import get_available_tools, get_tool_by_name
from .tools.preflight import preflight_tool


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _fallback_report_formats() -> list[str]:
    try:
        value = json.loads(os.getenv("REPORT_FORMATS", '["markdown", "json", "csv", "sarif"]'))
        return [str(item).lower() for item in value if isinstance(item, str)]
    except (TypeError, ValueError, json.JSONDecodeError):
        return ["markdown", "json", "csv", "sarif"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetworkForgeAI authorized security validation")
    parser.add_argument("--target", help="Authorized hostname, URL, IP, or CIDR member")
    parser.add_argument(
        "--scope", action="append", default=None, help="Allowed target or CIDR; repeatable"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="Excluded target; repeatable"
    )
    parser.add_argument("--mode", choices=["strict", "moderate", "lenient"], default=None)
    parser.add_argument(
        "--tool",
        choices=sorted(get_available_tools()),
        metavar="TOOL",
        help="Run one tool (see --list-tools for the full set)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Build commands without executing them"
    )
    parser.add_argument(
        "--host-execution",
        action="store_true",
        help="Explicitly disable Docker sandboxing (authorized development use only)",
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--orchestrate", action="store_true", help="Run the basic agent workflow")
    parser.add_argument(
        "--profile",
        choices=["recon", "appsec", "full"],
        default="recon",
        help=(
            "Agent depth: 'recon' (recon+vuln+planning+QA), 'appsec' (adds web+API "
            "testing), 'full' (adds exploitation+post-exploitation, always approval-gated)"
        ),
    )
    parser.add_argument(
        "--exploit-plan",
        metavar="PATH",
        help=(
            "JSON file with an explicit exploit plan for the 'full' profile: a list of "
            '{"target","module","payload","set_options","justification"} entries. Every '
            "entry still requires explicit human approval before execution."
        ),
    )
    parser.add_argument(
        "--justification",
        help="Written justification required by configured policy for critical actions",
    )
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
    parser.add_argument(
        "--diagnose-config",
        action="store_true",
        help="Print structured, secret-safe configuration diagnostics",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Check selected tool, sandbox, scope, and output prerequisites without scanning",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help=(
            "Run comprehensive readiness diagnostics (Python, package, Docker daemon, "
            "sandbox image, disk, memory, report dir, provider SDKs, runtime configuration)"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="With --doctor, emit structured JSON instead of human-readable text",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "With --doctor, treat 'skipped' and 'unverified' checks as failure "
            "(recommended for CI readiness gates)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"NetworkForgeAI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    from .observability import configure_logging

    configure_logging()
    args = build_parser().parse_args(argv)
    if args.list_tools:
        for name, tool_class in get_available_tools().items():
            print(f"{name}\t{tool_class.risk_level.value}\t{tool_class.category.value}")
        return 0
    if args.doctor:
        return _run_doctor(args)
    try:
        from .config import Settings

        runtime_settings = Settings()
    except ModuleNotFoundError as exc:
        if args.validate_config or args.diagnose_config:
            raise SystemExit("Configuration commands require the runtime dependencies") from exc
        runtime_settings = None
    if runtime_settings is not None:
        configure_logging(
            runtime_settings.log_level,
            log_format=runtime_settings.log_format,
            force=True,
        )
    output_dir = (
        runtime_settings.resolve_output_dir(args.output_dir)
        if runtime_settings is not None
        else args.output_dir or os.getenv("REPORT_OUTPUT_DIR") or "./reports"
    )
    if args.list_reports:
        for path in _list_reports(output_dir):
            print(path)
        return 0
    if args.show_report:
        try:
            print(_read_report(output_dir, args.show_report))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        return 0
    if args.validate_config:
        assert runtime_settings is not None
        runtime_settings.validate_runtime()
        print("Configuration is valid for authorized scanning.")
        return 0
    if args.diagnose_config:
        try:
            assert runtime_settings is not None
            diagnostics = runtime_settings.diagnostics()
            print(
                json.dumps(
                    {"ok": all(item["ok"] for item in diagnostics), "checks": diagnostics}, indent=2
                )
            )
            return 0 if all(item["ok"] for item in diagnostics) else 2
        except Exception as exc:
            print(json.dumps({"ok": False, "checks": [], "error": str(exc)}, indent=2))
            return 2
    if args.preflight and not args.target:
        raise SystemExit("--preflight requires --target and --scope")
    scope = (
        runtime_settings.resolve_scope(args.scope)
        if runtime_settings is not None
        else list(args.scope or filter(None, os.getenv("TARGET_SCOPE", "").split(",")))
    )
    if not args.target or not scope:
        raise SystemExit("--target and --scope are required for scan operations")
    policy = ScopePolicy(scope, args.exclude)
    if not policy.contains(args.target):
        raise SystemExit(f"Target is outside the explicitly supplied scope: {args.target}")

    if args.preflight:
        names = [args.tool] if args.tool else list(get_available_tools())
        checks = []
        for name in names:
            tool = get_tool_by_name(
                name,
                dry_run=args.dry_run,
                sandbox_mode=not args.host_execution,
                scope_policy=policy,
            )
            checks.append(preflight_tool(tool, args.target))
        print(json.dumps({"ok": all(item["ok"] for item in checks), "checks": checks}, indent=2))
        return 0 if all(item["ok"] for item in checks) else 2

    if args.tool:
        gateway = None
        if not args.dry_run:
            from .core.approval_gateway import ApprovalGateway

            gateway = ApprovalGateway(
                mode=(
                    runtime_settings.resolve_approval_mode(args.mode)
                    if runtime_settings is not None
                    else args.mode or os.getenv("APPROVAL_MODE", "strict")
                ),
                audit_log_path=Path(output_dir) / "approval_audit.jsonl",
                audit_enabled=(
                    runtime_settings.audit_all_approvals
                    if runtime_settings
                    else _env_bool("AUDIT_ALL_APPROVALS", True)
                ),
                block_destructive_actions=(
                    runtime_settings.block_destructive_actions
                    if runtime_settings
                    else _env_bool("BLOCK_DESTRUCTIVE_ACTIONS", True)
                ),
                require_justification_for_exploitation=(
                    runtime_settings.require_justification_for_exploitation
                    if runtime_settings
                    else _env_bool("REQUIRE_JUSTIFICATION_FOR_EXPLOITATION", True)
                ),
                ci_mode=runtime_settings.ci_mode
                if runtime_settings is not None
                else _env_bool("CI_MODE", False),
            )
            if runtime_settings is not None and runtime_settings.ci_mode:
                gateway.mode = "strict"
        tool = get_tool_by_name(
            args.tool,
            dry_run=args.dry_run,
            sandbox_mode=not args.host_execution,
            scope_policy=policy,
            approval_gateway=gateway,
        )
        result = asyncio.run(_execute_single_tool(tool, args.target, gateway, args.justification))
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0 if result.success else 1

    config = ScanConfig(
        target=args.target,
        scope=scope,
        excluded=args.exclude,
        approval_mode=(
            runtime_settings.resolve_approval_mode(args.mode)
            if runtime_settings is not None
            else args.mode or os.getenv("APPROVAL_MODE", "strict")
        ),
        max_agents=(
            runtime_settings.max_concurrent_agents
            if runtime_settings
            else int(os.getenv("MAX_CONCURRENT_AGENTS", "5"))
        ),
        save_dir=output_dir,
        report_formats=(
            [item.value for item in runtime_settings.report_formats]
            if runtime_settings is not None
            else _fallback_report_formats()
        ),
        audit_all_approvals=(
            runtime_settings.audit_all_approvals
            if runtime_settings
            else _env_bool("AUDIT_ALL_APPROVALS", True)
        ),
        block_destructive_actions=(
            runtime_settings.block_destructive_actions
            if runtime_settings
            else _env_bool("BLOCK_DESTRUCTIVE_ACTIONS", True)
        ),
        require_justification_for_exploitation=(
            runtime_settings.require_justification_for_exploitation
            if runtime_settings
            else _env_bool("REQUIRE_JUSTIFICATION_FOR_EXPLOITATION", True)
        ),
        timeout_hours=(
            runtime_settings.resolve_timeout_hours()
            if runtime_settings is not None
            else max(1, (int(os.getenv("SESSION_TIMEOUT_MINUTES", "60")) + 59) // 60)
        ),
        ci_mode=runtime_settings.ci_mode
        if runtime_settings is not None
        else _env_bool("CI_MODE", False),
        log_level=runtime_settings.log_level
        if runtime_settings is not None
        else os.getenv("LOG_LEVEL", "INFO"),
        log_format=runtime_settings.log_format
        if runtime_settings is not None
        else os.getenv("LOG_FORMAT", "text"),
    )
    orchestrator = ScanOrchestrator(config)
    model_adapter = None
    if args.provider:
        from .models.model_factory import ModelFactory

        model_adapter = ModelFactory.create_from_env(override_provider=args.provider)
    tool_registry = _build_tool_registry(policy, orchestrator, args)
    orchestrator.register_agent(
        ReconAgent(model_adapter=model_adapter, tool_registry=tool_registry)
    )
    orchestrator.register_agent(
        VulnerabilityScannerAgent(model_adapter=model_adapter, tool_registry=tool_registry)
    )
    orchestrator.register_agent(PlanningAgent())
    orchestrator.register_agent(QualityAssuranceAgent())

    if args.profile in {"appsec", "full"}:
        orchestrator.register_agent(
            WebApplicationAgent(model_adapter=model_adapter, tool_registry=tool_registry)
        )
        orchestrator.register_agent(
            APISecurityAgent(model_adapter=model_adapter, tool_registry=tool_registry)
        )
    if args.profile == "full":
        orchestrator.register_agent(
            NetworkExploitationAgent(model_adapter=model_adapter, tool_registry=tool_registry)
        )
        orchestrator.register_agent(
            PostExploitationAgent(model_adapter=model_adapter, tool_registry=tool_registry)
        )
        exploit_plan = _load_exploit_plan(args.exploit_plan)
        if exploit_plan is not None:
            orchestrator.shared_context["exploit_plan"] = exploit_plan

    asyncio.run(_run(orchestrator, args.orchestrate))
    print(f"Scan {orchestrator.scan_id} completed: {orchestrator.save_dir}")
    return 0


def _build_tool_registry(
    policy: ScopePolicy, orchestrator: ScanOrchestrator, args: argparse.Namespace
) -> dict[str, Any]:
    """Instantiate real tool wrappers whose binaries are available.

    In ``--dry-run`` mode all wrappers are registered (execution is short-circuited
    before the binary is invoked). Otherwise only tools whose binary is present on
    ``PATH`` are registered, so agents fall back to an honest "tool unavailable"
    status instead of failing or fabricating output.
    """
    import shutil

    registry: dict[str, Any] = {}
    for name, tool_class in get_available_tools().items():
        binary = tool_class.name
        if not args.dry_run and shutil.which(binary) is None:
            continue
        registry[name] = get_tool_by_name(
            name,
            dry_run=args.dry_run,
            sandbox_mode=not args.host_execution,
            scope_policy=policy,
            approval_gateway=orchestrator.approval_gateway,
        )
    return registry


def _load_exploit_plan(path: str | None) -> list[dict[str, Any]] | None:
    """Load and validate an operator-supplied exploit plan (JSON list of entries)."""
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(
        isinstance(entry, dict) and entry.get("module") for entry in data
    ):
        raise SystemExit("--exploit-plan must be a JSON list of objects each with a 'module'")
    return data


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


async def _execute_single_tool(
    tool: Any, target: str, gateway: Any, justification: str | None = None
) -> Any:
    """Run a single tool with the same approval policy as agent execution."""
    if tool.dry_run:
        return tool.execute(target)
    preflight = preflight_tool(tool, target)
    if not preflight["ok"]:
        raise RuntimeError(f"Tool preflight failed: {json.dumps(preflight, sort_keys=True)}")
    if gateway is not None:
        from .interface.cli_ui import ApprovalPrompt

        gateway.register_callback(
            "cli_prompt",
            ApprovalPrompt(gateway, interactive=not getattr(gateway, "ci_mode", False)),
        )
    requires_approval = action_requires_approval(
        tool.risk_level,
        tool.category.value,
        passive=getattr(tool, "passive", False),
        dry_run=tool.dry_run,
    )
    details = {"category": tool.category.value}
    if justification:
        details["justification"] = justification
    if gateway is not None and requires_approval and not tool._approval_required():
        request = await gateway.request_approval(
            agent_id=f"tool:{tool.name}",
            action_type=tool.name,
            description=f"Execute {tool.name} against {target}",
            target=target,
            risk_level=RiskLevel(tool.risk_level.value),
            details=details,
            timeout_seconds=300,
        )
        decision = await gateway.wait_for_approval(request.id)
        if decision.status is not ApprovalStatus.APPROVED:
            raise PermissionError(
                f"{tool.name} execution was not approved: {decision.status.value}"
            )
    return await tool.execute_async(target, approval_details=details if gateway else None)


async def _run(orchestrator: ScanOrchestrator, execute: bool) -> None:
    from .interface.cli_ui import ApprovalPrompt, StatusDisplay

    prompt = ApprovalPrompt(
        orchestrator.approval_gateway,
        interactive=not orchestrator.config.ci_mode,
    )
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


def _run_doctor(args: argparse.Namespace) -> int:
    """Handle ``networkforgeai --doctor``.

    Runs before ``Settings()`` is loaded so a broken configuration
    still surfaces as a diagnosed failure rather than an unhandled
    exception.
    """

    from .doctor import Doctor

    report_directory = args.output_dir or os.getenv("REPORT_OUTPUT_DIR") or "./reports"
    doctor = Doctor(strict=args.strict)
    doctor.run(report_directory=report_directory)
    if args.json:
        print(json.dumps(doctor.as_dict(), indent=2))
    else:
        print(doctor.as_text())
    return 0 if doctor.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
