"""Specialized agents: planning, reporting, QA, web, API, exploitation, post-ex.

Every agent here obeys two invariants:

* **Honest output.** Findings are produced only from real tool output or are
  explicitly tagged advisory (``source="llm_hypothesis"``/``validated=False``).
  When a required tool or model is absent, the agent records a ``*_status`` note
  and returns no findings instead of fabricating data.
* **Human-in-the-loop.** Active scanning, exploitation, and post-exploitation
  pass through the approval gateway. High/critical tools self-gate inside the
  wrapper; medium-risk active scans are gated at the agent boundary. Nothing
  destructive runs without an explicit approval.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core import mitre
from ..core.approval_gateway import RiskLevel, action_requires_approval
from ..core.base_agent import AgentStatus, BaseAgent
from ..core.enrichment import enrich_findings


class ContextAgent(BaseAgent):
    capability = "context_analysis"

    def get_capabilities(self) -> List[str]:
        return [self.capability]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _canonical_finding(
    raw: Dict[str, Any],
    *,
    default_target: str,
    source: str,
    default_type: str,
    default_severity: str = "informational",
) -> Dict[str, Any]:
    """Normalize a heterogeneous tool finding into a canonical finding dict.

    Preserves any CWE/OWASP/severity the tool already supplied and attaches a
    single evidence item so the downstream validation engine can score it.
    """
    ftype = str(raw.get("type") or default_type)
    target = str(raw.get("url") or raw.get("target") or default_target)
    title = str(raw.get("title") or raw.get("summary") or ftype.replace("_", " ").title())
    severity = str(raw.get("severity") or raw.get("risk_level") or default_severity)
    description = str(raw.get("description") or raw.get("summary") or "")
    evidence_text = description or title
    finding: Dict[str, Any] = {
        "type": ftype,
        "target": target or default_target,
        "title": title,
        "severity": severity,
        "description": description,
        "confidence": raw.get("confidence", "medium"),
        "source": source,
        "evidence": [{"kind": "tool_output", "content": evidence_text, "source": source}],
    }
    if raw.get("cwe"):
        finding["cwe"] = raw["cwe"]
    if raw.get("owasp"):
        finding["owasp"] = raw["owasp"]
    if raw.get("cve"):
        finding.setdefault("references", []).append(str(raw["cve"]))
    finding["metadata"] = {"raw": raw}
    return finding


async def _run_gated_scan(
    agent: BaseAgent,
    tool_name: str,
    target: str,
    *,
    action_type: str,
    description: str,
    risk_level: RiskLevel,
    options: Optional[Dict[str, Any]] = None,
    approval_details: Optional[Dict[str, Any]] = None,
) -> tuple[Any, str]:
    """Run a registered tool with exactly one approval gate.

    High/critical wrappers self-gate inside ``execute_async``; lower-risk active
    scans are gated here at the agent boundary. A dry-run tool previews the
    command only and needs no approval. Returns ``(tool_result | None, status)``.
    """
    tool = agent.tool_registry.get(tool_name)
    if tool is None:
        return None, "tool_unavailable"
    is_dry = getattr(tool, "dry_run", False)
    self_gates = bool(getattr(tool, "_approval_required", lambda: False)())

    requires_policy_approval = action_requires_approval(
        getattr(tool, "risk_level", risk_level),
        getattr(getattr(tool, "category", None), "value", action_type),
        passive=getattr(tool, "passive", False),
        dry_run=is_dry,
    )
    if requires_policy_approval and not is_dry and not self_gates:
        approved, _ = await agent.request_approval(
            action_type=action_type,
            description=description,
            target=target,
            risk_level=risk_level,
            details={"tool": tool_name, **(approval_details or {})},
            timeout_seconds=600,
        )
        if not approved:
            return None, "rejected"

    try:
        result = await agent.run_tool(
            tool_name, target, options=options, approval_details=approval_details
        )
    except PermissionError:
        return None, "rejected"
    if result is None:
        return None, "tool_unavailable"
    if not result.success:
        return result, "scan_failed"
    return result, "completed"


# ---------------------------------------------------------------------------
# Planning & correlation
# ---------------------------------------------------------------------------


class PlanningAgent(ContextAgent):
    """Correlate findings into scored attack paths using the enrichment engine."""

    capability = "attack_path_planning"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        raw = context.get("findings") or context.get("vulnerabilities") or []
        targets = context.get("targets") or ([context["target"]] if context.get("target") else None)
        # Conservative by default: only escalate for internet exposure when the
        # operator explicitly marks the scope internet-facing (avoids inflating
        # benign informational findings such as DNS resolution).
        internet_facing = bool(context.get("internet_facing", False))
        criticality = str(context.get("asset_criticality", "medium"))

        result = enrich_findings(
            raw,
            targets=targets,
            asset_criticality=criticality,
            internet_facing=internet_facing,
        )
        self.status = AgentStatus.COMPLETED
        return {
            "task": task,
            "findings": [],
            "context_updates": result.to_context_updates(),
        }


class ReportingAgent(ContextAgent):
    capability = "reporting"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        findings = list(context.get("enriched_findings") or context.get("findings") or [])
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": findings, "context_updates": {"report_ready": True}}


class QualityAssuranceAgent(ContextAgent):
    capability = "quality_assurance"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in context.get("findings", []):
            key = (str(finding.get("type", "")), str(finding.get("target", "")))
            unique.setdefault(key, finding)
        self.status = AgentStatus.COMPLETED
        return {
            "task": task,
            "findings": list(unique.values()),
            "context_updates": {"deduplicated_findings": list(unique.values())},
        }


# ---------------------------------------------------------------------------
# Web application testing
# ---------------------------------------------------------------------------


class WebApplicationAgent(ContextAgent):
    """Drive real web scanners for OWASP Top 10 surface; advise when absent."""

    capability = "web_application_testing"

    #: Web scanner wrappers this agent orchestrates, in execution order.
    _WEB_TOOLS = ("nikto", "owasp-zap")

    def _target_urls(self, context: Dict[str, Any]) -> List[str]:
        urls = context.get("discovered_urls") or []
        if urls:
            return list(urls)
        target = context.get("target")
        return [f"http://{target}/"] if target else []

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        results: Dict[str, Any] = {"task": task, "findings": [], "context_updates": {}}
        urls = self._target_urls(context)
        if not urls:
            results["context_updates"]["web_testing_status"] = "no_target"
            self.status = AgentStatus.COMPLETED
            return results

        available = [name for name in self._WEB_TOOLS if self.has_tool(name)]
        if not available:
            hypotheses = await self.llm_hypotheses(
                "Given the reconnaissance evidence, list plausible OWASP Top 10 web "
                "weaknesses to validate manually. Do not claim confirmation.",
                context,
            )
            results["findings"].extend(hypotheses)
            for item in hypotheses:
                self.add_finding(item)
            results["context_updates"]["web_testing_status"] = (
                "hypotheses_only" if hypotheses else "no_tool_or_model"
            )
            self.status = AgentStatus.COMPLETED
            return results

        target_url = urls[0]
        emitted = 0
        tool_statuses: Dict[str, str] = {}
        for tool_name in available:
            tool_result, status = await _run_gated_scan(
                self,
                tool_name,
                target_url,
                action_type="web_scan",
                description=f"Active web scan of {target_url} with {tool_name}",
                risk_level=RiskLevel.MEDIUM,
            )
            tool_statuses[tool_name] = status
            if tool_result is None or status != "completed":
                continue
            for parsed in tool_result.findings:
                finding = _canonical_finding(
                    parsed,
                    default_target=target_url,
                    source=f"tool:{tool_name}",
                    default_type="web_vulnerability",
                    default_severity="medium",
                )
                self.add_finding(finding)
                results["findings"].append(finding)
                emitted += 1

        results["context_updates"]["web_tool_status"] = tool_statuses
        results["context_updates"]["web_testing_status"] = "completed" if emitted else "no_findings"
        results["context_updates"]["web_targets_reviewed"] = urls
        self.status = AgentStatus.COMPLETED
        return results


# ---------------------------------------------------------------------------
# API security testing
# ---------------------------------------------------------------------------


class APISecurityAgent(ContextAgent):
    """Test API surfaces (GraphQL, JWT) with real probes; advise on auth/authz."""

    capability = "api_security_testing"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        results: Dict[str, Any] = {"task": task, "findings": [], "context_updates": {}}
        emitted = 0
        statuses: Dict[str, str] = {}

        # GraphQL endpoint probing (real, stdlib probe wrapper).
        graphql_endpoint = context.get("graphql_endpoint")
        if graphql_endpoint and self.has_tool("graphql-probe"):
            tool_result, status = await _run_gated_scan(
                self,
                "graphql-probe",
                str(graphql_endpoint),
                action_type="graphql_probe",
                description=f"Probe GraphQL endpoint {graphql_endpoint} for misconfigurations",
                risk_level=RiskLevel.MEDIUM,
            )
            statuses["graphql"] = status
            if tool_result is not None and status == "completed":
                for parsed in tool_result.findings:
                    finding = _canonical_finding(
                        parsed,
                        default_target=str(graphql_endpoint),
                        source="tool:graphql-probe",
                        default_type="security_misconfiguration",
                        default_severity="low",
                    )
                    self.add_finding(finding)
                    results["findings"].append(finding)
                    emitted += 1

        # JWT static analysis (low risk, no active request).
        token = context.get("jwt_token")
        if token and self.has_tool("jwt-analyzer"):
            tool_result, status = await _run_gated_scan(
                self,
                "jwt-analyzer",
                str(token),
                action_type="jwt_analysis",
                description="Analyze a captured JWT for algorithm/kid/expiry weaknesses",
                risk_level=RiskLevel.LOW,
            )
            statuses["jwt"] = status
            if tool_result is not None and status == "completed":
                for parsed in tool_result.findings:
                    finding = _canonical_finding(
                        parsed,
                        default_target=context.get("target", "jwt"),
                        source="tool:jwt-analyzer",
                        default_type="auth_bypass",
                        default_severity="medium",
                    )
                    self.add_finding(finding)
                    results["findings"].append(finding)
                    emitted += 1

        # Access-control (BOLA/BFLA) reasoning is advisory only.
        if context.get("api_endpoints"):
            hypotheses = await self.llm_hypotheses(
                "Given the API endpoints and any auth evidence, list plausible broken "
                "object/function level authorization (BOLA/BFLA) hypotheses to validate "
                "manually. Do not claim confirmation.",
                context,
            )
            results["findings"].extend(hypotheses)
            for item in hypotheses:
                self.add_finding(item)
            if hypotheses:
                statuses["access_control"] = "hypotheses_only"

        results["context_updates"]["api_tool_status"] = statuses
        results["context_updates"]["api_testing_status"] = (
            "completed" if emitted or statuses else "no_api_surface"
        )
        self.status = AgentStatus.COMPLETED
        return results


# ---------------------------------------------------------------------------
# Exploitation (full exploit, always human-approved)
# ---------------------------------------------------------------------------


class NetworkExploitationAgent(ContextAgent):
    """Run real exploits — but only through the CRITICAL approval gate.

    Exploit candidates are never auto-selected from a guess. The operator (or an
    upstream planning step) supplies an explicit ``exploit_plan`` of
    ``{target, module, payload?, set_options?, justification?}`` entries. Each
    entry is executed via the Metasploit wrapper, which self-gates as CRITICAL:
    no module runs without an explicit human approval carrying justification.
    """

    capability = "exploitation"

    def _candidates(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        plan = context.get("exploit_plan")
        if isinstance(plan, list):
            return [entry for entry in plan if isinstance(entry, dict) and entry.get("module")]
        return []

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        results: Dict[str, Any] = {"task": task, "findings": [], "context_updates": {}}

        if not self.has_tool("metasploit"):
            results["context_updates"]["exploitation_status"] = "no_exploit_tool_registered"
            self.status = AgentStatus.COMPLETED
            return results

        candidates = self._candidates(context)
        if not candidates:
            results["context_updates"]["exploitation_status"] = "no_exploit_module_specified"
            self.status = AgentStatus.COMPLETED
            return results

        statuses: List[Dict[str, Any]] = []
        emitted = 0
        for entry in candidates:
            target = str(entry.get("target") or context.get("target", ""))
            module = str(entry["module"])
            justification = str(entry.get("justification") or "").strip()
            if not justification:
                statuses.append(
                    {
                        "target": target,
                        "module": module,
                        "status": "rejected",
                        "reason": "missing_justification",
                    }
                )
                continue
            options = {
                "module": module,
                "payload": entry.get("payload"),
                "set_options": entry.get("set_options") or {},
                "check_only": bool(entry.get("check_only", False)),
            }
            try:
                tool_result = await self.run_tool(
                    "metasploit",
                    target,
                    options=options,
                    approval_details={
                        "framework": "metasploit",
                        "module": module,
                        "payload": entry.get("payload"),
                        "justification": justification,
                        "destructive": not bool(entry.get("check_only", False)),
                    },
                )
            except PermissionError:
                statuses.append({"target": target, "module": module, "status": "rejected"})
                continue
            if tool_result is None:
                statuses.append({"target": target, "module": module, "status": "tool_unavailable"})
                continue
            if not tool_result.success:
                statuses.append({"target": target, "module": module, "status": "exploit_failed"})
                continue

            module_emitted = 0
            for parsed in tool_result.findings:
                finding = self._exploit_finding(target, module, justification, parsed)
                if finding is None:
                    continue
                self.add_finding(finding)
                results["findings"].append(finding)
                emitted += 1
                module_emitted += 1
            statuses.append(
                {
                    "target": target,
                    "module": module,
                    "status": "exploited" if module_emitted else "no_result",
                }
            )

        results["context_updates"]["exploitation_status"] = "completed" if emitted else "no_result"
        results["context_updates"]["exploitation_attempts"] = statuses
        self.status = AgentStatus.COMPLETED
        return results

    @staticmethod
    def _exploit_finding(
        target: str, module: str, justification: str, parsed: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        kind = str(parsed.get("type", ""))
        if kind == "session_opened":
            severity, ftype = "critical", "remote_code_execution"
            title = f"Exploited: interactive session via {module}"
        elif kind == "confirmed_vulnerability":
            severity, ftype = "high", "confirmed_vulnerability"
            title = f"Confirmed exploitable: {module}"
        elif kind == "module_check_negative":
            severity, ftype = "informational", "exploit_not_confirmed"
            title = f"Not exploitable via {module}"
        else:
            return None
        return {
            "type": ftype,
            "target": target or module,
            "title": title,
            "severity": severity,
            "description": str(parsed.get("summary", title)),
            "confidence": parsed.get("confidence", "high"),
            "source": "tool:metasploit",
            "validated": kind in {"session_opened", "confirmed_vulnerability"},
            "evidence": [{"kind": "exploit_output", "content": str(parsed.get("summary", title))}],
            "metadata": {
                "module": module,
                "justification": justification,
                "raw": parsed,
            },
        }


# ---------------------------------------------------------------------------
# Post-exploitation (planning only; execution requires explicit approval)
# ---------------------------------------------------------------------------


class PostExploitationAgent(ContextAgent):
    """Produce an ATT&CK-mapped post-exploitation plan; never self-executes.

    The plan is grounded in real access when the context carries exploitation
    evidence (open sessions / confirmed RCE); otherwise it is clearly flagged as
    a contingency template. Every objective is marked ``requires_approval`` and
    carries its ATT&CK technique so an operator can authorize step by step.
    """

    capability = "post_exploitation"

    #: Objective -> (finding type used for ATT&CK lookup, human description).
    _OBJECTIVES: tuple[tuple[str, str, str], ...] = (
        ("persistence", "persistence", "Establish persistence on the compromised host"),
        (
            "privilege_escalation",
            "privilege_escalation",
            "Escalate privileges to administrative/root context",
        ),
        ("credential_access", "credential_dump", "Harvest credentials from the host"),
        ("lateral_movement", "lateral_movement", "Move laterally to adjacent in-scope hosts"),
        ("collection", "data_exfiltration", "Stage and assess sensitive-data access"),
    )

    def _has_foothold(self, context: Dict[str, Any]) -> bool:
        if context.get("sessions"):
            return True
        for finding in context.get("findings", []) or []:
            if str(finding.get("type", "")) in {"remote_code_execution", "session_opened"}:
                return True
        return False

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        grounded = self._has_foothold(context)
        target = str(context.get("target", "in-scope host"))

        plan: List[Dict[str, Any]] = []
        for objective, finding_type, description in self._OBJECTIVES:
            techniques = [t.to_dict() for t in mitre.techniques_for_type(finding_type)]
            plan.append(
                {
                    "objective": objective,
                    "description": description,
                    "attack_techniques": techniques,
                    "requires_approval": True,
                    "risk_level": RiskLevel.CRITICAL.value,
                    "status": "blocked_pending_approval",
                }
            )

        summary_finding = {
            "type": "post_exploitation_plan",
            "target": target,
            "title": "Post-exploitation plan prepared (approval required)",
            "severity": "informational",
            "description": (
                f"A {len(plan)}-objective post-exploitation plan is staged for {target}. "
                + (
                    "It is grounded in confirmed access evidence."
                    if grounded
                    else "No foothold is confirmed yet; the plan is a contingency template."
                )
                + " Every objective is blocked pending explicit human approval."
            ),
            "confidence": "high" if grounded else "low",
            "source": "agent:post_exploitation",
            "validated": False,
            "metadata": {"plan": plan, "grounded": grounded},
        }
        self.add_finding(summary_finding)

        self.status = AgentStatus.COMPLETED
        return {
            "task": task,
            "findings": [summary_finding],
            "context_updates": {
                "post_exploitation_plan": plan,
                "post_exploitation_grounded": grounded,
                "post_exploitation_blocked": True,
            },
        }
