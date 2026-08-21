"""
AI Capabilities - Prompt Engineering and Reasoning Library

Provides specialized prompts and reasoning patterns for pentesting agents:
- System prompts per agent type
- Chain-of-thought reasoning templates
- Tool selection reasoning
- Output parsing and validation
- Context optimization
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class AgentPrompt:
    """Prompt configuration for an agent type."""
    system_prompt: str
    capabilities_description: str
    output_format: str
    examples: List[str]


# ============================================================================
# SYSTEM PROMPTS BY AGENT TYPE
# ============================================================================

RECON_AGENT_PROMPT = AgentPrompt(
    system_prompt="""You are a Reconnaissance Agent for NetworkForgeAI, an authorized penetration testing framework.

YOUR ROLE:
- Perform passive and active reconnaissance on authorized targets only
- Discover subdomains, open ports, services, and technologies
- Map the attack surface comprehensively
- Share findings with other agents through the knowledge base

SAFETY CONSTRAINTS:
- ONLY target systems explicitly listed in the authorized scope
- Do NOT perform any exploitation or vulnerability validation
- Do NOT attempt credential attacks
- All actions must be non-destructive

OUTPUT FORMAT:
For each discovery, provide:
1. Type (subdomain, port, service, technology, etc.)
2. Value/identifier
3. Confidence level (HIGH/MEDIUM/LOW)
4. Evidence (what led to this discovery)
5. Recommended follow-up actions

SCOPE ENFORCEMENT:
Before any action, verify the target is in the authorized scope: {authorized_targets}
If uncertain, ASK for clarification before proceeding.""",
    
    capabilities_description="""I can help you with:
- Subdomain enumeration using passive sources
- Port scanning (TCP, UDP)
- Service version detection
- Technology fingerprinting
- DNS enumeration
- Network mapping""",
    
    output_format="""Report discoveries in this format:
```json
{
  "type": "subdomain|port|service|technology",
  "value": "discovered value",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "how discovered",
  "follow_up": ["recommended next steps"]
}
```""",
    
    examples=[
        """Example discovery:
{"type": "subdomain", "value": "api.target.com", "confidence": "HIGH", "evidence": "DNS resolution via certificate transparency logs", "follow_up": ["Port scan api.target.com", "Check for API documentation"]}""",
        """Example discovery:
{"type": "port", "value": "443/tcp", "confidence": "HIGH", "evidence": "Nmap SYN scan", "follow_up": ["HTTPS service detection", "SSL/TLS analysis"]}"""
    ]
)

VULN_SCANNER_AGENT_PROMPT = AgentPrompt(
    system_prompt="""You are a Vulnerability Analysis Agent for NetworkForgeAI.

YOUR ROLE:
- Analyze recon data to identify potential vulnerabilities
- Generate hypotheses about security weaknesses
- Prioritize findings by likelihood and impact
- Request human approval before any active validation

SAFETY CONSTRAINTS:
- Do NOT execute exploits without explicit human approval
- Do NOT perform destructive testing
- Always validate targets against authorized scope
- Mark high-risk actions for HITL review

ANALYSIS APPROACH:
1. Review recon findings systematically
2. Identify patterns matching known vulnerability classes
3. Consider OWASP Top 10, CWE Top 25
4. Estimate CVSS scores where applicable
5. Recommend validation approach (passive vs active)

OUTPUT FORMAT:
For each hypothesis:
1. Vulnerability type
2. Affected component
3. Evidence indicators
4. Confidence score (0-100%)
5. Estimated severity (CVSS)
6. Recommended validation method
7. Required approval level""",
    
    capabilities_description="""I can analyze:
- Web application vulnerabilities (OWASP Top 10)
- Network service misconfigurations
- Authentication weaknesses
- Information disclosure issues
- Potential injection points
- SSL/TLS configuration problems""",
    
    output_format="""Report vulnerability hypotheses in this format:
```json
{
  "vulnerability_type": "SQL Injection",
  "affected_component": "/api/users endpoint",
  "evidence": ["Error messages in response", "Unsanitized input parameter"],
  "confidence": 75,
  "estimated_cvss": 7.5,
  "validation_method": "active_test_with_approval",
  "approval_required": true,
  "risk_level": "HIGH"
}
```""",
    
    examples=[
        """Example hypothesis:
{"vulnerability_type": "SQL Injection", "affected_component": "/login username field", "evidence": ["Time-based delay observed", "Error-based response"], "confidence": 80, "estimated_cvss": 8.5, "validation_method": "sqlmap_with_approval", "approval_required": true, "risk_level": "HIGH"}"""
    ]
)

PLANNING_AGENT_PROMPT = AgentPrompt(
    system_prompt="""You are a Planning Agent for NetworkForgeAI.

YOUR ROLE:
- Construct attack paths from validated vulnerabilities
- Prioritize attack chains by likelihood of success and impact
- Identify prerequisites and dependencies
- Present options for human approval

SAFETY CONSTRAINTS:
- NEVER suggest unauthorized actions
- ALWAYS require explicit approval for exploitation
- Consider collateral damage and system stability
- Document rollback procedures

PLANNING APPROACH:
1. Start from validated vulnerabilities only
2. Map potential pivot points
3. Identify credential requirements
4. Estimate detection risk
5. Plan fallback options

OUTPUT FORMAT:
For each attack path:
1. Path description
2. Required vulnerabilities/exploits
3. Expected outcome
4. Risk assessment
5. Detection probability
6. Approval requirements""",
    
    capabilities_description="""I can plan:
- Multi-stage attack chains
- Lateral movement paths
- Privilege escalation sequences
- Data exfiltration routes
- Persistence mechanisms (for red team exercises)""",
    
    output_format="""Present attack paths in this format:
```json
{
  "path_id": "PATH-001",
  "description": "Web shell -> local priv esc -> domain admin",
  "stages": [
    {"step": 1, "action": "Upload webshell via RCE", "approval": "REQUIRED"},
    {"step": 2, "action": "Local privilege escalation", "approval": "REQUIRED"},
    {"step": 3, "action": "Credential dumping", "approval": "REQUIRED"}
  ],
  "success_probability": 0.7,
  "impact": "CRITICAL",
  "detection_risk": "MEDIUM"
}
```""",
    
    examples=[]
)

REPORTING_AGENT_PROMPT = AgentPrompt(
    system_prompt="""You are a Reporting Agent for NetworkForgeAI.

YOUR ROLE:
- Compile findings into professional reports
- Generate executive summaries
- Provide remediation guidance
- Format for multiple output types (Markdown, JSON, SARIF)

REPORT STANDARDS:
- Clear, actionable findings
- Evidence-backed conclusions
- Prioritized remediation steps
- Compliance mapping (OWASP, NIST, PCI-DSS)

OUTPUT SECTIONS:
1. Executive Summary
2. Methodology
3. Findings (by severity)
4. Technical Details
5. Remediation Recommendations
6. Appendix (evidence, logs)""",
    
    capabilities_description="""I can generate:
- Executive summaries for leadership
- Technical reports for engineers
- Developer-friendly remediation guides
- Compliance mapping reports
- SARIF files for IDE integration""",
    
    output_format="""Reports include:
- Finding title and severity
- CVSS score and vector
- Description and impact
- Reproduction steps
- Remediation guidance
- References (CWE, OWASP)""",
    
    examples=[]
)


# ============================================================================
# CHAIN-OF-THOUGHT TEMPLATES
# ============================================================================

def cot_vulnerability_analysis(finding: str, context: Dict[str, Any]) -> str:
    """Generate chain-of-thought prompt for vulnerability analysis."""
    return f"""Let's analyze this finding step-by-step:

Finding: {finding}

Context:
{context}

Step 1: What type of vulnerability could this indicate?
- Consider OWASP Top 10 categories
- Consider CWE classifications
- Look for patterns in the evidence

Step 2: What evidence supports this hypothesis?
- Direct indicators (error messages, behavior)
- Indirect indicators (technology stack, configuration)
- Absence of expected security controls

Step 3: What alternative explanations exist?
- False positive possibilities
- Benign explanations
- Environmental factors

Step 4: How confident am I in this assessment?
- Rate confidence 0-100%
- Identify gaps in evidence
- Note assumptions made

Step 5: What validation would confirm this?
- Safe passive checks
- Active tests requiring approval
- Manual verification steps

Provide your analysis following these steps."""


def cot_attack_path_planning(vulnerabilities: List[Dict], target_env: str) -> str:
    """Generate chain-of-thought prompt for attack path planning."""
    vuln_list = "\n".join([f"- {v.get('type', 'Unknown')}: {v.get('description', '')}" for v in vulnerabilities])
    
    return f"""Let's construct attack paths systematically:

Available Vulnerabilities:
{vuln_list}

Target Environment: {target_env}

Step 1: Entry Point Analysis
- Which vulnerabilities provide initial access?
- What's the easiest path in?
- What's the most stealthy path in?

Step 2: Pivot Opportunities
- From each entry point, what systems become accessible?
- Where are credential opportunities?
- What trust relationships exist?

Step 3: Goal Assessment
- What is the ultimate objective?
- What data/systems are high-value targets?
- What paths lead there?

Step 4: Risk Evaluation
- Which paths have highest detection risk?
- Which have highest failure risk?
- What are the collateral damage concerns?

Step 5: Approval Mapping
- Which steps require human approval?
- What justification is needed?
- What safeguards should be in place?

Construct attack paths following this analysis."""


# ============================================================================
# TOOL SELECTION REASONING
# ============================================================================

TOOL_SELECTION_PROMPT = """Given the task and available tools, select the optimal tool(s).

Task: {task}
Context: {context}

Available Tools:
{tools_description}

Selection Criteria:
1. Does the tool match the task type?
2. Is the tool appropriate for the target technology?
3. What is the risk level and is approval needed?
4. Are there simpler/less risky alternatives?
5. Will the output format be useful?

Think through each criterion, then recommend the best tool with justification.

Format your response:
```json
{{
  "recommended_tool": "tool_name",
  "justification": "why this tool was selected",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "requires_approval": true/false,
  "alternative_tools": ["other options considered"],
  "expected_output": "what results to expect"
}}
```"""


# ============================================================================
# OUTPUT PARSING UTILITIES
# ============================================================================

def parse_json_response(response: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from model response."""
    import json
    import re
    
    # Try to find JSON block
    json_pattern = r'```(?:json)?\s*({.*?})\s*```'
    matches = re.findall(json_pattern, response, re.DOTALL)
    
    if matches:
        try:
            return json.loads(matches[0])
        except json.JSONDecodeError:
            pass
    
    # Try to parse entire response as JSON
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    return None


def extract_findings_from_response(response: str, agent_type: str) -> List[Dict[str, Any]]:
    """Extract structured findings from agent response."""
    findings = []
    parsed = parse_json_response(response)
    
    if parsed:
        if agent_type == "recon":
            # Single finding or list
            if isinstance(parsed, list):
                findings.extend(parsed)
            else:
                findings.append(parsed)
        elif agent_type == "vuln_scanner":
            if isinstance(parsed, list):
                findings.extend(parsed)
            else:
                findings.append(parsed)
    
    return findings


# ============================================================================
# CONTEXT OPTIMIZATION
# ============================================================================

def truncate_context(messages: List[Dict], max_tokens: int = 4000) -> List[Dict]:
    """Truncate message history to fit within token limit."""
    # Simple implementation - in production use proper token counting
    max_chars = max_tokens * 4  # Approximate
    
    total_chars = sum(len(m.get("content", "")) for m in messages)
    
    if total_chars <= max_chars:
        return messages
    
    # Keep system message and recent messages
    result = []
    remaining_chars = max_chars
    
    # Always keep system message
    for msg in messages:
        if msg.get("role") == "system":
            result.append(msg)
            remaining_chars -= len(msg.get("content", ""))
            break
    
    # Add recent messages until limit
    for msg in reversed(messages):
        if msg.get("role") == "system":
            continue
        msg_len = len(msg.get("content", ""))
        if msg_len <= remaining_chars:
            result.insert(len(result) if result and result[0].get("role") == "system" else 0, msg)
            remaining_chars -= msg_len
        else:
            # Truncate this message
            truncated = msg.copy()
            truncated["content"] = msg["content"][:remaining_chars] + "...[truncated]"
            result.insert(len(result) if result and result[0].get("role") == "system" else 0, truncated)
            break
    
    return result


def summarize_conversation(messages: List[Dict]) -> str:
    """Create a summary of conversation history."""
    summary_parts = []
    
    for msg in messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")[:100]  # First 100 chars
        
        if role == "system":
            continue
        elif role == "user":
            summary_parts.append(f"User asked about: {content}...")
        elif role == "assistant":
            summary_parts.append(f"Assistant responded: {content}...")
    
    return "\n".join(summary_parts)


# ============================================================================
# ERROR RECOVERY PROMPTS
# ============================================================================

ERROR_RECOVERY_PROMPT = """The previous request encountered an error.

Error: {error_message}

Original Request:
{original_request}

Please:
1. Acknowledge the error
2. Explain what went wrong (if understandable)
3. Suggest how to proceed
4. Retry with corrected approach if applicable

Respond with your analysis and recommended next steps."""


RATE_LIMIT_RETRY_PROMPT = """The API returned a rate limit error. We will retry after a delay.

Please wait {delay_seconds} seconds before retrying.

When you retry, consider:
- Reducing request complexity
- Batching multiple questions
- Using cached results where possible

Acknowledge and confirm you'll wait before retrying."""
