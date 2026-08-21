import json

import pytest

from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools import (
    BrowserAutomationTool,
    CrackMapExecTool,
    GraphQLProbeTool,
    HydraTool,
    ImpacketTools,
    JwtAnalyzerTool,
    MetasploitTool,
    NmapTool,
)


def test_tool_requires_explicit_scope():
    tool = NmapTool(dry_run=True)
    with pytest.raises(ValueError):
        tool.execute("example.com")


def test_dry_run_builds_command_without_external_execution():
    tool = NmapTool(dry_run=True)
    tool.scope_policy = ScopePolicy(["example.com"])
    result = tool.execute("example.com")
    assert result.success
    assert "[DRY RUN]" in result.stdout


def test_high_risk_tool_cannot_execute_without_gateway():
    tool = HydraTool()
    tool.scope_policy = ScopePolicy(["example.com"])
    with pytest.raises(PermissionError):
        tool.execute("example.com", {"username": "user", "password": "pass"})


def test_sandbox_execution_fails_closed_without_configured_image():
    tool = NmapTool()
    tool.scope_policy = ScopePolicy(["example.com"])
    result = tool.execute("example.com")
    assert result.exit_code == -1
    assert "SANDBOX_IMAGE" in result.stderr


def test_metasploit_requires_approval_gateway():
    tool = MetasploitTool()
    tool.scope_policy = ScopePolicy(["example.com"])
    with pytest.raises(PermissionError):
        tool.execute("example.com", {"module": "exploit/test/module"})


def test_metasploit_dry_run_is_allowed_without_gateway():
    tool = MetasploitTool(dry_run=True)
    tool.scope_policy = ScopePolicy(["example.com"])
    result = tool.execute("example.com", {"module": "exploit/test/module"})
    assert result.success
    assert "[DRY RUN]" in result.stdout


def test_metasploit_requires_module_option():
    with pytest.raises(ValueError):
        MetasploitTool().build_command("example.com", {})


def test_metasploit_builds_resource_script():
    cmd = MetasploitTool().build_command(
        "example.com",
        {
            "module": "exploit/test/module",
            "payload": "cmd/unix/reverse_bash",
            "set_options": {"LPORT": 4444},
        },
    )
    assert cmd[:2] == ["msfconsole", "-q"]
    script = cmd[3]
    assert "use exploit/test/module" in script
    assert "set RHOSTS example.com" in script
    assert "set PAYLOAD cmd/unix/reverse_bash" in script
    assert "set LPORT 4444" in script
    assert script.rstrip().endswith("; exit")


def test_metasploit_check_only_runs_check():
    script = MetasploitTool().build_command(
        "example.com", {"module": "auxiliary/x", "check_only": True}
    )[3]
    assert "check" in script and "; run;" not in script


def test_metasploit_parses_sessions_and_checks():
    tool = MetasploitTool()
    stdout = (
        "[*] 1.2.3.4:445 - Vulnerable target\n"
        "Meterpreter session 3 opened\n"
        "check: not vulnerable here"
    )
    findings = {f["type"]: f for f in tool.parse_findings(stdout, "")}
    assert findings["session_opened"]["session_id"] == 3
    assert findings["confirmed_vulnerability"]["target"] == "1.2.3.4:445"
    assert findings["module_check_negative"]["confidence"] == "medium"
    assert tool.parse_findings("", "") == []


def test_hydra_requires_credentials():
    with pytest.raises(ValueError):
        HydraTool().build_command("example.com", {})
    cmd = HydraTool().build_command("example.com", {"userlist": "u.txt", "passlist": "p.txt"})
    assert "-L u.txt" in " ".join(cmd) and "-P p.txt" in " ".join(cmd)
    cmd = HydraTool().build_command(
        "example.com", {"username": "root", "password": "pw", "port": 2222, "verbose": True}
    )
    joined = " ".join(cmd)
    assert "-l root" in joined and "-p pw" in joined and "-s 2222" in joined and "-v" in joined


def test_hydra_parses_credential_findings_without_duplicates():
    tool = HydraTool()
    stdout = (
        "[ssh] host: 1.2.3.4 login: root password: secret\n"
        "login: admin password: hunter2\n"
        "login: admin password: hunter2\n"
    )
    findings = tool.parse_findings(stdout, "")
    creds = [(f["username"], f["password"]) for f in findings]
    assert ("root", "secret") in creds
    assert ("admin", "hunter2") in creds
    assert creds.count(("admin", "hunter2")) == 1


def test_crackmapexec_build_options_and_parse():
    tool = CrackMapExecTool()
    cmd = tool.build_command(
        "1.2.3.4",
        {
            "protocol": "winrm",
            "username": "svc",
            "hashes": "aad3b",
            "local_auth": True,
            "shares": True,
            "users": True,
            "passes": True,
            "command": "whoami",
        },
    )
    joined = " ".join(cmd)
    assert "winrm" in joined
    assert "-u svc" in joined and "-H aad3b" in joined
    for flag in ["--local-auth", "--shares", "--users", "--pass-pol", "-x", "whoami"]:
        assert flag in joined

    findings = tool.parse_findings("[++] 1.2.3.4:5985 svc:CORP\nREAD\tShare$", "")
    types = [f["type"] for f in findings]
    assert "successful_auth" in types and "share_access" in types


def test_impacket_tool_selection_and_parsing():
    tool = ImpacketTools()
    with pytest.raises(ValueError):
        tool.build_command("1.2.3.4", {"tool": "missing"})
    cmd = tool.build_command(
        "1.2.3.4", {"tool": "secretsdump", "username": "svc", "password": "pw", "domain": "CORP"}
    )
    assert cmd[0] == "secretsdump"
    assert "-credentials svc:pw" in " ".join(cmd) and "-domain CORP" in " ".join(cmd)
    no_pass = tool.build_command("1.2.3.4", {"no_pass": True})
    assert "-no-pass" in " ".join(no_pass)

    findings = tool.parse_findings("Session established\nCORP\\alice (admin)", "")
    types = sorted(f["type"] for f in findings)
    assert types == ["connection_success", "user_enumerated"]


def test_browser_tool_builds_playwright_command():
    tool = BrowserAutomationTool()
    cmd = tool.build_command("app.example.test", {"max_pages": 3})
    assert cmd[0] == "python" and cmd[1] == "-c"
    assert cmd[3] == "https://app.example.test"
    assert cmd[4] == "3"
    # Existing URL schemes are preserved, not double-prefixed
    assert BrowserAutomationTool().build_command("http://a.test")[3] == "http://a.test"


def test_browser_tool_parses_script_output():
    tool = BrowserAutomationTool()
    payload = {
        "url": "https://a.test",
        "pages": [{"url": "https://a.test", "status": 200, "title": "Login"}],
        "findings": [{"type": "insecure_form", "url": "https://a.test", "count": 1}],
    }
    findings = tool.parse_findings(json.dumps(payload), "")
    types = sorted(f["type"] for f in findings)
    assert types == ["insecure_form", "page_surface"]
    page = next(f for f in findings if f["type"] == "page_surface")
    assert page["status"] == 200 and page["title"] == "Login"


def test_browser_tool_handles_missing_playwright_and_bad_output():
    tool = BrowserAutomationTool()
    error = tool.parse_findings('{"error": "playwright is not installed"}', "")
    assert error[0]["type"] == "browser_error"
    assert tool.parse_findings("not json at all", "") == []


def test_browser_dry_run_is_allowed_without_gateway():
    tool = BrowserAutomationTool(dry_run=True)
    tool.scope_policy = ScopePolicy(["app.example.test"])
    result = tool.execute("app.example.test")
    assert result.success and "[DRY RUN]" in result.stdout


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def test_jwt_tool_rejects_non_jwt_input():
    with pytest.raises(ValueError):
        JwtAnalyzerTool().build_command("example.com", {})


def test_jwt_tool_flags_alg_none_and_missing_expiry():
    tool = JwtAnalyzerTool()
    header = _b64url(b'{"alg": "none", "typ": "JWT"}')
    payload = _b64url(b'{"sub": "1"}')
    cmd = tool.build_command("unused", {"token": f"{header}.{payload}."})
    assert cmd[3] == f"{header}.{payload}."
    findings = {
        f["type"]
        for f in tool.parse_findings(
            json.dumps(
                {
                    "header": {"alg": "none"},
                    "claims": {},
                    "findings": [{"type": "jwt_alg_none", "summary": "x"}],
                }
            ),
            "",
        )
    }
    assert findings == {"jwt_alg_none"}
    # No issues path yields informational finding; secrets in claims are dropped by the script
    clean = tool.parse_findings(json.dumps({"header": {}, "claims": {}, "findings": []}), "")
    assert clean[0]["type"] == "jwt_no_issues"
    bad = tool.parse_findings("garbage", "")
    assert bad[0]["type"] == "jwt_parse_error"
    invalid = tool.parse_findings(json.dumps({"error": "not a decodable JWT: x"}), "")
    assert invalid[0]["type"] == "jwt_invalid"


def test_graphql_probe_builds_url_and_parses():
    tool = GraphQLProbeTool()
    cmd = tool.build_command("api.example.test/graphql")
    assert cmd[0] == "python" and cmd[3] == "https://api.example.test/graphql" and cmd[4] == "10"
    payload = {
        "endpoint": "https://api.example.test/graphql",
        "findings": [
            {"type": "introspection_enabled", "summary": "on"},
            {"type": "batching_accepted", "summary": "yes"},
        ],
    }
    findings = tool.parse_findings(json.dumps(payload), "")
    severities = {f["type"]: f["severity"] for f in findings}
    assert severities["introspection_enabled"] == "medium"
    assert severities["batching_accepted"] == "low"
    empty = tool.parse_findings(json.dumps({"endpoint": "x", "findings": []}), "")
    assert empty[0]["type"] == "graphql_no_issues"
    broken = tool.parse_findings("<html>", "")
    assert broken[0]["type"] == "graphql_probe_error"


def test_new_tools_registered_and_dry_run_safe():
    from networkforgeai.tools import get_available_tools, get_tool_by_name

    tools = get_available_tools()
    assert "jwt-analyzer" in tools and "graphql-probe" in tools
    analyzer = get_tool_by_name("jwt-analyzer", dry_run=True)
    analyzer.scope_policy = ScopePolicy(["t.example"])
    token = _b64url(b'{"alg":"HS256"}') + "." + _b64url(b'{"exp":4102444800}') + ".sig"
    result = analyzer.execute(
        "t.example",
        {"token": token},
    )
    assert result.success and "[DRY RUN]" in result.stdout
