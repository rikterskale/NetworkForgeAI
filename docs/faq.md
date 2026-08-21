# Frequently Asked Questions

## Authorization and safety

### Can NetworkForgeAI scan targets without my approval?

No. Every invocation requires an explicit allow-list scope (`--scope` or
`TARGET_SCOPE`), and all high-risk actions pass through the human approval
gateway, which fails closed: without an explicit approval decision, nothing
executes. Reconnaissance-class actions may be auto-approved only in `moderate`
or `lenient` modes; exploitation always requires a human decision.

### What happens if I run the dashboard without attaching a scan?

Operator endpoints (approval queue, steering) return `503`. The dashboard can
never start scans — it only steers or approves actions for a scan that was
started deliberately.

### Does the tool ever execute commands on my host?

Only if you explicitly pass `--host-execution`, which disables the Docker
sandbox for authorized development use. By default, tool execution is wrapped
in a sandbox container with no network access, dropped capabilities, and
no-new-privileges enforcement.

## Setup and operation

### Why does `make typecheck` fail with missing module errors?

Strict MyPy needs type stubs from the optional LLM SDKs. Install them with:

```bash
python -m pip install '.[dev,runtime,llm]'
```

### Why does `pytest` fail on coverage?

The suite enforces a 90% line-coverage floor (`--cov-fail-under=90`). Run the
full suite rather than a single file, or write tests for new code before
committing.

### Where do scan results go?

Under `--output-dir` (default `./scans`), one directory per scan containing
`scan_state.json`, `findings.json`, `findings.csv`, `findings.sarif`, and
`report.md`. The dashboard lists whatever is under `REPORT_OUTPUT_DIR`.

### Which LLM providers are supported?

OpenAI, Anthropic, Google Gemini, Azure OpenAI, local models (Ollama/LM
Studio/vLLM), and anything reachable through LiteLLM. Providers are optional:
the whole framework runs model-free for deterministic workflows.

## Integrations

### How do I send findings to Slack or Jira?

Use `networkforgeai.integrations.notifications`. Both notifiers enforce
HTTPS-only endpoints and post sanitized finding data only. See
[Reporting Guide](reporting.md#notifications).

### Can findings block a CI pipeline?

Yes. The findings policy gate (`tools/ci_findings_gate.py`) fails when findings
at or above a severity threshold are open. See
[CI/CD Integration](ci-cd.md).

## Reporting

### Are reports evidence of exploitable vulnerabilities?

No. Reports are evidence containers. Every finding retains its approval and
validation context; validation output is advisory and must be confirmed by a
human before it is treated as fact.
