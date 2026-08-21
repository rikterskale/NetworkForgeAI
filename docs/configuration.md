# Configuration reference

NetworkForgeAI reads environment variables and, when present, a local `.env`
file from the current working directory. Start with:

```bash
cp .env.example .env
```

Never commit `.env`, provider keys, dashboard tokens, licenses, or scan evidence
containing secrets.

## Safety-first minimum configuration

```dotenv
TARGET_SCOPE=your-authorized-host.example
APPROVAL_MODE=strict
BLOCK_DESTRUCTIVE_ACTIONS=true
REQUIRE_JUSTIFICATION_FOR_EXPLOITATION=true
AUDIT_ALL_APPROVALS=true
DASHBOARD_AUTH_TOKEN=long-random-token
REPORT_OUTPUT_DIR=./reports
```

An empty `TARGET_SCOPE` denies execution by default. The CLI also accepts a
one-run scope through repeated `--scope` arguments.

## Environment variable reference

### LLM providers

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | empty | OpenAI credential |
| `ANTHROPIC_API_KEY` | empty | Anthropic credential |
| `GOOGLE_API_KEY` | empty | Google credential |
| `LITELLM_MODEL` | `openai/gpt-4` | LiteLLM model identifier |
| `LOCAL_LLM_URL` | empty | OpenAI-compatible local endpoint |

Provider settings are optional for CLI inventory, configuration validation, dry
runs, and readiness checks. Live model-backed analysis needs a configured
provider and the provider’s optional SDK package. Configure one provider first.

```dotenv
# Hosted provider
OPENAI_API_KEY=replace-me
LITELLM_MODEL=openai/gpt-4

# Or a local OpenAI-compatible endpoint
LOCAL_LLM_URL=http://127.0.0.1:11434/v1
LITELLM_MODEL=ollama/llama3
```

Do not paste keys into command-line arguments, tickets, screenshots, or reports.

### Target scope and approval controls

| Variable | Default | Valid values / format | Purpose |
|---|---|---|---|
| `TARGET_SCOPE` | empty | comma-separated hosts, IPs, or CIDRs | Persistent authorized allow-list |
| `APPROVAL_MODE` | `strict` | `strict`, `moderate`, `lenient` | Approval policy |
| `BLOCK_DESTRUCTIVE_ACTIONS` | `true` | `true` / `false` | Blocks destructive operations |
| `REQUIRE_JUSTIFICATION_FOR_EXPLOITATION` | `true` | `true` / `false` | Requires justification before exploitation |
| `AUDIT_ALL_APPROVALS` | `true` | `true` / `false` | Records approval decisions |

Scope examples:

```dotenv
TARGET_SCOPE=app.example.test
TARGET_SCOPE=app.example.test,api.example.test,192.0.2.0/24
```

Use `--exclude` for a one-run exclusion. Do not rely on a wildcard for a whole
organization unless the written authorization explicitly says so.

Approval modes:

- `strict`: safest default; approval-controlled actions wait for a human.
- `moderate`: low-risk reconnaissance may be auto-approved; higher-risk work waits.
- `lenient`: low- and medium-risk actions may be auto-approved; exploitation still requires approval.

Changing the mode does not expand scope or remove high/critical fail-closed rules.

### Dashboard and proxy

| Variable | Default | Purpose |
|---|---|---|
| `DASHBOARD_PORT` | `8080` | Local dashboard port |
| `DASHBOARD_AUTH_TOKEN` | empty | Bearer token for protected endpoints |
| `CAIDO_WEB_PORT` | `8090` | Optional Caido web port in Compose |
| `CAIDO_PROXY_PORT` | `8091` | Optional Caido proxy port in Compose |
| `CAIDO_LICENSE` | empty | Optional Caido license |

Use a long random dashboard token. An empty token or the literal `changeme` does
not authorize protected dashboard requests.

### Reporting and runtime

| Variable | Default | Purpose |
|---|---|---|
| `REPORT_FORMATS` | Markdown, JSON, CSV, SARIF | Output formats as a JSON array |
| `REPORT_OUTPUT_DIR` | `./reports` | Report and scan-state directory |
| `SESSION_TIMEOUT_MINUTES` | `60` | Session timeout, from 5 to 1440 |
| `MAX_CONCURRENT_AGENTS` | `5` | Agent concurrency, from 1 to 20 |
| `CI_MODE` | `false` | Pipeline mode |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `NETWORKFORGE_SANDBOX_IMAGE` | empty | Approved Docker image for sandbox execution |

`REPORT_FORMATS` must be valid JSON because it is a list setting:

```dotenv
REPORT_FORMATS=["markdown","json","csv","sarif"]
```

Do not use `REPORT_FORMATS=markdown,json,csv,sarif`; it cannot be parsed.

## CLI settings versus `.env`

The CLI can supply a temporary scope without changing `.env`:

```bash
python -m networkforgeai.cli \
  --target app.example.test \
  --scope app.example.test \
  --exclude admin.app.example.test \
  --tool nmap \
  --dry-run
```

The command-line scope applies to that invocation. `.env` values are used by
configuration-backed components such as orchestration, dashboard, and provider
selection.

## Validate configuration

```bash
python -m networkforgeai.cli --validate-config
```

This checks that a persistent target scope exists and that the dashboard token is
not the development placeholder. It does not verify provider credentials or
contact a target.

To troubleshoot settings parsing without printing secrets:

```bash
TARGET_SCOPE=app.example.test \
DASHBOARD_AUTH_TOKEN=local-test-token \
python -c 'from networkforgeai.config import Settings; s=Settings(); print(s.parsed_target_scope, s.approval_mode, s.report_formats)'
```

## Recommended profiles

### Local dry-run

```dotenv
TARGET_SCOPE=app.example.test
APPROVAL_MODE=strict
BLOCK_DESTRUCTIVE_ACTIONS=true
REPORT_FORMATS=["markdown","json"]
REPORT_OUTPUT_DIR=./reports
```

### CI

```dotenv
TARGET_SCOPE=app.example.test
APPROVAL_MODE=strict
BLOCK_DESTRUCTIVE_ACTIONS=true
CI_MODE=true
REPORT_FORMATS=["json","sarif"]
REPORT_OUTPUT_DIR=./reports
```

### Dashboard

```dotenv
DASHBOARD_PORT=8080
DASHBOARD_AUTH_TOKEN=replace-with-a-random-token
REPORT_OUTPUT_DIR=./reports
LOG_LEVEL=INFO
```

## Changes requiring review

Obtain operator review before:

- Expanding `TARGET_SCOPE`
- Changing `APPROVAL_MODE` away from `strict`
- Setting `BLOCK_DESTRUCTIVE_ACTIONS=false`
- Setting `AUDIT_ALL_APPROVALS=false`
- Enabling `--host-execution`
- Exposing the dashboard beyond `127.0.0.1`
