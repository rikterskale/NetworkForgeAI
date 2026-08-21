# Production deployment guide

This guide covers deploying NetworkForgeAI for operational use. For a first
install or evaluation, start with the [installation guide](installation.md)
instead.

## 0. Deployment prerequisites

Before deploying:

1. Written authorization covering every target and network in scope.
2. A dedicated host or VM for the toolkit; it runs offensive tooling by design.
3. Docker Engine (sandboxed execution fails closed without it).
4. An approved sandbox image containing the security tools you intend to run.
5. Approved storage for reports, scan state, and immutable audit logs.
6. A named human operator responsible for approval decisions.

## 1. Choose a deployment shape

| Shape | Use when | Components |
|---|---|---|
| Single host, venv | One operator, local lab | CLI + Docker, no dashboard |
| Single host, Compose | Team needs read-only reporting UI | `networkforgeai` + `dashboard` services |
| Air-gapped | Regulated environments | Local LLM (Ollama) + internal image registry |

Never expose the dashboard to the public internet.

## 2. Prepare environment configuration

Create `/etc/networkforgeai/.env` (or an equivalent root-owned file, mode 600)
from `.env.example`. Production minimums:

```dotenv
TARGET_SCOPE=exactly-your-authorized-targets        # comma-separated allow-list
APPROVAL_MODE=strict
BLOCK_DESTRUCTIVE_ACTIONS=true
REQUIRE_JUSTIFICATION_FOR_EXPLOITATION=true
AUDIT_ALL_APPROVALS=true
DASHBOARD_AUTH_TOKEN=<long-random-value>
REPORT_OUTPUT_DIR=/var/lib/networkforgeai/reports
LOG_LEVEL=INFO
CI_MODE=false
```

Generate the token without shell history:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Rotate `DASHBOARD_AUTH_TOKEN` on staff changes and at least quarterly.

## 3. Install

Either install the wheel into a system-isolated venv:

```bash
python3 -m venv /opt/networkforgeai/venv
/opt/networkforgeai/venv/bin/pip install networkforgeai-*.whl   # or '.[runtime]' from source
```

or use Docker Compose (recommended for the dashboard):

```bash
docker compose --env-file /etc/networkforgeai/.env config --quiet   # validate first
```

## 4. Sandbox image

Build one controlled image with the tools your authorization covers and pin it:

```bash
export NETWORKFORGE_SANDBOX_IMAGE=registry.internal/security-tools:2026-08
docker image inspect "$NETWORKFORGE_SANDBOX_IMAGE"
```

Execution fails closed if the image is absent — that is intentional. Do not use
`--host-execution` outside explicitly authorized development.

## 5. Run under Compose

The provided `docker-compose.yml` already applies production hardening to the
toolkit container: `no-new-privileges`, all capabilities dropped, read-only root
filesystem, and tmpfs `/tmp`.

```bash
mkdir -p workspaces reports logs config
docker compose up -d --build dashboard networkforgeai
docker compose ps          # both services should be healthy
curl -fsS http://127.0.0.1:8080/health
```

The dashboard mounts `./reports` and `./logs` read-only. Bind `DASHBOARD_PORT`
to localhost or place it behind an authenticated reverse proxy:

```yaml
# compose override: keep the UI off the network
services:
  dashboard:
    ports:
      - "127.0.0.1:8080:8080"
```

## 6. Storage, backups, audit integrity

- Reports (`REPORT_OUTPUT_DIR`) and audit JSONL logs contain sensitive evidence:
  restrict filesystem permissions and encrypt backups.
- Audit trails are append-only records of approval decisions; preserve them per
  your retention policy. Never edit them.
- Scan state lives under the output directory; include it in backups only if
  your policy allows retaining target data.

## 7. Upgrades and rollback

1. Read the change log and check for behavior changes to safety settings.
2. Pull/build the new version alongside the old one.
3. Run `networkforgeai --validate-config` against production config.
4. Smoke-test with a dry run (see [scenarios](scenarios.md)).
5. Swap traffic/services; keep the previous wheel or image tag for rollback.

## 8. Operational checklist

- [ ] `TARGET_SCOPE` lists exactly the authorized targets; nothing broader.
- [ ] `APPROVAL_MODE=strict`; destructive-action blocking enabled.
- [ ] Dashboard bound to localhost or behind authenticated proxy.
- [ ] `DASHBOARD_AUTH_TOKEN` is unique, stored securely, and rotated.
- [ ] Approved sandbox image pinned by digest/tag and present.
- [ ] Report/log directories have restricted permissions and backups.
- [ ] Named approver available during scanning windows.
- [ ] `--validate-config`, `--list-tools`, and a `--dry-run` succeed post-deploy.
- [ ] Emergency stop procedure documented for operators (see [approval system](approval-system.md)).

## See also

- [Installation](installation.md), [configuration reference](configuration.md),
  [interfaces](interfaces.md), [troubleshooting](troubleshooting.md).
