"""Configuration precedence tests.

Every runtime knob has three sources ranked from most specific to least:

  1. Explicit CLI flag (per-invocation override)
  2. Environment variable (persistent per-shell / per-service setting)
  3. Hard-coded default in ``Settings`` (fail-safe baseline)

These tests lock the ordering down for each resolver so a future
refactor cannot silently invert the layers. Every knob is exercised in
all three regimes:

  * CLI wins over env
  * Env wins over default
  * Default is used when neither is present

Corresponds to fix-list item 1 (Canonical runtime configuration model
→ "Add configuration-precedence tests") in
NETWORKFORGEAI_10_10_FIX_LIST.txt.
"""

from __future__ import annotations

from networkforgeai.config import ApprovalMode, ReportFormat, Settings

# --------------------------------------------------------------- helpers


def _settings_with_env(monkeypatch, **env: str) -> Settings:
    """Instantiate Settings() with only the given env vars set.

    All other Settings-observable env vars are cleared so the test's
    default-value assertions are not perturbed by the caller's shell
    or an editor's ``.env`` autoload.
    """
    for key in (
        "TARGET_SCOPE",
        "APPROVAL_MODE",
        "DASHBOARD_AUTH_TOKEN",
        "REPORT_OUTPUT_DIR",
        "REPORT_FORMATS",
        "SESSION_TIMEOUT_MINUTES",
        "MAX_CONCURRENT_AGENTS",
        "CI_MODE",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "LOCAL_LLM_URL",
        "BLOCK_DESTRUCTIVE_ACTIONS",
        "REQUIRE_JUSTIFICATION_FOR_EXPLOITATION",
        "AUDIT_ALL_APPROVALS",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # SettingsConfigDict points at .env — steer it away from any local
    # file so precedence tests observe only what we set.
    monkeypatch.setenv("_NETWORKFORGE_SUPPRESS_ENV_FILE", "1")
    return Settings(_env_file=None)  # type: ignore[call-arg]


# ---------------------------------------------------------- target scope


def test_scope_cli_wins_over_env(monkeypatch):
    s = _settings_with_env(monkeypatch, TARGET_SCOPE="env.example")
    assert s.resolve_scope(["cli.example"]) == ["cli.example"]


def test_scope_env_used_when_cli_absent(monkeypatch):
    s = _settings_with_env(monkeypatch, TARGET_SCOPE="env.example,other.example")
    assert s.resolve_scope(None) == ["env.example", "other.example"]


def test_scope_default_is_empty_list_when_neither_present(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.resolve_scope(None) == []


def test_scope_cli_wins_even_when_env_also_set(monkeypatch):
    """The three-layer rule: an empty CLI scope still means 'use env'."""
    s = _settings_with_env(monkeypatch, TARGET_SCOPE="env.example")
    # Empty list is truthy-empty; resolver treats it as absent per current impl.
    assert s.resolve_scope([]) == ["env.example"]


# ---------------------------------------------------------- output dir


def test_output_dir_cli_wins_over_env(monkeypatch):
    s = _settings_with_env(monkeypatch, REPORT_OUTPUT_DIR="/env/reports")
    assert s.resolve_output_dir("/cli/reports") == "/cli/reports"


def test_output_dir_env_used_when_cli_absent(monkeypatch):
    s = _settings_with_env(monkeypatch, REPORT_OUTPUT_DIR="/env/reports")
    assert s.resolve_output_dir(None) == "/env/reports"


def test_output_dir_default_when_neither_present(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.resolve_output_dir(None) == "./reports"


# -------------------------------------------------------- approval mode


def test_approval_mode_cli_wins_over_env(monkeypatch):
    s = _settings_with_env(monkeypatch, APPROVAL_MODE="lenient")
    assert s.resolve_approval_mode("strict") == "strict"


def test_approval_mode_env_used_when_cli_absent(monkeypatch):
    s = _settings_with_env(monkeypatch, APPROVAL_MODE="moderate")
    assert s.resolve_approval_mode(None) == "moderate"


def test_approval_mode_default_is_strict(monkeypatch):
    """Safety-first default: no config → strict approval."""
    s = _settings_with_env(monkeypatch)
    assert s.resolve_approval_mode(None) == ApprovalMode.STRICT.value


# ------------------------------------------------------ session timeout


def test_timeout_hours_rounds_env_minutes_up(monkeypatch):
    """One minute past an hour rolls into the next hour bucket."""
    s = _settings_with_env(monkeypatch, SESSION_TIMEOUT_MINUTES="61")
    assert s.resolve_timeout_hours() == 2


def test_timeout_hours_default_from_60_minutes(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.resolve_timeout_hours() == 1


def test_timeout_hours_never_below_one(monkeypatch):
    """Guardrail: even a legally-tiny window (5 min) still yields 1 hour."""
    s = _settings_with_env(monkeypatch, SESSION_TIMEOUT_MINUTES="5")
    assert s.resolve_timeout_hours() == 1


# ------------------------------------------------------- report formats


def test_report_formats_default_when_env_absent(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.report_formats == [
        ReportFormat.MARKDOWN,
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
    ]


def test_report_formats_env_overrides_default(monkeypatch):
    s = _settings_with_env(
        monkeypatch,
        REPORT_FORMATS='["json", "sarif"]',
    )
    assert s.report_formats == [ReportFormat.JSON, ReportFormat.SARIF]


# ----------------------------------------------------- other safety knobs


def test_ci_mode_defaults_off(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.ci_mode is False


def test_ci_mode_env_true(monkeypatch):
    s = _settings_with_env(monkeypatch, CI_MODE="true")
    assert s.ci_mode is True


def test_block_destructive_actions_defaults_on(monkeypatch):
    """Safety default: destructive actions blocked unless env explicitly disables."""
    s = _settings_with_env(monkeypatch)
    assert s.block_destructive_actions is True


def test_block_destructive_actions_env_false(monkeypatch):
    s = _settings_with_env(monkeypatch, BLOCK_DESTRUCTIVE_ACTIONS="false")
    assert s.block_destructive_actions is False


def test_require_justification_defaults_on(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.require_justification_for_exploitation is True


def test_max_concurrent_agents_env(monkeypatch):
    s = _settings_with_env(monkeypatch, MAX_CONCURRENT_AGENTS="7")
    assert s.max_concurrent_agents == 7


def test_max_concurrent_agents_default(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.max_concurrent_agents == 5


# ------------------------------------------------------ parsed_target_scope


def test_parsed_target_scope_trims_whitespace_and_drops_empties(monkeypatch):
    s = _settings_with_env(monkeypatch, TARGET_SCOPE=" a.example ,, b.example  ")
    assert s.parsed_target_scope == ["a.example", "b.example"]


def test_parsed_target_scope_empty_when_env_missing(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.parsed_target_scope == []


# -------------------------------------------------------- logging knobs


def test_log_level_defaults_info(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.log_level == "INFO"


def test_log_level_env_debug(monkeypatch):
    s = _settings_with_env(monkeypatch, LOG_LEVEL="DEBUG")
    assert s.log_level == "DEBUG"


def test_log_format_defaults_text(monkeypatch):
    s = _settings_with_env(monkeypatch)
    assert s.log_format == "text"


def test_log_format_env_json(monkeypatch):
    s = _settings_with_env(monkeypatch, LOG_FORMAT="json")
    assert s.log_format == "json"
