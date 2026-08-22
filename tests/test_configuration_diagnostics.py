from networkforgeai.config import Settings


def test_configuration_diagnostics_are_structured_and_secret_safe(monkeypatch):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    settings = Settings()
    checks = settings.diagnostics()
    assert all({"name", "ok", "detail"} <= set(check) for check in checks)
    rendered = str(checks)
    assert "diagnostic-token-value" not in rendered
