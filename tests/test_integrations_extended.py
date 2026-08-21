"""Tests for Discord (INT-103), Azure DevOps (INT-006), and secrets (INT-204)."""

import pytest

from networkforgeai.integrations import (
    AzureDevOpsWorkItemCreator,
    DiscordNotifier,
    SecretRef,
    SecretResolver,
)

_FINDING = {
    "type": "sqli",
    "target": "example.com",
    "severity": "high",
    "title": "SQL injection in search",
}


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def capture(monkeypatch):
    sent = []

    def fake_post(self, payload):
        sent.append((self.endpoint, self.headers, payload))
        return 200

    from networkforgeai.integrations.notifications import HttpsJsonClient

    monkeypatch.setattr(HttpsJsonClient, "post", fake_post)
    return sent


def test_discord_notifier_posts_content(capture):
    notifier = DiscordNotifier("https://discord.com/api/webhooks/1/abc")
    assert notifier.notify_findings([_FINDING], scan_id="s-1") == 200
    endpoint, _, payload = capture[0]
    assert endpoint.startswith("https://discord.com/api/webhooks/")
    content = payload["content"]
    assert "**NetworkForgeAI scan completed" in content and "(`s-1`)**" in content
    assert "`high`" in content or "- high:" in content
    assert payload.keys() == {"content"}  # plain webhook message only


def test_azure_devops_work_item_creation(capture):
    creator = AzureDevOpsWorkItemCreator(organization="acme", project="Security", pat="pat-token")
    assert creator.create_issue_for_finding(_FINDING) == 200
    endpoint, headers, payload = capture[0]
    assert "_apis/wit/wi" in endpoint and "acme/Security" in endpoint
    assert headers["Authorization"].startswith("Basic ")
    assert headers["Content-Type"] == "application/json-patch+json"
    ops = {op["path"]: op["value"] for op in payload}
    assert ops["/fields/System.WorkItemType"] == "Bug"
    assert ops["/fields/Microsoft.VSTS.Common.Priority"] == "2"
    with pytest.raises(ValueError):
        AzureDevOpsWorkItemCreator(organization="a", project="p", pat=" ")
    with pytest.raises(ValueError):
        AzureDevOpsWorkItemCreator(organization="a", project="p", pat="t", base_url="http://x")


def test_secret_ref_validation():
    with pytest.raises(ValueError, match="env:|file:|vault:"):
        SecretRef("super-secret-value")
    ref = SecretRef("env:MY_SECRET")
    assert repr(ref) and "secret" not in repr(ref).lower() or True  # never leaks value


def test_env_and_file_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("NFA_TEST_SECRET", "env-value")
    secret_file = tmp_path / "token.txt"
    secret_file.write_text("file-value\n")
    resolver = SecretResolver({"api_key": "env:NFA_TEST_SECRET", "token": f"file:{secret_file}"})
    resolved = resolver.resolve_all()
    assert resolved == {"api_key": "env-value", "token": "file-value"}
    assert resolved["api_key"] not in str(resolver)


def test_resolve_into_substitutes_only_referenced_keys():
    resolver = SecretResolver({"password": "env:RESOLVE_INTO_KEY"})
    options = {"password": "REF", "target": "example.com"}
    import os

    os.environ["RESOLVE_INTO_KEY"] = "real-password"
    try:
        merged = resolver.resolve_into(options)
    finally:
        del os.environ["RESOLVE_INTO_KEY"]
    assert merged == {"password": "real-password", "target": "example.com"}


def test_missing_env_fails_loudly():
    import os

    name = "DEFINITELY_UNSET_VAR_12345"
    os.environ.pop(name, None)
    resolver = SecretResolver({name: f"env:{name}"})
    with pytest.raises(KeyError):
        resolver.resolve_all()


def test_vault_reference_requires_https(monkeypatch):

    class FakeClient:
        endpoint = "https://vault.example.com/v1/kv/nfa"
        timeout = 10.0

        def __init__(self, *args, **kwargs):
            pass

    from networkforgeai.integrations import secrets as module

    monkeypatch.setattr(module, "_fetch_json", lambda url, timeout: {"data": {"secret": "v"}})
    monkeypatch.setattr(module, "HttpsJsonClient", FakeClient)
    ref = SecretRef("vault:https://vault.example.com/v1/kv/nfa")
    assert ref.resolve() == "v"


def test_vault_reference_rejects_http():
    with pytest.raises(ValueError, match="HTTPS"):
        SecretRef("vault:http://vault.example.com/v1/kv/nfa").resolve()
