"""Unit tests for networkforgeai.support_bundle and --diagnose-bundle."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from networkforgeai.cli import main
from networkforgeai.support_bundle import (
    AUDIT_TAIL_LINES,
    BundleEntry,
    SupportBundle,
    build_default_bundle,
    collect_audit_tail,
    collect_config_diagnostics,
    collect_doctor_report,
    collect_tool_inventory,
    collect_versions,
    default_destination,
)

# ------------------------------------------------------------- collectors


def test_collect_versions_reports_running_environment():
    versions = collect_versions()
    assert "networkforgeai" in versions
    assert "python" in versions
    assert "platform_system" in versions


def test_collect_config_diagnostics_returns_ok_shape(monkeypatch):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    payload = collect_config_diagnostics()
    assert "ok" in payload
    assert isinstance(payload["checks"], list)
    # Secret token value must NOT appear in the bundle payload.
    assert "diagnostic-token-value" not in json.dumps(payload)


def test_collect_config_diagnostics_survives_broken_settings(monkeypatch):
    """A broken Settings() must return a stub, not raise."""

    monkeypatch.setenv("APPROVAL_MODE", "not-a-real-mode")
    payload = collect_config_diagnostics()
    assert payload["ok"] is False
    assert "error" in payload
    assert payload["checks"] == []


def test_collect_doctor_report_returns_full_report(monkeypatch, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    payload = collect_doctor_report()
    assert payload["schema_version"] == 1
    assert isinstance(payload["checks"], list)
    assert any(c["name"] == "python version" for c in payload["checks"])


def test_collect_tool_inventory_lists_registered_tools():
    inventory = collect_tool_inventory()
    assert inventory
    names = {entry["name"] for entry in inventory}
    assert "nmap" in names
    for entry in inventory:
        assert "risk_level" in entry
        assert "category" in entry


def test_collect_audit_tail_missing_file_returns_placeholder(tmp_path):
    tail = collect_audit_tail(tmp_path / "does-not-exist.jsonl")
    payload = json.loads(tail.strip())
    assert payload["status"] == "no audit log at path"


def test_collect_audit_tail_trims_to_max_lines(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        "\n".join(f'{{"event": "entry-{i}"}}' for i in range(AUDIT_TAIL_LINES + 50)),
        encoding="utf-8",
    )
    tail = collect_audit_tail(audit, max_lines=10)
    lines = [line for line in tail.splitlines() if line]
    assert len(lines) == 10
    # The kept lines are the LAST ones, not the first.
    assert lines[-1] == json.dumps({"event": f"entry-{AUDIT_TAIL_LINES + 49}"})


def test_collect_audit_tail_reports_unreadable(monkeypatch, tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text("{}\n", encoding="utf-8")

    def _boom(self, encoding="utf-8", errors="replace"):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", _boom)
    tail = collect_audit_tail(audit)
    payload = json.loads(tail.strip())
    assert payload["status"] == "unreadable"


# ------------------------------------------------------------- bundle assembly


def test_bundle_manifest_captures_every_entry():
    bundle = SupportBundle()
    bundle.add("a.txt", "hello")
    bundle.add_json("b.json", {"x": 1})
    manifest = bundle.manifest()
    assert manifest["schema_version"] == 1
    assert [e["name"] for e in manifest["entries"]] == ["a.txt", "b.json"]
    assert manifest["entries"][0]["size"] == 5


def test_bundle_write_zip_contains_manifest_and_entries(tmp_path):
    bundle = SupportBundle()
    bundle.add("one.txt", "hello world")
    bundle.add_json("two.json", {"k": "v"})
    destination = tmp_path / "bundle.zip"
    written = bundle.write_zip(destination)
    assert written == destination
    assert written.is_file()
    with zipfile.ZipFile(written) as archive:
        names = set(archive.namelist())
        assert names == {"manifest.json", "one.txt", "two.json"}
        assert archive.read("one.txt") == b"hello world"
        assert json.loads(archive.read("two.json")) == {"k": "v"}
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["tool_version"]
        assert len(manifest["entries"]) == 2


def test_bundle_write_zip_creates_parent_dirs(tmp_path):
    dest = tmp_path / "nested" / "deep" / "bundle.zip"
    SupportBundle().write_zip(dest)
    assert dest.is_file()


def test_bundle_entry_as_manifest_reports_bytes_not_chars():
    entry = BundleEntry(name="x", content="ä")  # 1 char, 2 UTF-8 bytes
    assert entry.as_manifest()["size"] == 2


def test_build_default_bundle_includes_all_expected_files(monkeypatch, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    bundle = build_default_bundle(report_directory=tmp_path)
    names = {e.name for e in bundle.entries}
    assert names == {
        "versions.json",
        "config.json",
        "doctor.json",
        "tools.json",
        "audit_tail.jsonl",
    }


def test_build_default_bundle_never_includes_dashboard_token(monkeypatch, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "s3cret-token-string")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-appear")
    bundle = build_default_bundle(report_directory=tmp_path)
    full = "\n".join(entry.content for entry in bundle.entries)
    assert "s3cret-token-string" not in full
    assert "sk-should-not-appear" not in full


def test_default_destination_uses_iso_timestamp_and_zip_suffix(tmp_path):
    dest = default_destination(tmp_path)
    assert dest.parent == tmp_path
    assert dest.name.startswith("diagnostic_bundle_")
    assert dest.suffix == ".zip"


# --------------------------------------------------------------- CLI wiring


def test_cli_diagnose_bundle_writes_a_zip(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    rc = main(["--diagnose-bundle"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "wrote support bundle" in out
    # Find the bundle the CLI wrote.
    bundles = sorted(tmp_path.glob("diagnostic_bundle_*.zip"))
    assert len(bundles) == 1
    with zipfile.ZipFile(bundles[0]) as archive:
        assert "manifest.json" in archive.namelist()
        assert "doctor.json" in archive.namelist()


def test_cli_diagnose_bundle_honours_output_dir(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    other = tmp_path / "elsewhere"
    main(["--diagnose-bundle", "--output-dir", str(other)])
    bundles = sorted(other.glob("diagnostic_bundle_*.zip"))
    assert len(bundles) == 1


def test_cli_diagnose_bundle_runs_with_broken_config(monkeypatch, tmp_path, capsys):
    """The bundle is especially useful when config is broken."""

    monkeypatch.delenv("TARGET_SCOPE", raising=False)
    rc = main(["--diagnose-bundle", "--output-dir", str(tmp_path)])
    assert rc == 0
    bundle_path = next(tmp_path.glob("diagnostic_bundle_*.zip"))
    with zipfile.ZipFile(bundle_path) as archive:
        config = json.loads(archive.read("config.json"))
        # Either the diagnostics ran and flagged target_scope as failing,
        # or Settings() itself failed to instantiate. Both are valid.
        assert config["ok"] is False
