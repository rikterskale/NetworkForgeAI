"""Diagnostic support-bundle assembly for `networkforgeai --diagnose-bundle`.

A support bundle is a single ZIP the operator can attach to a bug
report. It contains:

* ``manifest.json`` — the top-level index (list of entries, generation
  time, tool version).
* ``versions.json`` — Python + platform + package versions.
* ``config.json`` — the output of :meth:`Settings.diagnostics` (already
  secret-safe).
* ``doctor.json`` — a full run of :class:`~networkforgeai.doctor.Doctor`.
* ``tools.json`` — the registered tool inventory (name, category,
  risk).
* ``audit_tail.jsonl`` — the last ``AUDIT_TAIL_LINES`` lines of the
  approval audit log, if it exists. Approval-audit entries are the
  operator's own actions; they are safe to include verbatim.

The bundle deliberately excludes:

* Secrets (API keys, tokens, credentials). ``Settings.diagnostics``
  already omits values; this module never reads them.
* Report artifacts under ``REPORT_OUTPUT_DIR`` beyond the audit log
  tail. Findings can contain sensitive engagement data — an operator
  who needs to share them should do so explicitly.
* ``.env`` files, credentials directories, and anything else outside
  the fixed contributor set above.

This matches the "diagnostic bundle command" bullet under
``TROUBLESHOOTING — 10/10`` in ``NETWORKFORGEAI_10_10_FIX_LIST.txt``:
"collecting versions, safe configuration statuses, Docker state,
tool inventory, recent errors, scan state, and audit status while
excluding secrets and target evidence by default."
"""

from __future__ import annotations

import json
import platform
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__

AUDIT_TAIL_LINES = 200


@dataclass
class BundleEntry:
    """One file inside the support bundle."""

    name: str
    content: str

    def as_manifest(self) -> dict[str, Any]:
        return {"name": self.name, "size": len(self.content.encode("utf-8"))}


@dataclass
class SupportBundle:
    entries: list[BundleEntry] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(tz=UTC).isoformat(timespec="seconds")
    )
    tool_version: str = __version__

    def add(self, name: str, content: str) -> None:
        self.entries.append(BundleEntry(name=name, content=content))

    def add_json(self, name: str, payload: Any) -> None:
        self.entries.append(BundleEntry(name=name, content=json.dumps(payload, indent=2)))

    def manifest(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "entries": [entry.as_manifest() for entry in self.entries],
        }

    def write_zip(self, destination: Path) -> Path:
        """Write every entry plus a top-level manifest into a ZIP archive."""

        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(self.manifest(), indent=2))
            for entry in self.entries:
                archive.writestr(entry.name, entry.content)
        return destination


# --------------------------------------------------------------- collectors


def collect_versions() -> dict[str, Any]:
    return {
        "networkforgeai": __version__,
        "python": sys.version.split()[0],
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
    }


def collect_config_diagnostics() -> dict[str, Any]:
    """Return the secret-safe subset of the running configuration.

    Falls back to a stub payload if ``Settings()`` cannot be
    instantiated (e.g. a broken .env) — the bundle is *especially*
    useful when config is broken, so we must never fail hard here.
    """

    try:
        from .config import Settings

        settings = Settings()
        checks = settings.diagnostics()
    except Exception as exc:
        return {
            "ok": False,
            "error": f"cannot instantiate Settings(): {type(exc).__name__}: {exc}",
            "checks": [],
        }
    return {"ok": all(bool(c.get("ok")) for c in checks), "checks": checks}


def collect_doctor_report() -> dict[str, Any]:
    """Run the doctor and return its structured output."""

    from .doctor import Doctor

    doctor = Doctor()
    doctor.run(report_directory="./reports")
    return doctor.as_dict()


def collect_tool_inventory() -> list[dict[str, str]]:
    try:
        from .tools import get_available_tools
    except Exception as exc:  # pragma: no cover - defensive
        return [{"error": f"{type(exc).__name__}: {exc}"}]
    inventory: list[dict[str, str]] = []
    for name, tool_class in sorted(get_available_tools().items()):
        inventory.append(
            {
                "name": name,
                "risk_level": getattr(tool_class.risk_level, "value", str(tool_class.risk_level)),
                "category": getattr(tool_class.category, "value", str(tool_class.category)),
                "binary": getattr(tool_class, "name", ""),
            }
        )
    return inventory


def collect_audit_tail(audit_log: Path, *, max_lines: int = AUDIT_TAIL_LINES) -> str:
    """Return the last ``max_lines`` lines of *audit_log*, or a placeholder."""

    if not audit_log.is_file():
        return json.dumps({"status": "no audit log at path", "path": str(audit_log)}) + "\n"
    try:
        raw = audit_log.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return json.dumps({"status": "unreadable", "error": str(exc)}) + "\n"
    lines = raw.splitlines()
    return "\n".join(lines[-max_lines:]) + "\n"


def build_default_bundle(*, report_directory: Path) -> SupportBundle:
    """Assemble the standard support-bundle content set."""

    bundle = SupportBundle()
    bundle.add_json("versions.json", collect_versions())
    bundle.add_json("config.json", collect_config_diagnostics())
    bundle.add_json("doctor.json", collect_doctor_report())
    bundle.add_json("tools.json", collect_tool_inventory())
    bundle.add(
        "audit_tail.jsonl",
        collect_audit_tail(report_directory / "approval_audit.jsonl"),
    )
    return bundle


def default_destination(report_directory: Path) -> Path:
    """Return ``<report_dir>/diagnostic_bundle_<timestamp>.zip``."""

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    return report_directory / f"diagnostic_bundle_{timestamp}.zip"
