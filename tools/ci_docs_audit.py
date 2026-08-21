#!/usr/bin/env python3
"""Audit local Markdown links and required user documentation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "docs/installation.md",
    "docs/configuration.md",
    "docs/agents.md",
    "docs/approval-system.md",
    "docs/reporting.md",
    "docs/ci-cd.md",
    "docs/ethics.md",
]
LINK_RE = re.compile(r"(?<!!)(?:\[[^\]]*\])\(([^)]+)\)")


def audit() -> dict[str, object]:
    errors: list[str] = []
    markdown = sorted(ROOT.rglob("*.md"))
    for required in REQUIRED:
        if not (ROOT / required).is_file():
            errors.append(f"missing required document: {required}")

    checked = 0
    for document in markdown:
        for raw_target in LINK_RE.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip().split(" ", 1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith("#"):
                continue
            relative = Path(unquote(parsed.path))
            candidate = (document.parent / relative).resolve()
            if not str(candidate).startswith(str(ROOT.resolve())):
                errors.append(f"link escapes repository: {document.relative_to(ROOT)} -> {target}")
            elif not candidate.exists():
                errors.append(f"broken local link: {document.relative_to(ROOT)} -> {target}")
            checked += 1
    return {"documents": len(markdown), "links_checked": checked, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"audited {result['documents']} documents and {result['links_checked']} links")
        for error in result["errors"]:
            print(f"ERROR: {error}")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
